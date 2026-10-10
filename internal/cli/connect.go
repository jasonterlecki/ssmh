package cli

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"time"

	sdkaws "github.com/aws/aws-sdk-go-v2/aws"
	sdkssm "github.com/aws/aws-sdk-go-v2/service/ssm"
	"github.com/aws/aws-sdk-go-v2/service/ssm/types"
	"ssmh/internal/aws"
	"ssmh/internal/command"
	"ssmh/internal/config"
	"ssmh/internal/ec2"
	"ssmh/internal/logging"
	"ssmh/internal/ssm"
	"ssmh/internal/terminal"
	"ssmh/internal/transport/native"
)

func connect(ctx context.Context, o config.Options, input, output, stderr *os.File, d dependencies) (result error) {
	query := ec2.Query{InstanceID: o.Instance}
	if !config.InstanceID(o.Instance) {
		query = ec2.Query{Name: o.Instance}
	}
	if err := query.Validate(); err != nil {
		return usageError{err}
	}
	var serialized string
	var err error
	forwarding := o.Forward != "" || o.ForwardHost != ""
	var target config.ForwardTarget
	if forwarding {
		value := o.Forward
		if o.ForwardHost != "" {
			value = o.ForwardHost
		}
		target, err = config.ParseForward(value, o.ForwardHost != "")
		if err != nil {
			return usageError{err}
		}
		if d.listen == nil || d.connectForward == nil || d.serveForward == nil {
			return errors.New("native forwarding dependencies are unavailable")
		}
	}
	if o.Command != "" {
		serialized, err = command.SerializeShell(o.Command)
		if err != nil {
			return usageError{err}
		}
	}
	if d.ec2Client == nil {
		return errors.New("EC2 target resolution is unavailable")
	}
	// The single setup deadline also covers initial diagnostic pipe writes.
	setup, cancelSetup := context.WithTimeout(ctx, o.Timeout)
	defer cancelSetup()
	var listener *onceForwardListener
	if forwarding {
		bound, bindErr := d.listen(setup, target)
		if bound != nil {
			listener = &onceForwardListener{Listener: bound}
			defer func() { result = errors.Join(result, listener.Close()) }()
		}
		if bindErr != nil {
			return bindErr
		}
		if listener == nil {
			return errors.New("forwarding listener creation returned no listener")
		}
	}
	diagnostic := diagnostics{writer: stderr, verbose: o.Verbose, debug: o.Debug}
	if o.Debug {
		setup, diagnostic.metrics = aws.WithAPIMetrics(setup)
	}
	var diagnosticOutput *diagnosticWriter
	if o.Verbose || o.Debug || forwarding && !o.Quiet {
		stream, err := terminal.OpenStream(stderr, true)
		if err != nil {
			return errors.New("cannot initialize private diagnostic stream")
		}
		defer func() { result = errors.Join(result, stream.Close()) }()
		diagnosticOutput = &diagnosticWriter{stream: stream, ctx: setup}
		diagnostic.writer = diagnosticOutput
	}
	authStarted, err := diagnostic.begin(stageCredentials)
	if err != nil {
		return errors.Join(ctx.Err(), err)
	}
	// One establishment deadline includes authentication, EC2 resolution, availability, StartSession
	// and channel handshake. It must not become the established socket's lifetime.
	prompt := &mfaPrompt{ctx: setup, read: terminal.PromptMFA}
	defer func() { cancelSetup(); prompt.close() }()
	cfg, err := d.load(setup, o, prompt.token)
	if err == nil {
		defer aws.Close(cfg)
	}
	err = diagnostic.end(stageCredentials, authStarted, err)
	if err != nil {
		return errors.Join(ctx.Err(), err)
	}
	if o.Verbose || o.Debug {
		if err = diagnostic.credentials(cfg); err != nil {
			return err
		}
		started, err := diagnostic.begin(stageIdentity)
		if err != nil {
			return err
		}
		if d.identity == nil {
			return errors.New("AWS identity diagnostics are unavailable")
		}
		identity, identityErr := d.identity(setup, cfg)
		if err = diagnostic.end(stageIdentity, started, identityErr); err != nil {
			return errors.Join(ctx.Err(), err)
		}
		if err = diagnostic.identity(identity); err != nil {
			return err
		}
	}
	resolutionStarted, err := diagnostic.begin(stageDiscovery)
	if err != nil {
		return err
	}
	instance, err := ec2.Resolve(setup, d.ec2Client(cfg), cfg.Region, o.Instance)
	if err == nil && instance.State != "running" {
		err = errors.New("target EC2 instance is not running; check its state in the selected account and region")
	}
	if err = diagnostic.end(stageDiscovery, resolutionStarted, err); err != nil {
		return errors.Join(setup.Err(), err)
	}
	// Only the validated, unique EC2 ID crosses the SSM/session boundary. Names
	// are not session targets and never select a running duplicate implicitly.
	instanceID := instance.ID
	client := d.client(cfg)
	availabilityStarted, err := diagnostic.begin(stageAvailability)
	if err != nil {
		return err
	}
	info, err := ssm.Online(setup, client, instanceID)
	if err == nil && info.PlatformType != types.PlatformTypeLinux {
		err = errors.New("native sessions require an SSM-managed Linux instance")
	}
	err = diagnostic.end(stageAvailability, availabilityStarted, err)
	if err != nil {
		return errors.Join(ctx.Err(), err)
	}
	sessionType, operation := "Standard_Stream", "shell"
	if o.Command != "" {
		sessionType, operation = "NonInteractiveCommands", "command"
	}
	if forwarding {
		sessionType, operation = "Port", "forwarding"
	}
	if !o.Quiet {
		if _, err := fmt.Fprintf(diagnostic.writer, "ssmh: native SSM %s to %s in %s\n", operation, instanceID, logging.SafeText(cfg.Region)); err != nil {
			return errors.New("cannot write connection diagnostics")
		}
	}
	request := &sdkssm.StartSessionInput{Target: sdkaws.String(instanceID)}
	// Leaving DocumentName unset respects the account's default session document.
	if o.Document != "" {
		request.DocumentName = sdkaws.String(o.Document)
	}
	if o.Command != "" {
		if request.DocumentName == nil {
			request.DocumentName = sdkaws.String("AWS-StartNonInteractiveCommand")
		}
		request.Parameters = map[string][]string{"command": {serialized}}
	}
	if o.Reason != "" {
		request.Reason = sdkaws.String(o.Reason)
	}
	var session *ssm.Session
	var lifetimeErr error
	operationStarted := false
	sessionStarted, err := diagnostic.begin(stageSession)
	if err != nil {
		return err
	}
	if forwarding {
		session, err = ssm.StartForward(setup, client, instanceID, cfg.Region, o.Reason, target)
	} else if o.Command == "" {
		documents, ok := client.(ssm.DocumentAPI)
		if !ok {
			err = errors.New("SSM client cannot validate shell documents")
		} else {
			session, err = ssm.StartShell(setup, client, documents, request, cfg.Region)
		}
	} else {
		documents, ok := client.(ssm.DocumentAPI)
		if !ok {
			err = errors.New("SSM client cannot validate command documents")
		} else {
			session, err = ssm.StartCommand(setup, client, documents, request, cfg.Region)
		}
	}
	if session != nil {
		defer func() {
			parentErr := ctx.Err() // Snapshot before cleanup can outlive the caller.
			// Cleanup survives signal/duration/setup cancellation and never addresses
			// any session except the one owned through this successful StartSession.
			// Also forbid prompting on early channel failures: an interactive callback
			// must not outlive cleanup's independent ten-second request budget.
			cancelSetup()
			prompt.close()
			// The port is released before the independent AWS cleanup budget,
			// including failures before ownership reaches native serving.
			if listener != nil {
				result = errors.Join(result, listener.Close())
			}
			if diagnosticOutput != nil {
				diagnosticOutput.ctx = context.Background()
			}
			cleanup, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			started := time.Now()
			cleanupErr := session.Terminate(cleanup) // Cleanup precedes diagnostic output.
			result = errors.Join(result, diagnostic.termination(parentErr, lifetimeErr, result, operationStarted, o.Duration > 0), diagnostic.end(stageCleanup, started, cleanupErr))
		}()
	}
	err = diagnostic.end(stageSession, sessionStarted, err)
	if err != nil {
		return errors.Join(ctx.Err(), err)
	}
	lifetime, cancel := context.WithCancel(ctx)
	if o.Duration > 0 {
		cancel()
		lifetime, cancel = context.WithTimeout(ctx, o.Duration)
	}
	defer cancel()
	// Snapshot before our deferred cancel: normal local shutdown must not be
	// misreported as caller cancellation or expiration of the duration limit.
	defer func() { lifetimeErr = lifetime.Err() }()
	if o.Debug {
		lifetime, diagnostic.trace = native.WithTrace(lifetime)
	}
	deadline, _ := setup.Deadline()
	channelStarted, err := diagnostic.begin(stageChannel)
	if err != nil {
		return err
	}
	remaining := time.Until(deadline)
	if remaining <= 0 {
		return diagnostic.end(stageChannel, channelStarted, errors.New("SSM connection establishment timed out"))
	}
	var channel terminal.Channel
	if forwarding {
		channel, err = d.connectForward(lifetime, cfg, session, target, remaining)
	} else {
		channel, err = d.connect(lifetime, cfg, session, sessionType, remaining)
	}
	if err == nil && channel == nil {
		err = errors.New("native channel establishment returned no channel")
	}
	err = diagnostic.end(stageChannel, channelStarted, err)
	if err != nil {
		if channel != nil {
			err = errors.Join(err, channel.Close())
		}
		return errors.Join(lifetime.Err(), err)
	}
	// Serialize with any in-flight SDK refresh callback before starting terminal
	// readers. Later refresh must fail closed rather than stealing remote input.
	cancelSetup()
	prompt.close()
	if diagnosticOutput != nil {
		diagnosticOutput.ctx = context.Background()
	}
	if forwarding {
		if !o.Quiet {
			destination := "instance-local:" + strconv.Itoa(target.RemotePort)
			if target.Host != "" {
				destination = net.JoinHostPort(target.Host, strconv.Itoa(target.RemotePort))
			}
			if _, err := fmt.Fprintf(diagnostic.writer, "ssmh: forwarding %s -> %s via %s; stop with Ctrl+C (loopback is not local-user authentication)\n", target.Address(), destination, instanceID); err != nil {
				return errors.Join(errors.New("cannot write forwarding diagnostics"), channel.Close())
			}
		}
		started, err := diagnostic.begin(stageExecution)
		if err != nil {
			return errors.Join(err, channel.Close())
		}
		operationStarted = true
		return diagnostic.end(stageExecution, started, d.serveForward(lifetime, channel, listener))
	}
	// Run owns channel shutdown and terminal restoration before AWS cleanup.
	if o.Verbose || o.Debug {
		message := "ssmh: native channel established; local disconnect: Enter, then ~."
		if o.Command != "" {
			message = "ssmh: native command channel established; waiting for verified remote status"
		}
		if _, err := fmt.Fprintln(diagnostic.writer, message); err != nil {
			return errors.Join(errors.New("cannot write channel diagnostics"), channel.Close())
		}
	}
	if o.Command != "" {
		started, err := diagnostic.begin(stageExecution)
		if err != nil {
			return errors.Join(err, channel.Close())
		}
		operationStarted = true
		status, err := command.Run(lifetime, channel, output, stderr)
		return diagnostic.end(stageExecution, started, commandResult(status, err))
	}
	started, err := diagnostic.begin(stageExecution)
	if err != nil {
		return errors.Join(err, channel.Close())
	}
	operationStarted = true
	return diagnostic.end(stageExecution, started, d.run(lifetime, channel, input, output, stderr))
}
