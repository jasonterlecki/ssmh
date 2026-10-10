package cli

import (
	"context"
	"errors"
	"os"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/ssm/types"
	"ssmh/internal/aws"
	"ssmh/internal/config"
	"ssmh/internal/ec2"
	"ssmh/internal/ssm"
	"ssmh/internal/terminal"
)

// list never receives a session-control client or opens a native channel.
func list(ctx context.Context, o config.Options, output, stderr *os.File, d dependencies) (result error) {
	state := o.State
	if state == "" {
		state = "running"
	}
	query := ec2.Query{Name: o.Name, State: state, Tags: o.Tags}
	if err := query.Validate(); err != nil {
		return usageError{err}
	}
	if ctx == nil || d.load == nil || d.ec2Client == nil || d.statusClient == nil {
		return errors.New("read-only discovery dependencies are unavailable")
	}
	setup, cancel := context.WithTimeout(ctx, o.Timeout)
	defer cancel()
	prompt := &mfaPrompt{ctx: setup, read: terminal.PromptMFA}
	defer prompt.close()
	diagnostic := diagnostics{writer: stderr, verbose: o.Verbose, debug: o.Debug}
	if o.Debug {
		setup, diagnostic.metrics = aws.WithAPIMetrics(setup)
	}
	if o.Verbose || o.Debug {
		stream, err := terminal.OpenStream(stderr, true)
		if err != nil {
			return errors.New("cannot initialize private diagnostic stream")
		}
		defer func() { result = errors.Join(result, stream.Close()) }()
		diagnostic.writer = &diagnosticWriter{stream: stream, ctx: setup}
	}
	started, err := diagnostic.begin(stageCredentials)
	if err != nil {
		return err
	}
	cfg, err := d.load(setup, o, prompt.token)
	if err == nil {
		defer aws.Close(cfg)
	}
	if err = diagnostic.end(stageCredentials, started, err); err != nil {
		return errors.Join(ctx.Err(), err)
	}
	if o.Verbose || o.Debug {
		if err := diagnostic.credentials(cfg); err != nil {
			return err
		}
		if d.identity == nil {
			return errors.New("AWS identity diagnostics are unavailable")
		}
		started, err = diagnostic.begin(stageIdentity)
		if err != nil {
			return err
		}
		identity, identityErr := d.identity(setup, cfg)
		if err := diagnostic.end(stageIdentity, started, identityErr); err != nil {
			return errors.Join(ctx.Err(), err)
		}
		if err := diagnostic.identity(identity); err != nil {
			return err
		}
	}
	started, err = diagnostic.begin(stageDiscovery)
	if err != nil {
		return err
	}
	instances, err := ec2.Discover(setup, d.ec2Client(cfg), cfg.Region, query)
	if err = diagnostic.end(stageDiscovery, started, err); err != nil {
		return errors.Join(ctx.Err(), err)
	}
	started, err = diagnostic.begin(stageAvailability)
	if err != nil {
		return err
	}
	statuses, err := ssm.Inventory(setup, d.statusClient(cfg))
	if err = diagnostic.end(stageAvailability, started, err); err != nil {
		return errors.Join(ctx.Err(), err)
	}
	// Only EC2 metadata supplies Name/state/address. SSM supplies registration,
	// ping and platform, never an alternate target or caller identity.
	online := make(map[string]ssm.Status, len(statuses))
	for _, status := range statuses {
		if status.PingStatus == types.PingStatusOnline {
			online[status.InstanceID] = status
		}
	}
	rows := make([]listRow, 0, len(instances))
	for _, instance := range instances {
		if status, ok := online[instance.ID]; ok {
			rows = append(rows, listRow{ID: instance.ID, Name: instance.Name, State: instance.State, SSM: string(status.PingStatus), Platform: string(status.Platform), PrivateIP: instance.PrivateIP, Region: instance.Region})
		}
	}
	prompt.close() // Output cannot trigger another interactive credential callback.
	data, err := formatList(rows, o.JSON)
	if err != nil {
		return err
	}
	if err := setup.Err(); err != nil {
		return err
	}
	stream, err := terminal.OpenStream(output, true)
	if err != nil {
		return errors.New("cannot initialize private listing output stream")
	}
	defer func() { result = errors.Join(result, stream.Close()) }()
	writeCtx, stopWrite := context.WithTimeout(setup, 10*time.Second)
	defer stopWrite()
	if err := stream.Write(writeCtx, data); err != nil {
		return errors.Join(writeCtx.Err(), errors.New("cannot write listing output; discard any incomplete output"))
	}
	return setup.Err()
}
