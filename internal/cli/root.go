package cli

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"time"

	sdkaws "github.com/aws/aws-sdk-go-v2/aws"
	sdkec2 "github.com/aws/aws-sdk-go-v2/service/ec2"
	sdkssm "github.com/aws/aws-sdk-go-v2/service/ssm"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"ssmh/internal/aws"
	"ssmh/internal/command"
	"ssmh/internal/config"
	"ssmh/internal/ec2"
	"ssmh/internal/forward"
	"ssmh/internal/ssm"
	"ssmh/internal/terminal"
	"ssmh/internal/transport/native"
	"ssmh/internal/version"
)

// dependencies holds genuine SDK, channel, and terminal boundaries for tests.
// Production always uses the standard credential chain and native SSM transport.
type dependencies struct {
	load           func(context.Context, config.Options, aws.TokenProvider) (sdkaws.Config, error)
	identity       func(context.Context, sdkaws.Config) (aws.Identity, error)
	client         func(sdkaws.Config) ssm.API
	ec2Client      func(sdkaws.Config) ec2.API
	statusClient   func(sdkaws.Config) ssm.StatusAPI
	documentClient func(sdkaws.Config) ssm.DocumentAPI
	connect        func(context.Context, sdkaws.Config, *ssm.Session, string, time.Duration) (terminal.Channel, error)
	run            func(context.Context, terminal.Channel, *os.File, *os.File, *os.File) error
	listen         func(context.Context, config.ForwardTarget) (net.Listener, error)
	connectForward func(context.Context, sdkaws.Config, *ssm.Session, config.ForwardTarget, time.Duration) (terminal.Channel, error)
	serveForward   func(context.Context, terminal.Channel, net.Listener) error
}

func production() dependencies {
	return dependencies{
		load: aws.Load,
		identity: func(ctx context.Context, cfg sdkaws.Config) (aws.Identity, error) {
			return aws.ReadIdentity(ctx, sts.NewFromConfig(cfg))
		},
		client:         func(cfg sdkaws.Config) ssm.API { return sdkssm.NewFromConfig(cfg) },
		ec2Client:      func(cfg sdkaws.Config) ec2.API { return sdkec2.NewFromConfig(cfg) },
		statusClient:   func(cfg sdkaws.Config) ssm.StatusAPI { return sdkssm.NewFromConfig(cfg) },
		documentClient: func(cfg sdkaws.Config) ssm.DocumentAPI { return sdkssm.NewFromConfig(cfg) },
		connect: func(ctx context.Context, cfg sdkaws.Config, s *ssm.Session, sessionType string, timeout time.Duration) (terminal.Channel, error) {
			channel, err := native.Connect(ctx, cfg, s, sessionType, timeout)
			if channel == nil {
				// Do not box a nil *native.Channel into a non-nil interface: the
				// setup-error path must never invoke Close on a nil receiver.
				return nil, err
			}
			return channel, err
		},
		run:    terminal.Run,
		listen: forward.Listen,
		connectForward: func(ctx context.Context, cfg sdkaws.Config, s *ssm.Session, target config.ForwardTarget, timeout time.Duration) (terminal.Channel, error) {
			channel, err := native.ConnectForward(ctx, cfg, s, target, timeout)
			if channel == nil {
				return nil, err
			}
			return channel, err
		},
		serveForward: serveNativeForward,
	}
}

type usageError struct{ error }

// Run parses an invocation, lists/checks prerequisites, or opens a native session.
// Diagnostics go to stderr; stdout contains help/version, list/check data or remote output.
func Run(ctx context.Context, args []string, input, output, stderr *os.File) error {
	return run(ctx, args, input, output, stderr, production())
}

func run(ctx context.Context, args []string, input, output, stderr *os.File, d dependencies) error {
	o, err := Parse(args)
	if err != nil {
		return usageError{err}
	}
	if output == nil || stderr == nil {
		return errors.New("missing local output stream")
	}
	if o.Help {
		var help bytes.Buffer
		help.WriteString("Usage: ssmh --instance INSTANCE_ID_OR_NAME [options]\n       ssmh --alias NAME [options]\n       ssmh --aliasinit [NAME]\n       ssmh --list [--json] [filters]\n       ssmh --check --instance INSTANCE_ID_OR_NAME [--json]\n\nNative SSM shell, commands, TCP forwarding and read-only discovery/checks (development build).\nShell disconnect: Enter, then ~. ; literal tilde at line start: ~~.\n\n")
		var defaults config.Options
		Flags(&defaults, &help).PrintDefaults()
		help.WriteString("\n--command uses remote /bin/sh -c, separate output and verified exit status.\nA compatible non-elevated NonInteractiveCommands document is required; see docs/remote-commands.md.\nForwarding binds only 127.0.0.1; stop with Ctrl+C. No stdin or terminal raw mode.\nAll sessions resolve an EC2 ID or exact Name and require running plus SSM Linux/Online.\nDuplicate Names require an explicit ID; stopped duplicates are not discarded.\n--list shows SSM Online instances, defaulting to EC2 state running; filters are exact.\nListing does not prove native/Linux compatibility or StartSession permission.\n--check reads EC2/SSM/STS and the default shell document without starting a session.\nPassing prerequisites does not prove StartSession permission or data-channel connectivity.\nMFA prompting uses /dev/tty with echo disabled; never consumes redirected stdin.\nNot implemented yet: plugin backend.\n")
		if _, err := io.Copy(output, &help); err != nil {
			return errors.New("cannot write CLI help")
		}
		return nil
	}
	if o.Version {
		if _, err := fmt.Fprintln(output, version.String()); err != nil {
			return errors.New("cannot write version information")
		}
		return nil
	}
	if o.AliasInit {
		if input == nil {
			return usageError{errors.New("alias initialization requires input")}
		}
		if err := initAlias(o.AliasInitName, input, stderr); err != nil {
			return usageError{err}
		}
		return nil
	}
	if err := supported(o); err != nil {
		return usageError{err}
	}
	if o.List {
		return list(ctx, o, output, stderr, d)
	}
	if o.Check {
		return check(ctx, o, output, stderr, d)
	}
	if input == nil && o.Command == "" && o.Forward == "" && o.ForwardHost == "" {
		return errors.New("missing local input stream")
	}
	return connect(ctx, o, input, output, stderr, d)
}

func supported(o config.Options) error {
	if o.Backend == "plugin" {
		return errors.New("official plugin compatibility backend is not implemented yet; native mode never falls back")
	}
	return nil
}

type commandExit struct{ code int }

func (e commandExit) Error() string {
	return fmt.Sprintf("remote command exited with status %d", e.code)
}

func commandResult(result command.Result, err error) error {
	if err != nil {
		return err
	}
	code, known := result.ExitCode()
	if !known {
		return errors.New("remote command result is unavailable")
	}
	if code != 0 {
		return commandExit{code}
	}
	return nil
}

// ExitCode propagates verified remote status only if no local/cleanup error is
// present. Joining a remote failure with cleanup failure must not conceal it.
func ExitCode(err error) int {
	if err == nil {
		return 0
	}
	var usage usageError
	if errors.As(err, &usage) {
		return 2
	}
	if errors.Is(err, context.Canceled) {
		return 130
	}
	for {
		joined, ok := err.(interface{ Unwrap() []error })
		if !ok {
			break
		}
		children := joined.Unwrap()
		if len(children) != 1 {
			return 1
		}
		err = children[0]
	}
	if status, ok := err.(commandExit); ok {
		return status.code
	}
	return 1
}
