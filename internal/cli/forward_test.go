package cli

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	sdkaws "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ssm/types"
	"ssmh/internal/aws"
	"ssmh/internal/config"
	"ssmh/internal/ssm"
	"ssmh/internal/terminal"
)

type cliForwardListener struct {
	port     int
	closed   int
	closeErr error
}

func (l *cliForwardListener) Addr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: l.port}
}
func (*cliForwardListener) Accept() (net.Conn, error) { panic("setup must not accept local traffic") }
func (l *cliForwardListener) Close() error            { l.closed++; return l.closeErr }

func forwardDeps(t *testing.T, api *cliAPI, channel *cliChannel, listener *cliForwardListener, httpClient *idleClient) dependencies {
	t.Helper()
	d := cliDeps(api, channel, httpClient)
	d.listen = func(ctx context.Context, target config.ForwardTarget) (net.Listener, error) {
		if _, ok := ctx.Deadline(); !ok || target.LocalPort != listener.port {
			t.Fatal("listener setup lacks deadline or changed port")
		}
		return listener, nil
	}
	d.connect = func(context.Context, sdkaws.Config, *ssm.Session, string, time.Duration) (terminal.Channel, error) {
		t.Fatal("forwarding used shell transport")
		return nil, nil
	}
	d.run = func(context.Context, terminal.Channel, *os.File, *os.File, *os.File) error {
		t.Fatal("forwarding used terminal input/raw mode")
		return nil
	}
	d.connectForward = func(ctx context.Context, cfg sdkaws.Config, s *ssm.Session, target config.ForwardTarget, timeout time.Duration) (terminal.Channel, error) {
		if ctx.Err() != nil || cfg.Region != "ca-central-1" || s.HandshakeOptional() || timeout <= 0 || timeout > 30*time.Second || target.LocalPort != listener.port {
			t.Fatal("forwarding capability/setup changed")
		}
		id, _, token := s.TransportMaterial()
		if id != "unit-owned" || token != "synthetic-token" {
			t.Fatal("owned session not passed to Port transport")
		}
		return channel, nil
	}
	d.serveForward = func(ctx context.Context, c terminal.Channel, l net.Listener) error {
		if ctx.Err() != nil || l.Addr().String() != fmt.Sprintf("127.0.0.1:%d", listener.port) {
			t.Fatal("serving inherited canceled setup or wrong listener")
		}
		return errors.Join(c.Close(), l.Close())
	}
	return d
}

func TestForwardCLIModesAndNoTerminal(t *testing.T) {
	for _, tc := range []struct{ flag, value, host string }{
		{"-L", "8080:80", ""},
		{"--forward-host", "8080:database.internal:80", "database.internal"},
		{"--forward-host", "8080:[2001:db8::1]:80", "2001:db8::1"},
	} {
		for _, verbosity := range []string{"", "--quiet", "--verbose", "--debug"} {
			_, out, stderr := cliFiles(t)
			a := &cliAPI{platform: types.PlatformTypeLinux}
			c := &cliChannel{}
			l := &cliForwardListener{port: 8080}
			httpClient := &idleClient{}
			d := forwardDeps(t, a, c, l, httpClient)
			a.onCleanup = func() {
				if l.closed != 1 || !c.closed {
					t.Fatal("AWS cleanup preceded local shutdown")
				}
			}
			args := []string{"-i", cliTarget, tc.flag, tc.value, "--reason", "Maintenance"}
			if verbosity != "" {
				args = append(args, verbosity)
			}
			if err := run(context.Background(), args, nil, out, stderr, d); err != nil {
				t.Fatal(err)
			}
			if a.checks != 1 || a.starts != 1 || a.terminates != 1 || !a.cleanupActive || !c.closed || l.closed != 1 || !httpClient.closed || a.documentRequest != nil {
				t.Fatal("forwarding lifecycle or document boundary changed")
			}
			wantDoc := "AWS-StartPortForwardingSession"
			params := map[string][]string{"portNumber": {"80"}, "localPortNumber": {"8080"}}
			if tc.host != "" {
				wantDoc += "ToRemoteHost"
				params["host"] = []string{tc.host}
			}
			if sdkaws.ToString(a.request.DocumentName) != wantDoc || sdkaws.ToString(a.request.Reason) != "Maintenance" || !reflect.DeepEqual(a.request.Parameters, params) {
				t.Fatal("CLI changed forwarding document or destination")
			}
			text := cliText(t, stderr)
			if cliText(t, out) != "" || strings.Contains(text, "synthetic-token") || strings.Contains(text, "local disconnect: Enter") {
				t.Fatal("forwarding output contaminated or misleading")
			}
			if verbosity == "--quiet" {
				if text != "" {
					t.Fatal("quiet forwarding emitted diagnostics")
				}
			} else if !strings.Contains(text, "forwarding 127.0.0.1:8080 ->") || !strings.Contains(text, "stop with Ctrl+C") {
				t.Fatal("listener/target/shutdown diagnostics missing")
			}
		}
	}
}

func TestForwardCLIFailureCleanup(t *testing.T) {
	for _, stage := range []string{"bind", "auth", "availability", "start", "channel", "nil-channel", "serve", "cleanup", "listener-close"} {
		t.Run(stage, func(t *testing.T) {
			_, out, stderr := cliFiles(t)
			a := &cliAPI{platform: types.PlatformTypeLinux}
			c := &cliChannel{}
			l := &cliForwardListener{port: 8080}
			httpClient := &idleClient{}
			d := forwardDeps(t, a, c, l, httpClient)
			failure := errors.New("synthetic failure")
			switch stage {
			case "bind":
				d.listen = func(context.Context, config.ForwardTarget) (net.Listener, error) { return l, failure }
			case "auth":
				d.load = func(context.Context, config.Options, aws.TokenProvider) (sdkaws.Config, error) {
					return sdkaws.Config{}, failure
				}
			case "availability":
				a.checkErr = errors.New("synthetic-token")
			case "start":
				a.startErr = errors.New("synthetic-token")
			case "channel":
				d.connectForward = func(context.Context, sdkaws.Config, *ssm.Session, config.ForwardTarget, time.Duration) (terminal.Channel, error) {
					return c, failure
				}
			case "nil-channel":
				d.connectForward = func(context.Context, sdkaws.Config, *ssm.Session, config.ForwardTarget, time.Duration) (terminal.Channel, error) {
					return nil, nil
				}
			case "serve":
				d.serveForward = func(_ context.Context, c terminal.Channel, l net.Listener) error {
					return errors.Join(failure, c.Close(), l.Close())
				}
			case "cleanup":
				a.cleanupErr = errors.New("synthetic-token")
			case "listener-close":
				l.closeErr = errors.New("synthetic-token")
			}
			a.onCleanup = func() {
				if l.closed != 1 {
					t.Fatal("listener remained open during AWS cleanup")
				}
			}
			err := run(context.Background(), []string{"-i", cliTarget, "-L", "8080:80"}, nil, out, stderr, d)
			if err == nil || l.closed != 1 || strings.Contains(err.Error(), "synthetic-token") || cliText(t, out) != "" {
				t.Fatal("forwarding failure lost, leaked or listener not closed exactly once")
			}
			owned := stage != "bind" && stage != "auth" && stage != "availability" && stage != "start"
			if owned && (a.terminates != 1 || !a.cleanupActive) || !owned && a.terminates != 0 {
				t.Fatal("incorrect owned AWS cleanup")
			}
			if stage == "bind" && a.checks != 0 || stage == "auth" && a.checks != 0 {
				t.Fatal("preflight failure continued to AWS")
			}
			if owned && stage != "nil-channel" && !c.closed {
				t.Fatal("established/partial channel leaked")
			}
		})
	}
}

func TestForwardCLICancellationAndDuration(t *testing.T) {
	for _, duringSetup := range []bool{false, true} {
		_, out, stderr := cliFiles(t)
		a := &cliAPI{platform: types.PlatformTypeLinux}
		c := &cliChannel{}
		l := &cliForwardListener{port: 8080}
		d := forwardDeps(t, a, c, l, &idleClient{})
		ctx, cancel := context.WithCancel(context.Background())
		if duringSetup {
			d.connectForward = func(ctx context.Context, _ sdkaws.Config, _ *ssm.Session, _ config.ForwardTarget, _ time.Duration) (terminal.Channel, error) {
				cancel()
				return c, ctx.Err()
			}
		} else {
			d.serveForward = func(ctx context.Context, c terminal.Channel, l net.Listener) error {
				cancel()
				<-ctx.Done()
				return errors.Join(ctx.Err(), c.Close(), l.Close())
			}
		}
		err := run(ctx, []string{"-i", cliTarget, "-L", "8080:80", "--quiet"}, nil, out, stderr, d)
		cancel()
		if !errors.Is(err, context.Canceled) || a.terminates != 1 || !a.cleanupActive || !c.closed || l.closed != 1 {
			t.Fatal("cancellation leaked local/AWS resources")
		}
	}
	_, out, stderr := cliFiles(t)
	a := &cliAPI{platform: types.PlatformTypeLinux}
	c := &cliChannel{}
	l := &cliForwardListener{port: 8080}
	d := forwardDeps(t, a, c, l, &idleClient{})
	d.serveForward = func(ctx context.Context, c terminal.Channel, l net.Listener) error {
		<-ctx.Done()
		return errors.Join(ctx.Err(), c.Close(), l.Close())
	}
	err := run(context.Background(), []string{"-i", cliTarget, "-L", "8080:80", "--duration", "30ms", "--quiet"}, nil, out, stderr, d)
	if !errors.Is(err, context.DeadlineExceeded) || a.terminates != 1 || !a.cleanupActive || l.closed != 1 || !c.closed {
		t.Fatal("duration cleanup failed")
	}
}

func TestForwardCLINoIdentityUnlessRequestedAndAuthOptions(t *testing.T) {
	_, out, stderr := cliFiles(t)
	a := &cliAPI{platform: types.PlatformTypeLinux}
	c := &cliChannel{}
	l := &cliForwardListener{port: 8080}
	d := forwardDeps(t, a, c, l, &idleClient{})
	d.identity = func(context.Context, sdkaws.Config) (aws.Identity, error) {
		t.Fatal("default forwarding made extra STS lookup")
		return aws.Identity{}, nil
	}
	d.load = func(ctx context.Context, o config.Options, _ aws.TokenProvider) (sdkaws.Config, error) {
		if o.Profile != "reviewed" || o.RoleARN != "arn:aws:iam::123456789012:role/ReviewedRole" || o.SessionName != "ForwardUnit" || o.Region != "ca-central-1" || o.ExternalID != "unit-external" {
			t.Fatal("forwarding changed selected identity/options")
		}
		if _, ok := ctx.Deadline(); !ok {
			t.Fatal("authentication lacks setup deadline")
		}
		return sdkaws.Config{Region: o.Region}, nil
	}
	err := run(context.Background(), []string{"-i", cliTarget, "-L", "8080:80", "--profile", "reviewed", "--region", "ca-central-1", "--arn", "arn:aws:iam::123456789012:role/ReviewedRole", "--session-name", "ForwardUnit", "--external-id", "unit-external"}, nil, out, stderr, d)
	if err != nil {
		t.Fatal(err)
	}
}

func TestForwardCLIFailClosedInvalidCombinations(t *testing.T) {
	for _, extra := range [][]string{{"--document", "CustomPort"}, {"--command", "echo secret"}, {"--backend", "plugin"}} {
		_, out, stderr := cliFiles(t)
		d := dependencies{load: func(context.Context, config.Options, aws.TokenProvider) (sdkaws.Config, error) {
			t.Fatal("invalid forwarding authenticated")
			return sdkaws.Config{}, nil
		}}
		err := run(context.Background(), append([]string{"-i", cliTarget, "-L", "8080:80"}, extra...), nil, out, stderr, d)
		if err == nil || ExitCode(err) != 2 || strings.Contains(err.Error(), "secret") {
			t.Fatal("invalid forwarding combination accepted/leaked")
		}
	}
}

func TestForwardCloseErrorClassification(t *testing.T) {
	for _, tc := range []struct {
		err         error
		independent bool
	}{
		{nil, false}, {context.Canceled, false}, {errors.Join(context.Canceled, context.Canceled), false},
		{fmt.Errorf("secret: %w", context.Canceled), true}, {errors.Join(context.Canceled, errors.New("secret")), true},
	} {
		if independentClose(tc.err) != tc.independent {
			t.Fatal("cleanup failure hidden")
		}
	}
}

func TestForwardRealAdapterFailureCleansOwnership(t *testing.T) {
	_, out, stderr := cliFiles(t)
	a := &cliAPI{platform: types.PlatformTypeLinux}
	c := &cliChannel{}
	l := &cliForwardListener{port: 8080}
	d := forwardDeps(t, a, c, l, &idleClient{})
	// Real native setup rejects the synthetic non-http.Client before network
	// access. It must return a true nil interface rather than a typed nil.
	d.connectForward = production().connectForward
	d.serveForward = func(context.Context, terminal.Channel, net.Listener) error {
		t.Fatal("failed Port setup reached serving")
		return nil
	}
	err := run(context.Background(), []string{"-i", cliTarget, "-L", "8080:80", "--debug"}, nil, out, stderr, d)
	if err == nil || a.starts != 1 || a.terminates != 1 || !a.cleanupActive || l.closed != 1 {
		t.Fatal("real native adapter skipped owned cleanup")
	}
	text := cliText(t, stderr)
	if strings.Contains(text, "synthetic-token") || strings.Contains(text, "wss:") || !strings.Contains(text, "WebSocket establishment failed") {
		t.Fatal("real failure leaked or lost native diagnostics")
	}
}

func TestForwardSetupBudgetClosesBoundListener(t *testing.T) {
	_, out, stderr := cliFiles(t)
	a := &cliAPI{platform: types.PlatformTypeLinux}
	l := &cliForwardListener{port: 8080}
	d := forwardDeps(t, a, &cliChannel{}, l, &idleClient{})
	d.load = func(ctx context.Context, _ config.Options, _ aws.TokenProvider) (sdkaws.Config, error) {
		<-ctx.Done()
		return sdkaws.Config{}, ctx.Err()
	}
	err := run(context.Background(), []string{"-i", cliTarget, "-L", "8080:80", "--timeout", "20ms", "--quiet"}, nil, out, stderr, d)
	if !errors.Is(err, context.DeadlineExceeded) || l.closed != 1 || a.checks != 0 || a.starts != 0 || a.terminates != 0 {
		t.Fatal("setup timeout leaked listener or continued AWS lifecycle")
	}
}

func TestForwardDisablesMFAThroughoutServingAndCleanup(t *testing.T) {
	_, out, stderr := cliFiles(t)
	a := &cliAPI{platform: types.PlatformTypeLinux}
	l := &cliForwardListener{port: 8080}
	d := forwardDeps(t, a, &cliChannel{}, l, &idleClient{})
	var prompt aws.TokenProvider
	d.load = func(_ context.Context, _ config.Options, p aws.TokenProvider) (sdkaws.Config, error) {
		prompt = p
		return sdkaws.Config{Region: "ca-central-1"}, nil
	}
	check := func() {
		if token, err := prompt(); token != "" || err == nil {
			t.Fatal("forwarding allowed post-setup MFA terminal input")
		}
	}
	d.serveForward = func(_ context.Context, c terminal.Channel, l net.Listener) error {
		check()
		return errors.Join(c.Close(), l.Close())
	}
	a.onCleanup = check
	err := run(context.Background(), []string{"-i", cliTarget, "-L", "8080:80", "--quiet"}, nil, out, stderr, d)
	if err != nil || a.terminates != 1 {
		t.Fatal("MFA disable changed owned cleanup")
	}
}

func TestForwardDefaultDiagnosticFailureCannotSkipOwnedCleanup(t *testing.T) {
	_, out, _ := cliFiles(t)
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	defer writer.Close()
	a := &cliAPI{platform: types.PlatformTypeLinux}
	c := &cliChannel{}
	l := &cliForwardListener{port: 8080}
	d := forwardDeps(t, a, c, l, &idleClient{})
	connect := d.connectForward
	d.connectForward = func(ctx context.Context, cfg sdkaws.Config, s *ssm.Session, target config.ForwardTarget, timeout time.Duration) (terminal.Channel, error) {
		if err := reader.Close(); err != nil {
			t.Fatal(err)
		}
		return connect(ctx, cfg, s, target, timeout)
	}
	d.serveForward = func(context.Context, terminal.Channel, net.Listener) error {
		t.Fatal("failed readiness reporting reached serving")
		return nil
	}
	a.onCleanup = func() {
		if !c.closed || l.closed != 1 {
			t.Fatal("diagnostic failure delayed local cleanup")
		}
	}
	err = run(context.Background(), []string{"-i", cliTarget, "-L", "8080:80"}, nil, out, writer, d)
	if err == nil || a.starts != 1 || a.terminates != 1 || !a.cleanupActive || l.closed != 1 || !c.closed {
		t.Fatal("default diagnostic failure leaked forwarding resources")
	}
}
