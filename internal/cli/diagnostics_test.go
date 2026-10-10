package cli

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	sdkaws "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ssm/types"
	"ssmh/internal/aws"
	"ssmh/internal/config"
	"ssmh/internal/ssm"
	"ssmh/internal/terminal"
	"ssmh/internal/transport/native"
)

type diagnosticProvider struct {
	t           *testing.T
	inspections int
}

func (p *diagnosticProvider) Retrieve(context.Context) (sdkaws.Credentials, error) {
	p.t.Fatal("diagnostic observation retrieved credentials")
	return sdkaws.Credentials{}, nil
}

func (p *diagnosticProvider) ProviderSources() []sdkaws.CredentialSource {
	p.inspections++
	return []sdkaws.CredentialSource{sdkaws.CredentialSourceEnvVars}
}

func TestCredentialDiagnosticsOptInWithoutRetrieval(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		provider := &diagnosticProvider{t: t}
		var output bytes.Buffer
		d := diagnostics{writer: &output, verbose: enabled}
		if err := d.credentials(sdkaws.Config{Credentials: provider}); err != nil {
			t.Fatal(err)
		}
		if enabled {
			if provider.inspections != 1 || output.String() != "ssmh: SDK credential sources: environment\n" {
				t.Fatal("incorrect credential-source observation")
			}
		} else if provider.inspections != 0 || output.Len() != 0 {
			t.Fatal("default diagnostics inspected provider metadata")
		}
	}
}

func TestDiagnosticModesIdentityAndStreamSeparation(t *testing.T) {
	for _, mode := range []string{"", "-q", "-v", "--debug"} {
		in, out, stderr := cliFiles(t)
		api := &cliAPI{platform: types.PlatformTypeLinux}
		d := cliDeps(api, &cliChannel{}, &idleClient{})
		calls := 0
		d.identity = func(ctx context.Context, cfg sdkaws.Config) (aws.Identity, error) {
			calls++
			if _, ok := ctx.Deadline(); !ok || cfg.Region != "ca-central-1" {
				t.Fatal("identity escaped setup deadline/selected config")
			}
			return aws.ReadIdentity(ctx, cliIdentityAPI{})
		}
		args := []string{"-i", cliTarget, "--reason", "synthetic-secret-reason"}
		if mode != "" {
			args = append(args, mode)
		}
		if err := run(context.Background(), args, in, out, stderr, d); err != nil {
			t.Fatal(err)
		}
		text := cliText(t, stderr)
		verbose := mode == "-v" || mode == "--debug"
		if strings.Contains(text, "SDK credential sources: unavailable\n") != verbose {
			t.Fatal("provider reporting ignored opt-in or fabricated missing metadata")
		}
		if (calls == 1) != verbose || (strings.Contains(text, "AWS account: 123456789012")) != verbose || (strings.Contains(text, "elapsed_ms=")) != (mode == "--debug") || strings.Contains(text, "synthetic-secret") || cliText(t, out) != "" {
			t.Fatal("diagnostic mode leaked data, affected stdout or performed extra identity lookup")
		}
		if verbose {
			for _, stage := range []string{"AWS authentication", "AWS caller identity", "SSM availability", "document validation and session creation", "native channel establishment", "remote operation", "owned-session cleanup"} {
				if !strings.Contains(text, stage+": completed") {
					t.Fatalf("missing completed stage %s", stage)
				}
			}
		}
		if mode == "-q" && text != "" {
			t.Fatal("quiet emitted diagnostics")
		}
	}
}

func TestIdentityDiagnosticFailurePreventsSession(t *testing.T) {
	in, out, stderr := cliFiles(t)
	api := &cliAPI{platform: types.PlatformTypeLinux}
	d := cliDeps(api, &cliChannel{}, &idleClient{})
	d.identity = func(context.Context, sdkaws.Config) (aws.Identity, error) {
		return aws.Identity{}, errors.New("allowlisted identity failure")
	}
	if err := run(context.Background(), []string{"-i", cliTarget, "-v"}, in, out, stderr, d); err == nil || api.starts != 0 || api.checks != 0 || api.terminates != 0 {
		t.Fatal("identity failure proceeded to session creation")
	}
}

func TestDiagnosticFailuresCannotSkipOwnedCleanup(t *testing.T) {
	in, out, _ := cliFiles(t)
	reader, stderr, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	defer stderr.Close()
	api := &cliAPI{platform: types.PlatformTypeLinux}
	channel := &cliChannel{}
	d := cliDeps(api, channel, &idleClient{})
	d.run = func(context.Context, terminal.Channel, *os.File, *os.File, *os.File) error {
		// Break diagnostics only after this process owns both session/channel.
		if err := reader.Close(); err != nil {
			t.Fatal(err)
		}
		return channel.Close()
	}
	err = run(context.Background(), []string{"-i", cliTarget, "--debug"}, in, out, stderr, d)
	if err == nil || !channel.closed || api.starts != 1 || api.terminates != 1 || !api.cleanupActive {
		t.Fatalf("diagnostic failure skipped cleanup: %v", err)
	}
}

func TestDiagnosticsNeverPrintRawOperationErrors(t *testing.T) {
	var output bytes.Buffer
	d := diagnostics{writer: &output, debug: true}
	secret := errors.New("synthetic-secret-token-and-url")
	if err := d.end(stageChannel, time.Now(), secret); !errors.Is(err, secret) || strings.Contains(output.String(), "synthetic-secret") || !strings.Contains(output.String(), "failed") {
		t.Fatal("stage error was printed or discarded")
	}
	var quiet bytes.Buffer
	if err := (diagnostics{writer: &quiet}).emit(stageChannel, "started", 0); err != nil || quiet.Len() != 0 {
		t.Fatal("default mode printed stages")
	}
}

func TestTerminationReasonsUseOnlyLocalEvidenceAndOptIn(t *testing.T) {
	secret := errors.New("synthetic-secret-url-token-command")
	for _, tc := range []struct {
		parent, lifetime, operation error
		started, duration           bool
		label                       string
	}{
		{nil, nil, nil, true, false, "operation returned successfully (remote completion or local disconnect)"},
		{nil, nil, secret, true, false, "operation or local reporting failed (cause omitted)"},
		{nil, nil, secret, false, false, "session setup failed"},
		{context.Canceled, nil, secret, false, false, "local cancellation requested"},
		{context.DeadlineExceeded, context.DeadlineExceeded, secret, true, true, "caller deadline exceeded"},
		{nil, context.DeadlineExceeded, secret, true, true, "local duration limit reached"},
		{nil, context.DeadlineExceeded, secret, true, false, "operation or local reporting failed (cause omitted)"},
	} {
		for _, enabled := range []bool{false, true} {
			var output bytes.Buffer
			if err := (diagnostics{writer: &output, verbose: enabled}).termination(tc.parent, tc.lifetime, tc.operation, tc.started, tc.duration); err != nil {
				t.Fatal(err)
			}
			if enabled && output.String() != "ssmh: termination reason: "+tc.label+"\n" || !enabled && output.Len() != 0 || strings.Contains(output.String(), "synthetic-secret") {
				t.Fatal("termination reason fabricated a cause, leaked data or ignored opt-in")
			}
		}
	}
}

func TestTerminationReportingFollowsOwnedCleanupAndSnapshotsDuration(t *testing.T) {
	for _, mode := range []string{"normal", "duration", "cancel", "operation-error", "channel-error", "cleanup-cancel"} {
		t.Run(mode, func(t *testing.T) {
			in, out, stderr := cliFiles(t)
			a, c := &cliAPI{platform: types.PlatformTypeLinux}, &cliChannel{}
			d := cliDeps(a, c, &idleClient{})
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			args := []string{"-i", cliTarget, "-v"}
			want := "operation returned successfully (remote completion or local disconnect)"
			switch mode {
			case "duration":
				args = append(args, "--duration", "20ms")
				want = "local duration limit reached"
				d.run = func(ctx context.Context, channel terminal.Channel, _, _, _ *os.File) error {
					<-ctx.Done()
					return errors.Join(ctx.Err(), channel.Close())
				}
			case "cancel":
				want = "local cancellation requested"
				d.run = func(ctx context.Context, channel terminal.Channel, _, _, _ *os.File) error {
					cancel()
					return errors.Join(ctx.Err(), channel.Close())
				}
			case "operation-error":
				want = "operation or local reporting failed (cause omitted)"
				d.run = func(_ context.Context, channel terminal.Channel, _, _, _ *os.File) error {
					return errors.Join(errors.New("synthetic-secret"), channel.Close())
				}
			case "channel-error":
				want = "session setup failed"
				d.connect = func(context.Context, sdkaws.Config, *ssm.Session, string, time.Duration) (terminal.Channel, error) {
					return nil, errors.New("synthetic-secret")
				}
			}
			a.onCleanup = func() {
				if strings.Contains(cliText(t, stderr), "termination reason:") {
					t.Fatal("termination reporting ran before owned cleanup")
				}
				if mode == "cleanup-cancel" {
					cancel()
				}
			}
			err := run(ctx, args, in, out, stderr, d)
			if (err == nil) != (mode == "normal" || mode == "cleanup-cancel") || a.terminates != 1 || !a.cleanupActive || cliText(t, out) != "" || !strings.Contains(cliText(t, stderr), "termination reason: "+want+"\n") || strings.Contains(cliText(t, stderr), "synthetic-secret") {
				t.Fatal("termination reason/lifetime snapshot/owned cleanup changed")
			}
		})
	}
}

func TestBlockedDiagnosticPipeIsBoundedBeforeAuthentication(t *testing.T) {
	in, out, _ := cliFiles(t)
	reader, stderr, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	defer stderr.Close()
	// Fill through a private cancellable descriptor, without changing stdio flags.
	stream, err := terminal.OpenStream(stderr, true)
	if err != nil {
		t.Fatal(err)
	}
	fill, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	err = stream.Write(fill, bytes.Repeat([]byte("x"), 1<<20))
	cancel()
	if err == nil {
		t.Fatal("test pipe was not filled")
	}
	if err := stream.Close(); err != nil {
		t.Fatal(err)
	}
	d := dependencies{load: func(context.Context, config.Options, aws.TokenProvider) (sdkaws.Config, error) {
		t.Fatal("blocked diagnostic output invoked AWS")
		return sdkaws.Config{}, nil
	}}
	started := time.Now()
	err = run(context.Background(), []string{"-i", cliTarget, "-v"}, in, out, stderr, d)
	if err == nil || time.Since(started) > 3*time.Second {
		t.Fatal("blocked diagnostic write did not fail promptly")
	}
	started = time.Now()
	err = run(context.Background(), []string{"-i", cliTarget, "-v", "--timeout", "20ms"}, in, out, stderr, d)
	if err == nil || time.Since(started) > 500*time.Millisecond {
		t.Fatal("diagnostics escaped the shorter setup deadline")
	}
	if _, err := stderr.Write([]byte{}); err != nil && err != io.ErrClosedPipe {
		t.Fatal("caller stream ownership changed")
	}
}

func TestVerboseCommandStatusAndDiagnosticCleanupFailure(t *testing.T) {
	for _, brokenCleanup := range []bool{false, true} {
		_, out, stderr := cliFiles(t)
		api := &commandAPI{cliAPI: &cliAPI{platform: types.PlatformTypeLinux}}
		channel := &commandChannel{messages: []native.Message{{PayloadType: native.Output, Payload: []byte("remote stdout")}, {PayloadType: native.ExitCode, Payload: []byte("EXIT_CODE: 42")}}}
		d := commandDeps(t, api, channel)
		var reader *os.File
		if brokenCleanup {
			var err error
			reader, stderr, err = os.Pipe()
			if err != nil {
				t.Fatal(err)
			}
			defer reader.Close()
			defer stderr.Close()
			api.onCleanup = func() {
				if err := reader.Close(); err != nil {
					t.Fatal(err)
				}
			}
		}
		err := run(context.Background(), []string{"-i", cliTarget, "-c", "synthetic-secret-command", "-v"}, nil, out, stderr, d)
		expected := 42
		if brokenCleanup {
			expected = 1
		}
		if ExitCode(err) != expected || cliText(t, out) != "remote stdout" || !channel.closed || api.terminates != 1 {
			t.Fatalf("diagnostics hid remote/local failure or skipped cleanup: %v", err)
		}
		if !brokenCleanup && strings.Contains(cliText(t, stderr), "synthetic-secret-command") {
			t.Fatal("command text entered diagnostics")
		}
	}
}
