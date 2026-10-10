package cli

import (
	"context"
	"errors"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	sdkaws "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ssm/types"
	"ssmh/internal/aws"
	"ssmh/internal/config"
	"ssmh/internal/ssm"
	"ssmh/internal/terminal"
)

func TestMFAGateFreshCodesAndPermanentClose(t *testing.T) {
	var calls int
	p := &mfaPrompt{ctx: context.Background(), read: func(context.Context) (string, error) {
		calls++
		if calls == 1 {
			return "123456", nil
		}
		return "654321", nil
	}}
	first, _ := p.token()
	second, _ := p.token()
	if first == second || calls != 2 {
		t.Fatal("MFA code reused")
	}
	p.close()
	if code, err := p.token(); err == nil || code != "" || calls != 2 {
		t.Fatal("closed gate read terminal")
	}
}

func TestMFAGateDeadlineAndInFlightClose(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	started := make(chan struct{})
	var calls atomic.Int32
	p := &mfaPrompt{ctx: ctx, read: func(ctx context.Context) (string, error) {
		calls.Add(1)
		close(started)
		<-ctx.Done()
		return "", ctx.Err()
	}}
	done := make(chan error, 1)
	go func() { _, err := p.token(); done <- err }()
	<-started
	closed := make(chan struct{})
	go func() { p.close(); close(closed) }()
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatal("MFA deadline ignored")
		}
	case <-time.After(time.Second):
		t.Fatal("MFA callback leaked")
	}
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("inflight MFA close blocked")
	}
	if _, err := p.token(); err == nil || calls.Load() != 1 {
		t.Fatal("closed MFA callback retried")
	}
}

func TestCLIProvidesMFACallbackAndDisablesBeforeTerminal(t *testing.T) {
	in, out, stderr := cliFiles(t)
	api := &cliAPI{platform: types.PlatformTypeLinux}
	d := cliDeps(api, &cliChannel{}, &idleClient{})
	var prompt aws.TokenProvider
	d.load = func(_ context.Context, o config.Options, p aws.TokenProvider) (sdkaws.Config, error) {
		if o.MFASerial == "" || p == nil {
			t.Fatal("MFA provider missing")
		}
		prompt = p
		return sdkaws.Config{Region: "ca-central-1"}, nil
	}
	d.run = func(_ context.Context, c terminal.Channel, _, _, _ *os.File) error {
		if code, err := prompt(); err == nil || code != "" {
			t.Fatal("MFA prompting active during remote input")
		}
		return c.Close()
	}
	args := []string{"-i", cliTarget, "-q", "--arn", "arn:aws:iam::123456789012:role/Example", "--mfa-serial", "arn:aws:iam::123456789012:mfa/Example"}
	if err := run(context.Background(), args, in, out, stderr, d); err != nil {
		t.Fatal(err)
	}
	if api.terminates != 1 {
		t.Fatal("MFA integration changed cleanup")
	}
}

func TestMFAHandshakeFailureDisablesPromptBeforeCleanup(t *testing.T) {
	in, out, stderr := cliFiles(t)
	api := &cliAPI{platform: types.PlatformTypeLinux}
	d := cliDeps(api, &cliChannel{}, &idleClient{})
	var prompt aws.TokenProvider
	d.load = func(_ context.Context, _ config.Options, p aws.TokenProvider) (sdkaws.Config, error) {
		prompt = p
		return sdkaws.Config{Region: "ca-central-1"}, nil
	}
	d.connect = func(context.Context, sdkaws.Config, *ssm.Session, string, time.Duration) (terminal.Channel, error) {
		return nil, errors.New("synthetic handshake failure")
	}
	api.onCleanup = func() {
		code, err := prompt()
		if code != "" || err == nil || !strings.Contains(err.Error(), "disabled") {
			t.Fatal("MFA prompt active during failed-channel cleanup")
		}
	}
	if err := run(context.Background(), []string{"-i", cliTarget, "-q"}, in, out, stderr, d); err == nil || api.terminates != 1 {
		t.Fatal("failed-handshake cleanup changed")
	}
}
