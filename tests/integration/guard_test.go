//go:build linux

package integration

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
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/aws/smithy-go"
	"ssmh/internal/terminal"
)

type guardIdentity struct {
	account string
	err     error
	calls   int
}

func (g *guardIdentity) GetCallerIdentity(context.Context, *sts.GetCallerIdentityInput, ...func(*sts.Options)) (*sts.GetCallerIdentityOutput, error) {
	g.calls++
	return &sts.GetCallerIdentityOutput{Account: sdkaws.String(g.account), Arn: sdkaws.String("arn:aws:iam::" + g.account + ":user/synthetic")}, g.err
}

func TestExpectedAccountGuardRequiresVerifiedSelectedIdentity(t *testing.T) {
	for _, tc := range []struct {
		account string
		cause   error
		pass    bool
	}{
		{"123456789012", nil, true}, {"999999999999", nil, false}, {"unsafe-secret", nil, false},
		{"123456789012", errors.New("unsafe-secret"), false},
		{"123456789012", &smithy.GenericAPIError{Code: "AccessDenied", Message: "unsafe-secret"}, false},
		{"123456789012", &smithy.GenericAPIError{Code: "ExpiredToken", Message: "unsafe-secret"}, false},
	} {
		identity := &guardIdentity{account: tc.account, err: tc.cause}
		err := verifyLiveAccount(context.Background(), identity, "123456789012")
		if identity.calls != 1 || (err == nil) != tc.pass || err != nil && strings.Contains(err.Error(), "unsafe-secret") {
			t.Fatal("account safety guard bypassed, retried another identity, or disclosed data")
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	identity := &guardIdentity{account: "123456789012"}
	if verifyLiveAccount(ctx, identity, "123456789012") == nil || identity.calls != 0 {
		t.Fatal("canceled account guard contacted AWS or passed")
	}
}

func TestLiveOptionsGateAndValidationWithoutAWS(t *testing.T) {
	base := map[string]string{"SSMH_TEST_AWS": "shell", "SSMH_LIVE_INSTANCE": "i-0123456789abcdef0", "SSMH_LIVE_REGION": "ca-central-1", "SSMH_LIVE_ACCOUNT": "123456789012", "SSMH_LIVE_PROFILE": "approved", "SSMH_LIVE_ROLE_ARN": "arn:aws:iam::123456789012:role/ReviewedRole"}
	get := func(key string) string { return base[key] }
	for _, mode := range []string{"check", "shell", "shell-tty", "command", "forward", "forward-host"} {
		base["SSMH_TEST_AWS"] = mode
		base["SSMH_LIVE_COMMAND_DOCUMENT"] = "SafeCommand"
		base["SSMH_LIVE_FORWARD"] = "18080:12345"
		if mode == "forward-host" {
			base["SSMH_LIVE_FORWARD"] = "18080:echo.internal:12345"
		}
		o, enabled, err := readLiveOptions(get, mode)
		if err != nil || !enabled || o.account != "123456789012" || o.options.Instance != base["SSMH_LIVE_INSTANCE"] || o.options.Region != base["SSMH_LIVE_REGION"] || o.options.Profile != "approved" || o.options.RoleARN != base["SSMH_LIVE_ROLE_ARN"] {
			t.Fatal("explicit live selection changed")
		}
		if _, enabled, err := readLiveOptions(get, "different-operation"); err != nil || enabled {
			t.Fatal("opt-in authorized another live operation")
		}
	}
	base["SSMH_TEST_AWS"] = ""
	base["SSMH_LIVE_INSTANCE"] = "unsafe-secret"
	if _, enabled, err := readLiveOptions(get, "shell"); err != nil || enabled {
		t.Fatal("default tests did not skip before configuration/authentication")
	}
	for _, tc := range []struct{ mode, key, value string }{
		{"unknown", "SSMH_TEST_AWS", "unknown"}, {"shell", "SSMH_LIVE_INSTANCE", "unsafe-secret"},
		{"shell", "SSMH_LIVE_REGION", ""}, {"shell", "SSMH_LIVE_ACCOUNT", ""}, {"shell", "SSMH_LIVE_ACCOUNT", "unsafe-secret"},
		{"shell", "SSMH_LIVE_PROFILE", "unsafe-secret\n"}, {"shell", "SSMH_LIVE_ROLE_ARN", "unsafe-secret"},
		{"command", "SSMH_LIVE_COMMAND_DOCUMENT", ""}, {"command", "SSMH_LIVE_COMMAND_DOCUMENT", "unsafe-secret\n"},
		{"forward", "SSMH_LIVE_FORWARD", "80:12345"}, {"forward", "SSMH_LIVE_FORWARD", "18080:0"},
		{"forward-host", "SSMH_LIVE_FORWARD", "18080:unsafe-secret/:12345"},
	} {
		values := map[string]string{"SSMH_TEST_AWS": tc.mode, "SSMH_LIVE_INSTANCE": "i-0123456789abcdef0", "SSMH_LIVE_REGION": "ca-central-1", "SSMH_LIVE_ACCOUNT": "123456789012", "SSMH_LIVE_FORWARD": "18080:12345", "SSMH_LIVE_COMMAND_DOCUMENT": "SafeCommand"}
		values[tc.key] = tc.value
		if _, enabled, err := readLiveOptions(func(key string) string { return values[key] }, tc.mode); err == nil || enabled || strings.Contains(err.Error(), "unsafe-secret") {
			t.Fatal("invalid opt-in accepted or values exposed")
		}
	}
}

func TestCaptureOperationPrivateStreamsAndEOF(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	stdout, stderr, err := captureOperation(ctx, "probe input\n", func(_ context.Context, input, output, stderr *os.File) error {
		data, err := io.ReadAll(input)
		if err != nil || string(data) != "probe input\n" {
			return errors.New("fixed input changed or EOF missing")
		}
		_, outErr := output.Write([]byte("synthetic stdout"))
		_, errErr := stderr.Write([]byte("synthetic stderr"))
		return errors.Join(outErr, errErr)
	})
	if err != nil || string(stdout) != "synthetic stdout" || string(stderr) != "synthetic stderr" {
		t.Fatal("private capture routing/EOF failed")
	}
}

func TestCaptureOverflowCancelsOperationAndBoundsMemory(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	stdout, _, err := captureOperation(ctx, "", func(ctx context.Context, _, output, _ *os.File) error {
		stream, err := terminal.OpenStream(output, true)
		if err != nil {
			return err
		}
		defer stream.Close()
		if err := stream.Write(ctx, bytes.Repeat([]byte{'x'}, captureLimit+8192)); err != nil {
			return err
		}
		<-ctx.Done()
		return ctx.Err()
	})
	if err == nil || stdout != nil || !errors.Is(err, context.Canceled) || ctx.Err() != nil {
		t.Fatal("overflow did not bound capture and cancel just the operation")
	}
}

func TestCaptureParentCancellationJoinsCollectors(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	_, _, err := captureOperation(ctx, "", func(ctx context.Context, _, _, _ *os.File) error { <-ctx.Done(); return ctx.Err() })
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("capture cancellation was lost")
	}
	if !onlyCancellation(errors.Join(context.Canceled, context.Canceled)) || onlyCancellation(errors.Join(context.Canceled, errors.New("independent"))) || onlyCancellation(errors.New("independent")) {
		t.Fatal("independent cleanup errors masked by cancellation")
	}
}
