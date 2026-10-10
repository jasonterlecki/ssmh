package cli

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	sdkaws "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ssm/types"
	"ssmh/internal/ssm"
	"ssmh/internal/terminal"
)

func TestShellLifecycleRequiresDocumentPreflight(t *testing.T) {
	for _, name := range []string{"", "ReviewedShell", "arn:aws:ssm:ca-central-1:123456789012:document/ReviewedShell"} {
		in, out, stderr := cliFiles(t)
		api := &cliAPI{platform: types.PlatformTypeLinux}
		d := cliDeps(api, &cliChannel{}, &idleClient{})
		d.connect = func(_ context.Context, _ sdkaws.Config, session *ssm.Session, kind string, _ time.Duration) (terminal.Channel, error) {
			if kind != "Standard_Stream" || !session.HandshakeOptional() || api.documentRequest == nil {
				t.Fatal("shell connected without authenticated preflight authorization")
			}
			return &cliChannel{}, nil
		}
		args := []string{"-i", cliTarget, "-q"}
		if name != "" {
			args = append(args, "--document", name)
		}
		if err := run(context.Background(), args, in, out, stderr, d); err != nil {
			t.Fatal(err)
		}
		expected := name
		if expected == "" {
			expected = "SSM-SessionManagerRunShell"
		}
		if sdkaws.ToString(api.documentRequest.Name) != expected || sdkaws.ToString(api.request.DocumentName) != name || api.starts != 1 || api.terminates != 1 {
			t.Fatal("document selection or owned cleanup changed")
		}
	}
	for _, variant := range []struct {
		content string
		err     error
	}{
		{err: errors.New("synthetic-secret")},
		{content: `{"schemaVersion":"1.0","sessionType":"Standard_Stream","inputs":{"kmsKeyId":"synthetic-secret"}}`},
		{content: `{"schemaVersion":"1.0","sessionType":"Port","inputs":{}}`},
	} {
		in, out, stderr := cliFiles(t)
		api := &cliAPI{platform: types.PlatformTypeLinux, documentContent: variant.content, documentErr: variant.err}
		d := cliDeps(api, &cliChannel{}, &idleClient{})
		d.connect = func(context.Context, sdkaws.Config, *ssm.Session, string, time.Duration) (terminal.Channel, error) {
			t.Fatal("unsafe shell document reached native transport")
			return nil, nil
		}
		err := run(context.Background(), []string{"-i", cliTarget, "-q"}, in, out, stderr, d)
		if err == nil || strings.Contains(err.Error(), "synthetic-secret") || api.starts != 0 || api.terminates != 0 {
			t.Fatal("document failure created session or exposed content")
		}
	}
}

func TestShellKMSCapabilityAndOwnedCleanup(t *testing.T) {
	const key = "arn:aws:kms:ca-central-1:123456789012:key/12345678-1234-1234-1234-123456789abc"
	for _, fail := range []bool{false, true} {
		in, out, stderr := cliFiles(t)
		api := &cliAPI{platform: types.PlatformTypeLinux, documentContent: `{"schemaVersion":"1.0","sessionType":"Standard_Stream","inputs":{"kmsKeyId":"` + key + `"}}`}
		d := cliDeps(api, &cliChannel{}, &idleClient{})
		calls := 0
		d.connect = func(_ context.Context, cfg sdkaws.Config, session *ssm.Session, kind string, _ time.Duration) (terminal.Channel, error) {
			calls++
			if cfg.Region != "ca-central-1" || kind != "Standard_Stream" || session.HandshakeOptional() || session.ShellKMSKey() != key || api.documentRequest == nil {
				t.Fatal("CLI lost verified KMS key, config or mandatory handshake")
			}
			if fail {
				return nil, errors.New("synthetic encrypted setup failure")
			}
			return &cliChannel{}, nil
		}
		err := run(context.Background(), []string{"-i", cliTarget, "-q"}, in, out, stderr, d)
		if (err != nil) != fail || calls != 1 || api.starts != 1 || api.terminates != 1 || api.request.DocumentName != nil {
			t.Fatal("KMS CLI capability or owned cleanup/default selection changed")
		}
	}
}
