package doccheck

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	sdkconfig "github.com/aws/aws-sdk-go-v2/config"
	"ssmh/internal/cli"
)

// These checks parse examples without executing commands or authenticating.
func TestAuthenticationExamples(t *testing.T) {
	content, err := os.ReadFile("../../docs/authentication.md")
	if err != nil {
		t.Fatal(err)
	}
	text := string(content)
	_, after, found := strings.Cut(text, "```ini\n")
	ini, _, closed := strings.Cut(after, "\n```")
	if !found || !closed || strings.Count(text, "```ini\n") != 1 {
		t.Fatal("expected one complete SSO profile example")
	}
	path := filepath.Join(t.TempDir(), "config")
	if err := os.WriteFile(path, []byte(ini), 0600); err != nil {
		t.Fatal(err)
	}
	profile, err := sdkconfig.LoadSharedConfigProfile(context.Background(), "production", func(o *sdkconfig.LoadSharedConfigOptions) {
		o.ConfigFiles = []string{path}
		o.CredentialsFiles = []string{}
	})
	if err != nil {
		t.Fatal(err)
	}
	if profile.Region != "ca-central-1" || profile.SSOAccountID != "123456789012" || profile.SSORoleName != "RemoteAccess" || profile.SSOSessionName != "company" || profile.SSOSession == nil || profile.SSOSession.SSORegion != "us-east-1" || profile.SSOSession.SSOStartURL != "https://example.awsapps.com/start" || profile.Credentials.HasKeys() {
		t.Fatal("SSO example lost intended profile/session settings or contains credentials")
	}
	remaining, count := text, 0
	for {
		_, after, found := strings.Cut(remaining, "```sh\n")
		if !found {
			break
		}
		block, rest, closed := strings.Cut(after, "\n```")
		if !closed {
			t.Fatal("unterminated shell example")
		}
		remaining = rest
		for _, line := range strings.Split(strings.ReplaceAll(block, "\\\n", ""), "\n") {
			if line == "aws sso login --profile production" {
				continue
			}
			args := strings.Fields(line)
			if len(args) == 0 || args[0] != "./bin/ssmh" {
				t.Fatal("unexpected executable in authentication example")
			}
			opts, err := cli.Parse(args[1:])
			if err != nil {
				t.Fatal(err)
			}
			if opts.Instance != "i-0123456789abcdef0" || opts.Region != "ca-central-1" || opts.MFAToken != "" || opts.Command != "" || opts.Forward != "" || opts.List || opts.Check {
				t.Fatal("authentication example changed operation or embeds an MFA code")
			}
			count++
		}
	}
	if count != 4 {
		t.Fatal("authentication example count changed; review coverage")
	}
}
