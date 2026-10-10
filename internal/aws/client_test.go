package aws

import (
	"context"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	sdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/aws/aws-sdk-go-v2/service/sts/types"

	"ssmh/internal/config"
)

type fakeSTS struct {
	input *sts.AssumeRoleInput
	calls int
	err   error
}

func (f *fakeSTS) AssumeRole(_ context.Context, in *sts.AssumeRoleInput, _ ...func(*sts.Options)) (*sts.AssumeRoleOutput, error) {
	f.calls++
	f.input = in
	if f.err != nil {
		return nil, f.err
	}
	return &sts.AssumeRoleOutput{Credentials: &types.Credentials{AccessKeyId: sdk.String("synthetic-key"), SecretAccessKey: sdk.String("synthetic-secret"), SessionToken: sdk.String("synthetic-token"), Expiration: sdk.Time(time.Now().Add(time.Hour))}}, nil
}
func options() config.Options {
	return config.Options{Instance: "i-0123456789abcdef0", Backend: "auto", Timeout: 30 * time.Second, RoleARN: "arn:aws:iam::123456789012:role/Admin", ExternalID: "customer", MFASerial: "arn:aws:iam::123456789012:mfa/device", MFAToken: "123456"}
}

func TestAssumeConfigurationRefreshAndFailure(t *testing.T) {
	f := &fakeSTS{}
	o := options()
	cfg := sdk.Config{Region: "us-east-1", Credentials: credentials.NewStaticCredentialsProvider("synthetic-base", "synthetic-base-secret", "")}
	prompts := 0
	got, err := Assume(context.Background(), cfg, f, o, func() (string, error) { prompts++; return "654321", nil })
	if err != nil {
		t.Fatal(err)
	}
	if f.calls != 1 || sdk.ToString(f.input.RoleArn) != o.RoleARN || sdk.ToString(f.input.ExternalId) != "customer" || sdk.ToString(f.input.TokenCode) != "123456" || !strings.HasPrefix(sdk.ToString(f.input.RoleSessionName), "ssmh-") {
		t.Fatal("incorrect AssumeRole request")
	}
	creds, err := got.Credentials.Retrieve(context.Background())
	if err != nil || creds.AccessKeyID != "synthetic-key" || f.calls != 1 {
		t.Fatal("assumed credentials not cached")
	}
	got.Credentials.(*sdk.CredentialsCache).Invalidate()
	if _, err = got.Credentials.Retrieve(context.Background()); err != nil {
		t.Fatal(err)
	}
	if prompts != 1 || sdk.ToString(f.input.TokenCode) != "654321" {
		t.Fatal("MFA refresh reused first code")
	}
	f.err = errors.New("synthetic-secret")
	failed, err := Assume(context.Background(), cfg, f, o, nil)
	if err == nil || failed.Credentials != nil || strings.Contains(err.Error(), "synthetic-secret") {
		t.Fatal("role failure leaked or fell back")
	}
}

func TestSignedEndpointRejectedBeforeNetwork(t *testing.T) {
	for _, endpoint := range []string{"http://sts.us-east-1.amazonaws.com/", "https://sts.us-east-1.amazonaws.com.attacker.invalid/", "https://attacker.invalid/", "https://sts.us-east-1.amazonaws.com:444/"} {
		r, err := http.NewRequest("POST", endpoint, nil)
		if err != nil {
			t.Fatal(err)
		}
		r.Header.Set("Authorization", "AWS4-HMAC-SHA256 synthetic")
		if _, err = (signedTransport{http.DefaultTransport.(*http.Transport).Clone()}).RoundTrip(r); err == nil {
			t.Fatalf("accepted %s", endpoint)
		}
	}
}

func isolate(t *testing.T) {
	t.Helper()
	for _, k := range []string{"AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN", "AWS_PROFILE", "AWS_DEFAULT_PROFILE", "AWS_REGION", "AWS_DEFAULT_REGION", "AWS_ENDPOINT_URL", "AWS_ENDPOINT_URL_STS", "AWS_ROLE_ARN", "AWS_WEB_IDENTITY_TOKEN_FILE", "AWS_CONTAINER_CREDENTIALS_FULL_URI", "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI"} {
		t.Setenv(k, "")
	}
	t.Setenv("AWS_EC2_METADATA_DISABLED", "true")
	dir := t.TempDir()
	t.Setenv("AWS_CONFIG_FILE", filepath.Join(dir, "config"))
	t.Setenv("AWS_SHARED_CREDENTIALS_FILE", filepath.Join(dir, "credentials"))
}

func TestLoadRegionAndEnvironment(t *testing.T) {
	isolate(t)
	t.Setenv("AWS_ACCESS_KEY_ID", "synthetic-key")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "synthetic-secret")
	t.Setenv("AWS_REGION", "ca-central-1")
	o := options()
	o.RoleARN = ""
	o.ExternalID = ""
	o.MFASerial = ""
	o.MFAToken = ""
	cfg, err := Load(context.Background(), o, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer Close(cfg)
	transport := cfg.HTTPClient.(*http.Client).Transport.(signedTransport).base
	if transport.Protocols == nil || !transport.Protocols.HTTP1() || transport.Protocols.HTTP2() {
		t.Fatal("AWS client cannot safely perform the HTTP/1.1 WebSocket upgrade")
	}
	if cfg.Region != "ca-central-1" {
		t.Fatal("environment region ignored")
	}
	o.Region = "us-east-2"
	cfg2, err := Load(context.Background(), o, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer Close(cfg2)
	if cfg2.Region != "us-east-2" {
		t.Fatal("explicit region not preferred")
	}
	t.Setenv("AWS_REGION", "")
	o.Region = ""
	if _, err := Load(context.Background(), o, nil); err == nil {
		t.Fatal("arbitrary default region")
	}
}

func TestLoadExplicitProfile(t *testing.T) {
	isolate(t)
	// Synthetic SDK profile fixture, never real credentials.
	if err := os.WriteFile(os.Getenv("AWS_CONFIG_FILE"), []byte("[profile production]\nregion = ca-central-1\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(os.Getenv("AWS_SHARED_CREDENTIALS_FILE"), []byte("[production]\naws_access_key_id = synthetic-profile-key\naws_secret_access_key = synthetic-profile-secret\n"), 0600); err != nil {
		t.Fatal(err)
	}
	o := config.Options{Instance: "web", Profile: "production", Backend: "auto", Timeout: time.Second}
	cfg, err := Load(context.Background(), o, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer Close(cfg)
	c, err := cfg.Credentials.Retrieve(context.Background())
	if err != nil || c.AccessKeyID != "synthetic-profile-key" || cfg.Region != "ca-central-1" {
		t.Fatal("SDK profile selection failed")
	}
}

func TestLoadRejectsServiceOverride(t *testing.T) {
	isolate(t)
	t.Setenv("AWS_ACCESS_KEY_ID", "synthetic-key")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "synthetic-secret")
	t.Setenv("AWS_REGION", "ca-central-1")
	for _, key := range []string{"AWS_ENDPOINT_URL", "AWS_ENDPOINT_URL_STS", "AWS_ENDPOINT_URL_SSM", "AWS_ENDPOINT_URL_SSO", "AWS_ENDPOINT_URL_SSO_OIDC"} {
		t.Run(key, func(t *testing.T) {
			t.Setenv(key, "https://attacker.invalid")
			o := config.Options{Instance: "web", Backend: "auto", Timeout: time.Second}
			cfg, err := Load(context.Background(), o, nil)
			if err == nil || cfg.Credentials != nil || strings.Contains(err.Error(), "attacker.invalid") {
				t.Fatal("custom service endpoint accepted or exposed")
			}
		})
	}
}
