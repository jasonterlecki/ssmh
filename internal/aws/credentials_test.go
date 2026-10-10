package aws

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	sdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"

	"ssmh/internal/config"
)

type sourceProvider struct {
	sources   []sdk.CredentialSource
	retrieves int
}

func (p *sourceProvider) Retrieve(context.Context) (sdk.Credentials, error) {
	p.retrieves++
	return sdk.Credentials{}, errors.New("synthetic-secret-provider-error")
}
func (p *sourceProvider) ProviderSources() []sdk.CredentialSource { return p.sources }

func TestCredentialSourcesDoNotRetrieveOrExposeRawStrings(t *testing.T) {
	p := &sourceProvider{sources: []sdk.CredentialSource{sdk.CredentialSourceProfileSourceProfile, sdk.CredentialSourceEnvVars, sdk.CredentialSourceSTSAssumeRole}}
	if got := CredentialSources(sdk.Config{Credentials: sdk.NewCredentialsCache(p)}); got != "source profile, environment, STS AssumeRole" || p.retrieves != 0 {
		t.Fatal("classification retrieved credentials or misreported SDK sources")
	}
	static := credentials.StaticCredentialsProvider{Value: sdk.Credentials{AccessKeyID: "synthetic-key", SecretAccessKey: "synthetic-secret", Source: "synthetic-secret-path\x1b[2J"}}
	if got := CredentialSources(sdk.Config{Credentials: sdk.NewCredentialsCache(static)}); got != "in-process/static" || strings.Contains(got, "synthetic-secret") {
		t.Fatal("classification inspected arbitrary credential source strings")
	}
	for _, provider := range []sdk.CredentialsProvider{nil, sdk.CredentialsProviderFunc(func(context.Context) (sdk.Credentials, error) {
		t.Fatal("classification called a provider without metadata")
		return sdk.Credentials{}, nil
	})} {
		if got := CredentialSources(sdk.Config{Credentials: provider}); got != "unavailable" {
			t.Fatal("missing metadata fabricated a provider")
		}
	}
}

func TestCredentialSourcesBoundsUnknownAndDeduplication(t *testing.T) {
	for _, sources := range [][]sdk.CredentialSource{nil, {}, {sdk.CredentialSourceUndefined}, {-1}, {1 << 30}, {sdk.CredentialSourceEnvVars, -1}, make([]sdk.CredentialSource, 33)} {
		p := &sourceProvider{sources: sources}
		if got := CredentialSources(sdk.Config{Credentials: p}); got != "unavailable" || p.retrieves != 0 {
			t.Fatal("unknown/oversized sources returned partial metadata or retrieved credentials")
		}
	}
	p := &sourceProvider{sources: make([]sdk.CredentialSource, 32)}
	for i := range p.sources {
		p.sources[i] = sdk.CredentialSourceEnvVars
	}
	if got := CredentialSources(sdk.Config{Credentials: p}); got != "environment" {
		t.Fatal("valid repeated sources were not bounded/deduplicated")
	}
	for _, test := range []struct {
		source sdk.CredentialSource
		label  string
	}{
		{sdk.CredentialSourceCode, "in-process/static"},
		{sdk.CredentialSourceEnvVars, "environment"},
		{sdk.CredentialSourceEnvVarsSTSWebIDToken, "web identity"},
		{sdk.CredentialSourceProfileSTSWebIDToken, "web identity"},
		{sdk.CredentialSourceSTSAssumeRoleWebID, "web identity"},
		{sdk.CredentialSourceSTSAssumeRole, "STS AssumeRole"},
		{sdk.CredentialSourceSTSAssumeRoleSaml, "STS SAML"},
		{sdk.CredentialSourceSTSFederationToken, "STS federation token"},
		{sdk.CredentialSourceSTSSessionToken, "STS session token"},
		{sdk.CredentialSourceProfile, "shared profile"},
		{sdk.CredentialSourceProfileSourceProfile, "source profile"},
		{sdk.CredentialSourceProfileNamedProvider, "profile credential source"},
		{sdk.CredentialSourceProfileSSO, "IAM Identity Center"},
		{sdk.CredentialSourceSSO, "IAM Identity Center"},
		{sdk.CredentialSourceProfileSSOLegacy, "IAM Identity Center (legacy)"},
		{sdk.CredentialSourceSSOLegacy, "IAM Identity Center (legacy)"},
		{sdk.CredentialSourceProfileProcess, "credential process"},
		{sdk.CredentialSourceProcess, "credential process"},
		{sdk.CredentialSourceHTTP, "HTTP credentials endpoint"},
		{sdk.CredentialSourceIMDS, "EC2 instance metadata"},
		{sdk.CredentialSourceProfileLogin, "login cache"},
		{sdk.CredentialSourceLogin, "login cache"},
	} {
		p := &sourceProvider{sources: []sdk.CredentialSource{test.source}}
		if got := CredentialSources(sdk.Config{Credentials: p}); got != test.label {
			t.Fatal("provider label changed")
		}
	}
}

func TestCredentialSourcesThroughSDKEnvironmentAndProfile(t *testing.T) {
	for _, profile := range []bool{false, true} {
		t.Run(map[bool]string{false: "environment", true: "profile"}[profile], func(t *testing.T) {
			isolate(t)
			o := config.Options{Instance: "i-0123456789abcdef0", Region: "ca-central-1", Backend: "auto", Timeout: time.Second}
			want := "environment"
			if profile {
				o.Profile = "unit"
				want = "shared profile"
				if err := os.WriteFile(os.Getenv("AWS_SHARED_CREDENTIALS_FILE"), []byte("[unit]\naws_access_key_id=synthetic-key\naws_secret_access_key=synthetic-secret\n"), 0600); err != nil {
					t.Fatal(err)
				}
			} else {
				t.Setenv("AWS_ACCESS_KEY_ID", "synthetic-key")
				t.Setenv("AWS_SECRET_ACCESS_KEY", "synthetic-secret")
			}
			cfg, err := Load(context.Background(), o, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer Close(cfg)
			if got := CredentialSources(cfg); got != want {
				t.Fatalf("real SDK provider metadata classified incorrectly: %s", got)
			}
		})
	}
}

func TestExplicitAssumeReportsFinalSDKProviderOnly(t *testing.T) {
	o := options()
	cfg, err := Assume(context.Background(), sdk.Config{}, &fakeSTS{}, o, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := CredentialSources(cfg); got != "STS AssumeRole" {
		t.Fatal("explicit role metadata was fabricated from its source identity")
	}
}
