package plugin

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	sdkconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials/endpointcreds"
)

func environmentRelay() *credentialServer {
	s := syntheticRelay(nil)
	s.lifetime = context.Background()
	return s
}

func TestChildEnvironmentExplicitIsolationAndCopies(t *testing.T) {
	s := environmentRelay()
	settings := []string{"PATH=/usr/bin:/bin", "TERM=xterm-256color", "LANG=en_US.UTF-8", "LC_ALL=en_US.UTF-8", "HTTPS_PROXY=http://proxy-user:SYNTHETIC-PROXY-PASSWORD@proxy.invalid:8080", "NO_PROXY=internal.invalid", "AWS_CA_BUNDLE=/synthetic/selected-ca.pem"}
	before := append([]string(nil), settings...)
	e, err := prepareChildEnvironment("ca-central-1", s, settings)
	if err != nil || !reflect.DeepEqual(settings, before) {
		t.Fatal("explicit settings rejected or modified")
	}
	defer e.clear()
	entries, err := e.environment()
	if err != nil {
		t.Fatal(err)
	}
	values := make(map[string]string)
	for _, entry := range entries {
		name, value, _ := strings.Cut(entry, "=")
		values[name] = value
	}
	for name, expected := range map[string]string{
		"AWS_CONFIG_FILE": "/dev/null", "AWS_SHARED_CREDENTIALS_FILE": "/dev/null",
		"AWS_EC2_METADATA_DISABLED": "true", "AWS_REGION": "ca-central-1", "AWS_DEFAULT_REGION": "ca-central-1",
		"AWS_DEFAULTS_MODE": "standard", "AWS_MAX_ATTEMPTS": "3", "AWS_RETRY_MODE": "standard",
		"AWS_CONTAINER_CREDENTIALS_FULL_URI": s.endpoint, "AWS_CONTAINER_AUTHORIZATION_TOKEN": s.token,
	} {
		if values[name] != expected {
			t.Fatalf("child identity setting %s differs", name)
		}
	}
	for _, entry := range settings {
		name, value, _ := strings.Cut(entry, "=")
		if values[name] != value {
			t.Fatal("selected noncredential setting was changed")
		}
	}
	entries[0] = "CHANGED=1"
	next, _ := e.environment()
	if next[0] == entries[0] {
		t.Fatal("caller could mutate retained child environment")
	}
	if text := fmt.Sprintf("%v %+v %#v", e, e, e); strings.Contains(text, "SYNTHETIC") || strings.Contains(text, "127.0.0.1") || strings.Contains(text, "proxy.invalid") {
		t.Fatal("environment formatting exposed values")
	}
	e.clear()
	if entries, err := e.environment(); entries != nil || err == nil {
		t.Fatal("cleared environment was usable")
	}
	(*childEnvironment)(nil).clear()
}

func TestChildEnvironmentRejectsOverridesAndBounds(t *testing.T) {
	for _, name := range []string{
		"AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN", "AWS_PROFILE", "AWS_DEFAULT_PROFILE",
		"AWS_ROLE_ARN", "AWS_ROLE_SESSION_NAME", "AWS_WEB_IDENTITY_TOKEN_FILE", "AWS_CONFIG_FILE", "AWS_SHARED_CREDENTIALS_FILE",
		"AWS_CONTAINER_CREDENTIALS_RELATIVE_URI", "AWS_CONTAINER_CREDENTIALS_FULL_URI", "AWS_CONTAINER_AUTHORIZATION_TOKEN", "AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE",
		"AWS_ENDPOINT_URL", "AWS_ENDPOINT_URL_SSM", "AWS_REGION", "AWS_DEFAULT_REGION", "AWS_EC2_METADATA_DISABLED", "AWS_DEFAULTS_MODE",
		"SSM_PLUGIN_SKIP_CLIENT_CONFIGURE", "AWS_SSM_START_SESSION_RESPONSE", "LD_PRELOAD", "LD_LIBRARY_PATH", "BASH_ENV", "HOME",
	} {
		t.Run(name, func(t *testing.T) {
			if e, err := prepareChildEnvironment("ca-central-1", environmentRelay(), []string{"PATH=/usr/bin", name + "=SYNTHETIC-SECRET"}); e != nil || err == nil || strings.Contains(err.Error(), "SYNTHETIC") {
				t.Fatal("unsafe override accepted or exposed")
			}
		})
	}
	for _, settings := range [][]string{
		nil, {}, {"PATH="}, {"PATH=relative"}, {"PATH=/usr/bin:"}, {"PATH=/usr/bin::/bin"},
		{"PATH=/usr/bin", "PATH=/bin"}, {"PATH=/usr/bin", "TERM=bad\nterm"}, {"PATH=/usr/bin", "TERM=☃"},
		{"PATH=/usr/bin", "TERM="}, {"PATH=/usr/bin", "AWS_CA_BUNDLE=relative"}, {"PATH=/usr/bin", "SSL_CERT_DIR=/absolute:relative"},
		{"PATH=/usr/bin", "HTTP_PROXY=\x00SYNTHETIC"}, {"PATH=/usr/bin", "HTTPS_PROXY=" + strings.Repeat("x", 4097)}, {strings.Repeat("x", 4161)}, make([]string, 17),
	} {
		if e, err := prepareChildEnvironment("ca-central-1", environmentRelay(), settings); e != nil || err == nil || strings.Contains(err.Error(), "SYNTHETIC") {
			t.Fatal("invalid/oversized settings accepted or exposed")
		}
	}
	if e, err := prepareChildEnvironment("", environmentRelay(), []string{"PATH=/usr/bin"}); e != nil || err == nil {
		t.Fatal("missing region accepted")
	}
	if e, err := prepareChildEnvironment("ca-central-1", nil, []string{"PATH=/usr/bin"}); e != nil || err == nil {
		t.Fatal("missing relay accepted")
	}
	s := environmentRelay()
	s.stopping = true
	if e, err := prepareChildEnvironment("ca-central-1", s, []string{"PATH=/usr/bin"}); e != nil || err == nil {
		t.Fatal("stopped relay accepted")
	}
}

type environmentHTTP struct {
	calls int
	fail  bool
}

func (h *environmentHTTP) Do(r *http.Request) (*http.Response, error) {
	if r.URL.String() != os.Getenv("AWS_CONTAINER_CREDENTIALS_FULL_URI") || r.Header.Get("Authorization") != os.Getenv("AWS_CONTAINER_AUTHORIZATION_TOKEN") {
		os.Exit(101)
	}
	h.calls++
	if h.fail {
		return &http.Response{StatusCode: 500, Header: http.Header{"Content-Type": {"application/json"}}, Body: io.NopCloser(strings.NewReader(`{"code":"CredentialUnavailable","message":"Synthetic provider failure"}`)), Request: r}, nil
	}
	credentials := syntheticCredentials()
	if h.calls == 2 {
		credentials.SessionToken = "SYNTHETIC-REFRESHED"
	}
	response, err := encodeCredentials(credentials, time.Now())
	if err != nil {
		os.Exit(102)
	}
	return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": {"application/json"}}, Body: io.NopCloser(strings.NewReader(string(response))), Request: r}, nil
}

// Resolve the actual SDK chain in a clean subprocess, never the parent's global
// environment. Before resolution, refuse any possibility of reading host profiles.
func verifyChildEnvironment(mode string) {
	if os.Getenv("AWS_CONFIG_FILE") != "/dev/null" || os.Getenv("AWS_SHARED_CREDENTIALS_FILE") != "/dev/null" || os.Getenv("AWS_EC2_METADATA_DISABLED") != "true" || os.Getenv("AWS_PROFILE") != "" || os.Getenv("AWS_ACCESS_KEY_ID") != "" || os.Getenv("AWS_SECRET_ACCESS_KEY") != "" || os.Getenv("AWS_CONTAINER_CREDENTIALS_RELATIVE_URI") != "" || os.Getenv("AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE") != "" {
		os.Exit(103)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	opts := []func(*sdkconfig.LoadOptions) error{sdkconfig.WithRegion("ca-central-1"), sdkconfig.WithRetryMaxAttempts(1)}
	// The explicit synthetic helper mode intercepts the endpoint provider's own
	// HTTP client. Generic WithHTTPClient does not configure this SDK provider.
	// Real loopback tests use its ordinary client/proxy selection unchanged.
	if mode == "synthetic" || mode == "failure" {
		opts = append(opts, sdkconfig.WithEndpointCredentialOptions(func(o *endpointcreds.Options) {
			o.HTTPClient = &environmentHTTP{fail: mode == "failure"}
			o.Retryer = aws.NopRetryer{}
		}))
	} else if mode != "tcp" {
		os.Exit(107)
	}
	cfg, err := sdkconfig.LoadDefaultConfig(ctx, opts...)
	if err != nil || cfg.Region != "ca-central-1" {
		os.Exit(104)
	}
	if mode == "failure" {
		credentials, err := cfg.Credentials.Retrieve(ctx)
		if err == nil || credentials.HasKeys() {
			os.Exit(108)
		}
		fmt.Print("child credential failure verified")
		return
	}
	for _, expected := range []string{"SYNTHETIC-TOKEN", "SYNTHETIC-REFRESHED"} {
		credentials, err := cfg.Credentials.Retrieve(ctx)
		if err != nil || credentials.SessionToken != expected || credentials.AccessKeyID != "SYNTHETIC-KEY" || credentials.SecretAccessKey != "SYNTHETIC-SECRET" || credentials.Source != "CredentialsEndpointProvider" {
			os.Exit(105)
		}
		cache, ok := cfg.Credentials.(*aws.CredentialsCache)
		if !ok {
			os.Exit(106)
		}
		cache.Invalidate()
	}
	fmt.Print("child identity environment verified")
}

func runEnvironmentChild(t *testing.T, e *childEnvironment, mode string) {
	t.Helper()
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, executable, "--verify-child-environment", mode)
	command.Env, err = e.environment()
	if err != nil {
		t.Fatal(err)
	}
	command.WaitDelay = 250 * time.Millisecond
	// The helper writes only a fixed acknowledgement; never retain raw child
	// stderr/errors or allow an unbounded subprocess-output capture.
	var output versionOutput
	command.Stdout = &output
	if err := command.Run(); err != nil {
		var exit *exec.ExitError
		if errors.As(err, &exit) {
			t.Fatalf("synthetic child SDK verification failed with status %d", exit.ExitCode())
		}
		t.Fatal("synthetic child SDK verification could not run")
	}
	expected := "child identity environment verified"
	if mode == "failure" {
		expected = "child credential failure verified"
	}
	if output.overflow || string(output.data[:output.used]) != expected {
		t.Fatal("child SDK identity environment verification failed")
	}
}

func TestChildEnvironmentSDKSubprocess(t *testing.T) {
	t.Setenv("AWS_ACCESS_KEY_ID", "SYNTHETIC-WRONG-KEY")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "SYNTHETIC-WRONG-SECRET")
	t.Setenv("AWS_PROFILE", "SYNTHETIC-WRONG-PROFILE")
	e, err := prepareChildEnvironment("ca-central-1", environmentRelay(), []string{"PATH=/usr/bin:/bin"})
	if err != nil {
		t.Fatal(err)
	}
	defer e.clear()
	runEnvironmentChild(t, e, "synthetic")
	runEnvironmentChild(t, e, "failure")
}

func TestChildEnvironmentRefusesCopiesAfterRelayStop(t *testing.T) {
	s := environmentRelay()
	e, err := prepareChildEnvironment("ca-central-1", s, []string{"PATH=/usr/bin"})
	if err != nil {
		t.Fatal(err)
	}
	defer e.clear()
	s.stopping = true
	if entries, err := e.environment(); entries != nil || err == nil {
		t.Fatal("stopped relay issued another child environment copy")
	}
}

func TestChildEnvironmentSDKSubprocessRealTCP(t *testing.T) {
	if os.Getenv("SSMH_TEST_TCP") != "1" {
		t.Skip("set SSMH_TEST_TCP=1 for child SDK credentials over loopback")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var calls atomic.Int32
	s, err := startCredentialServer(ctx, aws.CredentialsProviderFunc(func(context.Context) (aws.Credentials, error) {
		credentials := syntheticCredentials()
		if calls.Add(1) == 2 {
			credentials.SessionToken = "SYNTHETIC-REFRESHED"
		}
		return credentials, nil
	}))
	if err != nil {
		t.Fatal("start synthetic child relay failed")
	}
	t.Cleanup(func() {
		cleanup, stop := context.WithTimeout(context.Background(), time.Second)
		defer stop()
		if err := s.close(cleanup); err != nil {
			t.Error("child relay cleanup failed")
		}
	})
	e, err := prepareChildEnvironment("ca-central-1", s, []string{"PATH=/usr/bin:/bin", "HTTP_PROXY=http://127.0.0.1:1", "HTTPS_PROXY=http://127.0.0.1:1"})
	if err != nil {
		t.Fatal(err)
	}
	defer e.clear()
	runEnvironmentChild(t, e, "tcp")
	if calls.Load() != 2 {
		t.Fatal("child did not use the selected relay for both retrievals")
	}
}
