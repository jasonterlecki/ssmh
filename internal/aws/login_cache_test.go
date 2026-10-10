package aws

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	sdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials/logincreds"
	"github.com/aws/aws-sdk-go-v2/service/signin"
	"github.com/aws/aws-sdk-go-v2/service/signin/types"
	"ssmh/internal/config"
)

// No real authentication material or private key is needed: refresh uses a
// synthetic API boundary that does not execute the DPoP signing options.
func syntheticLoginCache(t *testing.T, expiration time.Time) []byte {
	t.Helper()
	data, err := json.Marshal(map[string]any{
		"accessToken": map[string]any{
			"accessKeyId": "synthetic-login-key", "secretAccessKey": "synthetic-login-secret",
			"sessionToken": "synthetic-login-token", "accountId": "123456789012", "expiresAt": expiration,
		},
		"clientId": "synthetic-client", "refreshToken": "synthetic-refresh",
		"dpopKey": "synthetic-not-a-private-key", "tokenType": "synthetic-type",
	})
	if err != nil {
		t.Fatal("cannot encode synthetic login cache")
	}
	return data
}

type loginCacheRefresh struct {
	path              string
	removeBeforeWrite bool
	fail              bool
	calls             int
}

func (f *loginCacheRefresh) CreateOAuth2Token(ctx context.Context, input *signin.CreateOAuth2TokenInput, _ ...func(*signin.Options)) (*signin.CreateOAuth2TokenOutput, error) {
	f.calls++
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if input.TokenInput == nil || sdk.ToString(input.TokenInput.GrantType) != "refresh_token" || sdk.ToString(input.TokenInput.RefreshToken) != "synthetic-refresh" {
		return nil, errors.New("invalid synthetic login refresh")
	}
	if f.fail {
		return nil, errors.New("synthetic-private-refresh-error")
	}
	if f.removeBeforeWrite {
		// This exact test-owned file simulates cache deletion during refresh,
		// so the SDK must create a new file rather than truncate an existing one.
		if err := os.Remove(f.path); err != nil {
			return nil, errors.New("cannot remove test-owned cache")
		}
	}
	return &signin.CreateOAuth2TokenOutput{TokenOutput: &types.CreateOAuth2TokenResponseBody{
		AccessToken: &types.AccessToken{AccessKeyId: sdk.String("synthetic-new-key"),
			SecretAccessKey: sdk.String("synthetic-new-secret"), SessionToken: sdk.String("synthetic-new-token")},
		ExpiresIn: sdk.Int32(900), RefreshToken: sdk.String("synthetic-new-refresh"),
	}}, nil
}

func TestSDKLoginRefreshCachePermissionsAndFailure(t *testing.T) {
	for _, mode := range []string{"new-file", "existing-file", "failure", "missing"} {
		t.Run(mode, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "synthetic-login-cache.json")
			original := syntheticLoginCache(t, time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC))
			if mode != "missing" {
				if err := os.WriteFile(path, original, 0600); err != nil {
					t.Fatal("cannot prepare synthetic cache")
				}
				if err := os.Chmod(path, 0640); err != nil {
					t.Fatal("cannot set test-owned cache permissions")
				}
			}
			api := &loginCacheRefresh{path: path, removeBeforeWrite: mode == "new-file", fail: mode == "failure"}
			provider := logincreds.New(api, path, func(o *logincreds.Options) { o.RestrictPermissions = true })
			creds, err := provider.Retrieve(context.Background())
			if mode == "failure" || mode == "missing" {
				if err == nil || creds.AccessKeyID != "" || creds.SecretAccessKey != "" || creds.SessionToken != "" {
					t.Fatal("failed refresh returned usable credentials")
				}
				if mode == "missing" {
					if api.calls != 0 {
						t.Fatal("missing cache invoked token API")
					}
					if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
						t.Fatal("missing cache was created")
					}
					return
				}
				data, err := os.ReadFile(path)
				if err != nil || string(data) != string(original) {
					t.Fatal("failed refresh changed cached material")
				}
			} else if err != nil || creds.AccessKeyID != "synthetic-new-key" || !creds.CanExpire || api.calls != 1 {
				t.Fatal("synthetic login refresh failed")
			}
			want := os.FileMode(0640) // SDK does not repair existing permissions.
			if mode == "new-file" {
				want = 0600
			}
			info, err := os.Stat(path)
			if err != nil || info.Mode().Perm() != want {
				t.Fatal("SDK cache permission contract changed")
			}
		})
	}
}

func TestLoadLoginProfileKeepsRestrictedCachePolicy(t *testing.T) {
	isolate(t)
	cacheDir := t.TempDir()
	t.Setenv("AWS_LOGIN_CACHE_DIRECTORY", cacheDir)
	t.Setenv("AWS_RESTRICT_FILE_PERMISSIONS", "unrestricted")
	if err := os.WriteFile(os.Getenv("AWS_CONFIG_FILE"), []byte("[profile synthetic-login]\nregion = ca-central-1\nlogin_session = synthetic-session\n"), 0600); err != nil {
		t.Fatal("cannot prepare synthetic login profile")
	}
	path, err := logincreds.StandardCachedTokenFilepath("synthetic-session", cacheDir)
	if err != nil {
		t.Fatal("cannot locate synthetic cache")
	}
	if err := os.WriteFile(path, syntheticLoginCache(t, time.Now().Add(time.Hour)), 0600); err != nil {
		t.Fatal("cannot prepare synthetic login cache")
	}
	o := config.Options{Instance: "web", Profile: "synthetic-login", Backend: "auto", Timeout: time.Second}
	cfg, err := Load(context.Background(), o, nil)
	if err != nil {
		t.Fatal("SDK login profile resolution failed")
	}
	defer Close(cfg)
	creds, err := cfg.Credentials.Retrieve(context.Background())
	if err != nil || creds.AccessKeyID != "synthetic-login-key" || cfg.Region != "ca-central-1" || cfg.RestrictFilePermissions != sdk.RestrictFilePermissionsUserReadWrite {
		t.Fatal("selected login provider or owner-only cache policy changed")
	}
	t.Setenv("AWS_RESTRICT_FILE_PERMISSIONS", "synthetic-private-invalid-value")
	failed, err := Load(context.Background(), o, nil)
	if err == nil || failed.Credentials != nil || strings.Contains(err.Error(), "synthetic-private") {
		t.Fatal("invalid SDK permission setting did not fail safely")
	}
}
