package aws

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	sdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials/ssocreds"
	"github.com/aws/aws-sdk-go-v2/service/ssooidc"
)

type ssoRefresh struct {
	calls int
	fail  bool
}

func (f *ssoRefresh) CreateToken(_ context.Context, in *ssooidc.CreateTokenInput, _ ...func(*ssooidc.Options)) (*ssooidc.CreateTokenOutput, error) {
	f.calls++
	if sdk.ToString(in.GrantType) != "refresh_token" || sdk.ToString(in.RefreshToken) != "synthetic-refresh" || sdk.ToString(in.ClientSecret) != "synthetic-client-secret" {
		return nil, errors.New("invalid synthetic refresh request")
	}
	if f.fail {
		return nil, errors.New("synthetic-auth-failure")
	}
	return &ssooidc.CreateTokenOutput{AccessToken: sdk.String("synthetic-new-access"), RefreshToken: sdk.String("synthetic-new-refresh"), ExpiresIn: 3600}, nil
}

// Verify the documented SDK-owned cache boundary, using only synthetic material.
func TestSDKSSORefreshCacheAndFailure(t *testing.T) {
	for _, mode := range []string{"refresh", "failure", "missing", "unrefreshable"} {
		t.Run(mode, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "synthetic-sso-cache.json")
			original := []byte(`{"accessToken":"synthetic-old-access","expiresAt":"2000-01-01T00:00:00Z","clientId":"synthetic-client","clientSecret":"synthetic-client-secret","refreshToken":"synthetic-refresh"}`)
			if mode == "unrefreshable" {
				original = []byte(`{"accessToken":"synthetic-old-access","expiresAt":"2000-01-01T00:00:00Z"}`)
			}
			if mode != "missing" {
				if err := os.WriteFile(path, original, 0600); err != nil {
					t.Fatal(err)
				}
			}
			api := &ssoRefresh{fail: mode == "failure"}
			provider := ssocreds.NewSSOTokenProvider(api, path)
			token, err := provider.RetrieveBearerToken(context.Background())
			if mode != "refresh" {
				if err == nil || token.Value != "" {
					t.Fatal("failed SSO refresh returned usable token")
				}
				if mode == "missing" {
					if _, e := os.Stat(path); !errors.Is(e, os.ErrNotExist) || api.calls != 0 {
						t.Fatal("missing login created cache or contacted token API")
					}
					return
				}
				content, e := os.ReadFile(path)
				if e != nil || string(content) != string(original) {
					t.Fatal("failed SSO refresh changed cached authentication material")
				}
				if mode == "unrefreshable" && api.calls != 0 {
					t.Fatal("missing refresh prerequisites contacted token API")
				}
				return
			}
			if err != nil || token.Value != "synthetic-new-access" || !token.CanExpire || api.calls != 1 {
				t.Fatal("SDK SSO refresh failed")
			}
			content, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			var updated struct{ AccessToken, RefreshToken string }
			if json.Unmarshal(content, &updated) != nil || updated.AccessToken != "synthetic-new-access" || updated.RefreshToken != "synthetic-new-refresh" {
				t.Fatal("SDK did not update its token cache")
			}
			info, err := os.Stat(path)
			if err != nil || info.Mode().Perm() != 0600 {
				t.Fatal("SDK cache refresh changed owner-only permissions")
			}
		})
	}
}
