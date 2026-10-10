package plugin

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials/endpointcreds"
)

func syntheticCredentials() aws.Credentials {
	return aws.Credentials{AccessKeyID: "SYNTHETIC-KEY", SecretAccessKey: "SYNTHETIC-SECRET", SessionToken: "SYNTHETIC-TOKEN", CanExpire: true, Expires: time.Now().Add(time.Hour), Source: "NEVER-SERIALIZE-SOURCE", AccountID: "123456789012"}
}

func TestCredentialResponseUsesSelectedSDKCache(t *testing.T) {
	var calls atomic.Int32
	selected := aws.NewCredentialsCache(aws.CredentialsProviderFunc(func(ctx context.Context) (aws.Credentials, error) {
		if ctx.Err() != nil {
			return aws.Credentials{}, ctx.Err()
		}
		credentials := syntheticCredentials()
		if calls.Add(1) > 1 {
			credentials.SessionToken = "SYNTHETIC-REFRESHED-TOKEN"
		}
		return credentials, nil
	}))
	decoder := endpointcreds.New("http://127.0.0.1/credentials", func(o *endpointcreds.Options) {
		o.HTTPClient = credentialHTTP{t: t, selected: selected}
		o.AuthorizationToken = "SYNTHETIC-LOCAL-AUTHORIZATION"
		o.Retryer = aws.NopRetryer{}
	})
	first, err := decoder.Retrieve(context.Background())
	if err != nil || !first.CanExpire || first.SessionToken != "SYNTHETIC-TOKEN" || calls.Load() != 1 {
		t.Fatal("actual SDK endpoint decoder did not receive selected expiring credentials")
	}
	selected.Invalidate() // Exercises the SDK cache's refresh path, not a new chain.
	second, err := decoder.Retrieve(context.Background())
	if err != nil || second.SessionToken != "SYNTHETIC-REFRESHED-TOKEN" || !second.CanExpire || !second.Expires.After(time.Now()) || calls.Load() != 2 {
		t.Fatal("selected SDK cache refresh was not propagated through the wire response")
	}
}

// Synthetic HTTP boundary only: no listener, socket, real credentials or AWS call.
type credentialHTTP struct {
	t        *testing.T
	selected aws.CredentialsProvider
}

func (h credentialHTTP) Do(request *http.Request) (*http.Response, error) {
	// net/http treats an unset method as GET; this SDK middleware leaves it unset
	// before handing the request to the HTTP client.
	if request.Method != "" && request.Method != http.MethodGet || request.URL.String() != "http://127.0.0.1/credentials" || request.Header.Get("Authorization") != "SYNTHETIC-LOCAL-AUTHORIZATION" {
		h.t.Fatal("unexpected SDK endpoint request")
	}
	response, err := credentialResponse(request.Context(), h.selected)
	if err != nil {
		return nil, err
	}
	return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": {"application/json"}}, Body: io.NopCloser(bytes.NewReader(response)), Request: request}, nil
}

func TestCredentialResponseFieldsAndExpiration(t *testing.T) {
	for _, expires := range []bool{false, true} {
		credentials := syntheticCredentials()
		credentials.CanExpire = expires
		response, err := encodeCredentials(credentials, time.Now())
		if err != nil {
			t.Fatal("synthetic credential encoding failed")
		}
		var decoded map[string]json.RawMessage
		if json.Unmarshal(response, &decoded) != nil {
			t.Fatal("credential response was not JSON")
		}
		expected := 3
		if expires {
			expected++
		}
		if len(decoded) != expected || decoded["AccessKeyId"] == nil || decoded["SecretAccessKey"] == nil || decoded["Token"] == nil || (decoded["Expiration"] != nil) != expires || bytes.Contains(response, []byte(credentials.Source)) || bytes.Contains(response, []byte(credentials.AccountID)) {
			t.Fatal("credential response changed or exposed non-allowlisted fields")
		}
		if expires {
			var expiration time.Time
			if json.Unmarshal(decoded["Expiration"], &expiration) != nil || !expiration.Equal(credentials.Expires) {
				t.Fatal("credential expiration was changed")
			}
		}
	}
}

func TestStaticCredentialResponseSDKDecoder(t *testing.T) {
	selected := aws.CredentialsProviderFunc(func(context.Context) (aws.Credentials, error) {
		credentials := syntheticCredentials()
		credentials.CanExpire = false
		credentials.SessionToken = ""
		return credentials, nil
	})
	decoder := endpointcreds.New("http://127.0.0.1/credentials", func(o *endpointcreds.Options) {
		o.HTTPClient = credentialHTTP{t: t, selected: selected}
		o.AuthorizationToken = "SYNTHETIC-LOCAL-AUTHORIZATION"
		o.Retryer = aws.NopRetryer{}
	})
	credentials, err := decoder.Retrieve(context.Background())
	if err != nil || credentials.CanExpire || !credentials.Expires.IsZero() || credentials.SessionToken != "" || credentials.AccessKeyID != "SYNTHETIC-KEY" || credentials.SecretAccessKey != "SYNTHETIC-SECRET" {
		t.Fatal("SDK decoder did not preserve nonexpiring key semantics")
	}
}

func TestCredentialResponseFailureAndCancellation(t *testing.T) {
	for _, test := range []struct {
		name                       string
		provider                   aws.CredentialsProvider
		cancelBefore, cancelDuring bool
	}{
		{name: "missing"},
		{name: "failure", provider: aws.CredentialsProviderFunc(func(context.Context) (aws.Credentials, error) {
			return syntheticCredentials(), errors.New("SYNTHETIC-SECRET raw provider failure")
		})},
		{name: "before", cancelBefore: true},
		{name: "during", cancelDuring: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if test.cancelBefore {
				cancel()
			}
			provider := test.provider
			if test.cancelDuring {
				provider = aws.CredentialsProviderFunc(func(context.Context) (aws.Credentials, error) { cancel(); return syntheticCredentials(), nil })
			}
			response, err := credentialResponse(ctx, provider)
			if response != nil || err == nil || strings.Contains(err.Error(), "SYNTHETIC-SECRET") {
				t.Fatal("failed/canceled retrieval returned data or exposed provider failure")
			}
			if (test.cancelBefore || test.cancelDuring) && !errors.Is(err, context.Canceled) {
				t.Fatal("credential response lost cancellation")
			}
		})
	}
}

func TestCredentialResponseValidation(t *testing.T) {
	now := time.Now()
	for _, change := range []func(*aws.Credentials){
		func(c *aws.Credentials) { c.AccessKeyID = "" },
		func(c *aws.Credentials) { c.SecretAccessKey = "" },
		func(c *aws.Credentials) { c.SessionToken = "\x00SYNTHETIC-SECRET" },
		func(c *aws.Credentials) { c.SessionToken = string([]byte{255}) },
		func(c *aws.Credentials) { c.SecretAccessKey = "secret with space" },
		func(c *aws.Credentials) { c.SessionToken = strings.Repeat("x", 65537) },
		func(c *aws.Credentials) { c.AccessKeyID = strings.Repeat("x", 129) },
		func(c *aws.Credentials) { c.SecretAccessKey = strings.Repeat("x", 4097) },
		func(c *aws.Credentials) { c.SessionToken = strings.Repeat("<", 65536) },
		func(c *aws.Credentials) { c.Expires = now },
		func(c *aws.Credentials) { c.Expires = now.Add(-time.Second) },
		func(c *aws.Credentials) { c.Expires = time.Time{} },
		func(c *aws.Credentials) { c.Expires = time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC) },
	} {
		credentials := syntheticCredentials()
		change(&credentials)
		response, err := encodeCredentials(credentials, now)
		if response != nil || err == nil || strings.Contains(err.Error(), "SYNTHETIC-SECRET") {
			t.Fatal("invalid/expired credentials accepted or exposed")
		}
	}
	// Long-lived keys can also come from a provider that rotates them using an
	// expiration time. Do not require an STS token merely because CanExpire is set.
	credentials := syntheticCredentials()
	credentials.SessionToken = ""
	if response, err := encodeCredentials(credentials, now); response == nil || err != nil {
		t.Fatal("refreshable long-lived key response rejected")
	}
}
