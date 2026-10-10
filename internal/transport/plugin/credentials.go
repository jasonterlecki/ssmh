package plugin

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
)

// credentialResponse adapts the parent's already selected SDK provider to the
// official endpoint-provider response format. It does not resolve another chain,
// snapshot a provider into child environment credentials, or open an endpoint.
// Returned bytes contain secrets and belong only on an authenticated credential
// transport, never terminal output, diagnostics, argv or disk. The relay supplies
// local transport; plugin process integration is still pending.
func credentialResponse(ctx context.Context, provider aws.CredentialsProvider) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if provider == nil {
		return nil, errors.New("selected plugin credential provider is unavailable")
	}
	// Calling the same provider/cache preserves its SDK refresh implementation.
	// A failure must never trigger a separate profile/environment lookup.
	credentials, err := provider.Retrieve(ctx)
	if err != nil {
		return nil, errors.Join(ctx.Err(), errors.New("retrieve selected plugin credentials failed"))
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	response, err := encodeCredentials(credentials, time.Now())
	if canceled := ctx.Err(); canceled != nil {
		return nil, canceled
	}
	return response, err
}

func encodeCredentials(credentials aws.Credentials, now time.Time) ([]byte, error) {
	invalid := errors.New("selected plugin credentials are invalid or expired")
	if !credentialField(credentials.AccessKeyID, 128, false) || !credentialField(credentials.SecretAccessKey, 4096, false) || !credentialField(credentials.SessionToken, 65536, true) {
		return nil, invalid
	}
	var expiration *time.Time
	if credentials.CanExpire {
		if !credentials.Expires.After(now) || credentials.Expires.Year() > 9999 {
			return nil, invalid
		}
		value := credentials.Expires.UTC()
		expiration = &value
	}
	response, err := json.Marshal(struct {
		AccessKeyID string     `json:"AccessKeyId"`
		SecretKey   string     `json:"SecretAccessKey"`
		Token       string     `json:"Token"`
		Expiration  *time.Time `json:"Expiration,omitempty"`
	}{credentials.AccessKeyID, credentials.SecretAccessKey, credentials.SessionToken, expiration})
	if err != nil || len(response) > maxResponseEntry {
		return nil, errors.New("selected plugin credential response exceeds encoding limits")
	}
	return response, nil
}

func credentialField(value string, limit int, empty bool) bool {
	if len(value) > limit || len(value) == 0 && !empty {
		return false
	}
	for i := range value {
		// AWS key/token material is printable ASCII, not terminal text. Refusing
		// non-ASCII/controls also prevents JSON replacement of invalid UTF-8.
		if value[i] < 0x21 || value[i] > 0x7e {
			return false
		}
	}
	return true
}
