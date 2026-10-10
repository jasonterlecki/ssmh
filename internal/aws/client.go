// Package aws centralizes SDK v2 configuration and explicit identity transitions.
package aws

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"syscall"
	"time"

	sdk "github.com/aws/aws-sdk-go-v2/aws"
	awshttp "github.com/aws/aws-sdk-go-v2/aws/transport/http"
	sdkconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/aws/smithy-go/middleware"

	"ssmh/internal/config"
	"ssmh/internal/logging"
)

// TokenProvider obtains a fresh MFA code; it must not log or persist the code.
type TokenProvider func() (string, error)

// Load loads the standard credential chain and validates credentials before returning.
// API operations respect ctx; SDK configuration file I/O can block independently.
// The caller closes the returned client's idle HTTP connections afterwards.
func Load(ctx context.Context, o config.Options, prompt TokenProvider) (sdk.Config, error) {
	if err := o.Validate(); err != nil {
		return sdk.Config{}, err
	}
	// The SDK CA resolver requires this exact builder type. Its transport guard
	// must exist before resolution, since SDK credential/default-mode clients
	// can capture copies before LoadDefaultConfig returns.
	builder := guardedBuilder()
	var transport *http.Transport
	loaded := false
	defer func() {
		if !loaded && transport != nil {
			transport.CloseIdleConnections()
		}
	}()
	// SDK-managed login refresh may create a replacement cache file. Keep new
	// files owner-only even if inherited AWS settings request unrestricted mode.
	// Existing file permissions remain SDK-owned and are not repaired here.
	opts := []func(*sdkconfig.LoadOptions) error{
		sdkconfig.WithHTTPClient(builder),
		sdkconfig.WithRetryMaxAttempts(3),
		sdkconfig.WithRestrictFilePermissions(sdk.RestrictFilePermissionsUserReadWrite),
		sdkconfig.WithAssumeRoleCredentialOptions(func(a *stscreds.AssumeRoleOptions) { a.TokenProvider = prompt }),
	}
	if metrics, ok := ctx.Value(apiMetricsKey{}).(*APIMetrics); o.Debug && ok {
		opts = append(opts, sdkconfig.WithAPIOptions([]func(*middleware.Stack) error{metrics.middleware}))
	}
	if o.Profile != "" {
		opts = append(opts, sdkconfig.WithSharedConfigProfile(o.Profile))
	}
	if o.Region != "" {
		opts = append(opts, sdkconfig.WithRegion(o.Region))
	}
	if o.CACert != "" {
		bundle, err := readCABundle(o.CACert)
		if err != nil {
			return sdk.Config{}, err
		}
		opts = append(opts, sdkconfig.WithCustomCABundle(bytes.NewReader(bundle)))
	}
	cfg, err := sdkconfig.LoadDefaultConfig(ctx, opts...)
	if err != nil {
		return sdk.Config{}, logging.Failure("load AWS configuration", err)
	}
	resolved, ok := cfg.HTTPClient.(*awshttp.BuildableClient)
	if !ok {
		return sdk.Config{}, errors.New("AWS configuration returned an unsupported HTTP client")
	}
	transport = resolved.GetTransport() // Clone includes SDK-selected CA roots.
	transport.DisableKeepAlives = false // This owned pool is closed through Close.
	cfg.HTTPClient = &http.Client{Transport: signedTransport{transport}, Timeout: 30 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("AWS HTTP redirects are not permitted") }}
	if err = config.Region(cfg.Region); err != nil {
		return sdk.Config{}, err
	}
	// Reject service endpoint overrides before any credentials are transmitted to STS.
	// Standard SDK credential-provider endpoints (IMDS/ECS/SSO) remain SDK-managed.
	if cfg.BaseEndpoint != nil {
		return sdk.Config{}, errors.New("custom AWS service endpoints are unsupported for remote access")
	}
	for _, source := range cfg.ConfigSources {
		if p, ok := source.(interface {
			GetServiceBaseEndpoint(context.Context, string) (string, bool, error)
		}); ok {
			for _, service := range []string{"STS", "SSM", "EC2", "SSO", "SSO OIDC", "Signin", "KMS"} {
				_, found, e := p.GetServiceBaseEndpoint(ctx, service)
				if e != nil || found {
					return sdk.Config{}, errors.New("custom AWS service endpoints are unsupported for remote access")
				}
			}
		}
	}
	if cfg.Credentials == nil {
		return sdk.Config{}, errors.New("AWS credential provider is unavailable")
	}
	if _, err = cfg.Credentials.Retrieve(ctx); err != nil {
		return sdk.Config{}, logging.Failure("resolve AWS credentials", err)
	}
	if o.RoleARN != "" {
		cfg, err = Assume(ctx, cfg, sts.NewFromConfig(cfg), o, prompt)
		if err != nil {
			return sdk.Config{}, err
		}
	}
	loaded = true
	return cfg, nil
}

// Explicit CA files are trusted user-selected configuration, not credential
// files. Nonblocking open refuses FIFO/device inputs without waiting for a peer.
// No contents, path or OS errors enter diagnostics; SDK parses the bounded PEM.
func readCABundle(path string) ([]byte, error) {
	const limit = 4 << 20
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, errors.New("cannot read --ca-cert PEM bundle; check the path and file permissions")
	}
	info, statErr := f.Stat()
	if statErr != nil || !info.Mode().IsRegular() || info.Size() > limit {
		if f.Close() != nil {
			return nil, errors.New("--ca-cert file rejected and its descriptor could not be closed")
		}
		return nil, errors.New("--ca-cert must refer to a regular PEM bundle no larger than 4 MiB")
	}
	bundle, readErr := io.ReadAll(io.LimitReader(f, limit+1))
	closeErr := f.Close()
	if readErr != nil || closeErr != nil || len(bundle) > limit {
		return nil, errors.New("cannot read bounded --ca-cert PEM bundle")
	}
	return bundle, nil
}

// Assume installs an SDK-refreshable role credential cache and eagerly authenticates.
// Explicit role failures never fall back to base credentials.
func Assume(ctx context.Context, cfg sdk.Config, client stscreds.AssumeRoleAPIClient, o config.Options, prompt TokenProvider) (sdk.Config, error) {
	if err := o.Validate(); err != nil {
		return sdk.Config{}, err
	}
	if o.RoleARN == "" {
		return sdk.Config{}, errors.New("an explicit role ARN is required")
	}
	if prompt != nil {
		original := prompt
		prompt = func() (string, error) {
			code, err := original()
			if err != nil {
				return "", errors.New("unable to obtain MFA code")
			}
			if len(code) != 6 {
				return "", errors.New("MFA code must contain six digits")
			}
			for _, r := range code {
				if r < '0' || r > '9' {
					return "", errors.New("MFA code must contain six digits")
				}
			}
			return code, nil
		}
	}
	name := o.SessionName
	if name == "" {
		var id [16]byte
		if _, err := rand.Read(id[:]); err != nil {
			return sdk.Config{}, errors.New("generate STS session identifier failed")
		}
		name = "ssmh-" + hex.EncodeToString(id[:])
	}
	provider := stscreds.NewAssumeRoleProvider(client, o.RoleARN, func(a *stscreds.AssumeRoleOptions) {
		a.RoleSessionName = name
		if o.ExternalID != "" {
			a.ExternalID = sdk.String(o.ExternalID)
		}
		if o.MFASerial != "" {
			a.SerialNumber = sdk.String(o.MFASerial)
			if o.MFAToken != "" {
				// A command-line MFA code is one-use. Refresh must obtain a new code.
				firstCode := o.MFAToken
				a.TokenProvider = func() (string, error) {
					if firstCode != "" {
						code := firstCode
						firstCode = ""
						return code, nil
					}
					if prompt == nil {
						return "", errors.New("fresh MFA code required")
					}
					return prompt()
				}
			} else {
				a.TokenProvider = prompt
			}
		}
	})
	cfg.Credentials = sdk.NewCredentialsCache(provider)
	if _, err := cfg.Credentials.Retrieve(ctx); err != nil {
		return sdk.Config{}, logging.Failure("assume requested IAM role", err)
	}
	return cfg, nil
}

// Close releases idle connections without affecting SDK credential refresh semantics.
func Close(cfg sdk.Config) {
	if c, ok := cfg.HTTPClient.(interface{ CloseIdleConnections() }); ok {
		c.CloseIdleConnections()
	}
}

// signedTransport prevents custom service endpoints from receiving AWS signatures.
// SDK-managed unsigned metadata credential requests retain their normal behavior.
type signedTransport struct{ base *http.Transport }

func (t signedTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if err := validateSignedRequest(r); err != nil {
		return nil, err
	}
	return t.base.RoundTrip(r)
}

func validateSignedRequest(r *http.Request) error {
	if strings.HasPrefix(r.Header.Get("Authorization"), "AWS4-") {
		host := r.URL.Hostname()
		trusted := strings.HasSuffix(host, ".amazonaws.com") || strings.HasSuffix(host, ".amazonaws.com.cn")
		if r.URL.Scheme != "https" || !trusted || r.URL.User != nil || r.URL.Port() != "" && r.URL.Port() != "443" {
			return errors.New("refusing to send AWS authentication to an unsupported endpoint")
		}
	}
	return nil
}
func (t signedTransport) CloseIdleConnections() { t.base.CloseIdleConnections() }

// guardedBuilder preserves SDK CA/profile precedence without permitting the
// builder's 307/308 redirect behavior. net/http calls Proxy to select a connection
// for every request, including pooled/direct requests, before any transmission.
// Copies made by the SDK retain this guard and use no persistent connections,
// since BuildableClient does not expose CloseIdleConnections on those copies.
func guardedBuilder() *awshttp.BuildableClient {
	return awshttp.NewBuildableClient().WithTimeout(30 * time.Second).WithTransportOptions(func(tr *http.Transport) {
		tr.Proxy = guardedProxy(tr.Proxy)
		tr.ResponseHeaderTimeout = 15 * time.Second
		tr.DisableKeepAlives = true
		tr.ForceAttemptHTTP2 = false
		tr.Protocols = new(http.Protocols)
		tr.Protocols.SetHTTP1(true)
	})
}

func guardedProxy(proxy func(*http.Request) (*url.URL, error)) func(*http.Request) (*url.URL, error) {
	return func(r *http.Request) (*url.URL, error) {
		if r.Response != nil {
			return nil, errors.New("AWS HTTP redirects are not permitted")
		}
		if err := validateSignedRequest(r); err != nil {
			return nil, err
		}
		if proxy == nil {
			return nil, nil
		}
		return proxy(r)
	}
}
