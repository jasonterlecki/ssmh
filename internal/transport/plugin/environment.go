package plugin

import (
	"errors"
	"path/filepath"
	"sort"
	"strings"

	"ssmh/internal/config"
)

// childEnvironment is a private process boundary, not a launch authorization.
// Entries include the relay's bearer secret; never format the entries themselves.
type childEnvironment struct {
	entries []string
	relay   *credentialServer
}

func (e *childEnvironment) String() string   { return "plugin child environment [values redacted]" }
func (e *childEnvironment) GoString() string { return e.String() }

func (e *childEnvironment) environment() ([]string, error) {
	if e == nil || len(e.entries) == 0 || e.relay == nil {
		return nil, errors.New("plugin child environment is unavailable")
	}
	if _, err := e.relay.environment(); err != nil {
		return nil, err
	}
	return append([]string(nil), e.entries...), nil
}

func (e *childEnvironment) clear() {
	if e != nil {
		clear(e.entries)
		e.entries = nil
		e.relay = nil
	}
}

// prepareChildEnvironment requires explicitly selected noncredential settings,
// never os.Environ. The future launcher must preserve resolved CA/proxy fidelity,
// pass an empty profile argument, inspect the trusted stty helper, and assemble
// the owned SSM response separately. This does not enable a plugin session.
func prepareChildEnvironment(region string, relay *credentialServer, settings []string) (*childEnvironment, error) {
	invalid := errors.New("invalid explicit plugin child settings")
	if config.Region(region) != nil || relay == nil || settings == nil || len(settings) > 16 {
		return nil, invalid
	}
	values := map[string]string{
		"AWS_CONFIG_FILE": "/dev/null", "AWS_SHARED_CREDENTIALS_FILE": "/dev/null",
		"AWS_EC2_METADATA_DISABLED": "true", "AWS_DEFAULTS_MODE": "standard",
		"AWS_REGION": region, "AWS_DEFAULT_REGION": region,
		"AWS_RETRY_MODE": "standard", "AWS_MAX_ATTEMPTS": "3",
		"LANG": "C", "LC_ALL": "C",
	}
	seen := make(map[string]bool)
	for _, entry := range settings {
		if len(entry) > 4160 {
			return nil, invalid
		}
		name, value, ok := strings.Cut(entry, "=")
		if !ok || seen[name] || !config.Text(value, 4096) {
			return nil, invalid
		}
		seen[name] = true
		switch name {
		case "PATH", "SSL_CERT_DIR":
			paths := filepath.SplitList(value)
			if len(paths) == 0 || len(paths) > 32 {
				return nil, invalid
			}
			for _, path := range paths {
				if !filepath.IsAbs(path) {
					return nil, invalid
				}
			}
		case "AWS_CA_BUNDLE", "SSL_CERT_FILE":
			if !filepath.IsAbs(value) {
				return nil, invalid
			}
		case "TERM":
			if len(value) == 0 || len(value) > 128 {
				return nil, invalid
			}
			for _, b := range []byte(value) {
				if !(b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z' || b >= '0' && b <= '9' || strings.ContainsRune("_.+-", rune(b))) {
					return nil, invalid
				}
			}
		case "LANG", "LC_ALL", "HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY", "http_proxy", "https_proxy", "no_proxy":
			// Preserve selected network/locale values unchanged. Their contents
			// are not diagnostics; proxies can include passwords. No NO_PROXY
			// exception is added here and AWS certificate checks remain enabled.
		default:
			return nil, invalid
		}
		values[name] = value
	}
	if values["PATH"] == "" {
		return nil, errors.New("plugin child requires an explicit trusted absolute PATH for its terminal helper")
	}
	endpoint, err := relay.environment()
	if err != nil {
		return nil, err
	}
	for _, entry := range endpoint {
		name, value, _ := strings.Cut(entry, "=")
		values[name] = value
	}
	names := make([]string, 0, len(values))
	for name := range values {
		names = append(names, name)
	}
	sort.Strings(names)
	result := &childEnvironment{entries: make([]string, 0, len(names)), relay: relay}
	for _, name := range names {
		result.entries = append(result.entries, name+"="+values[name])
	}
	return result, nil
}
