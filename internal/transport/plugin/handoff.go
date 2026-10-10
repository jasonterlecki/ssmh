package plugin

import (
	"encoding/json"
	"errors"
	"strings"
	"unicode/utf8"

	"ssmh/internal/ssm"
)

const (
	responseVariable = "AWS_SSM_START_SESSION_RESPONSE_SSMH"
	responsePrefix   = "AWS_SSM_START_SESSION_RESPONSE"
	// Stay below Linux's per-argument/environment-string limit even on a 4KiB
	// page system. The total launch environment/arguments need a separate budget.
	maxResponseEntry = 120 * 1024
)

// responseHandoff is exclusively a child-environment boundary. It must never be
// serialized as a command argument or diagnostic. Session launch is still pending.
type responseHandoff struct {
	entry string
}

func (h *responseHandoff) String() string {
	return "SSM plugin response handoff [authentication material redacted]"
}

func (h *responseHandoff) GoString() string { return h.String() }

func prepareHandoff(session *ssm.Session) (*responseHandoff, error) {
	invalid := errors.New("cannot prepare plugin response from an unavailable owned SSM session")
	if session == nil {
		return nil, invalid
	}
	id, stream, token := session.TransportMaterial()
	// Private Session ownership already validates these fields at Start. Refuse
	// zero/terminated objects and invalid UTF-8 instead of JSON replacing bytes in
	// authentication material. Encoding expansion is checked separately below.
	if id == "" || stream == "" || token == "" || len(id) > 128 || len(stream) > 8192 || len(token) > 65536 || !utf8.ValidString(id) || !utf8.ValidString(stream) || !utf8.ValidString(token) {
		return nil, invalid
	}
	response, err := json.Marshal(struct {
		SessionID string `json:"SessionId"`
		StreamURL string `json:"StreamUrl"`
		Token     string `json:"TokenValue"`
	}{id, stream, token})
	if err != nil || len(responseVariable)+1+len(response) > maxResponseEntry {
		return nil, errors.New("SSM plugin response exceeds the safe environment handoff limit")
	}
	return &responseHandoff{entry: responseVariable + "=" + string(response)}, nil
}

// environment uses an explicitly supplied child environment, never os.Environ or
// process-global mutation. Old response variables are removed, including aliases
// understood by the official plugin. Identity, proxy and other launch environment
// policy must be supplied by the future process layer, not inferred here.
func (h *responseHandoff) environment(base []string) ([]string, error) {
	if h == nil || h.entry == "" || base == nil {
		return nil, errors.New("plugin response requires a live handoff and explicit child environment")
	}
	if len(base) > 256 {
		return nil, errors.New("plugin child environment exceeds the handoff safety limit")
	}
	total := len(h.entry)
	result := make([]string, 0, len(base)+1)
	for _, entry := range base {
		if len(entry) > maxResponseEntry {
			return nil, errors.New("plugin child environment entry exceeds the handoff safety limit")
		}
		name, _, ok := strings.Cut(entry, "=")
		if !ok || name == "" || strings.IndexByte(entry, 0) != -1 {
			return nil, errors.New("invalid plugin child environment")
		}
		if strings.HasPrefix(name, responsePrefix) {
			continue
		}
		total += len(entry)
		if total > 256*1024 {
			return nil, errors.New("plugin child environment exceeds the handoff safety limit")
		}
		result = append(result, entry)
	}
	return append(result, h.entry), nil
}

// clear releases only this object's reference; copied child environments and Go
// string memory are not erased. The future launch layer owns their lifecycle.
func (h *responseHandoff) clear() {
	if h != nil {
		h.entry = ""
	}
}
