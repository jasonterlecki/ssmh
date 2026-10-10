package native

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"ssmh/internal/config"
	"ssmh/internal/ssm"
)

const (
	// Port shares the same reviewed wire capabilities as shell/commands.
	portClientVersion = wireClientVersion
	portTerminate     = 2
	portConnectError  = 3
)

// ConnectForward establishes an authenticated Port data channel for exactly the
// validated forwarding destination. It owns no local listener or AWS session
// cleanup. The caller must supply bounded mux/socket orchestration, not terminal
// I/O; channel readiness is not proof that the destination accepts connections.
func ConnectForward(ctx context.Context, cfg aws.Config, session *ssm.Session, target config.ForwardTarget, timeout time.Duration) (*Channel, error) {
	if session == nil || timeout <= 0 || timeout > 10*time.Minute {
		return nil, errors.New("invalid native forwarding setup")
	}
	id, _, _ := session.TransportMaterial()
	p, err := newPortProtocol(id, target)
	if err != nil {
		return nil, err
	}
	return connectProtocol(ctx, cfg, session, p, timeout)
}

func newPortProtocol(sessionID string, target config.ForwardTarget) (*Protocol, error) {
	if target.Validate() != nil {
		return nil, errors.New("invalid native forwarding destination")
	}
	p, err := NewProtocol(sessionID, "Standard_Stream")
	if err != nil {
		return nil, err
	}
	p.expectedType = "Port"
	p.clientVersion = portClientVersion
	p.port = &target // A private copy; remote properties cannot change it.
	return p, nil
}

// portAgentSupported uses the official plugin's strict greater-than capability
// check for disabling smux keepalives. Requiring that feature also excludes old
// basic-only agents; this client never downgrades to an unframed byte stream.
func portAgentSupported(value string) bool {
	if len(value) > 43 {
		return false
	}
	parts := strings.Split(value, ".")
	if len(parts) != 4 {
		return false
	}
	var version [4]uint32
	for i, part := range parts {
		if part == "" || len(part) > 10 || (len(part) > 1 && part[0] == '0') {
			return false
		}
		for _, ch := range part {
			if ch < '0' || ch > '9' {
				return false
			}
		}
		n, err := strconv.ParseUint(part, 10, 32)
		if err != nil {
			return false
		}
		version[i] = uint32(n)
	}
	minimum := [4]uint32{3, 1, 1511, 0}
	for i, n := range version {
		if n != minimum[i] {
			return n > minimum[i]
		}
	}
	return false
}

func (p *Protocol) portPropertiesMatch(parameters []byte) bool {
	var session map[string]json.RawMessage
	if decodeControlJSON(parameters, &session) != nil || len(session) != 2 {
		return false
	}
	var kind string
	if json.Unmarshal(session["SessionType"], &kind) != nil || kind != "Port" {
		return false
	}
	var properties map[string]json.RawMessage
	if decodeControlJSON(session["Properties"], &properties) != nil {
		return false
	}
	values := make(map[string]string, len(properties))
	for key, raw := range properties {
		switch key {
		case "type", "host", "portNumber", "localPortNumber", "localConnectionType", "localUnixSocket":
		default:
			return false
		}
		// Unmarshal(null, &string) succeeds with empty value; refuse it rather
		// than treating an ambiguous property as an absent optional string.
		var value string
		if len(raw) == 0 || raw[0] != '"' || json.Unmarshal(raw, &value) != nil {
			return false
		}
		values[key] = value
	}
	return values["type"] == "LocalPortForwarding" &&
		values["host"] == p.port.Host &&
		values["portNumber"] == strconv.Itoa(p.port.RemotePort) &&
		values["localPortNumber"] == strconv.Itoa(p.port.LocalPort) &&
		(values["localConnectionType"] == "" || values["localConnectionType"] == "tcp") &&
		values["localUnixSocket"] == ""
}

func validPortFlag(data []byte, flag uint32) bool {
	return len(data) == 4 && binary.BigEndian.Uint32(data) == flag
}
