package native

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"math"
	"time"

	"ssmh/internal/config"
)

const (
	// AWS wire compatibility level, not the ssmh release or an assertion that
	// this is the official plugin. Covers separate command output (1.2.312.0)
	// and Port mux without keepalives (>1.2.331.0). Never user/linker controlled.
	wireClientVersion = "1.2.339.0"
	window            = 64
	maxBuffered       = 1 << 20
	// InputSize follows the official plugin's terminal input chunk size.
	InputSize             = 1024
	maxResends            = 5
	kmsUnsupportedMessage = "native KMS encryption requires a document-verified owned shell or command; unverified KMS actions and other session types are unsupported (no plugin fallback is available)"
)

// ErrBackpressure means the caller must wait for an acknowledgement/publication.
var ErrBackpressure = errors.New("SSM input window is full or publication is paused")

type ack struct {
	Type       string `json:"AcknowledgedMessageType"`
	ID         string `json:"AcknowledgedMessageId"`
	Sequence   int64  `json:"AcknowledgedMessageSequenceNumber"`
	Sequential bool   `json:"IsSequentialMessage"`
}

type pending struct {
	message  Message
	sent     time.Time
	attempts int
}
type fingerprint struct {
	id             UUID
	digest         [32]byte
	created, flags uint64
	payloadType    uint32
}

func stamp(m Message) fingerprint {
	return fingerprint{m.ID, sha256.Sum256(m.Payload), m.Created, m.Flags, m.PayloadType}
}

// Event contains already ordered output and bounded protocol responses. Outgoing
// messages must be written in order even when Process returns a handshake error.
type Event struct {
	Outgoing        []Message
	Output          []Message
	Ready, Closed   bool
	CustomerMessage string
}

func (e Event) String() string   { return "SSM protocol event [payloads redacted]" }
func (e Event) GoString() string { return e.String() }

// Protocol is a single-owner state machine. Run all methods from one event loop.
// It does not reconnect or restart operations after a transport failure.
type Protocol struct {
	sessionID, expectedType, clientVersion   string
	port                                     *config.ForwardTarget
	nextInput, nextOutput                    int64
	requested, ready, closed, failed, paused bool
	allowNoHandshake                         bool
	incoming                                 map[int64]Message
	buffered                                 int
	received                                 map[int64]fingerprint
	outgoing                                 map[int64]pending
	acked                                    map[int64]string
	selectedKMSKey                           string
	prepareEncryption                        kmsKeyPreparer
	encryption                               *sessionCipher
	challengeAnswered                        bool
	requiresEncryption                       bool
}

func (p *Protocol) String() string   { return "SSM protocol state [stream data redacted]" }
func (p *Protocol) GoString() string { return p.String() }

// NewProtocol selects exactly one supported session type and owned session ID.
func NewProtocol(sessionID, sessionType string) (*Protocol, error) {
	if sessionID == "" || len(sessionID) > 128 {
		return nil, errors.New("invalid protocol session identity")
	}
	switch sessionType {
	case "Standard_Stream", "InteractiveCommands", "NonInteractiveCommands":
	default:
		return nil, errors.New("native session type is unsupported")
	}
	return &Protocol{sessionID: sessionID, expectedType: sessionType, clientVersion: wireClientVersion, incoming: map[int64]Message{}, received: map[int64]fingerprint{}, outgoing: map[int64]pending{}, acked: map[int64]string{}}, nil
}

// Ready reports verified handshake completion or a document-authorized shell's
// first ordered Output frame. TLS and data-channel authentication always apply.
func (p *Protocol) Ready() bool {
	return p.ready && !p.failed && !p.closed && (!p.requiresEncryption ||
		p.encryption != nil && p.encryption.encryptor != nil && p.encryption.decryptor != nil && p.challengeAnswered)
}

func (p *Protocol) queue(payloadType uint32, data []byte, now time.Time) (Message, error) {
	if len(p.outgoing) >= window || p.paused {
		return Message{}, ErrBackpressure
	}
	if p.nextInput >= math.MaxInt64-1 {
		return Message{}, errors.New("SSM input sequence exhausted")
	}
	if p.encryption != nil && payloadType == Output {
		var err error
		data, err = p.encryption.encrypt(data)
		if err != nil {
			p.failed = true
			p.clearEncryption()
			return Message{}, err
		}
	}
	m, err := message(inputStream, payloadType, p.nextInput, bytes.Clone(data))
	if err != nil {
		return m, err
	}
	p.outgoing[p.nextInput] = pending{m, now, 0}
	p.nextInput++
	// The caller cannot mutate data retained for verified protocol retransmission.
	m.Payload = bytes.Clone(m.Payload)
	return m, nil
}

// Input queues a bounded shell chunk/resize or Port binary/control payload after
// verified channel readiness. Forwarding never accepts terminal resize input.
func (p *Protocol) Input(payloadType uint32, data []byte, now time.Time) (Message, error) {
	if !p.Ready() {
		return Message{}, errors.New("SSM channel is not ready or session ended")
	}
	if len(data) == 0 || len(data) > InputSize {
		return Message{}, errors.New("invalid SSM input chunk size")
	}
	if p.port != nil {
		if payloadType != Output && (payloadType != Flag || !validPortFlag(data, portTerminate)) {
			return Message{}, errors.New("unsupported native forwarding input payload")
		}
		return p.queue(payloadType, data, now)
	}
	if payloadType != Output && payloadType != Size {
		return Message{}, errors.New("unsupported native input payload")
	}
	if payloadType == Size {
		var size struct{ Cols, Rows uint32 }
		if decodeControlJSON(data, &size) != nil || size.Cols == 0 || size.Rows == 0 || size.Cols > 65535 || size.Rows > 65535 {
			return Message{}, errors.New("invalid terminal dimensions")
		}
	}
	return p.queue(payloadType, data, now)
}

// Process validates and dispatches one complete SSM frame. Any protocol violation
// permanently fails this state machine, preventing later user input.
func (p *Protocol) Process(raw []byte, now time.Time) (event Event, err error) {
	if p.failed || p.closed {
		return event, errors.New("SSM protocol is no longer active")
	}
	defer func() {
		if err != nil {
			p.failed = true
			p.clearEncryption()
		}
	}()
	m, err := Decode(raw)
	if err != nil {
		return event, err
	}
	switch m.Type {
	case startPublication:
		p.paused = false
		return event, nil
	case pausePublication:
		p.paused = true
		return event, nil
	case acknowledge:
		var a ack
		if len(m.Payload) > 4096 || decodeControlJSON(m.Payload, &a) != nil || !a.Sequential || a.Type != inputStream || a.Sequence < 0 || a.Sequence >= p.nextInput {
			return event, errors.New("invalid SSM acknowledgement")
		}
		if sent, ok := p.outgoing[a.Sequence]; ok {
			if a.ID != sent.message.ID.String() {
				return event, errors.New("SSM acknowledgement identity mismatch")
			}
			delete(p.outgoing, a.Sequence)
			p.acked[a.Sequence] = a.ID
			// Retain only a bounded history of acknowledged messages.
			for seq := range p.acked {
				if seq < p.nextInput-window {
					delete(p.acked, seq)
				}
			}
		} else if p.acked[a.Sequence] != a.ID {
			return event, errors.New("unexpected or stale SSM acknowledgement")
		}
		return event, nil
	case channelClosed:
		var closed struct {
			SessionID string `json:"SessionId"`
			Output    string
		}
		if len(m.Payload) > 16384 || decodeControlJSON(m.Payload, &closed) != nil || closed.SessionID != p.sessionID {
			return event, errors.New("invalid SSM channel-close ownership")
		}
		if len(p.incoming) != 0 {
			return event, errors.New("SSM channel closed with missing ordered output")
		}
		p.closed = true
		p.clearEncryption()
		event.Closed = true
		if closed.Output != "" {
			return event, errors.New("SSM service ended the session with an error; check Session Manager policies and agent status")
		}
		return event, nil
	case outputStream:
		if m.Sequence < p.nextOutput {
			if previous, ok := p.received[m.Sequence]; !ok || previous != stamp(m) {
				return event, errors.New("stale or conflicting SSM output replay")
			}
			a, e := acknowledgement(m)
			if e != nil {
				return event, e
			}
			event.Outgoing = append(event.Outgoing, a)
			return event, nil
		}
		if m.Sequence-p.nextOutput >= window {
			return event, errors.New("SSM output exceeds sequence window")
		}
		if previous, ok := p.incoming[m.Sequence]; ok {
			if stamp(previous) != stamp(m) {
				return event, errors.New("conflicting buffered SSM output")
			}
			return event, nil // Buffered frames are acknowledged after processing in order.
		}
		if len(p.incoming) >= window || p.buffered+len(m.Payload) > maxBuffered {
			return event, errors.New("SSM output buffer limit exceeded")
		}
		p.incoming[m.Sequence] = m
		p.buffered += len(m.Payload)
		for {
			next, ok := p.incoming[p.nextOutput]
			if !ok {
				break
			}
			handshake := next.PayloadType == HandshakeRequest || next.PayloadType == HandshakeComplete || next.PayloadType == EncryptionChallenge
			if handshake {
				a, e := acknowledgement(next)
				if e != nil {
					return event, e
				}
				event.Outgoing = append(event.Outgoing, a)
			}
			if err = p.processOrdered(next, now, &event); err != nil {
				return event, err
			}
			if !handshake {
				a, e := acknowledgement(next)
				if e != nil {
					return event, e
				}
				event.Outgoing = append(event.Outgoing, a)
			}
			delete(p.incoming, p.nextOutput)
			p.buffered -= len(next.Payload)
			p.received[p.nextOutput] = stamp(next)
			p.nextOutput++
			delete(p.received, p.nextOutput-window-1)
		}
		return event, nil
	default:
		return event, errors.New("unexpected client-direction SSM message")
	}
}

func acknowledgement(m Message) (Message, error) {
	data, err := json.Marshal(ack{m.Type, m.ID.String(), m.Sequence, true})
	if err != nil {
		return Message{}, errors.New("serialize SSM acknowledgement failed")
	}
	a, err := message(acknowledge, 0, 0, data)
	a.Flags = 3
	return a, err
}

func (p *Protocol) processOrdered(m Message, now time.Time, event *Event) error {
	switch m.PayloadType {
	case HandshakeRequest:
		if p.requested || p.ready {
			return errors.New("unexpected repeated SSM handshake")
		}
		var request struct {
			AgentVersion           string
			RequestedClientActions []struct {
				ActionType       string
				ActionParameters json.RawMessage
			}
		}
		if len(m.Payload) > 65536 || decodeControlJSON(m.Payload, &request) != nil || len(request.RequestedClientActions) == 0 || len(request.RequestedClientActions) > 16 {
			return errors.New("invalid SSM handshake request")
		}
		if p.port != nil && !portAgentSupported(request.AgentVersion) {
			return errors.New("native forwarding requires an agent supporting multiplexing without mux keepalives")
		}
		type action struct {
			ActionType   string
			ActionStatus int
			ActionResult any
			Error        string
		}
		response := struct {
			ClientVersion          string
			ProcessedClientActions []action
			Errors                 []string
		}{p.clientVersion, []action{}, []string{}}
		matched := false
		kmsRequested := false
		kmsIndex := -1
		var kmsRequest kmsParameters
		for _, a := range request.RequestedClientActions {
			result := action{ActionType: a.ActionType, ActionStatus: 3, Error: "unsupported client action"}
			if a.ActionType == "SessionType" {
				var session struct{ SessionType string }
				if matched || decodeControlJSON(a.ActionParameters, &session) != nil || session.SessionType != p.expectedType || (p.port != nil && !p.portPropertiesMatch(a.ActionParameters)) {
					result.ActionStatus = 2
					result.Error = "session type does not match the requested operation"
				} else {
					matched = true
					result.ActionStatus = 1
					result.Error = ""
				}
			} else if a.ActionType == "KMSEncryption" {
				duplicate := kmsRequested
				kmsRequested = true
				result.Error = kmsUnsupportedMessage
				if p.prepareEncryption != nil && p.selectedKMSKey != "" {
					parsed, err := parseKMSParameters(a.ActionParameters, p.selectedKMSKey)
					if duplicate || err != nil {
						result.ActionStatus = 2
						result.Error = "invalid or repeated KMS handshake action"
					} else {
						kmsIndex = len(response.ProcessedClientActions)
						kmsRequest = parsed
						result.ActionStatus, result.Error = 1, ""
					}
				}
			}
			if result.Error != "" {
				response.Errors = append(response.Errors, result.Error)
			}
			response.ProcessedClientActions = append(response.ProcessedClientActions, result)
		}
		if !matched {
			response.Errors = append(response.Errors, "missing supported session type")
		}
		if p.selectedKMSKey != "" && !kmsRequested {
			response.Errors = append(response.Errors, "required KMS handshake action is missing")
		}
		// Validate all actions first: an unknown/mismatched/duplicate action must
		// never cause a key-generation side effect, regardless of action order.
		if len(response.Errors) == 0 && kmsIndex >= 0 {
			prepare := p.prepareEncryption
			p.prepareEncryption = nil // One key preparation per protocol lifetime.
			codec, blob, err := prepare(kmsRequest)
			if err != nil || codec == nil || codec.encryptor == nil || codec.decryptor == nil || codec.sent != 0 || len(blob) == 0 || len(blob) > 6144 {
				codec.clear()
				response.ProcessedClientActions[kmsIndex].ActionStatus = 2
				response.ProcessedClientActions[kmsIndex].Error = "KMS session key preparation failed"
				response.Errors = append(response.Errors, "KMS session key preparation failed")
			} else {
				p.encryption = codec
				response.ProcessedClientActions[kmsIndex].ActionResult = struct {
					KMSCipherTextKey         []byte
					ChallengeAcknowledgement bool
				}{bytes.Clone(blob), kmsRequest.challenge != ""}
			}
		}
		data, e := json.Marshal(response)
		if e != nil {
			return errors.New("serialize SSM handshake response failed")
		}
		reply, e := p.queue(HandshakeResponse, data, now)
		if e != nil {
			return e
		}
		event.Outgoing = append(event.Outgoing, reply)
		if len(response.Errors) > 0 {
			if p.selectedKMSKey != "" {
				return errors.New("native encrypted handshake validation or key preparation failed")
			}
			if kmsRequested {
				return errors.New(kmsUnsupportedMessage)
			}
			return errors.New("SSM requested an unsupported handshake feature; native transport refused the session")
		}
		p.requested = true
		return nil
	case EncryptionChallenge:
		return p.answerEncryptionChallenge(m, now, event)
	case HandshakeComplete:
		if !p.requested || p.ready || p.requiresEncryption && (p.encryption == nil || !p.challengeAnswered) {
			return errors.New("unexpected SSM handshake completion")
		}
		var complete struct{ CustomerMessage string }
		if len(m.Payload) > 16384 || decodeControlJSON(m.Payload, &complete) != nil {
			return errors.New("invalid SSM handshake completion")
		}
		p.ready = true
		event.Ready = true
		event.CustomerMessage = complete.CustomerMessage
		return nil
	case Output, StdErr, ExitCode:
		if p.requiresEncryption && (p.encryption == nil || !p.challengeAnswered) {
			return errors.New("encrypted application data arrived without a verified cipher challenge")
		}
		if p.port != nil && m.PayloadType != Output {
			return errors.New("unexpected terminal payload on native forwarding channel")
		}
		if !p.ready {
			if p.requiresEncryption || !p.allowNoHandshake || p.expectedType != "Standard_Stream" || p.requested || m.PayloadType != Output || m.Sequence != 0 {
				return errors.New("SSM sent application data before handshake completion")
			}
			p.ready = true
			event.Ready = true
		}
		if m.PayloadType == ExitCode && p.expectedType != "NonInteractiveCommands" {
			return errors.New("unexpected SSM exit-code payload for session type")
		}
		if p.encryption != nil {
			plaintext, err := p.encryption.decrypt(m.Payload)
			if err != nil {
				return err
			}
			m.Payload = plaintext // Original incoming ciphertext remains immutable.
		}
		event.Output = append(event.Output, m)
		return nil
	case Flag:
		if p.port == nil || !p.Ready() || !validPortFlag(m.Payload, portConnectError) {
			return errors.New("unexpected or malformed native forwarding flag")
		}
		// AWS's destination-failure flag carries no stream ID. Deliver it as a
		// distinct control, never application bytes or an invented per-stream ID.
		event.Output = append(event.Output, m)
		return nil
	case Error:
		return errors.New("SSM agent reported a session error")
	default:
		return errors.New("unexpected or unsupported SSM stream payload")
	}
}

// Retransmit returns the oldest unacknowledged frame when its bounded timeout
// expires. It preserves UUID and sequence so the peer can suppress duplicates.
// It never creates a new session, replays a command in a new session, or loops forever.
func (p *Protocol) Retransmit(now time.Time) (*Message, error) {
	if p.failed || p.closed {
		return nil, errors.New("SSM protocol is no longer active")
	}
	if p.paused {
		return nil, nil
	}
	oldest := int64(math.MaxInt64)
	for seq := range p.outgoing {
		if seq < oldest {
			oldest = seq
		}
	}
	if oldest == math.MaxInt64 {
		return nil, nil
	}
	sent := p.outgoing[oldest]
	delay := 200 * time.Millisecond * time.Duration(1<<min(sent.attempts, 3))
	if now.Sub(sent.sent) < delay {
		return nil, nil
	}
	if sent.attempts >= maxResends {
		p.failed = true
		p.clearEncryption()
		return nil, errors.New("SSM acknowledgement timed out after bounded retransmissions")
	}
	sent.attempts++
	sent.sent = now
	p.outgoing[oldest] = sent
	m := sent.message
	m.Payload = bytes.Clone(m.Payload)
	return &m, nil
}
