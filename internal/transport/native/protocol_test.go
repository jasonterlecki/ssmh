package native

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

const ownedID = "synthetic-user-session"

var handshake = []byte(`{"AgentVersion":"3.3.0.0","RequestedClientActions":[{"ActionType":"SessionType","ActionParameters":{"SessionType":"Standard_Stream","Properties":{}}}]}`)

func frame(t *testing.T, kind string, payloadType uint32, seq int64, data []byte) []byte {
	t.Helper()
	m, err := message(kind, payloadType, seq, data)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := Encode(m)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
func protocol(t *testing.T) *Protocol {
	t.Helper()
	p, err := NewProtocol(ownedID, "Standard_Stream")
	if err != nil {
		t.Fatal(err)
	}
	return p
}
func ready(t *testing.T) *Protocol {
	t.Helper()
	p := protocol(t)
	event, err := p.Process(frame(t, outputStream, HandshakeRequest, 0, handshake), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if len(event.Outgoing) != 2 || event.Outgoing[0].Type != acknowledge || event.Outgoing[1].PayloadType != HandshakeResponse {
		t.Fatal("incorrect handshake response/ack order")
	}
	event, err = p.Process(frame(t, outputStream, HandshakeComplete, 1, []byte(`{"CustomerMessage":"ready"}`)), time.Now())
	if err != nil || !event.Ready || !p.Ready() {
		t.Fatal("handshake incomplete")
	}
	return p
}

func TestHandshakeFailClosed(t *testing.T) {
	for _, payload := range [][]byte{[]byte(`{`), []byte(`{"RequestedClientActions":[]}`), []byte(`{"RequestedClientActions":[{"ActionType":"SessionType","ActionParameters":{"SessionType":"Port"}}]}`), []byte(`{"RequestedClientActions":[{"ActionType":"KMSEncryption","ActionParameters":{"KMSKeyId":"synthetic"}},{"ActionType":"SessionType","ActionParameters":{"SessionType":"Standard_Stream"}}]}`), []byte(`{"RequestedClientActions":[{"ActionType":"Unknown"}]}`)} {
		p := protocol(t)
		_, err := p.Process(frame(t, outputStream, HandshakeRequest, 0, payload), time.Now())
		if err == nil || p.Ready() {
			t.Fatal("unsupported handshake accepted")
		}
		if _, err = p.Input(Output, []byte("secret"), time.Now()); err == nil {
			t.Fatal("input allowed after handshake failure")
		}
	}
	p := protocol(t)
	if _, err := p.Process(frame(t, outputStream, Output, 0, []byte("secret")), time.Now()); err == nil || strings.Contains(err.Error(), "secret") {
		t.Fatal("pre-handshake output accepted or logged")
	}
	p = protocol(t)
	if _, err := p.Process(frame(t, outputStream, HandshakeComplete, 0, []byte(`{}`)), time.Now()); err == nil {
		t.Fatal("completion without negotiation accepted")
	}
}

func TestKMSRefusalIsActionableAndNeverAcknowledgesEncryption(t *testing.T) {
	for _, optional := range []bool{false, true} {
		for _, challenge := range []string{"", ",\"Challenge\":\"AAECAwQFBgcICQoLDA0ODw==\""} {
			p := protocol(t)
			p.allowNoHandshake = optional
			payload := []byte(`{"RequestedClientActions":[{"ActionType":"SessionType","ActionParameters":{"SessionType":"Standard_Stream"}},{"ActionType":"KMSEncryption","ActionParameters":{"KMSKeyId":"SYNTHETIC-SECRET"` + challenge + `}}]}`)
			event, err := p.Process(frame(t, outputStream, HandshakeRequest, 0, payload), time.Now())
			if err == nil || err.Error() != kmsUnsupportedMessage || p.Ready() || event.Ready || len(event.Output) != 0 || len(event.Outgoing) != 2 {
				t.Fatal("KMS requirement hidden, accepted or downgraded")
			}
			if event.Outgoing[0].Type != acknowledge || event.Outgoing[1].PayloadType != HandshakeResponse {
				t.Fatal("KMS refusal did not preserve handshake ACK/response ordering")
			}
			var response struct {
				ProcessedClientActions []struct {
					ActionType   string
					ActionStatus int
					ActionResult json.RawMessage
					Error        string
				}
				Errors []string
			}
			wire := event.Outgoing[1].Payload
			if json.Unmarshal(wire, &response) != nil || len(response.ProcessedClientActions) != 2 || len(response.Errors) != 1 {
				t.Fatal("invalid KMS refusal response")
			}
			kms := response.ProcessedClientActions[1]
			if kms.ActionType != "KMSEncryption" || kms.ActionStatus != 3 || string(kms.ActionResult) != "null" || kms.Error != kmsUnsupportedMessage || response.Errors[0] != kmsUnsupportedMessage {
				t.Fatal("unsupported encryption falsely acknowledged")
			}
			for _, forbidden := range []string{"SYNTHETIC-SECRET", "AAECAwQFBgcICQoLDA0ODw==", "KMSCipherTextKey", "ChallengeAcknowledgement", "select the official plugin backend"} {
				if strings.Contains(err.Error(), forbidden) || bytes.Contains(wire, []byte(forbidden)) {
					t.Fatal("KMS response exposed request data or recommended unavailable fallback")
				}
			}
			for _, kind := range []uint32{Output, Size} {
				if _, err := p.Input(kind, []byte("private-input"), time.Now()); err == nil {
					t.Fatal("input allowed after KMS refusal")
				}
			}
			for _, kind := range []uint32{HandshakeComplete, EncryptionChallenge, Output} {
				if next, err := p.Process(frame(t, outputStream, kind, 1, []byte(`{}`)), time.Now()); err == nil || next.Ready || len(next.Output) != 0 || p.Ready() {
					t.Fatal("later completion/challenge/plaintext revived a rejected KMS session")
				}
			}
		}
	}
}

func TestWireVersionForShellAndCommandNegotiation(t *testing.T) {
	for _, kind := range []string{"Standard_Stream", "InteractiveCommands", "NonInteractiveCommands"} {
		p, err := NewProtocol(ownedID, kind)
		if err != nil {
			t.Fatal(err)
		}
		request := []byte(`{"AgentVersion":"3.3.0.0","RequestedClientActions":[{"ActionType":"SessionType","ActionParameters":{"SessionType":"` + kind + `","Properties":{}}}]}`)
		event, err := p.Process(frame(t, outputStream, HandshakeRequest, 0, request), time.Now())
		if err != nil || len(event.Outgoing) != 2 {
			t.Fatal("supported session negotiation failed")
		}
		var response struct {
			ClientVersion string
			Errors        []string
		}
		if json.Unmarshal(event.Outgoing[1].Payload, &response) != nil || response.ClientVersion != "1.2.339.0" || len(response.Errors) != 0 || p.clientVersion != response.ClientVersion {
			t.Fatal("wire advertisements disagree or contain build metadata")
		}
		// Numeric advertisement never relaxes the exact session-type or KMS
		// gate: readiness still requires ordered authenticated completion.
		if p.Ready() {
			t.Fatal("version advertisement bypassed completion")
		}
		complete, err := p.Process(frame(t, outputStream, HandshakeComplete, 1, []byte(`{}`)), time.Now())
		if err != nil || !complete.Ready {
			t.Fatal("completion refused")
		}
	}
}

func TestDocumentAuthorizedShellWithoutHandshake(t *testing.T) {
	p := protocol(t)
	p.allowNoHandshake = true // Production authorization comes only from StartShell.
	if _, err := p.Input(Output, []byte("premature"), time.Now()); err == nil {
		t.Fatal("input enabled before first ordered output")
	}
	later := frame(t, outputStream, Output, 1, []byte("later"))
	event, err := p.Process(later, time.Now())
	if err != nil || event.Ready || p.Ready() || len(event.Output) != 0 {
		t.Fatal("out-of-order first frame established readiness")
	}
	first := frame(t, outputStream, Output, 0, []byte("prompt"))
	event, err = p.Process(first, time.Now())
	if err != nil || !event.Ready || !p.Ready() || len(event.Output) != 2 || string(event.Output[0].Payload) != "prompt" || string(event.Output[1].Payload) != "later" || len(event.Outgoing) != 2 {
		t.Fatal("ordered initial shell output lost or unacknowledged")
	}
	for _, m := range event.Outgoing {
		if m.Type != acknowledge {
			t.Fatal("handshake response invented for handshake-free shell")
		}
	}
	if event, err = p.Process(first, time.Now()); err != nil || event.Ready || len(event.Output) != 0 || len(event.Outgoing) != 1 {
		t.Fatal("duplicate first output established readiness or was redelivered")
	}
	m, err := p.Input(Size, []byte(`{"cols":80,"rows":24}`), time.Now())
	if err != nil || m.Sequence != 0 || m.PayloadType != Size {
		t.Fatal("handshake-free input did not start at sequence zero")
	}
	if _, err := p.Process(frame(t, outputStream, HandshakeRequest, 2, handshake), time.Now()); err == nil || p.Ready() {
		t.Fatal("late handshake changed established shell protocol")
	}
}

func TestOptionalShellHandshakeStillFailsClosed(t *testing.T) {
	for _, kind := range []uint32{StdErr, ExitCode, HandshakeComplete, EncryptionChallenge, Error} {
		p := protocol(t)
		p.allowNoHandshake = true
		if _, err := p.Process(frame(t, outputStream, kind, 0, []byte(`{}`)), time.Now()); err == nil || p.Ready() {
			t.Fatalf("unexpected initial payload %d selected shell", kind)
		}
	}
	for _, sessionType := range []string{"InteractiveCommands", "NonInteractiveCommands"} {
		p, _ := NewProtocol(ownedID, sessionType)
		p.allowNoHandshake = true
		if _, err := p.Process(frame(t, outputStream, Output, 0, []byte("data")), time.Now()); err == nil || p.Ready() {
			t.Fatal("shell capability weakened command handshake")
		}
	}
	p := protocol(t)
	p.allowNoHandshake = true
	corrupt := frame(t, outputStream, Output, 0, []byte("secret"))
	corrupt[len(corrupt)-1] ^= 1
	if _, err := p.Process(corrupt, time.Now()); err == nil || p.Ready() {
		t.Fatal("corrupt first output bypassed validation")
	}
	p = protocol(t)
	p.allowNoHandshake = true
	kms := []byte(`{"RequestedClientActions":[{"ActionType":"SessionType","ActionParameters":{"SessionType":"Standard_Stream"}},{"ActionType":"KMSEncryption","ActionParameters":{"KMSKeyId":"synthetic"}}]}`)
	if _, err := p.Process(frame(t, outputStream, HandshakeRequest, 0, kms), time.Now()); err == nil || p.Ready() {
		t.Fatal("preflight allowed required KMS downgrade")
	}
	p = protocol(t)
	p.allowNoHandshake = true
	if _, err := p.Process(frame(t, outputStream, HandshakeRequest, 0, handshake), time.Now()); err != nil {
		t.Fatal(err)
	}
	if _, err := p.Process(frame(t, outputStream, Output, 1, []byte("early")), time.Now()); err == nil || p.Ready() {
		t.Fatal("negotiated handshake was bypassed mid-flight")
	}
	p = protocol(t)
	p.allowNoHandshake = true
	if _, err := p.Process(frame(t, outputStream, HandshakeRequest, 0, handshake), time.Now()); err != nil {
		t.Fatal(err)
	}
	if event, err := p.Process(frame(t, outputStream, HandshakeComplete, 1, []byte(`{}`)), time.Now()); err != nil || !event.Ready || !p.Ready() {
		t.Fatal("optional handshake did not preserve negotiated path")
	}
}

func TestTypedExitCodeRequiresNegotiatedNoninteractiveSession(t *testing.T) {
	for _, sessionType := range []string{"Standard_Stream", "InteractiveCommands", "NonInteractiveCommands"} {
		t.Run(sessionType, func(t *testing.T) {
			p, err := NewProtocol(ownedID, sessionType)
			if err != nil {
				t.Fatal(err)
			}
			request := bytes.ReplaceAll(handshake, []byte("Standard_Stream"), []byte(sessionType))
			if _, err := p.Process(frame(t, outputStream, HandshakeRequest, 0, request), time.Now()); err != nil {
				t.Fatal(err)
			}
			if _, err := p.Process(frame(t, outputStream, HandshakeComplete, 1, []byte(`{}`)), time.Now()); err != nil {
				t.Fatal(err)
			}
			wire := frame(t, outputStream, ExitCode, 2, []byte("EXIT_CODE: 42"))
			event, err := p.Process(wire, time.Now())
			if sessionType != "NonInteractiveCommands" {
				if err == nil || len(event.Output) != 0 {
					t.Fatal("exit code delivered for wrong session type")
				}
				return
			}
			if err != nil || len(event.Output) != 1 || event.Output[0].PayloadType != ExitCode || string(event.Output[0].Payload) != "EXIT_CODE: 42" {
				t.Fatal("typed exit status was changed or lost")
			}
			if event, err = p.Process(wire, time.Now()); err != nil || len(event.Output) != 0 {
				t.Fatal("wire retransmission delivered duplicate exit status")
			}
		})
	}
}

func TestOwnedCloseRejectsSequenceGap(t *testing.T) {
	p := ready(t)
	if _, err := p.Process(frame(t, outputStream, Output, 3, []byte("buffered output with missing sequence 2")), time.Now()); err != nil {
		t.Fatal(err)
	}
	payload, _ := json.Marshal(map[string]string{"SessionId": ownedID})
	event, err := p.Process(frame(t, channelClosed, 0, 0, payload), time.Now())
	if err == nil || event.Closed || p.Ready() {
		t.Fatal("sequence gap was reported as complete output")
	}
}

func TestOrderingAndDuplicateSuppression(t *testing.T) {
	p := ready(t)
	later := frame(t, outputStream, Output, 3, []byte("second"))
	event, err := p.Process(later, time.Now())
	if err != nil || len(event.Output) != 0 {
		t.Fatal("out-of-order output leaked")
	}
	first := frame(t, outputStream, Output, 2, []byte("first"))
	event, err = p.Process(first, time.Now())
	if err != nil || len(event.Output) != 2 || string(event.Output[0].Payload) != "first" || string(event.Output[1].Payload) != "second" {
		t.Fatal("output not drained in order")
	}
	event, err = p.Process(first, time.Now())
	if err != nil || len(event.Output) != 0 || len(event.Outgoing) != 1 {
		t.Fatal("duplicate emitted twice or not acknowledged")
	}
	if _, err = p.Process(frame(t, outputStream, Output, 2, []byte("different")), time.Now()); err == nil {
		t.Fatal("conflicting replay accepted")
	}
}

func TestAcknowledgementIdentityAndBackpressure(t *testing.T) {
	p := ready(t)
	now := time.Now()
	m, err := p.Input(Output, []byte("input"), now)
	if err != nil {
		t.Fatal(err)
	}
	data, _ := json.Marshal(ack{inputStream, m.ID.String(), m.Sequence, true})
	event, err := p.Process(frame(t, acknowledge, 0, 0, data), now)
	if err != nil || len(event.Output) != 0 {
		t.Fatal("valid ack rejected")
	}
	if _, err = p.Process(frame(t, acknowledge, 0, 0, data), now); err != nil {
		t.Fatal("duplicate ack rejected")
	}
	data, _ = json.Marshal(ack{inputStream, "wrong-id", m.Sequence, true})
	if _, err = p.Process(frame(t, acknowledge, 0, 0, data), now); err == nil {
		t.Fatal("mismatched ack accepted")
	}
	p = ready(t)
	for i := 0; i < window-1; i++ {
		if _, err := p.Input(Output, []byte("x"), now); err != nil {
			t.Fatal(err)
		}
	}
	if _, err = p.Input(Output, []byte("x"), now); !errors.Is(err, ErrBackpressure) {
		t.Fatal("unbounded input window")
	}
}

func TestBoundedRetransmission(t *testing.T) {
	p := ready(t)
	now := time.Now().Add(time.Second)
	first := p.outgoing[0].message
	firstRaw, _ := Encode(first)
	for i := 0; i < maxResends; i++ {
		now = now.Add(10 * time.Second)
		m, err := p.Retransmit(now)
		if err != nil || m == nil {
			t.Fatal("missing retransmission")
		}
		raw, _ := Encode(*m)
		if !bytes.Equal(raw, firstRaw) {
			t.Fatal("retransmission changed identity or command bytes")
		}
		m.Payload[0] ^= 1
	}
	if _, err := p.Retransmit(now.Add(10 * time.Second)); err == nil || p.Ready() {
		t.Fatal("infinite retransmission")
	}
}

func TestPublicationAndOwnedClose(t *testing.T) {
	p := ready(t)
	_, err := p.Process(frame(t, pausePublication, 0, 0, nil), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if _, err = p.Input(Output, []byte("x"), time.Now()); !errors.Is(err, ErrBackpressure) {
		t.Fatal("publication pause ignored")
	}
	if _, err = p.Process(frame(t, startPublication, 0, 0, nil), time.Now()); err != nil {
		t.Fatal(err)
	}
	if _, err = p.Input(Size, []byte(`{"cols":80,"rows":24}`), time.Now()); err != nil {
		t.Fatal(err)
	}
	if _, err = p.Process(frame(t, channelClosed, 0, 0, []byte(`{"SessionId":"unrelated"}`)), time.Now()); err == nil {
		t.Fatal("unrelated session close accepted")
	}
	p = ready(t)
	data, _ := json.Marshal(map[string]string{"SessionId": ownedID})
	event, err := p.Process(frame(t, channelClosed, 0, 0, data), time.Now())
	if err != nil || !event.Closed || p.Ready() {
		t.Fatal("owned close not handled")
	}
}

func TestOutputMemoryAndSequenceBounds(t *testing.T) {
	p := ready(t)
	if _, err := p.Process(frame(t, outputStream, Output, 2+window, []byte("x")), time.Now()); err == nil {
		t.Fatal("unbounded sequence accepted")
	}
	p = ready(t)
	if _, err := p.Process(frame(t, outputStream, Output, 3, make([]byte, MaxPayload)), time.Now()); err != nil {
		t.Fatal(err)
	}
	if _, err := p.Process(frame(t, outputStream, Output, 4, []byte("x")), time.Now()); err == nil {
		t.Fatal("unbounded reorder buffer")
	}
}

func FuzzProtocol(f *testing.F) {
	f.Add(fixture())
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, b []byte) {
		p := protocol(t)
		_, _ = p.Process(b, time.Now())
		if p.buffered > maxBuffered || len(p.incoming) > window || len(p.outgoing) > window {
			t.Fatal("unbounded protocol state")
		}
	})
}
