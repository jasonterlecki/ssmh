package native

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

const testKMSKey = "synthetic-document-selected-key"
const testKMSChallenge = "AAECAwQFBgcICQoLDA0ODw=="

func encryptedProtocol(t *testing.T, kind string, prepare kmsKeyPreparer) *Protocol {
	t.Helper()
	p, err := newEncryptedProtocol(ownedID, kind, testKMSKey, prepare)
	if err != nil {
		t.Fatal("encrypted protocol construction failed")
	}
	t.Cleanup(p.clearEncryption)
	return p
}

func kmsHandshake(kind, challenge string) []byte {
	parameters := map[string]string{"KMSKeyId": testKMSKey}
	if challenge != "" {
		parameters["Challenge"] = challenge
	}
	data, _ := json.Marshal(map[string]any{"RequestedClientActions": []any{
		map[string]any{"ActionType": "SessionType", "ActionParameters": map[string]string{"SessionType": kind}},
		map[string]any{"ActionType": "KMSEncryption", "ActionParameters": parameters},
	}})
	return data
}

func challengePayload(t *testing.T, plaintext []byte) []byte {
	t.Helper()
	data, err := json.Marshal(struct{ Challenge []byte }{referencePayload(t, syntheticSessionMaterial()[:32], plaintext)})
	if err != nil {
		t.Fatal("challenge fixture serialization failed")
	}
	return data
}

func decodeClientCipher(t *testing.T, wire []byte) []byte {
	t.Helper()
	block, err := aes.NewCipher(syntheticSessionMaterial()[32:])
	if err != nil {
		t.Fatal("reference key rejected")
	}
	mode, err := cipher.NewGCM(block)
	if err != nil || len(wire) < 28 {
		t.Fatal("invalid reference ciphertext")
	}
	plain, err := mode.Open(nil, wire[:12], wire[12:], nil)
	if err != nil {
		t.Fatal("client ciphertext failed independent agent-direction authentication")
	}
	return plain
}

func negotiateEncryption(t *testing.T, kind string) (*Protocol, *sessionCipher) {
	t.Helper()
	codec := payloadCipher(t, syntheticSessionMaterial())
	p := encryptedProtocol(t, kind, func(k kmsParameters) (*sessionCipher, []byte, error) {
		return codec, []byte("synthetic-kms-ciphertext"), nil
	})
	if _, err := p.Process(frame(t, outputStream, HandshakeRequest, 0, kmsHandshake(kind, testKMSChallenge)), time.Now()); err != nil {
		t.Fatal("encrypted negotiation failed")
	}
	if _, err := p.Process(frame(t, outputStream, EncryptionChallenge, 1, challengePayload(t, bytes.Repeat([]byte{0x51}, 64))), time.Now()); err != nil {
		t.Fatal("encrypted challenge failed")
	}
	if event, err := p.Process(frame(t, outputStream, HandshakeComplete, 2, []byte(`{}`)), time.Now()); err != nil || !event.Ready || !p.Ready() {
		t.Fatal("encrypted readiness failed")
	}
	return p, codec
}

func TestKMSParametersExactBoundedAndRedacted(t *testing.T) {
	for _, challenge := range []string{"", testKMSChallenge} {
		var request struct {
			RequestedClientActions []struct{ ActionParameters json.RawMessage }
		}
		if json.Unmarshal(kmsHandshake("Standard_Stream", challenge), &request) != nil {
			t.Fatal("fixture decode failed")
		}
		parameters, err := parseKMSParameters(request.RequestedClientActions[1].ActionParameters, testKMSKey)
		if err != nil || parameters.keyID != testKMSKey || parameters.challenge != challenge {
			t.Fatal("valid legacy/current parameters refused")
		}
		for _, format := range []string{"%v", "%+v", "%#v"} {
			if strings.Contains(fmt.Sprintf(format, parameters), testKMSKey) || strings.Contains(fmt.Sprintf(format, &parameters), testKMSKey) {
				t.Fatal("parameters exposed selected key")
			}
		}
	}
	invalid := []string{
		`null`, `{}`, `{"KMSKeyId":null}`, `{"KMSKeyId":1}`, `{"KMSKeyId":"wrong"}`,
		`{"kmskeyid":"` + testKMSKey + `"}`, `{"KMSKeyId":"` + testKMSKey + `","Unknown":"secret"}`,
		`{"KMSKeyId":"` + testKMSKey + `","Challenge":""}`,
		`{"KMSKeyId":"` + testKMSKey + `","Challenge":null}`,
		`{"KMSKeyId":"` + testKMSKey + `","Challenge":"AAECAwQFBgcICQoLDA0ODx=="}`,
		`{"KMSKeyId":"` + testKMSKey + `","Challenge":"AA=="}`,
		`{"KMSKeyId":"` + testKMSKey + `","Challenge":"` + testKMSChallenge + `","challenge":"` + testKMSChallenge + `"}`,
		strings.Repeat(" ", 4097),
	}
	for i, raw := range invalid {
		if value, err := parseKMSParameters([]byte(raw), testKMSKey); err == nil || value != (kmsParameters{}) || err.Error() != "invalid KMS handshake parameters" {
			t.Fatalf("invalid parameter fixture %d accepted or disclosed", i)
		}
	}
	for _, key := range []string{"", "invalid\nkey", strings.Repeat("x", 2049)} {
		if p, err := newEncryptedProtocol(ownedID, "Standard_Stream", key, func(kmsParameters) (*sessionCipher, []byte, error) { return nil, nil, nil }); err == nil || p != nil {
			t.Fatal("invalid selected key accepted")
		}
	}
	if p, err := newEncryptedProtocol(ownedID, "Standard_Stream", testKMSKey, nil); err == nil || p != nil {
		t.Fatal("missing owned preparer accepted")
	}
}

func TestKMSHandshakeAndChallengeGate(t *testing.T) {
	for _, challenge := range []string{"", testKMSChallenge} {
		codec := payloadCipher(t, syntheticSessionMaterial())
		calls := 0
		blob := []byte("synthetic-kms-ciphertext")
		p := encryptedProtocol(t, "Standard_Stream", func(k kmsParameters) (*sessionCipher, []byte, error) {
			calls++
			if k.keyID != testKMSKey || k.challenge != challenge {
				t.Fatal("key preparation parameters changed")
			}
			return codec, blob, nil
		})
		event, err := p.Process(frame(t, outputStream, HandshakeRequest, 0, kmsHandshake("Standard_Stream", challenge)), time.Now())
		if err != nil || calls != 1 || p.Ready() || len(event.Outgoing) != 2 || event.Outgoing[0].Type != acknowledge || event.Outgoing[1].PayloadType != HandshakeResponse {
			t.Fatal("invalid handshake transition or response order")
		}
		var response struct {
			ProcessedClientActions []struct {
				ActionStatus int
				ActionResult struct {
					KMSCipherTextKey         []byte
					ChallengeAcknowledgement bool
				}
			}
			Errors []string
		}
		if json.Unmarshal(event.Outgoing[1].Payload, &response) != nil || len(response.Errors) != 0 || len(response.ProcessedClientActions) != 2 {
			t.Fatal("invalid encrypted response")
		}
		result := response.ProcessedClientActions[1]
		if result.ActionStatus != 1 || !bytes.Equal(result.ActionResult.KMSCipherTextKey, blob) || result.ActionResult.ChallengeAcknowledgement != (challenge != "") {
			t.Fatal("KMS response lost ciphertext/context acknowledgement")
		}
		if _, err := p.Input(Output, []byte("early"), time.Now()); err == nil {
			t.Fatal("input before encrypted challenge")
		}
		plain := bytes.Repeat([]byte{0x53}, 64)
		raw := frame(t, outputStream, EncryptionChallenge, 1, challengePayload(t, plain))
		event, err = p.Process(raw, time.Now())
		if err != nil || p.Ready() || len(event.Outgoing) != 2 || event.Outgoing[0].Type != acknowledge || event.Outgoing[1].PayloadType != EncryptionResponse {
			t.Fatal("challenge response order/readiness incorrect")
		}
		var answer struct{ Challenge []byte }
		if json.Unmarshal(event.Outgoing[1].Payload, &answer) != nil || !bytes.Equal(decodeClientCipher(t, answer.Challenge), plain) || codec.sent != 1 {
			t.Fatal("challenge direction, plaintext or encryption quota changed")
		}
		if duplicate, err := p.Process(raw, time.Now()); err != nil || len(duplicate.Outgoing) != 1 || len(duplicate.Output) != 0 || codec.sent != 1 || calls != 1 {
			t.Fatal("duplicate challenge regenerated key/response or output")
		}
		if event, err := p.Process(frame(t, outputStream, HandshakeComplete, 2, []byte(`{}`)), time.Now()); err != nil || !event.Ready || !p.Ready() {
			t.Fatal("completion after challenge refused")
		}
	}
}

func TestKMSAllActionsValidatedBeforePreparation(t *testing.T) {
	valid := string(kmsHandshake("Standard_Stream", testKMSChallenge))
	for name, payload := range map[string]string{
		"wrong type":        strings.Replace(valid, "Standard_Stream", "Port", 1),
		"wrong key":         strings.Replace(valid, testKMSKey, "wrong-key", 1),
		"missing KMS":       string(handshake),
		"unknown after KMS": strings.TrimSuffix(valid, "]}") + `,{"ActionType":"Unknown","ActionParameters":{}}]}`,
		"duplicate KMS":     strings.TrimSuffix(valid, "]}") + `,{"ActionType":"KMSEncryption","ActionParameters":{"KMSKeyId":"` + testKMSKey + `"}}]}`,
		"duplicate session": strings.TrimSuffix(valid, "]}") + `,{"ActionType":"SessionType","ActionParameters":{"SessionType":"Standard_Stream"}}]}`,
	} {
		t.Run(name, func(t *testing.T) {
			calls := 0
			p := encryptedProtocol(t, "Standard_Stream", func(kmsParameters) (*sessionCipher, []byte, error) { calls++; return nil, nil, nil })
			event, err := p.Process(frame(t, outputStream, HandshakeRequest, 0, []byte(payload)), time.Now())
			if err == nil || calls != 0 || p.Ready() || len(event.Output) != 0 || p.prepareEncryption != nil || p.selectedKMSKey != "" {
				t.Fatal("invalid actions invoked key preparer or retained capability")
			}
		})
	}
}

func TestKMSPreparationFailureIsRedactedAndReleasesCipher(t *testing.T) {
	for _, mode := range []string{"error", "nil", "cleared", "used", "empty blob", "oversized blob"} {
		t.Run(mode, func(t *testing.T) {
			codec := payloadCipher(t, syntheticSessionMaterial())
			p := encryptedProtocol(t, "Standard_Stream", func(kmsParameters) (*sessionCipher, []byte, error) {
				blob := []byte("synthetic-ciphertext")
				switch mode {
				case "error":
					return codec, blob, errors.New("SYNTHETIC-SECRET-PROVIDER-ERROR")
				case "nil":
					return nil, blob, nil
				case "cleared":
					codec.clear()
				case "used":
					codec.sent = 1
				case "empty blob":
					blob = nil
				case "oversized blob":
					blob = make([]byte, 6145)
				}
				return codec, blob, nil
			})
			event, err := p.Process(frame(t, outputStream, HandshakeRequest, 0, kmsHandshake("Standard_Stream", testKMSChallenge)), time.Now())
			if err == nil || p.Ready() || p.encryption != nil || len(event.Outgoing) != 2 || strings.Contains(err.Error(), "SYNTHETIC-SECRET") || bytes.Contains(event.Outgoing[1].Payload, []byte("SYNTHETIC-SECRET")) {
				t.Fatal("key preparation failure accepted, retained or disclosed")
			}
			if mode != "nil" && (codec.encryptor != nil || codec.decryptor != nil) {
				t.Fatal("partial/invalid key preparation retained key schedule")
			}
		})
	}
}

func TestKMSEncryptedDataReplayAndRetransmit(t *testing.T) {
	p, codec := negotiateEncryption(t, "NonInteractiveCommands")
	now := time.Now()
	plain := []byte{0, 3, 4, 0xff, '\n'}
	m, err := p.Input(Output, plain, now)
	if err != nil || !bytes.Equal(decodeClientCipher(t, m.Payload), plain) || codec.sent != 2 {
		t.Fatal("input not encrypted exactly once")
	}
	// Remove acknowledged setup frames to select application input as oldest.
	for seq := range p.outgoing {
		if seq < m.Sequence {
			delete(p.outgoing, seq)
		}
	}
	retry, err := p.Retransmit(now.Add(time.Second))
	if err != nil || retry == nil || retry.ID != m.ID || retry.Sequence != m.Sequence || !bytes.Equal(retry.Payload, m.Payload) || codec.sent != 2 {
		t.Fatal("retransmission regenerated ciphertext/nonce/identity")
	}
	clear(retry.Payload)
	if !bytes.Equal(p.outgoing[m.Sequence].message.Payload, m.Payload) {
		t.Fatal("retransmission caller mutated retained ciphertext")
	}
	size := []byte(`{"cols":80,"rows":24}`)
	resize, err := p.Input(Size, size, now)
	if err != nil || !bytes.Equal(resize.Payload, size) || codec.sent != 2 {
		t.Fatal("resize was encrypted or consumed nonce quota")
	}
	later := frame(t, outputStream, StdErr, 4, referencePayload(t, syntheticSessionMaterial()[:32], []byte("stderr")))
	if event, err := p.Process(later, now); err != nil || len(event.Output) != 0 {
		t.Fatal("out-of-order ciphertext delivered early")
	}
	first := frame(t, outputStream, Output, 3, referencePayload(t, syntheticSessionMaterial()[:32], plain))
	event, err := p.Process(first, now)
	if err != nil || len(event.Output) != 2 || !bytes.Equal(event.Output[0].Payload, plain) || string(event.Output[1].Payload) != "stderr" {
		t.Fatal("ordered encrypted output corrupted")
	}
	clear(event.Output[0].Payload)
	if duplicate, err := p.Process(first, now); err != nil || len(duplicate.Output) != 0 || len(duplicate.Outgoing) != 1 {
		t.Fatal("plaintext mutation broke original ciphertext replay stamp")
	}
	status := frame(t, outputStream, ExitCode, 5, referencePayload(t, syntheticSessionMaterial()[:32], []byte("37")))
	if event, err := p.Process(status, now); err != nil || len(event.Output) != 1 || string(event.Output[0].Payload) != "37" {
		t.Fatal("encrypted typed exit code lost")
	}
	if _, err := p.Process(frame(t, channelClosed, 0, 0, []byte(`{"SessionId":"`+ownedID+`"}`)), now); err != nil || p.Ready() || codec.encryptor != nil || codec.decryptor != nil {
		t.Fatal("owned close did not release encryption")
	}
}

func TestKMSChallengeAndDataFailuresNeverDowngrade(t *testing.T) {
	for _, mode := range []string{"early complete", "early output", "short challenge", "corrupt challenge", "repeated challenge", "plaintext data", "released before handshake", "released after ready"} {
		t.Run(mode, func(t *testing.T) {
			codec := payloadCipher(t, syntheticSessionMaterial())
			p := encryptedProtocol(t, "Standard_Stream", func(kmsParameters) (*sessionCipher, []byte, error) { return codec, []byte("synthetic-ciphertext"), nil })
			p.allowNoHandshake = true // Even accidental shell capability cannot downgrade.
			seq := int64(0)
			kind, data := uint32(Output), []byte("SYNTHETIC-PRIVATE-DATA")
			if mode == "released before handshake" {
				p.clearEncryption()
			} else {
				if _, err := p.Process(frame(t, outputStream, HandshakeRequest, seq, kmsHandshake("Standard_Stream", testKMSChallenge)), time.Now()); err != nil {
					t.Fatal("negotiation failed")
				}
				seq++
				switch mode {
				case "early complete":
					kind, data = HandshakeComplete, []byte(`{}`)
				case "short challenge":
					kind, data = EncryptionChallenge, challengePayload(t, []byte("short"))
				case "corrupt challenge":
					wire := referencePayload(t, syntheticSessionMaterial()[:32], make([]byte, 64))
					wire[len(wire)-1] ^= 1
					kind = EncryptionChallenge
					data, _ = json.Marshal(struct{ Challenge []byte }{wire})
				case "repeated challenge", "plaintext data", "released after ready":
					if _, err := p.Process(frame(t, outputStream, EncryptionChallenge, seq, challengePayload(t, make([]byte, 64))), time.Now()); err != nil {
						t.Fatal("challenge failed")
					}
					seq++
					if mode == "repeated challenge" {
						kind, data = EncryptionChallenge, challengePayload(t, make([]byte, 64))
					} else {
						if _, err := p.Process(frame(t, outputStream, HandshakeComplete, seq, []byte(`{}`)), time.Now()); err != nil {
							t.Fatal("completion failed")
						}
						seq++
						if mode == "released after ready" {
							p.clearEncryption()
							if p.Ready() {
								t.Fatal("released cipher still ready")
							}
						}
					}
				}
			}
			event, err := p.Process(frame(t, outputStream, kind, seq, data), time.Now())
			if err == nil || len(event.Output) != 0 || event.Ready || p.Ready() || p.encryption != nil {
				t.Fatal("invalid encrypted transition allowed data/readiness or retained keys")
			}
			// Before preparation this fixture remains caller-owned, not protocol-owned.
			if mode != "released before handshake" && (codec.encryptor != nil || codec.decryptor != nil) {
				t.Fatal("failed encrypted protocol retained an owned key schedule")
			}
			if _, err := p.Input(Output, []byte("later input"), time.Now()); err == nil {
				t.Fatal("failed encrypted protocol revived plaintext input")
			}
		})
	}
}

func TestKMSMalformedChallengeFrames(t *testing.T) {
	valid := challengePayload(t, make([]byte, 64))
	for _, payload := range [][]byte{
		nil, []byte(`null`), []byte(`{}`), []byte(`{"Challenge":null}`),
		[]byte(`{"Challenge":"invalid base64"}`), bytes.Repeat([]byte{' '}, 4097),
		[]byte(strings.TrimSuffix(string(valid), "}") + `,"challenge":""}`),
	} {
		codec := payloadCipher(t, syntheticSessionMaterial())
		p := encryptedProtocol(t, "Standard_Stream", func(kmsParameters) (*sessionCipher, []byte, error) { return codec, []byte("synthetic-ciphertext"), nil })
		if _, err := p.Process(frame(t, outputStream, HandshakeRequest, 0, kmsHandshake("Standard_Stream", "")), time.Now()); err != nil {
			t.Fatal("negotiation failed")
		}
		if event, err := p.Process(frame(t, outputStream, EncryptionChallenge, 1, payload), time.Now()); err == nil || len(event.Output) != 0 || p.Ready() || codec.encryptor != nil || codec.decryptor != nil {
			t.Fatal("malformed challenge accepted or retained owned keys")
		}
	}
	p := encryptedProtocol(t, "Standard_Stream", func(kmsParameters) (*sessionCipher, []byte, error) {
		t.Fatal("premature challenge invoked preparer")
		return nil, nil, nil
	})
	if _, err := p.Process(frame(t, outputStream, EncryptionChallenge, 0, valid), time.Now()); err == nil || p.Ready() {
		t.Fatal("challenge before key negotiation accepted")
	}
	p, codec := negotiateEncryption(t, "Standard_Stream")
	if _, err := p.Process(frame(t, outputStream, ExitCode, 3, referencePayload(t, syntheticSessionMaterial()[:32], []byte("0"))), time.Now()); err == nil || codec.encryptor != nil {
		t.Fatal("encryption bypassed session-specific exit status restriction")
	}
}

func TestKMSEncryptedChannelShutdownReleasesKeys(t *testing.T) {
	for _, mode := range []string{"cancel", "disconnect", "owned EOF", "authentication failure"} {
		t.Run(mode, func(t *testing.T) {
			p, codec := negotiateEncryption(t, "Standard_Stream")
			local, remote := net.Pipe()
			defer remote.Close()
			if err := remote.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			c := startChannel(ctx, cancel, &Socket{stream: local}, p)
			defer c.Close()
			switch mode {
			case "cancel":
				cancel()
			case "disconnect":
				_ = remote.Close()
			case "owned EOF":
				if err := sendRemote(t, remote, channelClosed, 0, 0, []byte(`{"SessionId":"`+ownedID+`"}`)); err != nil {
					t.Fatal("owned close fixture failed")
				}
			case "authentication failure":
				if err := sendRemote(t, remote, outputStream, Output, 3, []byte("SYNTHETIC-PRIVATE-PLAINTEXT")); err != nil {
					t.Fatal("failure fixture failed")
				}
			}
			select {
			case <-c.done:
			case <-time.After(3 * time.Second):
				t.Fatal("encrypted channel did not join shutdown")
			}
			// The done channel synchronizes with the single owner's cleanup.
			if !p.closed || p.Ready() || p.encryption != nil || p.prepareEncryption != nil || p.selectedKMSKey != "" || codec.encryptor != nil || codec.decryptor != nil {
				t.Fatal("channel shutdown retained cipher/capability or allowed reuse")
			}
			_, err := c.Receive(context.Background())
			if mode == "owned EOF" {
				if !errors.Is(err, io.EOF) {
					t.Fatal("owned close did not produce EOF")
				}
			} else if err == nil || errors.Is(err, io.EOF) {
				t.Fatal("failure fabricated successful EOF")
			}
		})
	}
}

func TestKMSEncryptedChannelWireExchange(t *testing.T) {
	codec := payloadCipher(t, syntheticSessionMaterial())
	p := encryptedProtocol(t, "Standard_Stream", func(k kmsParameters) (*sessionCipher, []byte, error) {
		if k.keyID != testKMSKey || k.challenge != testKMSChallenge {
			return nil, nil, errors.New("unexpected synthetic parameters")
		}
		return codec, []byte("synthetic-ciphertext"), nil
	})
	request := kmsHandshake("Standard_Stream", testKMSChallenge)
	challenge := challengePayload(t, bytes.Repeat([]byte{0x61}, 64))
	output := referencePayload(t, syntheticSessionMaterial()[:32], []byte("synthetic response"))
	local, remote := net.Pipe()
	defer remote.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	lifetime, stop := context.WithCancel(ctx)
	defer stop()
	if err := remote.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	c := startChannel(lifetime, stop, &Socket{stream: local}, p)
	defer c.Close()
	agentDone := make(chan error, 1)
	var clientWire, answerWire []byte // Read only after agentDone synchronizes.
	go func() {
		defer remote.Close()
		agentDone <- func() error {
			for seq, stage := range []struct {
				kind     uint32
				data     []byte
				response uint32
			}{
				{HandshakeRequest, request, HandshakeResponse},
				{EncryptionChallenge, challenge, EncryptionResponse},
				{HandshakeComplete, []byte(`{}`), 0},
			} {
				if err := sendRemote(t, remote, outputStream, stage.kind, int64(seq), stage.data); err != nil {
					return err
				}
				ack, err := clientMessage(remote)
				if err != nil || ack.Type != acknowledge {
					return errors.New("encrypted setup acknowledgement missing")
				}
				if stage.response != 0 {
					response, err := clientMessage(remote)
					if err != nil || response.PayloadType != stage.response {
						return errors.New("encrypted setup response missing")
					}
					if stage.response == EncryptionResponse {
						var answer struct{ Challenge []byte }
						if json.Unmarshal(response.Payload, &answer) != nil {
							return errors.New("invalid encrypted challenge response")
						}
						answerWire = answer.Challenge
					}
					if err := acknowledgeInput(t, remote, response); err != nil {
						return err
					}
				}
			}
			input, err := clientMessage(remote)
			if err != nil || input.PayloadType != Output || bytes.Equal(input.Payload, []byte("synthetic input")) {
				return errors.New("input was absent or plaintext")
			}
			// The same reference decoder used above independently checks this wire
			// frame after the goroutine joins; retain only synthetic ciphertext.
			clientWire = input.Payload
			if err := acknowledgeInput(t, remote, input); err != nil {
				return err
			}
			if err := sendRemote(t, remote, outputStream, Output, 3, output); err != nil {
				return err
			}
			ack, err := clientMessage(remote)
			if err != nil || ack.Type != acknowledge {
				return errors.New("encrypted output acknowledgement missing")
			}
			return sendRemote(t, remote, channelClosed, 0, 0, []byte(`{"SessionId":"`+ownedID+`"}`))
		}()
	}()
	select {
	case <-c.ready:
	case <-ctx.Done():
		t.Fatal("encrypted wire handshake did not establish readiness")
	}
	if err := c.Send(ctx, Output, []byte("synthetic input")); err != nil {
		t.Fatal("encrypted channel send failed")
	}
	m, err := c.Receive(ctx)
	if err != nil || m.PayloadType != Output || string(m.Payload) != "synthetic response" {
		t.Fatal("encrypted wire output not delivered")
	}
	if _, err := c.Receive(ctx); !errors.Is(err, io.EOF) {
		t.Fatal("encrypted owned completion not delivered")
	}
	if err := <-agentDone; err != nil {
		t.Fatal("synthetic encrypted agent exchange failed")
	}
	if string(decodeClientCipher(t, clientWire)) != "synthetic input" || !bytes.Equal(decodeClientCipher(t, answerWire), bytes.Repeat([]byte{0x61}, 64)) {
		t.Fatal("wire input/challenge failed independent authentication")
	}
	if err := c.Close(); err != nil || codec.encryptor != nil || codec.decryptor != nil || p.Ready() {
		t.Fatal("encrypted wire shutdown retained keys or failed cleanup")
	}
}

func TestKMSRetryExhaustionReleasesKeys(t *testing.T) {
	p, codec := negotiateEncryption(t, "Standard_Stream")
	now := time.Now()
	for i := 0; i < maxResends; i++ {
		now = now.Add(10 * time.Second)
		if m, err := p.Retransmit(now); err != nil || m == nil {
			t.Fatal("bounded retransmit failed early")
		}
	}
	if _, err := p.Retransmit(now.Add(10 * time.Second)); err == nil || p.Ready() || codec.encryptor != nil || codec.decryptor != nil || p.encryption != nil {
		t.Fatal("retry exhaustion retained keys or readiness")
	}
}

func FuzzKMSParameters(f *testing.F) {
	f.Add([]byte(`{"KMSKeyId":"` + testKMSKey + `","Challenge":"` + testKMSChallenge + `"}`))
	f.Add([]byte(`{"KMSKeyId":"` + testKMSKey + `"}`))
	f.Add([]byte(`null`))
	f.Fuzz(func(t *testing.T, raw []byte) {
		parameters, err := parseKMSParameters(raw, testKMSKey)
		if err != nil {
			if parameters != (kmsParameters{}) || err.Error() != "invalid KMS handshake parameters" {
				t.Fatal("invalid parameters disclosed data")
			}
			return
		}
		if parameters.keyID != testKMSKey || parameters.challenge != "" && len(parameters.challenge) != 24 {
			t.Fatal("parser violated selected key/challenge bound")
		}
	})
}
