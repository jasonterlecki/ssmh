package native

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"time"

	"ssmh/internal/config"
)

type kmsParameters struct{ keyID, challenge string }

func (k kmsParameters) String() string   { return "KMS handshake parameters [values redacted]" }
func (k kmsParameters) GoString() string { return k.String() }

// kmsKeyPreparer is the key-generation boundary, not a new credential chain.
// The future production adapter must retain the selected SDK config, bind owned
// session/target and supplied random challenge, validate the document-selected
// key, honor the establishment context and clear its plaintext key buffer. A
// blocking implementation stalls the single protocol owner; no goroutine or
// unbounded timeout is added here. kms.go supplies the selected-config SDK
// adapter, and Connect binds it to the document-owned session and setup lifetime.
type kmsKeyPreparer func(kmsParameters) (*sessionCipher, []byte, error)

// newEncryptedProtocol is private; Connect requires StartShell/StartCommand's authenticated
// document capability. Remote handshake fields or a CLI switch cannot enable it.
func newEncryptedProtocol(id, sessionType, selectedKey string, prepare kmsKeyPreparer) (*Protocol, error) {
	if selectedKey == "" || !config.Text(selectedKey, 2048) || prepare == nil {
		return nil, errors.New("native encrypted protocol requires a selected key and owned key preparer")
	}
	p, err := NewProtocol(id, sessionType)
	if err != nil {
		return nil, err
	}
	p.selectedKMSKey, p.prepareEncryption = selectedKey, prepare
	p.requiresEncryption = true // Immutable policy survives release of key references.
	return p, nil
}

func parseKMSParameters(raw []byte, selected string) (kmsParameters, error) {
	invalid := errors.New("invalid KMS handshake parameters")
	var fields map[string]json.RawMessage
	if len(raw) > 4096 || decodeControlJSON(raw, &fields) != nil || fields == nil {
		return kmsParameters{}, invalid
	}
	var parameters kmsParameters
	for name, value := range fields {
		var text *string
		if json.Unmarshal(value, &text) != nil || text == nil {
			return kmsParameters{}, invalid
		}
		switch name {
		case "KMSKeyId":
			if *text != selected || selected == "" {
				return kmsParameters{}, invalid
			}
			parameters.keyID = *text
		case "Challenge":
			// The pinned current agent supplies exactly 16 random bytes in
			// canonical standard base64. Missing is legacy; present-empty is not.
			if len(*text) != 24 {
				return kmsParameters{}, invalid
			}
			decoded, err := base64.StdEncoding.Strict().DecodeString(*text)
			if err != nil || len(decoded) != 16 || base64.StdEncoding.EncodeToString(decoded) != *text {
				return kmsParameters{}, invalid
			}
			parameters.challenge = *text
		default:
			return kmsParameters{}, invalid
		}
	}
	if parameters.keyID == "" {
		return kmsParameters{}, invalid
	}
	return parameters, nil
}

func (p *Protocol) answerEncryptionChallenge(m Message, now time.Time, event *Event) error {
	invalid := errors.New("invalid or unexpected encrypted session challenge")
	if !p.requested || p.ready || p.encryption == nil || p.challengeAnswered || len(m.Payload) > 4096 {
		return invalid
	}
	var request struct{ Challenge []byte }
	if decodeControlJSON(m.Payload, &request) != nil || len(request.Challenge) != 64+encryptedOverhead {
		return invalid
	}
	plaintext, err := p.encryption.decrypt(request.Challenge)
	if err != nil {
		return invalid
	}
	defer clear(plaintext)
	if len(plaintext) != 64 {
		return invalid
	}
	encrypted, err := p.encryption.encrypt(plaintext)
	if err != nil {
		return invalid
	}
	data, err := json.Marshal(struct{ Challenge []byte }{encrypted})
	if err != nil {
		return invalid
	}
	reply, err := p.queue(EncryptionResponse, data, now)
	if err != nil {
		return err
	}
	event.Outgoing = append(event.Outgoing, reply)
	p.challengeAnswered = true
	return nil
}

// Clear only from the protocol's single owner, after users have been joined.
// Copies/provider work and expanded-key memory are not guaranteed erased.
func (p *Protocol) clearEncryption() {
	p.encryption.clear()
	p.encryption, p.prepareEncryption, p.selectedKMSKey = nil, nil, ""
}
