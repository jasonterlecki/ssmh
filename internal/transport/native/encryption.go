package native

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/subtle"
	"errors"
)

const (
	sessionKeyBytes     = 64
	encryptedOverhead   = 28 // AWS wire: 12-byte nonce and 16-byte GCM tag.
	maxEncryptedSends   = uint64(1) << 32
	invalidCipherError  = "invalid native encrypted payload or inactive cipher"
	invalidDataKeyError = "invalid native session data key"
)

// sessionCipher is a single-owner payload codec, not an established KMS session.
// The protocol owner binds key generation to the selected SDK identity,
// owned session/target/context and verified document, completes the challenge,
// retains original ciphertext for replay suppression/retransmission, and clears
// this handle on every shutdown path. The private encrypted protocol uses it;
// Connect authorizes it only through StartShell/StartCommand document ownership.
type sessionCipher struct {
	encryptor, decryptor cipher.AEAD
	sent                 uint64
}

func (c sessionCipher) String() string {
	return "native session cipher [key and payload data redacted]"
}
func (c sessionCipher) GoString() string { return c.String() }

// newSessionCipher accepts exactly two directional AES-256 keys from the
// 64-byte KMS plaintext data key. First half is agent→client, second client→agent,
// matching AWS's pinned encrypter. Equal halves are refused as an additional
// defense against reflection, not an AWS framing requirement. It retains no
// caller buffer reference. The caller still owns and must clear that buffer.
func newSessionCipher(material []byte) (*sessionCipher, error) {
	invalid := errors.New(invalidDataKeyError)
	if len(material) != sessionKeyBytes || subtle.ConstantTimeCompare(material[:32], material[32:]) == 1 {
		return nil, invalid
	}
	makeCipher := func(key []byte) (cipher.AEAD, error) {
		block, err := aes.NewCipher(key)
		if err != nil {
			return nil, invalid
		}
		mode, err := cipher.NewGCMWithRandomNonce(block)
		if err != nil || mode.NonceSize() != 0 || mode.Overhead() != encryptedOverhead {
			return nil, invalid
		}
		return mode, nil
	}
	decryptor, err := makeCipher(material[:32])
	if err != nil {
		return nil, err
	}
	encryptor, err := makeCipher(material[32:])
	if err != nil {
		return nil, err
	}
	return &sessionCipher{encryptor: encryptor, decryptor: decryptor}, nil
}

// encrypt returns independent nonce-prefixed ciphertext. The standard library
// generates each random nonce. The send quota enforces its per-key 2^32-message
// limit; retransmission must reuse returned ciphertext, not call encrypt again.
// Empty plaintext is valid for this codec; operation-specific bounds belong to
// the protocol. Invalid bounds/quota/handle permanently deactivate the cipher.
func (c *sessionCipher) encrypt(plaintext []byte) ([]byte, error) {
	if c == nil || c.encryptor == nil || c.decryptor == nil || len(plaintext) > MaxPayload-encryptedOverhead || c.sent >= maxEncryptedSends {
		c.clear()
		return nil, errors.New(invalidCipherError)
	}
	c.sent++
	return c.encryptor.Seal(nil, nil, plaintext, nil), nil
}

// decrypt validates the wire bound before invoking GCM. No partial plaintext or
// raw authentication error escapes on failure; any failure deactivates the
// codec. This supplies authenticity, not sequence/replay or readiness checks.
func (c *sessionCipher) decrypt(ciphertext []byte) ([]byte, error) {
	if c == nil || c.encryptor == nil || c.decryptor == nil || len(ciphertext) < encryptedOverhead || len(ciphertext) > MaxPayload {
		c.clear()
		return nil, errors.New(invalidCipherError)
	}
	plaintext, err := c.decryptor.Open(nil, nil, ciphertext, nil)
	if err != nil {
		clear(plaintext)
		c.clear()
		return nil, errors.New(invalidCipherError)
	}
	return plaintext, nil
}

// clear releases key-schedule references. Go/crypto memory, copied inputs and
// returned plaintext/ciphertext are not guaranteed erased. No handle reuse.
func (c *sessionCipher) clear() {
	if c != nil {
		c.encryptor, c.decryptor = nil, nil
		c.sent = 0
	}
}
