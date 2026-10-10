package native

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/hex"
	"fmt"
	"testing"
)

// Go's AES-256 GCM fixture (32-byte key, 16-byte plaintext, no AAD):
// https://github.com/golang/go/blob/go1.27.2/src/crypto/cipher/gcm_test.go
const publishedCipherKey = "feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308"
const publishedCipherWire = "54cc7dc2c37ec006bcc6d1dad50b9e252b70945d4240d351677eb10f937cdaef6f2822b6a3191654ba41b197"
const publishedCipherPlaintext = "007c5e5b3e59df24a7c355584fc1518d"

func cipherFixture(t testing.TB, encoded string) []byte {
	t.Helper()
	decoded, err := hex.DecodeString(encoded)
	if err != nil {
		t.Fatal("invalid fixed cipher fixture")
	}
	return decoded
}

func TestSessionCipherPublishedAES256Vector(t *testing.T) {
	material := append(cipherFixture(t, publishedCipherKey), make([]byte, 32)...)
	codec := payloadCipher(t, material)
	plaintext, err := codec.decrypt(cipherFixture(t, publishedCipherWire))
	if err != nil || !bytes.Equal(plaintext, cipherFixture(t, publishedCipherPlaintext)) {
		t.Fatal("published AES-256 GCM fixture failed")
	}
}

func syntheticSessionMaterial() []byte {
	material := make([]byte, sessionKeyBytes)
	for i := range material {
		material[i] = byte(i)
	}
	return material
}

func payloadCipher(t *testing.T, material []byte) *sessionCipher {
	t.Helper()
	codec, err := newSessionCipher(material)
	if err != nil {
		t.Fatal("synthetic cipher construction failed")
	}
	t.Cleanup(codec.clear)
	return codec
}

// Independently compose the AWS nonce-prefix convention with standard GCM,
// instead of relying only on a round trip through the codec under test.
func referencePayload(t *testing.T, key, plaintext []byte) []byte {
	t.Helper()
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	mode, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	nonce := bytes.Repeat([]byte{0x7a}, 12) // Synthetic fixture only; never production.
	return append(nonce, mode.Seal(nil, nonce, plaintext, nil)...)
}

func TestSessionCipherDirectionalAWSWireAndOwnership(t *testing.T) {
	material := syntheticSessionMaterial()
	codec := payloadCipher(t, material)
	if !bytes.Equal(material, syntheticSessionMaterial()) {
		t.Fatal("constructor modified caller key material")
	}
	// Clearing the caller's original key buffer must not corrupt the codec.
	clear(material)
	material = syntheticSessionMaterial()
	for _, original := range [][]byte{nil, {0, 3, 4, 0xff, '\n'}, []byte("SYNTHETIC-PRIVATE-PAYLOAD")} {
		plaintext := bytes.Clone(original)
		wire, err := codec.encrypt(plaintext)
		if err != nil || len(wire) != len(original)+28 || !bytes.Equal(plaintext, original) {
			t.Fatal("ciphertext bounds or input ownership changed")
		}
		block, err := aes.NewCipher(material[32:])
		if err != nil {
			t.Fatal(err)
		}
		mode, err := cipher.NewGCM(block)
		if err != nil {
			t.Fatal(err)
		}
		decoded, err := mode.Open(nil, wire[:12], wire[12:], nil)
		if err != nil || !bytes.Equal(decoded, original) {
			t.Fatal("client encrypted with wrong directional key or wire format")
		}
		clear(plaintext)
		decoded, err = mode.Open(nil, wire[:12], wire[12:], nil)
		if err != nil || !bytes.Equal(decoded, original) {
			t.Fatal("ciphertext aliased caller plaintext")
		}
		incoming := referencePayload(t, material[:32], original)
		before := bytes.Clone(incoming)
		decoded, err = codec.decrypt(incoming)
		if err != nil || !bytes.Equal(decoded, original) || !bytes.Equal(incoming, before) {
			t.Fatal("agent encryption convention or ciphertext ownership changed")
		}
		clear(incoming)
		if !bytes.Equal(decoded, original) {
			t.Fatal("returned plaintext aliased ciphertext")
		}
	}
	for _, value := range []any{codec, *codec} {
		for _, format := range []string{"%v", "%+v", "%#v", "%s"} {
			if text := fmt.Sprintf(format, value); text != "native session cipher [key and payload data redacted]" {
				t.Fatal("cipher formatting exposed implementation/key data")
			}
		}
	}
}

func TestSessionCipherKeyBoundsAndReflection(t *testing.T) {
	for _, size := range []int{0, 1, 16, 32, 48, 63, 65, 128, 65536} {
		if codec, err := newSessionCipher(bytes.Repeat([]byte{1}, size)); codec != nil || err == nil || err.Error() != invalidDataKeyError {
			t.Fatal("invalid data key accepted or exposed")
		}
	}
	if codec, err := newSessionCipher(bytes.Repeat([]byte{1}, 64)); codec != nil || err == nil {
		t.Fatal("identical directional keys accepted")
	}
	codec := payloadCipher(t, syntheticSessionMaterial())
	wire, err := codec.encrypt([]byte("SYNTHETIC-PRIVATE-PAYLOAD"))
	if err != nil {
		t.Fatal("fixture encryption failed")
	}
	if plaintext, err := codec.decrypt(wire); err == nil || plaintext != nil || err.Error() != invalidCipherError {
		t.Fatal("reflected client ciphertext accepted as agent output")
	}
	if _, err := codec.encrypt([]byte("later")); err == nil {
		t.Fatal("authentication failure left cipher active")
	}
}

func TestSessionCipherAuthenticationRejectsEveryCorruptedByte(t *testing.T) {
	material := syntheticSessionMaterial()
	wire := referencePayload(t, material[:32], []byte("SYNTHETIC-PRIVATE-PAYLOAD"))
	for i := range wire {
		codec := payloadCipher(t, material)
		bad := bytes.Clone(wire)
		bad[i] ^= 1
		plaintext, err := codec.decrypt(bad)
		if plaintext != nil || err == nil || err.Error() != invalidCipherError || codec.encryptor != nil || codec.decryptor != nil {
			t.Fatal("nonce/ciphertext/tag corruption leaked plaintext or retained active keys")
		}
		if plaintext, err := codec.decrypt(wire); plaintext != nil || err == nil {
			t.Fatal("valid later ciphertext revived failed codec")
		}
	}
}

func TestSessionCipherPayloadLimitsAndClear(t *testing.T) {
	material := syntheticSessionMaterial()
	for size := 0; size < encryptedOverhead; size++ {
		codec := payloadCipher(t, material)
		if plaintext, err := codec.decrypt(make([]byte, size)); plaintext != nil || err == nil {
			t.Fatal("short encrypted payload accepted")
		}
	}
	codec := payloadCipher(t, material)
	plain := bytes.Repeat([]byte{0xff}, MaxPayload-encryptedOverhead)
	wire, err := codec.encrypt(plain)
	if err != nil || len(wire) != MaxPayload {
		t.Fatal("exact encrypted payload limit refused")
	}
	// Agent uses the opposite direction: verify the exact receive bound too.
	wire = referencePayload(t, material[:32], plain)
	decoded, err := codec.decrypt(wire)
	if err != nil || !bytes.Equal(decoded, plain) {
		t.Fatal("exact encrypted receive limit refused")
	}
	for _, encrypt := range []bool{false, true} {
		codec := payloadCipher(t, material)
		var result []byte
		var err error
		if encrypt {
			result, err = codec.encrypt(make([]byte, MaxPayload-encryptedOverhead+1))
		} else {
			result, err = codec.decrypt(make([]byte, MaxPayload+1))
		}
		if result != nil || err == nil || codec.encryptor != nil || codec.decryptor != nil {
			t.Fatal("oversized payload accepted or cipher remained active")
		}
	}
	codec.clear()
	codec.clear()
	var absent *sessionCipher
	absent.clear()
	for _, value := range []*sessionCipher{nil, {}, codec} {
		if data, err := value.encrypt(nil); data != nil || err == nil {
			t.Fatal("inactive encryption accepted")
		}
		if data, err := value.decrypt(wire); data != nil || err == nil {
			t.Fatal("inactive decryption accepted")
		}
	}
}

func TestSessionCipherFreshNoncesAndQuota(t *testing.T) {
	codec := payloadCipher(t, syntheticSessionMaterial())
	seen := map[[12]byte]bool{}
	for range 256 {
		wire, err := codec.encrypt([]byte("same plaintext"))
		if err != nil {
			t.Fatal("encryption failed")
		}
		nonce := [12]byte(wire[:12])
		if seen[nonce] {
			t.Fatal("reused nonce")
		}
		seen[nonce] = true
	}
	codec.sent = maxEncryptedSends - 1
	if _, err := codec.encrypt(nil); err != nil || codec.sent != maxEncryptedSends {
		t.Fatal("last allowed encryption refused")
	}
	if wire, err := codec.encrypt(nil); wire != nil || err == nil || codec.encryptor != nil || codec.decryptor != nil {
		t.Fatal("per-key nonce quota exceeded")
	}
}

func FuzzSessionCipherDecrypt(f *testing.F) {
	f.Add([]byte{})
	f.Add(bytes.Repeat([]byte{1}, encryptedOverhead))
	f.Add(cipherFixture(f, publishedCipherWire))
	f.Fuzz(func(t *testing.T, wire []byte) {
		material := append(cipherFixture(t, publishedCipherKey), make([]byte, 32)...)
		codec := payloadCipher(t, material)
		plaintext, err := codec.decrypt(wire)
		if err != nil {
			if plaintext != nil || err.Error() != invalidCipherError || codec.encryptor != nil || codec.decryptor != nil {
				t.Fatal("decryption failure leaked bytes/errors or retained active cipher")
			}
		} else if len(wire) < encryptedOverhead || len(wire) > MaxPayload || len(plaintext) != len(wire)-encryptedOverhead {
			t.Fatal("successful decryption violated wire bounds")
		}
		if fmt.Sprintf("%#v", codec) != "native session cipher [key and payload data redacted]" {
			t.Fatal("cipher formatting was not redacted")
		}
	})
}
