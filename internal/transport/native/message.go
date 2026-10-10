// Package native implements the verified SSM data-channel wire protocol.
package native

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"math"
	"strings"
	"time"
)

const (
	headerLength = 116 // AWS's length excludes the four-byte payload length field.
	framePrefix  = 120
	// MaxPayload bounds one decoded SSM payload before copying or processing it.
	MaxPayload       = 1 << 20
	inputStream      = "input_stream_data"
	outputStream     = "output_stream_data"
	acknowledge      = "acknowledge"
	channelClosed    = "channel_closed"
	startPublication = "start_publication"
	pausePublication = "pause_publication"
)

// Payload types are assigned by the official AWS Session Manager implementation.
const (
	Output              uint32 = 1
	Error               uint32 = 2
	Size                uint32 = 3
	Parameter           uint32 = 4
	HandshakeRequest    uint32 = 5
	HandshakeResponse   uint32 = 6
	HandshakeComplete   uint32 = 7
	EncryptionChallenge uint32 = 8
	EncryptionResponse  uint32 = 9
	Flag                uint32 = 10
	StdErr              uint32 = 11
	ExitCode            uint32 = 12
)

// UUID stores canonical UUID bytes; the AWS wire encoding swaps its 64-bit halves.
type UUID [16]byte

func newUUID() (UUID, error) {
	var id UUID
	if _, err := rand.Read(id[:]); err != nil {
		return id, errors.New("generate data-channel identifier failed")
	}
	id[6] = (id[6] & 15) | 64
	id[8] = (id[8] & 63) | 128
	return id, nil
}

// String returns the canonical UUID used in acknowledgement JSON.
func (id UUID) String() string {
	var b [36]byte
	hex.Encode(b[:8], id[:4])
	b[8] = '-'
	hex.Encode(b[9:13], id[4:6])
	b[13] = '-'
	hex.Encode(b[14:18], id[6:8])
	b[18] = '-'
	hex.Encode(b[19:23], id[8:10])
	b[23] = '-'
	hex.Encode(b[24:], id[10:])
	return string(b[:])
}

// Message represents one bounded, validated frame. Payload is a remote stream,
// not diagnostic text; formatting the message never exposes its content.
type Message struct {
	Type        string
	Created     uint64
	Sequence    int64
	Flags       uint64
	ID          UUID
	PayloadType uint32
	Payload     []byte
}

func (m Message) String() string   { return "SSM protocol message [payload redacted]" }
func (m Message) GoString() string { return m.String() }

func message(kind string, payloadType uint32, sequence int64, payload []byte) (Message, error) {
	id, err := newUUID()
	if err != nil {
		return Message{}, err
	}
	return Message{Type: kind, Created: uint64(time.Now().UnixMilli()), Sequence: sequence, ID: id, PayloadType: payloadType, Payload: payload}, nil
}

// Decode validates sizes and framing before accessing offsets or copying data.
func Decode(raw []byte) (Message, error) {
	var m Message
	if len(raw) < framePrefix || len(raw) > framePrefix+MaxPayload {
		return m, errors.New("invalid SSM frame size")
	}
	if binary.BigEndian.Uint32(raw[:4]) != headerLength {
		return m, errors.New("unsupported SSM header length")
	}
	if binary.BigEndian.Uint32(raw[36:40]) != 1 {
		return m, errors.New("unsupported SSM message schema")
	}
	n := binary.BigEndian.Uint32(raw[116:120])
	if uint64(n) != uint64(len(raw)-framePrefix) {
		return m, errors.New("SSM payload length mismatch")
	}
	kind := strings.TrimRight(string(raw[4:36]), " \x00")
	if !knownType(kind) {
		return m, errors.New("unexpected SSM message type")
	}
	digest := sha256.Sum256(raw[framePrefix:])
	// AWS publication notifications can carry an unused zero digest and no payload.
	publication := kind == startPublication || kind == pausePublication
	if !bytes.Equal(digest[:], raw[80:112]) && !(publication && n == 0 && bytes.Equal(raw[80:112], make([]byte, 32))) {
		return m, errors.New("SSM payload digest mismatch")
	}
	m.Type = kind
	m.Created = binary.BigEndian.Uint64(raw[40:48])
	m.Sequence = int64(binary.BigEndian.Uint64(raw[48:56]))
	m.Flags = binary.BigEndian.Uint64(raw[56:64])
	m.PayloadType = binary.BigEndian.Uint32(raw[112:116])
	copy(m.ID[8:], raw[64:72])
	copy(m.ID[:8], raw[72:80])
	if m.Sequence < 0 || m.Sequence == math.MaxInt64 || m.Flags & ^uint64(3) != 0 {
		return Message{}, errors.New("invalid SSM sequence or flags")
	}
	if !publication && (m.Created == 0 || m.ID == (UUID{})) {
		return Message{}, errors.New("missing SSM message metadata")
	}
	if m.PayloadType > ExitCode {
		return Message{}, errors.New("unsupported SSM payload type")
	}
	if publication && (n != 0 || m.PayloadType != 0) {
		return Message{}, errors.New("invalid SSM publication notification")
	}
	m.Payload = bytes.Clone(raw[framePrefix:])
	return m, nil
}

func knownType(s string) bool {
	switch s {
	case inputStream, outputStream, acknowledge, channelClosed, startPublication, pausePublication:
		return true
	}
	return false
}

// Encode serializes a frame using the official AWS offsets and UUID ordering.
func Encode(m Message) ([]byte, error) {
	if !knownType(m.Type) || len(m.Payload) > MaxPayload || m.Sequence < 0 || m.Sequence == math.MaxInt64 || m.PayloadType > ExitCode || m.Flags & ^uint64(3) != 0 || m.Created == 0 || m.ID == (UUID{}) {
		return nil, errors.New("invalid outgoing SSM message")
	}
	raw := make([]byte, framePrefix+len(m.Payload))
	binary.BigEndian.PutUint32(raw[:4], headerLength)
	for i := 4; i < 36; i++ {
		raw[i] = ' '
	}
	copy(raw[4:36], m.Type)
	binary.BigEndian.PutUint32(raw[36:40], 1)
	binary.BigEndian.PutUint64(raw[40:48], m.Created)
	binary.BigEndian.PutUint64(raw[48:56], uint64(m.Sequence))
	binary.BigEndian.PutUint64(raw[56:64], m.Flags)
	copy(raw[64:72], m.ID[8:])
	copy(raw[72:80], m.ID[:8])
	sum := sha256.Sum256(m.Payload)
	copy(raw[80:112], sum[:])
	binary.BigEndian.PutUint32(raw[112:116], m.PayloadType)
	binary.BigEndian.PutUint32(raw[116:120], uint32(len(m.Payload)))
	copy(raw[120:], m.Payload)
	return raw, nil
}
