package native

import (
	"encoding/binary"
	"errors"
)

// AWS Port sessions use smux's default version-1 protocol inside ordered Output
// payloads. These are inner stream frames, not SSM frames or TCP packets. See
// docs/native-forwarding.md for the reviewed AWS and upstream references.
const (
	muxHeaderSize = 8
	muxMaxData    = 65535 // The wire length is an unsigned little-endian uint16.
)

const (
	muxOpen byte = iota
	muxClose
	muxData
	muxNoop
)

type muxFrame struct {
	command byte
	stream  uint32
	data    []byte
}

func (muxFrame) String() string     { return "SSM multiplex frame [data redacted]" }
func (f muxFrame) GoString() string { return f.String() }

func validateMuxHeader(h [muxHeaderSize]byte) error {
	if h[0] != 1 || h[1] > muxNoop {
		return errors.New("unsupported forwarding multiplex version or command")
	}
	size := binary.LittleEndian.Uint16(h[2:4])
	id := binary.LittleEndian.Uint32(h[4:8])
	if h[1] != muxData && size != 0 {
		return errors.New("forwarding multiplex control frame contains data")
	}
	if h[1] == muxNoop && id != 0 || h[1] != muxNoop && id == 0 {
		return errors.New("invalid forwarding multiplex stream identity")
	}
	return nil
}

func encodeMux(f muxFrame) ([]byte, error) {
	if len(f.data) > muxMaxData {
		return nil, errors.New("forwarding multiplex data exceeds wire limit")
	}
	var h [muxHeaderSize]byte
	h[0], h[1] = 1, f.command
	binary.LittleEndian.PutUint16(h[2:4], uint16(len(f.data)))
	binary.LittleEndian.PutUint32(h[4:8], f.stream)
	if err := validateMuxHeader(h); err != nil {
		return nil, err
	}
	raw := make([]byte, muxHeaderSize+len(f.data))
	copy(raw, h[:])
	copy(raw[muxHeaderSize:], f.data)
	return raw, nil
}

// muxDecoder has one owner. It retains at most one partial 8-byte header and
// one bounded body. A completed body's ownership transfers to consume; it never
// aliases the supplied chunk or the next frame. The caller must apply bounded
// backpressure instead of retaining an unbounded collection of delivered frames.
// There is no network I/O, listener, stream lifecycle or negotiation here.
type muxDecoder struct {
	header [muxHeaderSize]byte
	used   int
	body   []byte
	filled int
	failed bool
}

func (*muxDecoder) String() string     { return "SSM multiplex decoder [data redacted]" }
func (d *muxDecoder) GoString() string { return d.String() }

// feed consumes ordered bytes, which may end anywhere within an inner frame.
// Valid frames preceding a later bad frame may already have been delivered.
// Any error permanently closes the decoder and drops its partial-data reference.
func (d *muxDecoder) feed(chunk []byte, consume func(muxFrame) error) (err error) {
	if d.failed {
		return errors.New("forwarding multiplex decoder is no longer active")
	}
	defer func() {
		if err != nil {
			d.failed = true
			d.body = nil
			d.header = [muxHeaderSize]byte{}
			d.used, d.filled = 0, 0
		}
	}()
	if len(chunk) > MaxPayload || consume == nil {
		return errors.New("invalid forwarding multiplex input")
	}
	for len(chunk) != 0 {
		if d.used < muxHeaderSize {
			n := copy(d.header[d.used:], chunk)
			d.used += n
			chunk = chunk[n:]
			if d.used < muxHeaderSize {
				break
			}
			if err = validateMuxHeader(d.header); err != nil {
				return err
			}
			size := int(binary.LittleEndian.Uint16(d.header[2:4]))
			if size != 0 {
				d.body = make([]byte, size)
			}
		}
		n := copy(d.body[d.filled:], chunk)
		d.filled += n
		chunk = chunk[n:]
		if d.filled < len(d.body) {
			break
		}
		frame := muxFrame{d.header[1], binary.LittleEndian.Uint32(d.header[4:8]), d.body}
		d.body = nil
		d.used, d.filled = 0, 0
		if consume(frame) != nil {
			// Consumer errors may contain forwarded data or endpoint information.
			return errors.New("forwarding multiplex frame delivery failed")
		}
	}
	return nil
}

// finish closes the decoder, refusing a truncated stream rather than treating
// missing forwarded bytes as a clean EOF. References are released, not erased.
func (d *muxDecoder) finish() error {
	truncated := d.used != 0
	failed := d.failed
	d.failed = true
	d.body = nil
	d.header = [muxHeaderSize]byte{}
	d.used, d.filled = 0, 0
	if failed {
		return errors.New("forwarding multiplex decoder failed")
	}
	if truncated {
		return errors.New("forwarding multiplex stream ended with an incomplete frame")
	}
	return nil
}
