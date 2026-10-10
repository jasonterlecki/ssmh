package native

import "errors"

const (
	muxMaxStreams = 64
	muxSendSize   = 32768 // smux's reviewed default maximum outgoing frame size.
)

var errMuxCapacity = errors.New("forwarding multiplex active-stream limit reached")

// muxDelivery transfers ordered bytes or one peer receive-EOF to a locally
// owned stream. It is not diagnostic data or an application exit status.
type muxDelivery struct {
	stream uint32
	data   []byte
	eof    bool
}

func (muxDelivery) String() string     { return "SSM multiplex delivery [data redacted]" }
func (m muxDelivery) GoString() string { return m.String() }

// muxState is a single-owner client state machine, driven only after Port
// negotiation and outer SSM ordering. It opens no sockets and retains no
// delivered data. Its caller must bound queues, serialize encoded writes and
// stop the whole session on a write failure/unknown delivery, never replay an
// open/data frame on a new connection. Local socket cleanup remains caller-owned.
type muxState struct {
	decoder muxDecoder
	last    uint32
	// Value records peer FIN; the local send direction can remain open.
	streams map[uint32]bool
	closed  bool
}

func newMuxState() *muxState {
	// The reviewed smux client starts at 1 and increments by 2 before opening.
	return &muxState{last: 1, streams: make(map[uint32]bool)}
}

func (*muxState) String() string     { return "SSM multiplex state [data redacted]" }
func (m *muxState) GoString() string { return m.String() }

func (m *muxState) active() bool { return !m.closed && m.streams != nil }

// open reserves a never-reused client stream and returns its SYN frame. State
// advances before transmission; unknown transmission cannot safely be retried.
func (m *muxState) open() (uint32, []byte, error) {
	if !m.active() {
		return 0, nil, errors.New("forwarding multiplex session is inactive")
	}
	if len(m.streams) >= muxMaxStreams {
		return 0, nil, errMuxCapacity
	}
	if m.last > ^uint32(0)-2 {
		return 0, nil, errors.New("forwarding multiplex stream identifiers exhausted")
	}
	id := m.last + 2
	wire, err := encodeMux(muxFrame{command: muxOpen, stream: id})
	if err != nil {
		return 0, nil, err
	}
	m.last = id
	m.streams[id] = false
	return id, wire, nil
}

func (m *muxState) send(id uint32, data []byte) ([]byte, error) {
	if !m.active() {
		return nil, errors.New("forwarding multiplex session is inactive")
	}
	if _, owned := m.streams[id]; !owned {
		return nil, errors.New("forwarding multiplex stream is not locally owned")
	}
	if len(data) == 0 || len(data) > muxSendSize {
		return nil, errors.New("invalid forwarding multiplex outgoing chunk size")
	}
	return encodeMux(muxFrame{command: muxData, stream: id, data: data})
}

// closeStream closes both local directions and emits FIN once. Already ordered
// peer traffic may still arrive; it is discarded, never delivered to another ID.
func (m *muxState) closeStream(id uint32) ([]byte, error) {
	if !m.active() {
		return nil, errors.New("forwarding multiplex session is inactive")
	}
	if _, owned := m.streams[id]; !owned {
		return nil, errors.New("forwarding multiplex stream is not locally owned")
	}
	wire, err := encodeMux(muxFrame{command: muxClose, stream: id})
	if err != nil {
		return nil, err
	}
	delete(m.streams, id)
	return wire, nil
}

func (m *muxState) receive(chunk []byte, deliver func(muxDelivery) error) error {
	if !m.active() {
		return errors.New("forwarding multiplex session is inactive")
	}
	if deliver == nil {
		m.shutdown()
		return errors.New("missing forwarding multiplex consumer")
	}
	err := m.decoder.feed(chunk, func(f muxFrame) error {
		if f.command == muxNoop {
			return nil // Never echo/generate keepalives that extend AWS idle time.
		}
		if f.command == muxOpen || f.stream < 3 || f.stream%2 == 0 || f.stream > m.last {
			return errors.New("unexpected forwarding multiplex stream")
		}
		peerClosed, owned := m.streams[f.stream]
		if !owned {
			// All odd IDs 3..last were actually issued; none are reused. Like
			// upstream smux, discard traffic racing a completed local close.
			return nil
		}
		switch f.command {
		case muxClose:
			if peerClosed {
				return nil // Upstream FIN notification is idempotent.
			}
			m.streams[f.stream] = true
			return deliver(muxDelivery{stream: f.stream, eof: true})
		case muxData:
			if peerClosed {
				return errors.New("forwarding multiplex data follows peer EOF")
			}
			if len(f.data) == 0 {
				return nil
			}
			return deliver(muxDelivery{stream: f.stream, data: f.data})
		}
		return errors.New("unexpected forwarding multiplex command")
	})
	if err != nil {
		m.shutdown()
	}
	return err
}

// finish does not turn a transport disconnect into EOF. The caller may invoke
// it only when outer SSM completion has independently been validated.
func (m *muxState) finish() error {
	if !m.active() {
		return errors.New("forwarding multiplex session is inactive")
	}
	err := m.decoder.finish()
	if err == nil && len(m.streams) != 0 {
		err = errors.New("forwarding multiplex session ended with open local streams")
	}
	m.shutdown()
	return err
}

// shutdown drops state on cancellation/failure without network I/O or FIN
// replay. It cannot close the caller's local connections or AWS session.
func (m *muxState) shutdown() {
	m.closed = true
	m.streams = nil
	m.decoder = muxDecoder{failed: true}
}
