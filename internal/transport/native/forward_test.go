package native

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"ssmh/internal/config"
)

type forwardTestChannel struct {
	reads    chan forwardRead
	writes   chan []byte
	closed   chan struct{}
	once     sync.Once
	closes   atomic.Int32
	gate     <-chan struct{}
	sendErr  error
	closeErr error
}

func newForwardTestChannel() *forwardTestChannel {
	return &forwardTestChannel{reads: make(chan forwardRead, 16), writes: make(chan []byte, 4096), closed: make(chan struct{})}
}
func (c *forwardTestChannel) Send(ctx context.Context, kind uint32, data []byte) error {
	if kind != Output || len(data) == 0 || len(data) > InputSize {
		return errors.New("incorrect forwarding SSM chunk")
	}
	if _, bounded := ctx.Deadline(); !bounded {
		return errors.New("forwarding transmission has no deadline")
	}
	if c.gate != nil {
		select {
		case <-c.gate:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	if c.sendErr != nil {
		return c.sendErr
	}
	select {
	case c.writes <- bytes.Clone(data):
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
func (c *forwardTestChannel) Receive(ctx context.Context) (Message, error) {
	select {
	case read := <-c.reads:
		return read.message, read.err
	case <-ctx.Done():
		return Message{}, ctx.Err()
	case <-c.closed:
		return Message{}, errors.New("closed fixture channel")
	}
}
func (c *forwardTestChannel) Close() error {
	c.once.Do(func() { c.closes.Add(1); close(c.closed) })
	return c.closeErr
}
func (c *forwardTestChannel) inner(t *testing.T, frames ...muxFrame) {
	t.Helper()
	var data []byte
	for _, frame := range frames {
		wire, err := encodeMux(frame)
		if err != nil {
			t.Fatal(err)
		}
		data = append(data, wire...)
	}
	c.reads <- forwardRead{message: Message{PayloadType: Output, Payload: data}}
}

type forwardAccept struct {
	conn net.Conn
	err  error
}
type forwardTestListener struct {
	accept   chan forwardAccept
	closed   chan struct{}
	once     sync.Once
	closes   atomic.Int32
	calls    atomic.Int32
	address  net.Addr
	closeErr error
}

func newForwardTestListener() *forwardTestListener {
	return &forwardTestListener{accept: make(chan forwardAccept), closed: make(chan struct{}), address: &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 8080}}
}
func (l *forwardTestListener) Accept() (net.Conn, error) {
	l.calls.Add(1)
	select {
	case accept := <-l.accept:
		return accept.conn, accept.err
	case <-l.closed:
		return nil, net.ErrClosed
	}
}
func (l *forwardTestListener) Close() error {
	l.once.Do(func() { l.closes.Add(1); close(l.closed) })
	return l.closeErr
}
func (l *forwardTestListener) Addr() net.Addr { return l.address }

type forwardTestConn struct {
	net.Conn
	closes                atomic.Int32
	closeErr, deadlineErr error
	writeStarted          chan struct{}
	writeSeen             sync.Once
	immediateDeadline     bool
}

func (c *forwardTestConn) Close() error {
	c.closes.Add(1)
	err := c.Conn.Close()
	return errors.Join(err, c.closeErr)
}
func (c *forwardTestConn) SetWriteDeadline(deadline time.Time) error {
	if c.writeStarted != nil {
		c.writeSeen.Do(func() { close(c.writeStarted) })
	}
	if c.deadlineErr != nil {
		return c.deadlineErr
	}
	if c.immediateDeadline {
		deadline = time.Now().Add(-time.Second)
	}
	return c.Conn.SetWriteDeadline(deadline)
}

func offerForwardConn(t *testing.T, listener *forwardTestListener) (*forwardTestConn, net.Conn) {
	t.Helper()
	local, client := net.Pipe()
	owned := &forwardTestConn{Conn: local}
	_ = client.SetDeadline(time.Now().Add(5 * time.Second))
	select {
	case listener.accept <- forwardAccept{conn: owned}:
	case <-listener.closed:
		_ = local.Close()
		_ = client.Close()
		t.Fatal("listener closed before fixture offer")
	case <-time.After(3 * time.Second):
		_ = local.Close()
		_ = client.Close()
		t.Fatal("fixture accept timed out")
	}
	return owned, client
}

type forwardTestDecoder struct {
	decoder muxDecoder
	frames  []muxFrame
}

func (d *forwardTestDecoder) next(t *testing.T, channel *forwardTestChannel) muxFrame {
	t.Helper()
	for len(d.frames) == 0 {
		select {
		case data := <-channel.writes:
			if err := d.decoder.feed(data, func(frame muxFrame) error {
				d.frames = append(d.frames, frame)
				return nil
			}); err != nil {
				t.Fatal(err)
			}
		case <-time.After(3 * time.Second):
			t.Fatal("outgoing mux frame timed out")
		}
	}
	frame := d.frames[0]
	d.frames = d.frames[1:]
	return frame
}

func forwardResult(t *testing.T, done <-chan error) error {
	t.Helper()
	select {
	case err := <-done:
		return err
	case <-time.After(3 * time.Second):
		t.Fatal("forwarding owner failed to join workers")
		return nil
	}
}

func TestServeForwardConcurrentBinaryStreams(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	channel, listener := newForwardTestChannel(), newForwardTestListener()
	done := make(chan error, 1)
	go func() { done <- serveForward(ctx, channel, listener) }()
	var decoder forwardTestDecoder
	owned3, client3 := offerForwardConn(t, listener)
	defer client3.Close()
	if frame := decoder.next(t, channel); frame.command != muxOpen || frame.stream != 3 {
		t.Fatal("first local stream not opened as ID 3")
	}
	owned5, client5 := offerForwardConn(t, listener)
	defer client5.Close()
	if frame := decoder.next(t, channel); frame.command != muxOpen || frame.stream != 5 {
		t.Fatal("second local stream not opened as ID 5")
	}
	binary3, binary5 := []byte{'\n', '\r', 0, 255}, []byte("separate\x00stream")
	writes := make(chan error, 2)
	go func() { writes <- writeAll(client3, binary3) }()
	go func() { writes <- writeAll(client5, binary5) }()
	seen := make(map[uint32][]byte)
	for i := 0; i < 2; i++ {
		frame := decoder.next(t, channel)
		if frame.command != muxData {
			t.Fatal("client application bytes not encoded as mux PSH")
		}
		seen[frame.stream] = frame.data
	}
	if !bytes.Equal(seen[3], binary3) || !bytes.Equal(seen[5], binary5) || <-writes != nil || <-writes != nil {
		t.Fatal("concurrent binary input changed or crossed streams")
	}
	type output struct {
		id   uint32
		data []byte
		err  error
	}
	outputs := make(chan output, 2)
	go func() { data, err := io.ReadAll(client3); outputs <- output{3, data, err} }()
	go func() { data, err := io.ReadAll(client5); outputs <- output{5, data, err} }()
	channel.inner(t, muxFrame{command: muxData, stream: 5, data: binary5}, muxFrame{command: muxData, stream: 3, data: binary3}, muxFrame{command: muxClose, stream: 3}, muxFrame{command: muxClose, stream: 5})
	for i := 0; i < 2; i++ {
		out := <-outputs
		want := binary3
		if out.id == 5 {
			want = binary5
		}
		if out.err != nil || !bytes.Equal(out.data, want) {
			t.Fatal("peer FIN discarded pending bytes or crossed streams")
		}
	}
	closed := map[uint32]bool{}
	for i := 0; i < 2; i++ {
		frame := decoder.next(t, channel)
		if frame.command != muxClose || closed[frame.stream] {
			t.Fatal("missing or duplicate local FIN")
		}
		closed[frame.stream] = true
	}
	channel.reads <- forwardRead{err: io.EOF}
	if err := forwardResult(t, done); err != nil || owned3.closes.Load() != 1 || owned5.closes.Load() != 1 || listener.closes.Load() != 1 || channel.closes.Load() != 1 {
		t.Fatalf("owned completion or cleanup failed: %v", err)
	}
}

func TestServeForwardLocalEOFRetiresWithoutIDReuse(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	channel, listener := newForwardTestChannel(), newForwardTestListener()
	done := make(chan error, 1)
	go func() { done <- serveForward(ctx, channel, listener) }()
	var decoder forwardTestDecoder
	owned, client := offerForwardConn(t, listener)
	if frame := decoder.next(t, channel); frame.stream != 3 {
		t.Fatal("incorrect first ID")
	}
	_ = client.Close()
	if frame := decoder.next(t, channel); frame.command != muxClose || frame.stream != 3 {
		t.Fatal("local EOF did not emit FIN")
	}
	second, nextClient := offerForwardConn(t, listener)
	defer nextClient.Close()
	if frame := decoder.next(t, channel); frame.command != muxOpen || frame.stream != 5 {
		t.Fatal("retired ID reused")
	}
	channel.inner(t, muxFrame{command: muxData, stream: 3, data: []byte("retired-secret")}, muxFrame{command: muxClose, stream: 3}, muxFrame{command: muxData, stream: 5, data: []byte("current")})
	data := make([]byte, 7)
	if _, err := io.ReadFull(nextClient, data); err != nil || string(data) != "current" {
		t.Fatal("late retired bytes reached a new connection")
	}
	cancel()
	if err := forwardResult(t, done); err == nil || owned.closes.Load() != 1 || second.closes.Load() != 1 {
		t.Fatal("canceled ownership not cleaned")
	}
}

func TestServeForwardFailuresAndCleanup(t *testing.T) {
	for _, kind := range []string{"destination", "invalid-flag", "terminal", "disconnect", "malformed-mux", "truncated-eof", "active-eof", "send", "socket-deadline", "socket-write-timeout", "socket-close", "listener-close", "channel-close", "accept"} {
		t.Run(kind, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			channel, listener := newForwardTestChannel(), newForwardTestListener()
			marker := errors.New("synthetic-secret-marker")
			if kind == "send" {
				channel.sendErr = marker
			}
			if kind == "listener-close" {
				listener.closeErr = marker
			}
			if kind == "channel-close" {
				channel.closeErr = errors.Join(context.Canceled, marker)
			}
			done := make(chan error, 1)
			go func() { done <- serveForward(ctx, channel, listener) }()
			var owned *forwardTestConn
			if kind == "send" || kind == "active-eof" || kind == "socket-deadline" || kind == "socket-write-timeout" || kind == "socket-close" {
				local, client := net.Pipe()
				defer client.Close()
				owned = &forwardTestConn{Conn: local}
				if kind == "socket-deadline" {
					owned.deadlineErr = marker
				}
				owned.immediateDeadline = kind == "socket-write-timeout"
				if kind == "socket-close" {
					owned.closeErr = marker
				}
				listener.accept <- forwardAccept{conn: owned}
				if kind != "send" {
					var decoder forwardTestDecoder
					_ = decoder.next(t, channel)
				}
			}
			switch kind {
			case "destination":
				channel.reads <- forwardRead{message: Message{PayloadType: Flag, Payload: []byte{0, 0, 0, 3}}}
			case "invalid-flag":
				channel.reads <- forwardRead{message: Message{PayloadType: Flag, Payload: []byte{3}}}
			case "terminal":
				channel.reads <- forwardRead{message: Message{PayloadType: StdErr, Payload: []byte("synthetic-secret-marker")}}
			case "disconnect":
				channel.reads <- forwardRead{err: marker}
			case "malformed-mux":
				channel.reads <- forwardRead{message: Message{PayloadType: Output, Payload: []byte{2, 0, 0, 0, 3, 0, 0, 0}}}
			case "truncated-eof":
				channel.reads <- forwardRead{message: Message{PayloadType: Output, Payload: []byte{1, 2}}}
				channel.reads <- forwardRead{err: io.EOF}
			case "active-eof", "listener-close", "channel-close":
				channel.reads <- forwardRead{err: io.EOF}
			case "socket-deadline", "socket-write-timeout":
				channel.inner(t, muxFrame{command: muxData, stream: 3, data: []byte("synthetic-secret-marker")})
			case "socket-close":
				channel.inner(t, muxFrame{command: muxClose, stream: 3})
			case "accept":
				listener.accept <- forwardAccept{err: marker}
			}
			err := forwardResult(t, done)
			if err == nil || strings.Contains(err.Error(), "synthetic-secret-marker") || listener.closes.Load() != 1 || channel.closes.Load() != 1 {
				t.Fatalf("failure suppressed, disclosed, or not cleaned: %v", err)
			}
			if owned != nil && owned.closes.Load() != 1 {
				t.Fatal("owned connection not closed once")
			}
		})
	}
}

func TestServeForwardPartialAcceptCleanup(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	channel, listener := newForwardTestChannel(), newForwardTestListener()
	done := make(chan error, 1)
	go func() { done <- serveForward(ctx, channel, listener) }()
	local, client := net.Pipe()
	defer client.Close()
	owned := &forwardTestConn{Conn: local, closeErr: errors.New("synthetic-secret-marker")}
	listener.accept <- forwardAccept{conn: owned, err: errors.New("synthetic-secret-marker")}
	err := forwardResult(t, done)
	if err == nil || strings.Contains(err.Error(), "synthetic-secret-marker") || !strings.Contains(err.Error(), "close failed-accept") || owned.closes.Load() != 1 {
		t.Fatal("partial accept lost ownership, close error or redaction")
	}
}

func TestServeForwardCapacityAndBlockedSenderCancellation(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	channel, listener := newForwardTestChannel(), newForwardTestListener()
	channel.gate = make(chan struct{}) // All native transmission remains blocked.
	done := make(chan error, 1)
	go func() { done <- serveForward(ctx, channel, listener) }()
	owned := make([]*forwardTestConn, muxMaxStreams)
	for i := range owned {
		conn, client := offerForwardConn(t, listener)
		owned[i] = conn
		defer client.Close()
	}
	if listener.calls.Load() != muxMaxStreams {
		t.Fatal("accept capacity exceeded before backpressure")
	}
	// No 65th connection can be accepted while all slots are held. This is a
	// readiness probe on the fixture, not a timing-based negative assertion.
	local, client := net.Pipe()
	defer local.Close()
	defer client.Close()
	select {
	case listener.accept <- forwardAccept{conn: local}:
		t.Fatal("65th connection accepted")
	default:
	}
	cancel()
	if err := forwardResult(t, done); !errors.Is(err, context.Canceled) {
		t.Fatal("blocked sender cancellation lost")
	}
	for _, conn := range owned {
		if conn.closes.Load() != 1 {
			t.Fatal("capacity-limit connection leaked or closed twice")
		}
	}
	if listener.closes.Load() != 1 || channel.closes.Load() != 1 {
		t.Fatal("capacity cancellation failed to close owners")
	}
}

func TestServeForwardSlowLocalReaderCancellation(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	channel, listener := newForwardTestChannel(), newForwardTestListener()
	done := make(chan error, 1)
	go func() { done <- serveForward(ctx, channel, listener) }()
	local, client := net.Pipe()
	owned := &forwardTestConn{Conn: local, writeStarted: make(chan struct{})}
	listener.accept <- forwardAccept{conn: owned}
	defer client.Close() // Never read: the writer and bounded queue must block.
	var decoder forwardTestDecoder
	_ = decoder.next(t, channel)
	frames := make([]muxFrame, 12)
	for i := range frames {
		frames[i] = muxFrame{command: muxData, stream: 3, data: bytes.Repeat([]byte{0xff}, muxMaxData)}
	}
	channel.inner(t, frames...)
	select {
	case <-owned.writeStarted:
	case <-ctx.Done():
		t.Fatal("fixture never reached blocked local write")
	}
	cancel()
	if err := forwardResult(t, done); err == nil || owned.closes.Load() != 1 || channel.closes.Load() != 1 || listener.closes.Load() != 1 {
		t.Fatal("slow local delivery prevented cancellation/cleanup")
	}
}

func TestServeForwardLoopbackAndCapabilityGate(t *testing.T) {
	target := config.ForwardTarget{LocalPort: 8080, RemotePort: 80}
	for _, kind := range []string{"nil-channel", "shell", "nil-listener", "public", "other-loopback", "ipv6", "wrong-port", "unix", "not-ready", "ended", "already-owned"} {
		t.Run(kind, func(t *testing.T) {
			channel := &Channel{forwardTarget: &target, ready: make(chan struct{}), done: make(chan struct{})}
			if kind != "not-ready" {
				close(channel.ready)
			}
			listener := newForwardTestListener()
			var candidate net.Listener = listener
			switch kind {
			case "nil-channel":
				channel = nil
			case "shell":
				channel.forwardTarget = nil
			case "nil-listener":
				candidate = nil
			case "public":
				listener.address = &net.TCPAddr{IP: net.IPv4zero, Port: 8080}
			case "other-loopback":
				listener.address = &net.TCPAddr{IP: net.IPv4(127, 0, 0, 2), Port: 8080}
			case "ipv6":
				listener.address = &net.TCPAddr{IP: net.IPv6loopback, Port: 8080}
			case "wrong-port":
				listener.address = &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 8081}
			case "unix":
				listener.address = &net.UnixAddr{Name: "synthetic-secret-marker", Net: "unix"}
			case "ended":
				close(channel.done)
			case "already-owned":
				channel.forwardServing = true
			}
			err := ServeForward(context.Background(), channel, candidate)
			if err == nil || strings.Contains(err.Error(), "synthetic-secret-marker") || listener.closes.Load() != 0 || listener.calls.Load() != 0 {
				t.Fatal("invalid setup accepted or took ownership")
			}
		})
	}
}

func TestForwardSocketFullReadBeforeEOFAndFormatting(t *testing.T) {
	// A reader may return bytes and EOF together; those bytes precede FIN.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	base, peer := net.Pipe()
	defer peer.Close()
	conn := &forwardBytesEOFConn{Conn: base}
	data, ended := make(chan forwardData), make(chan forwardEnd)
	socket := startForwardSocket(ctx, 3, conn, data, ended)
	chunk := <-data
	if chunk.id != 3 || string(chunk.data) != "synthetic-secret-marker" {
		t.Fatal("bytes accompanying EOF lost")
	}
	if end := <-ended; end.id != 3 || end.failed {
		t.Fatal("local EOF misclassified")
	}
	if err := socket.stop(); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(fmt.Sprintf("%v %#v", chunk, chunk), "synthetic-secret-marker") {
		t.Fatal("local packet formatting exposed bytes")
	}
	if forwardCloseError(errors.Join(context.Canceled, errors.New("independent"))) == nil || forwardCloseError(errors.Join(context.Canceled, context.Canceled)) != nil {
		t.Fatal("shutdown filtering hid an independent failure")
	}
}

type forwardBytesEOFConn struct{ net.Conn }

func (c *forwardBytesEOFConn) Read(data []byte) (int, error) {
	return copy(data, "synthetic-secret-marker"), io.EOF
}

func TestServeForwardLargeFramesApplyBackpressure(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	channel, listener := newForwardTestChannel(), newForwardTestListener()
	done := make(chan error, 1)
	go func() { done <- serveForward(ctx, channel, listener) }()
	owned, client := offerForwardConn(t, listener)
	defer client.Close()
	var decoder forwardTestDecoder
	_ = decoder.next(t, channel)
	input := bytes.Repeat([]byte{'\n', 0, 255, '\r'}, 2*muxSendSize/4)
	writeDone := make(chan error, 1)
	go func() { writeDone <- writeAll(client, input) }()
	var got []byte
	for len(got) < len(input) {
		frame := decoder.next(t, channel)
		if frame.command != muxData || frame.stream != 3 || len(frame.data) > muxSendSize {
			t.Fatal("large local input not bounded by mux chunk size")
		}
		got = append(got, frame.data...)
	}
	if !bytes.Equal(got, input) || <-writeDone != nil {
		t.Fatal("large local binary input changed")
	}
	// More inner frames than queue slots in one outer payload must apply
	// backpressure, not immediately fail even when the reader is ready.
	frames := make([]muxFrame, 31)
	want := bytes.Repeat([]byte{0, 255, '\n'}, muxSendSize/3)
	for i := range frames {
		frames[i] = muxFrame{command: muxData, stream: 3, data: want}
	}
	output := make([]byte, len(want)*len(frames))
	readDone := make(chan error, 1)
	go func() { _, err := io.ReadFull(client, output); readDone <- err }()
	channel.inner(t, frames...)
	if err := <-readDone; err != nil || !bytes.Equal(output, bytes.Repeat(want, len(frames))) {
		t.Fatal("batched output lost to queue pressure")
	}
	channel.inner(t, muxFrame{command: muxClose, stream: 3})
	if frame := decoder.next(t, channel); frame.command != muxClose {
		t.Fatal("batched output did not close cleanly")
	}
	channel.reads <- forwardRead{err: io.EOF}
	if err := forwardResult(t, done); err != nil || owned.closes.Load() != 1 {
		t.Fatal("large transfer failed cleanup")
	}
}

// This composes the real outer SSM sequencing/acknowledgement loop, inner mux,
// listener owner and socket workers over in-memory connections. TLS/authentication
// is covered separately by ConnectForward tests; no OS TCP listener or AWS is used.
func TestServeForwardRealNativeChannel(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	local, agent := net.Pipe()
	defer agent.Close()
	_ = agent.SetDeadline(time.Now().Add(5 * time.Second))
	target := config.ForwardTarget{LocalPort: 8080, RemotePort: 80}
	channelCtx, channelCancel := context.WithCancel(ctx)
	channel := startChannel(channelCtx, channelCancel, &Socket{stream: local}, portProtocol(t, target))
	defer channel.Close()
	binary := bytes.Repeat([]byte{'\n', '\r', 0, 255}, 300)
	agentDone := make(chan error, 1)
	go func() {
		if err := portAgentHandshake(t, agent, portRequest(t, target, "3.3.0.0")); err != nil {
			agentDone <- err
			return
		}
		var decoder muxDecoder
		var frames []muxFrame
		readInner := func() error {
			m, err := clientMessage(agent)
			if err != nil {
				return err
			}
			if m.Type != inputStream || m.PayloadType != Output || len(m.Payload) > InputSize {
				return errors.New("invalid outer forwarding input")
			}
			if err := acknowledgeInput(t, agent, m); err != nil {
				return err
			}
			return decoder.feed(m.Payload, func(frame muxFrame) error { frames = append(frames, frame); return nil })
		}
		for len(frames) < 2 {
			if err := readInner(); err != nil {
				agentDone <- err
				return
			}
		}
		if frames[0].command != muxOpen || frames[0].stream != 3 || frames[1].command != muxData || frames[1].stream != 3 || !bytes.Equal(frames[1].data, binary) {
			agentDone <- errors.New("native input lost mux ordering or bytes")
			return
		}
		data, _ := encodeMux(muxFrame{command: muxData, stream: 3, data: binary})
		fin, _ := encodeMux(muxFrame{command: muxClose, stream: 3})
		wire := frame(t, outputStream, Output, 2, data)
		for i := 0; i < 2; i++ {
			// Exact outer retransmission while the local stream is active must
			// not inject the same TCP application bytes twice.
			if err := writeAll(agent, serverFrame(wsBinary, true, wire)); err != nil {
				agentDone <- err
				return
			}
			m, err := clientMessage(agent)
			if err != nil || m.Type != acknowledge {
				agentDone <- errors.New("native mux output/retransmission not acknowledged")
				return
			}
		}
		if err := sendRemote(t, agent, outputStream, Output, 3, fin); err != nil {
			agentDone <- err
			return
		}
		m, err := clientMessage(agent)
		if err != nil || m.Type != acknowledge {
			agentDone <- errors.New("native mux FIN not acknowledged")
			return
		}
		for len(frames) < 3 {
			if err := readInner(); err != nil {
				agentDone <- err
				return
			}
		}
		if frames[2].command != muxClose || frames[2].stream != 3 {
			agentDone <- errors.New("native peer EOF did not retire the local stream")
			return
		}
		err = sendRemote(t, agent, channelClosed, 0, 0, []byte(`{"SessionId":"`+ownedID+`"}`))
		agentDone <- err
	}()
	select {
	case <-channel.ready:
	case <-ctx.Done():
		t.Fatal("Port channel not ready")
	}
	listener := newForwardTestListener()
	done := make(chan error, 1)
	go func() { done <- ServeForward(ctx, channel, listener) }()
	owned, client := offerForwardConn(t, listener)
	defer client.Close()
	if err := writeAll(client, binary); err != nil {
		t.Fatal(err)
	}
	output, err := io.ReadAll(client)
	if err != nil || !bytes.Equal(output, binary) {
		t.Fatal("real native mux output changed or was truncated")
	}
	if err := forwardResult(t, done); err != nil {
		t.Fatal(err)
	}
	if err := <-agentDone; err != nil {
		t.Fatal(err)
	}
	if owned.closes.Load() != 1 || listener.closes.Load() != 1 {
		t.Fatal("native composed ownership cleanup failed")
	}
}
