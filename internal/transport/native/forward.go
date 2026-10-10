package native

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"time"
)

const (
	forwardOutputQueue = 4
	forwardWriteBudget = 10 * time.Second
)

// ServeForward transfers ownership of a matching loopback listener and an
// established Port channel, accepts bounded local connections and serves smux
// traffic until cancellation or owned remote completion. Validation failures
// leave both resources with the caller. AWS termination remains caller-owned.
// Local/peer EOF closes the whole local connection; this serving path does not
// provide independent TCP half-close. Application bytes never enter diagnostics.
func ServeForward(ctx context.Context, channel *Channel, listener net.Listener) error {
	if channel == nil || channel.forwardTarget == nil || listener == nil {
		return errors.New("forwarding requires an established explicit-destination Port channel and loopback listener")
	}
	address, ok := listener.Addr().(*net.TCPAddr)
	if !ok || address == nil || !address.IP.Equal(net.IPv4(127, 0, 0, 1)) || address.Zone != "" || address.Port != channel.forwardTarget.LocalPort {
		return errors.New("forwarding listener must match the requested 127.0.0.1 TCP port")
	}
	select {
	case <-channel.done:
		return errors.New("forwarding channel has ended")
	default:
	}
	select {
	case <-channel.ready:
	default:
		return errors.New("forwarding channel is not ready")
	}
	channel.mu.Lock()
	if channel.forwardServing {
		channel.mu.Unlock()
		return errors.New("forwarding channel already transferred to a listener owner")
	}
	channel.forwardServing = true
	channel.mu.Unlock()
	return serveForward(ctx, channel, listener)
}

// forwardChannel is the test boundary below authenticated Port negotiation.
// The public entrypoint accepts only a native Channel carrying that capability.
type forwardChannel interface {
	Send(context.Context, uint32, []byte) error
	Receive(context.Context) (Message, error)
	Close() error
}

type forwardRead struct {
	message Message
	err     error
}
type forwardData struct {
	id   uint32
	data []byte
}
type forwardEnd struct {
	id     uint32
	failed bool
}

func (forwardData) String() string     { return "forwarding socket data [redacted]" }
func (d forwardData) GoString() string { return d.String() }

type forwardListener struct {
	listener net.Listener
	once     sync.Once
	err      error
}

func (l *forwardListener) close() error {
	l.once.Do(func() {
		if l.listener.Close() != nil {
			l.err = errors.New("close owned forwarding listener failed")
		}
	})
	return l.err
}

type forwardSocket struct {
	conn   net.Conn
	cancel context.CancelFunc
	output chan muxDelivery
	wg     sync.WaitGroup
}

// stop is called only by the owner, once, after removing the wire stream.
func (s *forwardSocket) stop() error {
	s.cancel()
	err := s.conn.Close() // net.Conn Close interrupts blocked reads/writes.
	s.wg.Wait()
	if err != nil {
		return errors.New("close owned forwarding connection failed")
	}
	return nil
}

func serveForward(parent context.Context, channel forwardChannel, listener net.Listener) (result error) {
	ctx, cancel := context.WithCancel(parent)
	ownedListener := &forwardListener{listener: listener}
	stopListener := context.AfterFunc(ctx, func() { _ = ownedListener.close() })
	state := newMuxState()
	connections := make(map[uint32]*forwardSocket)
	// One reserved slot is acquired before Accept. Pending accepts and active
	// connections together cannot exceed 64; the OS backlog provides backpressure.
	slots := make(chan struct{}, muxMaxStreams)
	accepted := make(chan net.Conn)
	acceptFailure := make(chan struct{}, 1)
	acceptDone := make(chan struct{})
	var acceptCleanup error // Read only after joining acceptDone.
	go func() {
		defer close(acceptDone)
		for {
			select {
			case slots <- struct{}{}:
			case <-ctx.Done():
				return
			}
			conn, err := listener.Accept()
			if err != nil || conn == nil {
				if conn != nil && conn.Close() != nil {
					acceptCleanup = errors.New("close failed-accept forwarding connection failed")
				}
				<-slots
				if ctx.Err() == nil {
					acceptFailure <- struct{}{}
				}
				return
			}
			select {
			case accepted <- conn:
			case <-ctx.Done():
				if conn.Close() != nil {
					acceptCleanup = errors.New("close pending forwarding connection failed")
				}
				<-slots
				return
			}
		}
	}()
	reads := make(chan forwardRead, 1)
	readDone := make(chan struct{})
	go func() {
		defer close(readDone)
		for {
			message, err := channel.Receive(ctx)
			select {
			case reads <- forwardRead{message, err}:
			case <-ctx.Done():
				return
			}
			if err != nil {
				return
			}
		}
	}()
	// Reserve 64 extra entries for one FIN per active stream. Data/accept
	// admission stops at 64 entries; EOF handling never needs unbounded storage.
	writes := make(chan []byte, 2*muxMaxStreams)
	written := make(chan error)
	writeDone := make(chan struct{})
	go func() {
		defer close(writeDone)
		for {
			select {
			case data := <-writes:
				var failed error
				transmitCtx, transmitCancel := context.WithTimeout(ctx, forwardWriteBudget)
				for len(data) != 0 {
					size := min(len(data), InputSize)
					if channel.Send(transmitCtx, Output, data[:size]) != nil {
						failed = errors.New("native forwarding data transmission failed")
						break
					}
					data = data[size:]
				}
				transmitCancel()
				select {
				case written <- failed:
				case <-ctx.Done():
					return
				}
				if failed != nil {
					return
				}
			case <-ctx.Done():
				return
			}
		}
	}()
	localData := make(chan forwardData)
	ended := make(chan forwardEnd)
	pendingWrites := 0
	enqueue := func(data []byte) error {
		select {
		case writes <- data:
			pendingWrites++
			return nil
		default:
			return errors.New("forwarding control queue limit exceeded")
		}
	}
	defer func() {
		// Preserve caller cancellation even when a worker failure races it, while
		// retaining independent transmission, protocol or cleanup failures.
		result = errors.Join(result, parent.Err())
		cancel()
		stopListener()
		result = errors.Join(result, ownedListener.close())
		// Stop local I/O before waiting for network-channel shutdown. A slow
		// channel Close must not leave local reads or queued delivery running.
		for _, socket := range connections {
			result = errors.Join(result, socket.stop())
		}
		// Native cancellation joins its own reader/event loop and unblocks Send.
		if closeErr := forwardCloseError(channel.Close()); closeErr != nil {
			result = errors.Join(result, errors.New("close native forwarding channel failed"))
		}
		<-acceptDone
		<-readDone
		<-writeDone
		result = errors.Join(result, acceptCleanup)
		state.shutdown()
	}()
	for {
		dataInput, nextAccepted := localData, accepted
		if len(writes) >= muxMaxStreams {
			dataInput, nextAccepted = nil, nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-acceptFailure:
			return errors.New("accept local forwarding connection failed")
		case conn := <-nextAccepted:
			id, syn, err := state.open()
			if err != nil {
				closeErr := conn.Close()
				<-slots
				if closeErr != nil {
					return errors.Join(err, errors.New("close rejected forwarding connection failed"))
				}
				return err
			}
			socket := startForwardSocket(ctx, id, conn, localData, ended)
			connections[id] = socket
			if err := enqueue(syn); err != nil {
				return err
			}
		case data := <-dataInput:
			if connections[data.id] == nil {
				continue // A read raced a completed full local close; never reuse IDs.
			}
			wire, err := state.send(data.id, data.data)
			if err != nil {
				return err
			}
			if err := enqueue(wire); err != nil {
				return err
			}
		case end := <-ended:
			socket := connections[end.id]
			if socket == nil {
				continue
			}
			if end.failed {
				return errors.New("local forwarding connection I/O failed")
			}
			fin, err := state.closeStream(end.id)
			if err != nil {
				return err
			}
			delete(connections, end.id)
			closeErr := socket.stop()
			<-slots
			if closeErr != nil {
				return closeErr
			}
			if err := enqueue(fin); err != nil {
				return err
			}
		case err := <-written:
			pendingWrites--
			if err != nil {
				return err
			}
		case read := <-reads:
			if read.err != nil {
				if read.err != io.EOF {
					return errors.New("native forwarding channel interrupted")
				}
				if len(connections) != 0 {
					return state.finish() // Active streams cannot produce normal EOF.
				}
				flushCtx, flushCancel := context.WithTimeout(ctx, forwardWriteBudget)
				defer flushCancel()
				for pendingWrites != 0 {
					select {
					case err := <-written:
						pendingWrites--
						if err != nil {
							return err
						}
					case <-flushCtx.Done():
						return errors.New("forwarding session ended with pending transmission")
					}
				}
				return state.finish()
			}
			if read.message.PayloadType == Flag {
				if !validPortFlag(read.message.Payload, portConnectError) {
					return errors.New("invalid forwarding destination control")
				}
				return errors.New("SSM agent could not connect to a forwarding destination; unscoped failure stopped the session")
			}
			if read.message.PayloadType != Output {
				return errors.New("unexpected nonbinary forwarding output")
			}
			// Apply one delivery budget per outer frame, not a fresh timeout per
			// inner frame. A slow reader cannot block this owner indefinitely.
			deliveryCtx, deliveryCancel := context.WithTimeout(ctx, forwardWriteBudget)
			err := state.receive(read.message.Payload, func(delivery muxDelivery) error {
				socket := connections[delivery.stream]
				if socket == nil {
					return errors.New("forwarding delivery has no owned local connection")
				}
				select {
				case socket.output <- delivery:
					return nil
				case <-deliveryCtx.Done():
					return errors.New("forwarding local output backpressure timed out or was canceled")
				}
			})
			deliveryCancel()
			if err != nil {
				return err
			}
		}
	}
}

func startForwardSocket(parent context.Context, id uint32, conn net.Conn, data chan<- forwardData, ended chan<- forwardEnd) *forwardSocket {
	ctx, cancel := context.WithCancel(parent)
	socket := &forwardSocket{conn: conn, cancel: cancel, output: make(chan muxDelivery, forwardOutputQueue)}
	socket.wg.Add(2)
	finish := func(failed bool) {
		select {
		case ended <- forwardEnd{id, failed}:
		case <-ctx.Done():
		}
	}
	go func() {
		defer socket.wg.Done()
		for {
			buffer := make([]byte, muxSendSize)
			n, err := conn.Read(buffer)
			if n < 0 || n > len(buffer) || (n == 0 && err == nil) {
				finish(true)
				return
			}
			if n != 0 {
				select {
				case data <- forwardData{id, buffer[:n]}:
				case <-ctx.Done():
					return
				}
			}
			if err != nil {
				finish(err != io.EOF)
				return
			}
		}
	}()
	go func() {
		defer socket.wg.Done()
		for {
			select {
			case delivery := <-socket.output:
				if delivery.eof {
					finish(false) // Previously queued bytes have all been written.
					return
				}
				if conn.SetWriteDeadline(time.Now().Add(forwardWriteBudget)) != nil || writeAll(conn, delivery.data) != nil {
					finish(true)
					return
				}
			case <-ctx.Done():
				return
			}
		}
	}()
	return socket
}

// Remove only exact local shutdown cancellation leaves; do not hide another
// failure joined with cancellation. Replace surviving causes at the I/O boundary.
func forwardCloseError(err error) error {
	if err == nil || err == context.Canceled {
		return nil
	}
	if joined, ok := err.(interface{ Unwrap() []error }); ok {
		var remaining error
		for _, child := range joined.Unwrap() {
			remaining = errors.Join(remaining, forwardCloseError(child))
		}
		return remaining
	}
	return err
}
