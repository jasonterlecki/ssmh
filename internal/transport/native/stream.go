package native

import (
	"context"
	"errors"
	"io"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"ssmh/internal/config"
	"ssmh/internal/ssm"
)

type inputRequest struct {
	payloadType uint32
	data        []byte
	result      chan error
	ctx         context.Context
}
type wireRead struct {
	opcode byte
	data   []byte
	err    error
}

// Channel owns the socket reader and a single protocol event loop. Output is
// bounded and consumed by Receive; application/terminal data is never logged.
type Channel struct {
	cancel          context.CancelFunc
	done, ready     chan struct{}
	input           chan inputRequest
	output          chan Message
	mu              sync.Mutex
	err             error
	remoteCompleted bool
	forwardTarget   *config.ForwardTarget
	forwardServing  bool
}

func (c *Channel) String() string {
	return "SSM native channel [authentication and stream data redacted]"
}
func (c *Channel) GoString() string { return c.String() }

// RemoteCompleted reports authenticated normal owned-session closure only after
// socket/reader shutdown has joined successfully. Transport EOF is not completion.
func (c *Channel) RemoteCompleted() bool {
	select {
	case <-c.done:
		c.mu.Lock()
		defer c.mu.Unlock()
		return c.remoteCompleted && c.err == nil
	default:
		return false
	}
}

// Connect establishes a native shell/command channel and waits for the verified
// agent handshake, or first ordered output for a verified non-KMS shell. The
// caller still owns SSM TerminateSession and terminal state.
func Connect(ctx context.Context, cfg aws.Config, session *ssm.Session, sessionType string, timeout time.Duration) (*Channel, error) {
	if ctx == nil || session == nil || timeout <= 0 || timeout > 10*time.Minute {
		return nil, errors.New("invalid native connection setup")
	}
	if kind, key := session.DocumentKMSContext(); key != "" && sessionType != kind {
		return nil, errors.New("owned document KMS capability cannot authorize a different session type")
	}
	id, _, _ := session.TransportMaterial()
	protocol, err := NewProtocol(id, sessionType)
	if err != nil {
		return nil, err
	}
	protocol.allowNoHandshake = sessionType == "Standard_Stream" && session.HandshakeOptional()
	return connectProtocol(ctx, cfg, session, protocol, timeout)
}

func connectProtocol(ctx context.Context, cfg aws.Config, session *ssm.Session, protocol *Protocol, timeout time.Duration) (*Channel, error) {
	lifetime, cancel := context.WithCancel(ctx)
	// A single establishment budget includes credential retrieval, HTTP upgrade,
	// token submission, and verified channel readiness; afterwards only ctx applies.
	timer := time.AfterFunc(timeout, cancel)
	if kind, selectedKey := session.DocumentKMSContext(); selectedKey != "" {
		if kind != protocol.expectedType {
			timer.Stop()
			cancel()
			return nil, errors.New("owned document KMS capability does not match protocol type")
		}
		prepare, err := newKMSPreparer(lifetime, cfg, session, selectedKey)
		if err == nil {
			protocol, err = newEncryptedProtocol(protocol.sessionID, protocol.expectedType, selectedKey, prepare)
		}
		if err != nil {
			timer.Stop()
			cancel()
			return nil, err
		}
	}
	recordTrace(lifetime, traceOpening)
	socket, err := openSocket(lifetime, cfg, session, timeout, protocol.clientVersion)
	if err != nil {
		recordTrace(lifetime, traceOpenFailed)
		protocol.clearEncryption()
		timer.Stop()
		cancel()
		return nil, err
	}
	recordTrace(lifetime, traceAuthenticated)
	c := startChannel(lifetime, cancel, socket, protocol)
	select {
	case <-c.ready:
		if !timer.Stop() || lifetime.Err() != nil {
			return nil, errors.Join(errors.New("native SSM readiness timed out or was canceled"), c.Close())
		}
		return c, nil
	case <-c.done:
		timer.Stop()
		cancel()
		err := c.result()
		if err == nil {
			err = errors.New("SSM session ended before verified native readiness")
		}
		return nil, err
	case <-lifetime.Done():
		timer.Stop()
		return nil, errors.Join(errors.New("native SSM connection timed out or was canceled"), c.Close())
	}
}

func startChannel(ctx context.Context, cancel context.CancelFunc, socket *Socket, protocol *Protocol) *Channel {
	c := &Channel{cancel: cancel, done: make(chan struct{}), ready: make(chan struct{}), input: make(chan inputRequest), output: make(chan Message, 8)}
	if protocol.port != nil {
		target := *protocol.port
		c.forwardTarget = &target
	}
	go c.run(ctx, socket, protocol)
	return c
}

// Send submits one bounded operation-specific input/control chunk. Cancellation
// while a send is in progress closes the channel instead of letting a caller
// retry with unknown delivery.
func (c *Channel) Send(ctx context.Context, payloadType uint32, data []byte) error {
	if len(data) == 0 || len(data) > InputSize {
		return errors.New("invalid native input chunk size")
	}
	copyData := append([]byte(nil), data...)
	request := inputRequest{payloadType, copyData, make(chan error, 1), ctx}
	select {
	case c.input <- request:
	case <-ctx.Done():
		return ctx.Err()
	case <-c.done:
		return c.sendEnded()
	}
	select {
	case err := <-request.result:
		if ctx.Err() != nil {
			c.cancel()
			<-c.done
			return ctx.Err()
		}
		return err
	case <-ctx.Done():
		c.cancel()
		<-c.done
		return ctx.Err()
	case <-c.done:
		return c.sendEnded()
	}
}

// Receive returns ordered output or io.EOF only after a validated owned-session
// close message. Transport interruption is an error, never a fabricated success.
func (c *Channel) Receive(ctx context.Context) (Message, error) {
	select {
	case m, ok := <-c.output:
		if ok {
			return m, nil
		}
		err := c.result()
		if err == nil {
			return Message{}, io.EOF
		}
		return Message{}, err
	case <-ctx.Done():
		return Message{}, ctx.Err()
	}
}

// Close cancels network operations, joins both goroutines, and reports failures.
func (c *Channel) Close() error  { c.cancel(); <-c.done; return c.result() }
func (c *Channel) result() error { c.mu.Lock(); defer c.mu.Unlock(); return c.err }
func (c *Channel) sendEnded() error {
	if err := c.result(); err != nil {
		return err
	}
	return io.EOF
}

func (c *Channel) run(ctx context.Context, socket *Socket, p *Protocol) {
	var result error
	remoteCompleted := false
	recordTrace(ctx, traceWaiting)
	stopClose := context.AfterFunc(ctx, func() { _ = socket.Close() })
	defer stopClose()
	reads := make(chan wireRead, 1)
	readerDone := make(chan struct{})
	go func() {
		defer close(readerDone)
		for {
			op, data, err := socket.Read()
			select {
			case reads <- wireRead{op, data, err}:
			case <-ctx.Done():
				return
			}
			if err != nil {
				return
			}
		}
	}()
	defer func() {
		c.cancel()
		p.closed = true
		p.clearEncryption()
		closeErr := socket.Close()
		if closeErr != nil {
			recordTrace(ctx, traceCloseFailed)
		} else {
			recordTrace(ctx, traceClosed)
		}
		// Classify the pre-cleanup cause without hiding independent close failure.
		if result != nil {
			if closeErr == nil && (result == context.Canceled || result == context.DeadlineExceeded) {
				recordTrace(ctx, traceCanceled)
			} else {
				recordTrace(ctx, traceFailed)
			}
		}
		result = errors.Join(result, closeErr)
		<-readerDone
		c.mu.Lock()
		c.err = result
		c.remoteCompleted = remoteCompleted && result == nil
		c.mu.Unlock()
		close(c.output)
		close(c.done)
	}()
	retries := time.NewTicker(100 * time.Millisecond)
	defer retries.Stop()
	keepalive := time.NewTicker(time.Minute)
	defer keepalive.Stop()
	var pending *inputRequest
	var pendingCancel <-chan struct{}
	for {
		// At most one blocked send is retained while the acknowledgement window is
		// full. The unbuffered input queue applies backpressure to producers.
		if pending != nil {
			if err := pending.ctx.Err(); err != nil {
				pending.result <- err
				result = err
				return
			} else {
				m, err := p.Input(pending.payloadType, pending.data, time.Now())
				if !errors.Is(err, ErrBackpressure) {
					if err == nil {
						err = writeMessage(socket, m)
					}
					pending.result <- err
					pending = nil
					pendingCancel = nil
					if err != nil {
						result = err
						return
					}
				}
			}
		}
		input := c.input
		if pending != nil {
			input = nil
		}
		select {
		case <-ctx.Done():
			// Explicit local cancellation is expected; callers separately report
			// duration expiration or the signal that caused cancellation.
			result = ctx.Err()
			return
		case <-pendingCancel:
			pending.result <- pending.ctx.Err()
			result = pending.ctx.Err()
			return
		case request := <-input:
			pending = &request
			pendingCancel = request.ctx.Done()
		case r := <-reads:
			if ctx.Err() != nil {
				result = ctx.Err()
				return
			}
			if r.err != nil {
				result = r.err
				return
			}
			if r.opcode != wsBinary {
				result = errors.New("unexpected text message on authenticated SSM binary channel")
				return
			}
			wasPaused := p.paused
			event, err := p.Process(r.data, time.Now())
			for _, m := range event.Outgoing {
				if e := writeMessage(socket, m); e != nil {
					result = errors.Join(err, e)
					return
				}
			}
			if err != nil {
				result = err
				return
			}
			if event.Ready {
				if p.requested {
					recordTrace(ctx, traceHandshakeReady)
				} else {
					recordTrace(ctx, traceShellReady)
				}
				close(c.ready)
			}
			if p.paused != wasPaused {
				if p.paused {
					recordTrace(ctx, tracePaused)
				} else {
					recordTrace(ctx, traceResumed)
				}
			}
			// Handshake CustomerMessage is metadata, not remote terminal output.
			// Presentation belongs to CLI diagnostics; it is deliberately excluded
			// from command stdout until that diagnostic path is implemented.
			for _, m := range event.Output {
				select {
				case c.output <- m:
				case <-ctx.Done():
					result = ctx.Err()
					return
				}
			}
			if event.Closed {
				remoteCompleted = true
				recordTrace(ctx, traceOwnedEOF)
				return
			}
		case now := <-retries.C:
			m, err := p.Retransmit(now)
			if err != nil {
				result = err
				return
			}
			if m != nil {
				recordTrace(ctx, traceRetransmit)
				if err = writeMessage(socket, *m); err != nil {
					result = err
					return
				}
			}
		case <-keepalive.C:
			if err := socket.Write(wsPing, []byte("keepalive")); err != nil {
				result = err
				return
			}
		}
	}
}

func writeMessage(socket *Socket, m Message) error {
	raw, err := Encode(m)
	if err != nil {
		return err
	}
	return socket.Write(wsBinary, raw)
}
