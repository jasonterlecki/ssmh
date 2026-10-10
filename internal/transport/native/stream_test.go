package native

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"testing"
	"time"
)

func sendRemote(t *testing.T, conn net.Conn, kind string, payloadType uint32, sequence int64, data []byte) error {
	t.Helper()
	wire := frame(t, kind, payloadType, sequence, data)
	return writeAll(conn, serverFrame(wsBinary, true, wire))
}

func clientMessage(conn net.Conn) (Message, error) {
	op, wire, err := readClientFrame(conn)
	if err != nil {
		return Message{}, err
	}
	if op != wsBinary {
		return Message{}, errors.New("expected client binary frame")
	}
	return Decode(wire)
}

func acknowledgeInput(t *testing.T, conn net.Conn, m Message) error {
	t.Helper()
	payload, err := json.Marshal(ack{m.Type, m.ID.String(), m.Sequence, true})
	if err != nil {
		return err
	}
	return sendRemote(t, conn, acknowledge, 0, 0, payload)
}

func agentHandshake(t *testing.T, conn net.Conn) error {
	t.Helper()
	if err := sendRemote(t, conn, outputStream, HandshakeRequest, 0, handshake); err != nil {
		return err
	}
	m, err := clientMessage(conn)
	if err != nil {
		return err
	}
	if m.Type != acknowledge {
		return errors.New("handshake request not acknowledged first")
	}
	m, err = clientMessage(conn)
	if err != nil {
		return err
	}
	if m.Type != inputStream || m.PayloadType != HandshakeResponse {
		return errors.New("missing handshake response")
	}
	var response struct{ ClientVersion string }
	if json.Unmarshal(m.Payload, &response) != nil || response.ClientVersion != "1.2.339.0" {
		return errors.New("handshake did not advertise numeric wire compatibility")
	}
	if err = acknowledgeInput(t, conn, m); err != nil {
		return err
	}
	if err = sendRemote(t, conn, outputStream, HandshakeComplete, 1, []byte(`{}`)); err != nil {
		return err
	}
	m, err = clientMessage(conn)
	if err != nil {
		return err
	}
	if m.Type != acknowledge {
		return errors.New("handshake completion not acknowledged")
	}
	return nil
}

func TestNativeChannelBidirectionalStreamAndOwnedEOF(t *testing.T) {
	local, remote := net.Pipe()
	_ = remote.SetDeadline(time.Now().Add(5 * time.Second))
	defer remote.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ctx, trace := WithTrace(ctx)
	c := startChannel(ctx, cancel, &Socket{stream: local}, protocol(t))
	agentDone := make(chan error, 1)
	publicationSent := make(chan struct{})
	go func() {
		defer remote.Close()
		if err := agentHandshake(t, remote); err != nil {
			agentDone <- err
			return
		}
		for _, kind := range []string{pausePublication, pausePublication, startPublication, startPublication} {
			if err := sendRemote(t, remote, kind, 0, 0, nil); err != nil {
				agentDone <- err
				return
			}
		}
		close(publicationSent)
		m, err := clientMessage(remote)
		if err != nil {
			agentDone <- err
			return
		}
		if m.Type != inputStream || m.PayloadType != Output || string(m.Payload) != "hello world" {
			agentDone <- errors.New("terminal input not preserved")
			return
		}
		if err = acknowledgeInput(t, remote, m); err != nil {
			agentDone <- err
			return
		}
		if err = sendRemote(t, remote, outputStream, Output, 2, []byte("response")); err != nil {
			agentDone <- err
			return
		}
		m, err = clientMessage(remote)
		if err != nil || m.Type != acknowledge {
			agentDone <- errors.New("output not acknowledged")
			return
		}
		if err = sendRemote(t, remote, outputStream, StdErr, 3, []byte("stderr")); err != nil {
			agentDone <- err
			return
		}
		m, err = clientMessage(remote)
		if err != nil || m.Type != acknowledge {
			agentDone <- errors.New("stderr not acknowledged")
			return
		}
		data, _ := json.Marshal(map[string]string{"SessionId": ownedID})
		agentDone <- sendRemote(t, remote, channelClosed, 0, 0, data)
	}()
	select {
	case <-c.ready:
	case <-time.After(3 * time.Second):
		t.Fatal("native handshake did not complete")
	}
	// net.Pipe has no TCP send buffer: finish server publication writes before
	// client input, so both peers do not block writing instead of reading.
	select {
	case <-publicationSent:
	case <-time.After(3 * time.Second):
		t.Fatal("publication notifications did not finish")
	}
	if err := c.Send(context.Background(), Output, []byte("hello world")); err != nil {
		t.Fatal(err)
	}
	for _, expected := range []struct {
		kind uint32
		data string
	}{{Output, "response"}, {StdErr, "stderr"}} {
		m, err := c.Receive(context.Background())
		if err != nil || m.PayloadType != expected.kind || string(m.Payload) != expected.data {
			t.Fatal("ordered stream output not preserved")
		}
	}
	if _, err := c.Receive(context.Background()); !errors.Is(err, io.EOF) {
		t.Fatalf("owned close did not produce EOF: %v", err)
	}
	if err := c.Send(context.Background(), Output, []byte("after close")); !errors.Is(err, io.EOF) {
		t.Fatal("input accepted after channel closure")
	}
	if err := <-agentDone; err != nil {
		t.Fatal(err)
	}
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	labels := traceLabels(t, trace)
	if len(labels) != 6 || labels[0] != "protocol readiness pending" || labels[1] != "protocol handshake verified" || labels[2] != "protocol publication paused" || labels[3] != "protocol publication resumed" || labels[4] != "owned-session EOF verified" || labels[5] != "WebSocket closed" {
		t.Fatal("authenticated handshake trace did not preserve state order")
	}
}

func TestNativeChannelCancellationJoinsReader(t *testing.T) {
	local, remote := net.Pipe()
	defer remote.Close()
	ctx, cancel := context.WithCancel(context.Background())
	ctx, trace := WithTrace(ctx)
	c := startChannel(ctx, cancel, &Socket{stream: local}, protocol(t))
	closed := make(chan error, 1)
	go func() { closed <- c.Close() }()
	select {
	case err := <-closed:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("unexpected cancel outcome: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("native reader or event-loop goroutine leaked")
	}
	if _, err := c.Receive(context.Background()); errors.Is(err, io.EOF) || err == nil {
		t.Fatal("local interruption fabricated remote completion")
	}
	labels := traceLabels(t, trace)
	if len(labels) != 3 || labels[0] != "protocol readiness pending" || labels[1] != "WebSocket closed" || labels[2] != "channel canceled" {
		t.Fatal("local cancellation trace fabricated failure or owned completion")
	}
}

func TestNativeChannelDisconnectIsFailure(t *testing.T) {
	local, remote := net.Pipe()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	c := startChannel(ctx, cancel, &Socket{stream: local}, protocol(t))
	_ = remote.Close()
	select {
	case <-c.done:
	case <-time.After(time.Second):
		t.Fatal("disconnect did not end channel")
	}
	if _, err := c.Receive(context.Background()); err == nil || errors.Is(err, io.EOF) {
		t.Fatal("network disconnect represented as successful remote execution")
	}
}

func TestNativeChannelCanceledBackpressureSend(t *testing.T) {
	local, remote := net.Pipe()
	_ = remote.SetDeadline(time.Now().Add(5 * time.Second))
	defer remote.Close()
	lifetime, cancel := context.WithCancel(context.Background())
	defer cancel()
	p := ready(t)
	for i := 0; i < window-1; i++ {
		if _, err := p.Input(Output, []byte("x"), time.Now()); err != nil {
			t.Fatal(err)
		}
	}
	c := startChannel(lifetime, cancel, &Socket{stream: local}, p)
	ctx, stop := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer stop()
	if err := c.Send(ctx, Output, []byte("unsent")); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("blocked send cancellation: %v", err)
	}
	select {
	case <-c.done:
	case <-time.After(time.Second):
		t.Fatal("canceled send did not close channel")
	}
}
