//go:build linux

package terminal

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/signal"
	"sync"
	"syscall"

	"ssmh/internal/transport/native"
)

// Channel is the authenticated shell-stream boundary. Receive must return EOF
// only for validated remote completion. Close must unblock and join channel I/O.
type Channel interface {
	Send(context.Context, uint32, []byte) error
	Receive(context.Context) (native.Message, error)
	Close() error
}

// Run connects local stdio to an established interactive native shell. It owns
// channel shutdown and terminal restoration, not AWS TerminateSession. It handles
// external termination signals; physical Ctrl+C is transmitted in raw mode.
// Input EOF sends one remote Ctrl+D and continues draining output. Only TTY input
// enables escapes; redirected input is unchanged. Files remain caller-owned.
func Run(ctx context.Context, channel Channel, input, output, stderr *os.File) error {
	lifetime, stop := signal.NotifyContext(ctx, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP, syscall.SIGQUIT)
	defer stop()
	resizes := make(chan os.Signal, 1)
	signal.Notify(resizes, syscall.SIGWINCH)
	defer signal.Stop(resizes)
	return runSession(lifetime, channel, input, output, stderr, resizes)
}

type workerResult struct {
	worker     int
	disconnect bool
	err        error
}

const (
	inputWorker = iota
	outputWorker
	resizeWorker
)

func runSession(ctx context.Context, channel Channel, input, output, stderr *os.File, resizes <-chan os.Signal) (result error) {
	if channel == nil {
		return errors.New("missing authenticated terminal channel")
	}
	lifetime, cancel := context.WithCancel(ctx)
	var workers sync.WaitGroup
	results := make(chan workerResult, 3)
	var streams []*Stream
	var state *State
	defer func() {
		cancel()
		closeErr := withoutCanceled(channel.Close())
		workers.Wait()
		// Preserve independent worker failures that raced with completion or local
		// cancellation. Expected cancellation alone is not a cleanup failure.
		close(results)
		for r := range results {
			if r.worker == inputWorker && r.err == io.EOF {
				continue
			}
			result = errors.Join(result, withoutCanceled(r.err))
		}
		result = errors.Join(result, closeErr, state.Restore())
		for _, stream := range streams {
			result = errors.Join(result, stream.Close())
		}
	}()
	if err := ctx.Err(); err != nil {
		return err
	}
	if input == nil {
		return errors.New("missing local input")
	}
	fd, err := fileDescriptor(input)
	if err != nil {
		return err
	}
	tty, err := IsTerminal(fd)
	if err != nil {
		return err
	}
	for _, file := range []*os.File{input, output, stderr} {
		stream, err := OpenStream(file, len(streams) > 0)
		if err != nil {
			return err
		}
		streams = append(streams, stream)
	}
	if tty {
		state, err = MakeRaw(fd)
		if err != nil {
			return err
		}
		if err = sendSize(lifetime, channel, fd); err != nil {
			return err
		}
	}
	start := func(worker int, work func() (bool, error)) {
		workers.Add(1)
		go func() {
			defer workers.Done()
			disconnect, err := work()
			results <- workerResult{worker, disconnect, err}
		}()
	}
	start(inputWorker, func() (bool, error) { return sendInput(lifetime, channel, streams[0], tty) })
	start(outputWorker, func() (bool, error) { return false, receiveOutput(lifetime, channel, streams[1], streams[2]) })
	if tty {
		start(resizeWorker, func() (bool, error) {
			for {
				select {
				case <-lifetime.Done():
					return false, lifetime.Err()
				case _, ok := <-resizes:
					if !ok {
						return false, errors.New("terminal resize notification channel closed")
					}
					if err := sendSize(lifetime, channel, fd); err != nil {
						return false, err
					}
				}
			}
		})
	}
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case r := <-results:
			if r.worker == inputWorker && !r.disconnect && (r.err == nil || r.err == io.EOF) {
				continue
			}
			if ctx.Err() != nil {
				return errors.Join(ctx.Err(), withoutCanceled(r.err))
			}
			return r.err
		}
	}
}

func sendSize(ctx context.Context, channel Channel, fd int) error {
	cols, rows, err := Size(fd)
	if err != nil {
		return err
	}
	// AWS SizeData uses lower-case JSON keys (agent/session/contracts/model.go).
	data, err := json.Marshal(struct {
		Cols uint16 `json:"cols"`
		Rows uint16 `json:"rows"`
	}{cols, rows})
	if err != nil {
		return errors.New("cannot encode terminal dimensions")
	}
	return channel.Send(ctx, native.Size, data)
}

func sendChunks(ctx context.Context, channel Channel, data []byte) error {
	for len(data) > 0 {
		n := min(len(data), native.InputSize)
		if err := channel.Send(ctx, native.Output, data[:n]); err != nil {
			return err
		}
		data = data[n:]
	}
	return nil
}

func sendInput(ctx context.Context, channel Channel, input *Stream, tty bool) (bool, error) {
	var escape Escape
	buffer := make([]byte, native.InputSize)
	for {
		n, err := input.Read(ctx, buffer)
		if err == io.EOF {
			if tty {
				if err := sendChunks(ctx, channel, escape.Flush()); err != nil {
					return false, err
				}
			}
			return false, sendChunks(ctx, channel, []byte{4})
		}
		if err != nil {
			return false, err
		}
		data := buffer[:n]
		disconnect := false
		if tty {
			data, disconnect = escape.Feed(data)
		}
		if err := sendChunks(ctx, channel, data); err != nil {
			return false, err
		}
		if disconnect {
			return true, nil
		}
	}
}

func receiveOutput(ctx context.Context, channel Channel, output, stderr *Stream) error {
	for {
		m, err := channel.Receive(ctx)
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		if len(m.Payload) > native.MaxPayload {
			return errors.New("oversized native terminal output")
		}
		stream := output
		switch m.PayloadType {
		case native.Output:
		case native.StdErr:
			stream = stderr
		default:
			return errors.New("unexpected native interactive terminal payload")
		}
		if err := stream.Write(ctx, m.Payload); err != nil {
			return err
		}
	}
}

// Native shutdown joins may contain expected context cancellation AND important
// cleanup failures. Remove only exact cancellation leaves, retaining other errors.
func withoutCanceled(err error) error {
	if err == nil || err == context.Canceled {
		return nil
	}
	if joined, ok := err.(interface{ Unwrap() []error }); ok {
		var kept []error
		for _, e := range joined.Unwrap() {
			if e = withoutCanceled(e); e != nil {
				kept = append(kept, e)
			}
		}
		return errors.Join(kept...)
	}
	return err
}
