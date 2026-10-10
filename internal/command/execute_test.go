package command

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	"ssmh/internal/transport/native"
)

type testChannel struct {
	messages      []native.Message
	end, closeErr error
	closed        int
	receive       func(context.Context) (native.Message, error)
}

func (c *testChannel) Receive(ctx context.Context) (native.Message, error) {
	if c.receive != nil {
		return c.receive(ctx)
	}
	if len(c.messages) > 0 {
		message := c.messages[0]
		c.messages = c.messages[1:]
		return message, nil
	}
	if c.end != nil {
		return native.Message{}, c.end
	}
	return native.Message{}, io.EOF
}

func (c *testChannel) Close() error { c.closed++; return c.closeErr }

func message(kind uint32, payload string) native.Message {
	return native.Message{PayloadType: kind, Payload: []byte(payload)}
}

func outputFiles(t *testing.T) (*os.File, *os.File) {
	t.Helper()
	files := make([]*os.File, 2)
	for i := range files {
		file, err := os.CreateTemp(t.TempDir(), "output")
		if err != nil {
			t.Fatal(err)
		}
		files[i] = file
		t.Cleanup(func() { file.Close() })
	}
	return files[0], files[1]
}

func text(t *testing.T, file *os.File) string {
	t.Helper()
	info, err := file.Stat()
	if err != nil {
		t.Fatal(err)
	}
	payload := make([]byte, info.Size())
	if _, err := file.ReadAt(payload, 0); err != nil && err != io.EOF {
		t.Fatal(err)
	}
	return string(payload)
}

func TestResultsAndOutputSeparation(t *testing.T) {
	for _, code := range []int{0, 1, 2, 42, 130, 255} {
		t.Run(fmt.Sprint(code), func(t *testing.T) {
			out, stderr := outputFiles(t)
			channel := &testChannel{messages: []native.Message{
				message(native.Output, "EXIT_CODE: 255\nquotes ' \" $() ; λ\x00\xff"),
				message(native.StdErr, "remote stderr\x1b[31m"),
				message(native.Output, "tail"),
				message(native.ExitCode, fmt.Sprintf("EXIT_CODE: %d", code)),
			}}
			result, err := Run(context.Background(), channel, out, stderr)
			got, known := result.ExitCode()
			if err != nil || !known || got != code || channel.closed != 1 {
				t.Fatalf("result %d/%t: %v; closes %d", got, known, err, channel.closed)
			}
			if text(t, out) != "EXIT_CODE: 255\nquotes ' \" $() ; λ\x00\xfftail" || text(t, stderr) != "remote stderr\x1b[31m" {
				t.Fatal("output changed, merged or status leaked")
			}
			if _, err := out.WriteString("parent remains open"); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestFailuresAlwaysInvalidateResult(t *testing.T) {
	status := message(native.ExitCode, "EXIT_CODE: 0")
	for name, channel := range map[string]*testChannel{
		"missing":              {},
		"stdout impersonation": {messages: []native.Message{message(native.Output, "EXIT_CODE: 0")}},
		"malformed":            {messages: []native.Message{message(native.ExitCode, "synthetic-secret")}},
		"signal unknown":       {messages: []native.Message{message(native.ExitCode, "EXIT_CODE: -1")}},
		"duplicate":            {messages: []native.Message{status, status}},
		"conflicting":          {messages: []native.Message{status, message(native.ExitCode, "EXIT_CODE: 42")}},
		"late stdout":          {messages: []native.Message{status, message(native.Output, "do not deliver")}},
		"late stderr":          {messages: []native.Message{status, message(native.StdErr, "do not deliver")}},
		"unexpected":           {messages: []native.Message{message(native.Size, "synthetic-secret")}},
		"oversize":             {messages: []native.Message{message(native.Output, strings.Repeat("x", native.MaxPayload+1))}},
		"disconnect":           {messages: []native.Message{status}, end: io.ErrUnexpectedEOF},
		"wrapped EOF":          {messages: []native.Message{status}, end: fmt.Errorf("transport failure: %w", io.EOF)},
		"close failure":        {messages: []native.Message{status}, closeErr: errors.New("close failure")},
		"joined close failure": {messages: []native.Message{status}, closeErr: errors.Join(context.Canceled, errors.New("close failure"))},
		"wrapped cancellation": {messages: []native.Message{status}, closeErr: fmt.Errorf("independent failure: %w", context.Canceled)},
	} {
		t.Run(name, func(t *testing.T) {
			out, stderr := outputFiles(t)
			result, err := Run(context.Background(), channel, out, stderr)
			if _, known := result.ExitCode(); err == nil || known || channel.closed != 1 {
				t.Fatalf("failure fabricated status: %v", err)
			}
			if strings.Contains(err.Error(), "synthetic-secret") || strings.Contains(text(t, out)+text(t, stderr), "do not deliver") {
				t.Fatal("invalid payload exposed")
			}
		})
	}
}

func TestNormalShutdownCancellationOnly(t *testing.T) {
	out, stderr := outputFiles(t)
	channel := &testChannel{messages: []native.Message{message(native.ExitCode, "EXIT_CODE: 42")}, closeErr: errors.Join(context.Canceled, context.Canceled)}
	result, err := Run(context.Background(), channel, out, stderr)
	if code, known := result.ExitCode(); err != nil || !known || code != 42 {
		t.Fatal("shutdown cancellation changed result")
	}
}

func TestCanceledReceiveAndEOFDoNotSucceed(t *testing.T) {
	for _, eof := range []bool{false, true} {
		out, stderr := outputFiles(t)
		ctx, cancel := context.WithCancel(context.Background())
		channel := &testChannel{}
		channel.receive = func(ctx context.Context) (native.Message, error) {
			cancel()
			if eof {
				return native.Message{}, io.EOF
			}
			return native.Message{}, ctx.Err()
		}
		result, err := Run(ctx, channel, out, stderr)
		if _, known := result.ExitCode(); known || !errors.Is(err, context.Canceled) || channel.closed != 1 {
			t.Fatal("cancellation lost")
		}
	}
}

func TestCancellationAfterStatusInvalidatesResult(t *testing.T) {
	out, stderr := outputFiles(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	first := true
	channel := &testChannel{receive: func(context.Context) (native.Message, error) {
		if first {
			first = false
			return message(native.ExitCode, "EXIT_CODE: 0"), nil
		}
		cancel()
		return native.Message{}, io.EOF
	}}
	result, err := Run(ctx, channel, out, stderr)
	if _, known := result.ExitCode(); known || !errors.Is(err, context.Canceled) || channel.closed != 1 {
		t.Fatal("canceled owned close fabricated success")
	}
}

func TestBlockedReceiveAndOutputCancel(t *testing.T) {
	for _, outputBlocked := range []bool{false, true} {
		out, stderr := outputFiles(t)
		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
		defer cancel()
		channel := &testChannel{}
		if outputBlocked {
			reader, writer, err := os.Pipe()
			if err != nil {
				t.Fatal(err)
			}
			defer reader.Close()
			defer writer.Close()
			out = writer
			channel.messages = []native.Message{message(native.Output, strings.Repeat("x", native.MaxPayload)), message(native.ExitCode, "EXIT_CODE: 0")}
		} else {
			channel.receive = func(ctx context.Context) (native.Message, error) { <-ctx.Done(); return native.Message{}, ctx.Err() }
		}
		start := time.Now()
		result, err := Run(ctx, channel, out, stderr)
		if _, known := result.ExitCode(); known || !errors.Is(err, context.DeadlineExceeded) || channel.closed != 1 || time.Since(start) > time.Second {
			t.Fatal("blocked operation did not cancel and close")
		}
	}
}

func TestMissingOrBrokenOutputClosesChannel(t *testing.T) {
	for _, broken := range []bool{false, true} {
		out, stderr := outputFiles(t)
		if broken {
			reader, writer, err := os.Pipe()
			if err != nil {
				t.Fatal(err)
			}
			reader.Close()
			defer writer.Close()
			out = writer
		} else {
			out = nil
		}
		channel := &testChannel{messages: []native.Message{message(native.Output, "synthetic-secret"), message(native.ExitCode, "EXIT_CODE: 0")}}
		result, err := Run(context.Background(), channel, out, stderr)
		if _, known := result.ExitCode(); known || err == nil || channel.closed != 1 || strings.Contains(err.Error(), "synthetic-secret") {
			t.Fatal("output failure ignored or exposed payload")
		}
	}
}
