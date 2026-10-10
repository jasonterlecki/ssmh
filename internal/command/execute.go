// Package command receives noninteractive Session Manager command results.
// Session creation and document selection remain the caller's responsibility.
package command

import (
	"context"
	"errors"
	"io"
	"os"

	"ssmh/internal/terminal"
	"ssmh/internal/transport/native"
)

// Channel is an established, authenticated NonInteractiveCommands channel.
// Receive must validate framing, sequence, digest and session ownership, and
// return io.EOF only for the owned session's authenticated channel_closed.
// Transport errors must already be redacted. Run owns Close, not AWS cleanup.
type Channel interface {
	Receive(context.Context) (native.Message, error)
	Close() error
}

// Result is valid only after exactly one validated status, owned-session close,
// complete output delivery and successful local cleanup. Its zero value is unknown.
type Result struct {
	code  int
	known bool
}

// ExitCode returns a verified Linux process status and whether it is available.
// Signal termination, missing status or any local failure is not a known status.
func (r Result) ExitCode() (int, bool) { return r.code, r.known }

// Run drains separate stdout/stderr without opening stdin, changing terminal
// settings, sending control input or executing anything locally. It neither
// buffers transcripts nor parses status-looking text from ordinary output.
// Nonzero remote status is a Result, not a transport/local error. Any failure
// invalidates the result, including one occurring after receiving an exit code.
func Run(ctx context.Context, channel Channel, output, stderr *os.File) (result Result, err error) {
	if channel == nil {
		return Result{}, errors.New("missing command channel")
	}
	defer func() {
		// Closing an active native channel cancels its workers. Remove only exact
		// cancellation leaves caused by shutdown; keep independent close errors.
		err = errors.Join(err, withoutCanceled(channel.Close()), ctx.Err())
		if err != nil {
			result = Result{}
		}
	}()
	stdout, err := terminal.OpenStream(output, true)
	if err != nil {
		return Result{}, err
	}
	defer func() { err = errors.Join(err, stdout.Close()) }()
	stdErr, err := terminal.OpenStream(stderr, true)
	if err != nil {
		return Result{}, err
	}
	defer func() { err = errors.Join(err, stdErr.Close()) }()
	var status Result
	for {
		if err := ctx.Err(); err != nil {
			return Result{}, err
		}
		message, err := channel.Receive(ctx)
		if err == io.EOF {
			if !status.known {
				return Result{}, errors.New("remote command closed without a verified exit status (separate-output document required)")
			}
			return status, nil
		}
		if err != nil {
			return Result{}, err
		}
		if len(message.Payload) > native.MaxPayload {
			return Result{}, errors.New("command payload exceeds size limit")
		}
		switch message.PayloadType {
		case native.Output, native.StdErr:
			if status.known {
				return Result{}, errors.New("command output arrived after exit status")
			}
			stream := stdout
			if message.PayloadType == native.StdErr {
				stream = stdErr
			}
			if err := stream.Write(ctx, message.Payload); err != nil {
				return Result{}, err
			}
		case native.ExitCode:
			if status.known {
				return Result{}, errors.New("duplicate command exit status")
			}
			code, err := parseExitCode(message.Payload)
			if err != nil {
				return Result{}, err
			}
			status = Result{code: code, known: true}
		default:
			return Result{}, errors.New("unexpected command payload type")
		}
	}
}

func withoutCanceled(err error) error {
	if err == nil || err == context.Canceled {
		return nil
	}
	if joined, ok := err.(interface{ Unwrap() []error }); ok {
		var kept []error
		for _, child := range joined.Unwrap() {
			if child = withoutCanceled(child); child != nil {
				kept = append(kept, child)
			}
		}
		return errors.Join(kept...)
	}
	return err
}
