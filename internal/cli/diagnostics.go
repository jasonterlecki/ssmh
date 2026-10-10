package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"time"

	sdkaws "github.com/aws/aws-sdk-go-v2/aws"

	"ssmh/internal/aws"
	"ssmh/internal/terminal"
	"ssmh/internal/transport/native"
)

// diagnostics accepts only fixed stage/provider labels and validated identity metadata.
// Raw errors, SDK objects, command/document text and authentication material
// must never be supplied. SDK summaries come only from the bounded collector.
type diagnostics struct {
	writer         io.Writer
	verbose, debug bool
	metrics        *aws.APIMetrics
	trace          *native.Trace
}

// diagnosticWriter uses private cancellable descriptors. Once a write fails,
// do not retry diagnostic output during required AWS/channel cleanup.
type diagnosticWriter struct {
	stream *terminal.Stream
	ctx    context.Context
	failed bool
}

func (w *diagnosticWriter) Write(data []byte) (int, error) {
	if w.failed {
		return 0, errors.New("cannot write connection diagnostics")
	}
	ctx, cancel := context.WithTimeout(w.ctx, time.Second)
	defer cancel()
	if err := w.stream.Write(ctx, data); err != nil {
		w.failed = true
		return 0, errors.New("cannot write connection diagnostics")
	}
	return len(data), nil
}

type stage uint8

const (
	stageCredentials stage = iota
	stageIdentity
	stageAvailability
	stageSession
	stageChannel
	stageExecution
	stageCleanup
	stageDiscovery
	stageShellDocument
)

func (d diagnostics) emit(s stage, outcome string, elapsed time.Duration) error {
	if !d.verbose && !d.debug {
		return nil
	}
	labels := [...]string{"AWS authentication", "AWS caller identity", "SSM availability", "document validation and session creation", "native channel establishment", "remote operation", "owned-session cleanup", "EC2 discovery", "SSM shell document compatibility"}
	if int(s) >= len(labels) {
		return errors.New("invalid diagnostic stage")
	}
	var err error
	if d.debug && outcome != "started" {
		_, err = fmt.Fprintf(d.writer, "ssmh: %s: %s (elapsed_ms=%d)\n", labels[s], outcome, max(0, elapsed.Milliseconds()))
	} else {
		_, err = fmt.Fprintf(d.writer, "ssmh: %s: %s\n", labels[s], outcome)
	}
	if err != nil {
		return errors.New("cannot write connection diagnostics")
	}
	return nil
}

func (d diagnostics) begin(s stage) (time.Time, error) { return time.Now(), d.emit(s, "started", 0) }
func (d diagnostics) end(s stage, start time.Time, operation error) error {
	outcome := "completed"
	if operation != nil {
		outcome = "failed"
	}
	return errors.Join(operation, d.emit(s, outcome, time.Since(start)), d.apiMetrics(), d.nativeTrace())
}

// termination describes local lifecycle evidence, not an invented remote cause.
// Call only after the owned AWS cleanup attempt. Raw errors are never formatted,
// and classification cannot suppress an independent operation/cleanup failure.
func (d diagnostics) termination(parentErr, lifetimeErr, operationErr error, started, localDuration bool) error {
	if !d.verbose && !d.debug {
		return nil
	}
	reason := "operation or local reporting failed (cause omitted)"
	switch {
	case parentErr == context.Canceled:
		reason = "local cancellation requested"
	case parentErr == context.DeadlineExceeded:
		reason = "caller deadline exceeded"
	case localDuration && lifetimeErr == context.DeadlineExceeded:
		reason = "local duration limit reached"
	case !started:
		reason = "session setup failed"
	case operationErr == nil:
		reason = "operation returned successfully (remote completion or local disconnect)"
	}
	if _, err := fmt.Fprintf(d.writer, "ssmh: termination reason: %s\n", reason); err != nil {
		return errors.New("cannot write termination diagnostics")
	}
	return nil
}

func (d diagnostics) nativeTrace() error {
	if !d.debug {
		return nil
	}
	events, omitted := d.trace.Drain()
	for _, event := range events {
		if _, err := fmt.Fprintf(d.writer, "ssmh: native state: %s (since_trace_ms=%d)\n", event.Label(), event.Elapsed().Milliseconds()); err != nil {
			return errors.New("cannot write native transport diagnostics")
		}
	}
	if omitted {
		if _, err := fmt.Fprintln(d.writer, "ssmh: additional native state diagnostics omitted (buffer limit)"); err != nil {
			return errors.New("cannot write native transport diagnostics")
		}
	}
	return nil
}

func (d diagnostics) apiMetrics() error {
	if !d.debug {
		return nil
	}
	events, omitted := d.metrics.Drain()
	for _, event := range events {
		outcome := "completed"
		if !event.Success() {
			outcome = "failed"
		}
		attempts := "unavailable"
		if count, known := event.Attempts(); known {
			attempts = fmt.Sprintf("%d retries=%d", count, max(0, count-1))
		}
		if _, err := fmt.Fprintf(d.writer, "ssmh: AWS API %s.%s: %s (elapsed_ms=%d attempts=%s)\n", event.Service(), event.Operation(), outcome, event.Elapsed().Milliseconds(), attempts); err != nil {
			return errors.New("cannot write AWS API diagnostics")
		}
	}
	if omitted {
		if _, err := fmt.Fprintln(d.writer, "ssmh: additional AWS API diagnostics omitted (buffer limit)"); err != nil {
			return errors.New("cannot write AWS API diagnostics")
		}
	}
	return nil
}

func (d diagnostics) identity(i aws.Identity) error {
	if !d.verbose && !d.debug {
		return nil
	}
	if i.Account() == "" || i.ARN() == "" {
		return errors.New("caller identity is unavailable")
	}
	if _, err := fmt.Fprintf(d.writer, "ssmh: AWS account: %s; caller: %s (SSM permissions not yet verified)\n", i.Account(), i.ARN()); err != nil {
		return errors.New("cannot write identity diagnostics")
	}
	return nil
}

func (d diagnostics) credentials(cfg sdkaws.Config) error {
	if !d.verbose && !d.debug {
		return nil
	}
	if _, err := fmt.Fprintf(d.writer, "ssmh: SDK credential sources: %s\n", aws.CredentialSources(cfg)); err != nil {
		return errors.New("cannot write credential-provider diagnostics")
	}
	return nil
}
