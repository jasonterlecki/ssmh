package native

import (
	"context"
	"sync"
	"time"
)

const maxTraceEvents = 64

type traceKey struct{}
type traceState uint8

const (
	traceOpening traceState = iota
	traceAuthenticated
	traceOpenFailed
	traceWaiting
	traceHandshakeReady
	traceShellReady
	tracePaused
	traceResumed
	traceRetransmit
	traceOwnedEOF
	traceCanceled
	traceFailed
	traceClosed
	traceCloseFailed
)

// Trace observes bounded local transport states, without I/O or remote data.
// Recording never changes protocol validation, cancellation, replay or ownership.
type Trace struct {
	mu      sync.Mutex
	start   time.Time
	events  []TraceEvent
	omitted bool
}

// TraceEvent holds only a fixed label and time since collection began.
// Private fields prevent arbitrary caller-supplied diagnostic text.
type TraceEvent struct {
	label   string
	elapsed time.Duration
}

// Label returns a fixed local-state label, never remote metadata.
func (e TraceEvent) Label() string { return e.label }

// Elapsed returns nonnegative time since trace creation, not operation duration.
func (e TraceEvent) Elapsed() time.Duration { return e.elapsed }

// WithTrace attaches a fresh collector, preserving cancellation and deadlines.
// The CLI uses this only for debug; transport never writes diagnostics.
func WithTrace(ctx context.Context) (context.Context, *Trace) {
	t := &Trace{start: time.Now()}
	return context.WithValue(ctx, traceKey{}, t), t
}

// Drain transfers events and overflow indication. Concurrent later events remain
// for the next drain; this collector is not a persistent audit log.
func (t *Trace) Drain() ([]TraceEvent, bool) {
	if t == nil {
		return nil, false
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	events, omitted := t.events, t.omitted
	t.events, t.omitted = nil, false
	return events, omitted
}
func recordTrace(ctx context.Context, state traceState) {
	t, ok := ctx.Value(traceKey{}).(*Trace)
	if !ok || t == nil {
		return
	}
	labels := [...]string{"WebSocket opening", "WebSocket authenticated; token submitted", "WebSocket establishment failed", "protocol readiness pending", "protocol handshake verified", "document-authorized shell output verified", "protocol publication paused", "protocol publication resumed", "protocol retransmission attempted", "owned-session EOF verified", "channel canceled", "channel failed", "WebSocket closed", "WebSocket close failed"}
	if int(state) >= len(labels) {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if len(t.events) == maxTraceEvents {
		t.omitted = true
		return
	}
	t.events = append(t.events, TraceEvent{labels[state], max(0, time.Since(t.start))})
}
