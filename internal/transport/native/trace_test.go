package native

import (
	"context"
	"reflect"
	"sync"
	"testing"
	"time"
)

func traceLabels(t *testing.T, trace *Trace) []string {
	t.Helper()
	events, omitted := trace.Drain()
	if omitted {
		t.Fatal("unexpected trace overflow")
	}
	var labels []string
	for _, event := range events {
		if event.Elapsed() < 0 {
			t.Fatal("negative trace timestamp")
		}
		labels = append(labels, event.Label())
	}
	return labels
}

func TestTraceBoundsControlAndStaticLabels(t *testing.T) {
	parent, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	ctx, trace := WithTrace(parent)
	a, _ := parent.Deadline()
	b, _ := ctx.Deadline()
	if a != b {
		t.Fatal("trace changed context deadline")
	}
	want := []string{"WebSocket opening", "WebSocket authenticated; token submitted", "WebSocket establishment failed", "protocol readiness pending", "protocol handshake verified", "document-authorized shell output verified", "protocol publication paused", "protocol publication resumed", "protocol retransmission attempted", "owned-session EOF verified", "channel canceled", "channel failed", "WebSocket closed", "WebSocket close failed"}
	for state := traceOpening; state <= traceCloseFailed; state++ {
		recordTrace(ctx, state)
	}
	recordTrace(ctx, 255)
	if got := traceLabels(t, trace); !reflect.DeepEqual(got, want) {
		t.Fatal("unreviewed trace label")
	}
	recordTrace(context.Background(), traceOpening)
	if events, omitted := trace.Drain(); len(events) != 0 || omitted {
		t.Fatal("drain did not release events")
	}
	for range 100 {
		recordTrace(ctx, tracePaused)
	}
	events, omitted := trace.Drain()
	if len(events) != 64 || !omitted {
		t.Fatal("trace buffer unbounded or overflow silent")
	}
	recordTrace(ctx, traceClosed)
	if got := traceLabels(t, trace); !reflect.DeepEqual(got, []string{"WebSocket closed"}) {
		t.Fatal("overflow prevented later cleanup observation")
	}
	cancel()
	if ctx.Err() != context.Canceled {
		t.Fatal("trace detached cancellation")
	}
	var absent *Trace
	if events, omitted := absent.Drain(); len(events) != 0 || omitted {
		t.Fatal("nil trace is not inert")
	}
}

func TestTraceConcurrentRecordingAndDraining(t *testing.T) {
	ctx, trace := WithTrace(context.Background())
	var workers sync.WaitGroup
	for range 8 {
		workers.Go(func() {
			for range 1000 {
				recordTrace(ctx, traceRetransmit)
			}
		})
	}
	workers.Go(func() {
		for range 1000 {
			events, _ := trace.Drain()
			if len(events) > 64 {
				t.Error("unbounded trace drain")
			}
			for _, event := range events {
				if event.Label() != "protocol retransmission attempted" {
					t.Error("corrupted trace label")
				}
			}
		}
	})
	workers.Wait()
}
