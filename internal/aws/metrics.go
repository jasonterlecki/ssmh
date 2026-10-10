package aws

import (
	"context"
	"sync"
	"time"

	awsmiddleware "github.com/aws/aws-sdk-go-v2/aws/middleware"
	"github.com/aws/aws-sdk-go-v2/aws/retry"
	"github.com/aws/smithy-go/middleware"
)

const maxAPIMetrics = 64

type apiMetricsKey struct{}

// APIMetrics holds bounded, allowlisted SDK operation summaries. Recording never
// performs I/O or changes the operation's response/error, including StartSession.
// It contains no request, response, error, credential or authentication objects.
type APIMetrics struct {
	mu      sync.Mutex
	events  []APIMetric
	omitted bool
}

// APIMetric exposes only fixed service/operation labels, timing, a success bit
// and the SDK's retry-loop attempt count. Fields cannot be supplied by callers.
type APIMetric struct {
	service, operation string
	elapsed            time.Duration
	success            bool
	attempts           int
	attemptsKnown      bool
}

// Service returns an allowlisted service label.
func (m APIMetric) Service() string { return m.service }

// Operation returns an allowlisted operation label.
func (m APIMetric) Operation() string { return m.operation }

// Elapsed returns the nonnegative SDK operation duration, including retries.
func (m APIMetric) Elapsed() time.Duration { return m.elapsed }

// Success reports whether the observed SDK operation returned no error.
func (m APIMetric) Success() bool { return m.success }

// Attempts returns the retry-loop count and whether SDK metadata provided it.
// This is not a count of HTTP transmissions; a canceled attempt may not send one.
func (m APIMetric) Attempts() (int, bool) { return m.attempts, m.attemptsKnown }

// WithAPIMetrics creates a collector for Load's opt-in debug instrumentation.
// The returned context preserves cancellation/deadlines. Only clients constructed
// by Load with Debug enabled capture it; ordinary/verbose clients are unchanged.
func WithAPIMetrics(ctx context.Context) (context.Context, *APIMetrics) {
	m := &APIMetrics{}
	return context.WithValue(ctx, apiMetricsKey{}, m), m
}

// Drain atomically transfers recorded summaries and the buffer-overflow flag.
// Events recorded concurrently after draining remain for a subsequent drain.
func (m *APIMetrics) Drain() ([]APIMetric, bool) {
	if m == nil {
		return nil, false
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	events, omitted := m.events, m.omitted
	m.events, m.omitted = nil, false
	return events, omitted
}

func (m *APIMetrics) record(event APIMetric) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.events) == maxAPIMetrics {
		m.omitted = true
		return
	}
	m.events = append(m.events, event)
}

func (m *APIMetrics) middleware(stack *middleware.Stack) error {
	return stack.Initialize.Add(middleware.InitializeMiddlewareFunc("ssmhAPIMetrics", func(ctx context.Context, input middleware.InitializeInput, next middleware.InitializeHandler) (middleware.InitializeOutput, middleware.Metadata, error) {
		service, operation, allowed := metricLabels(awsmiddleware.GetServiceID(ctx), awsmiddleware.GetOperationName(ctx))
		if !allowed {
			return next.HandleInitialize(ctx, input)
		}
		started := time.Now()
		out, metadata, err := next.HandleInitialize(ctx, input)
		event := APIMetric{service: service, operation: operation, elapsed: max(0, time.Since(started)), success: err == nil}
		if attempts, ok := retry.GetAttemptResults(metadata); ok {
			event.attempts, event.attemptsKnown = len(attempts.Results), true
		}
		m.record(event)
		return out, metadata, err
	}), middleware.After)
}

// Never print arbitrary SDK metadata, even when a client extension supplies it.
func metricLabels(service, operation string) (string, string, bool) {
	switch service {
	case "EC2":
		if operation == "DescribeInstances" {
			return "EC2", "DescribeInstances", true
		}
	case "SSM":
		switch operation {
		case "DescribeInstanceInformation":
			return "SSM", "DescribeInstanceInformation", true
		case "GetDocument":
			return "SSM", "GetDocument", true
		case "StartSession":
			return "SSM", "StartSession", true
		case "TerminateSession":
			return "SSM", "TerminateSession", true
		}
	case "STS":
		switch operation {
		case "AssumeRole":
			return "STS", "AssumeRole", true
		case "GetCallerIdentity":
			return "STS", "GetCallerIdentity", true
		}
	case "KMS":
		if operation == "GenerateDataKey" {
			return "KMS", "GenerateDataKey", true
		}
	}
	return "", "", false
}
