package cli

import (
	"context"
	"errors"
	"net"
	"sync"

	"ssmh/internal/terminal"
	"ssmh/internal/transport/native"
)

// onceForwardListener makes setup and serving cleanup share one owned Close.
// It retains independent failure without retaining raw network error text.
type onceForwardListener struct {
	net.Listener
	once sync.Once
	err  error
}

func (l *onceForwardListener) Close() error {
	l.once.Do(func() {
		if l.Listener.Close() != nil {
			l.err = errors.New("close owned forwarding listener failed")
		}
	})
	return l.err
}

// serveNativeForward closes the native channel even if ServeForward refuses
// ownership before starting workers. Native Close is idempotent and joins its
// loop; the listener's setup owner independently supplies once-only cleanup.
func serveNativeForward(ctx context.Context, channel terminal.Channel, listener net.Listener) error {
	c, ok := channel.(*native.Channel)
	if !ok || c == nil {
		return errors.New("forwarding requires an authenticated native Port channel")
	}
	err := native.ServeForward(ctx, c, listener)
	if independentClose(c.Close()) {
		err = errors.Join(err, errors.New("close native forwarding channel failed"))
	}
	return err
}

// Ignore only exact native shutdown-cancellation leaves, never a wrapped or
// independently joined failure whose cause may carry secret-bearing material.
func independentClose(err error) bool {
	if err == nil || err == context.Canceled {
		return false
	}
	if joined, ok := err.(interface{ Unwrap() []error }); ok {
		for _, child := range joined.Unwrap() {
			if independentClose(child) {
				return true
			}
		}
		return false
	}
	return true
}
