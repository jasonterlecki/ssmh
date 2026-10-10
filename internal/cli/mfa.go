package cli

import (
	"context"
	"errors"
	"sync"
)

// mfaPrompt serializes SDK MFA callbacks and closes prompting permanently before
// terminal Run. It cannot consume remote input during refresh or cleanup. Its
// context is the explicit setup deadline, even if SDK cache goroutines suppress
// cancellation on their provider context. No code is retained in this object.
type mfaPrompt struct {
	mu     sync.Mutex
	ctx    context.Context
	read   func(context.Context) (string, error)
	closed bool
}

func (p *mfaPrompt) token() (string, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return "", errors.New("fresh MFA code required; prompting is disabled during remote sessions and cleanup")
	}
	if err := p.ctx.Err(); err != nil {
		return "", err
	}
	return p.read(p.ctx)
}
func (p *mfaPrompt) close() { p.mu.Lock(); defer p.mu.Unlock(); p.closed = true }
