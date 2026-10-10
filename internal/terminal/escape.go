package terminal

// Escape processes SSH-style local escapes across arbitrary input chunk splits.
// Use only for interactive TTY input; redirected input must remain unchanged.
// The zero value is ready at the beginning of a line. It retains at most a tilde,
// never a command or a terminal buffer. An Escape is owned by one input reader.
type Escape struct {
	midLine bool
	pending bool
	closed  bool
}

// Feed emits literal input, except ~. at line start disconnects locally and ~~
// emits one literal tilde. Input following a disconnect is discarded, not sent.
func (e *Escape) Feed(input []byte) (output []byte, disconnect bool) {
	if e.closed {
		return nil, true
	}
	output = make([]byte, 0, len(input)+1)
	for _, b := range input {
		if e.pending {
			e.pending = false
			if b == '.' {
				e.closed = true
				return output, true
			}
			output = append(output, '~')
			e.midLine = true
			if b == '~' {
				continue
			}
		} else if !e.midLine && b == '~' {
			e.pending = true
			continue
		}
		output = append(output, b)
		e.midLine = b != '\r' && b != '\n'
	}
	return output, false
}

// Flush emits a dangling literal tilde at input EOF.
func (e *Escape) Flush() []byte {
	if e.pending && !e.closed {
		e.pending = false
		e.midLine = true
		return []byte{'~'}
	}
	return nil
}
