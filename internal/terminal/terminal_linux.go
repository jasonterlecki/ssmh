//go:build linux

// Package terminal implements Linux terminal controls without recording streams.
package terminal

import (
	"errors"
	"sync"

	"golang.org/x/sys/unix"
)

type controls interface {
	get(int) (*unix.Termios, error)
	set(int, *unix.Termios) error
}
type linuxControls struct{}

func (linuxControls) get(fd int) (*unix.Termios, error) {
	return unix.IoctlGetTermios(fd, unix.TCGETS)
}
func (linuxControls) set(fd int, state *unix.Termios) error {
	return unix.IoctlSetTermios(fd, unix.TCSETS, state)
}

// State owns a saved terminal configuration, not the descriptor. Restore retries
// after failures; callers must keep the descriptor open until restoration finishes.
type State struct {
	mu       sync.Mutex
	fd       int
	saved    unix.Termios
	control  controls
	restored bool
}

// IsTerminal distinguishes non-terminal descriptors from unexpected ioctl errors.
func IsTerminal(fd int) (bool, error) {
	_, err := (linuxControls{}).get(fd)
	if errors.Is(err, unix.ENOTTY) {
		return false, nil
	}
	if err != nil {
		return false, errors.New("cannot inspect local terminal")
	}
	return true, nil
}

// MakeRaw disables local echo, signal generation and newline translation. Ctrl+C
// and Ctrl+D are subsequently input bytes, not local signals or local EOF.
func MakeRaw(fd int) (*State, error) { return makeRaw(fd, linuxControls{}) }

func makeRaw(fd int, control controls) (*State, error) {
	saved, err := control.get(fd)
	if err != nil {
		return nil, errors.New("cannot read local terminal settings")
	}
	raw := *saved
	raw.Iflag &^= unix.IGNBRK | unix.BRKINT | unix.PARMRK | unix.ISTRIP | unix.INLCR | unix.IGNCR | unix.ICRNL | unix.IXON | unix.INPCK
	raw.Oflag &^= unix.OPOST
	raw.Lflag &^= unix.ECHO | unix.ECHONL | unix.ICANON | unix.ISIG | unix.IEXTEN
	raw.Cflag &^= unix.CSIZE | unix.PARENB
	raw.Cflag |= unix.CS8
	raw.Cc[unix.VMIN] = 1
	raw.Cc[unix.VTIME] = 0
	if err := control.set(fd, &raw); err != nil {
		// A failed change may have affected state; attempt restoration as well.
		var restore error
		if control.set(fd, saved) != nil {
			restore = errors.New("cannot restore local terminal after raw-mode failure")
		}
		return nil, errors.Join(errors.New("cannot enable local terminal raw mode"), restore)
	}
	return &State{fd: fd, saved: *saved, control: control}, nil
}

// Restore reinstates the complete saved configuration. SIGKILL and abrupt process
// loss cannot be handled; a reported restoration failure is never hidden.
func (s *State) Restore() error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.restored {
		return nil
	}
	copy := s.saved
	if s.control.set(s.fd, &copy) != nil {
		return errors.New("cannot restore local terminal settings")
	}
	s.restored = true
	return nil
}

// Size returns columns and rows. An unknown (zero) kernel dimension uses 80x24.
func Size(fd int) (columns, rows uint16, err error) {
	size, e := unix.IoctlGetWinsize(fd, unix.TIOCGWINSZ)
	if e != nil {
		return 0, 0, errors.New("cannot read local terminal dimensions")
	}
	columns, rows = size.Col, size.Row
	if columns == 0 {
		columns = 80
	}
	if rows == 0 {
		rows = 24
	}
	return columns, rows, nil
}
