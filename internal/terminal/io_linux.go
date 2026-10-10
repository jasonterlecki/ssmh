//go:build linux

package terminal

import (
	"context"
	"errors"
	"io"
	"os"
	"strconv"

	"golang.org/x/sys/unix"
)

// Stream owns a private descriptor. Read/Write are context-cancellable for pipes
// and terminals without changing the inherited descriptor's O_NONBLOCK flags.
// Regular files share the original offset; kernel filesystem I/O is not always
// interruptible. The owner must join users before Close. Streams are not logged.
type Stream struct {
	fd    int
	write bool
	poll  bool
}

// OpenStream accepts regular files, pipes and terminals only. It never creates
// files and never closes or changes flags on the caller's descriptor.
func OpenStream(file *os.File, write bool) (*Stream, error) {
	if file == nil {
		return nil, errors.New("missing local stream")
	}
	info, err := file.Stat()
	if err != nil {
		return nil, errors.New("cannot inspect local stream")
	}
	fd, err := fileDescriptor(file)
	if err != nil {
		return nil, err
	}
	if info.Mode().IsRegular() {
		owned, err := unix.FcntlInt(uintptr(fd), unix.F_DUPFD_CLOEXEC, 0)
		if err != nil {
			return nil, errors.New("cannot duplicate local stream")
		}
		return &Stream{fd: owned, write: write}, nil
	}
	if info.Mode()&os.ModeCharDevice != 0 {
		tty, err := IsTerminal(fd)
		if err != nil {
			return nil, err
		}
		if !tty {
			return nil, errors.New("local character stream is not a terminal")
		}
	} else if info.Mode()&os.ModeNamedPipe == 0 {
		return nil, errors.New("unsupported local stream type")
	}
	access := unix.O_RDONLY
	if write {
		access = unix.O_WRONLY
	}
	// Reopening procfs creates an independent open-file description. dup plus
	// SetNonblock would also change the parent's/inherited stdio flags.
	owned, err := unix.Open("/proc/self/fd/"+strconv.Itoa(fd), access|unix.O_NONBLOCK|unix.O_CLOEXEC|unix.O_NOCTTY, 0)
	if err != nil {
		return nil, errors.New("cannot open private local stream descriptor (procfs required)")
	}
	return &Stream{fd: owned, write: write, poll: true}, nil
}

// File.Fd can change a Go-managed descriptor to blocking mode. SyscallConn
// exposes the descriptor without altering flags; the caller keeps file open.
func fileDescriptor(file *os.File) (int, error) {
	if file == nil {
		return 0, errors.New("missing local stream")
	}
	raw, err := file.SyscallConn()
	if err != nil {
		return 0, errors.New("cannot access local stream descriptor")
	}
	var fd int
	if err := raw.Control(func(value uintptr) { fd = int(value) }); err != nil {
		return 0, errors.New("cannot access local stream descriptor")
	}
	return fd, nil
}

// Close reports descriptor cleanup failure. Repeated calls are harmless.
func (s *Stream) Close() error {
	if s.fd < 0 {
		return nil
	}
	fd := s.fd
	s.fd = -1
	if unix.Close(fd) != nil {
		return errors.New("cannot close local stream descriptor")
	}
	return nil
}

func (s *Stream) wait(ctx context.Context, events int16) error {
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		if s.fd < 0 {
			return errors.New("local stream is closed")
		}
		if !s.poll {
			return nil
		}
		fds := []unix.PollFd{{Fd: int32(s.fd), Events: events}}
		_, err := unix.Poll(fds, 100)
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil {
			return errors.New("cannot poll local stream")
		}
		if fds[0].Revents&unix.POLLNVAL != 0 {
			return errors.New("invalid local stream descriptor")
		}
		if fds[0].Revents&(events|unix.POLLHUP|unix.POLLERR) != 0 {
			return ctx.Err()
		}
	}
}

// Read reads at most 1024 bytes, so callers can submit bounded native input.
func (s *Stream) Read(ctx context.Context, data []byte) (int, error) {
	if s.write {
		return 0, errors.New("local stream is not readable")
	}
	if len(data) == 0 {
		return 0, nil
	}
	if len(data) > 1024 {
		data = data[:1024]
	}
	for {
		if err := s.wait(ctx, unix.POLLIN); err != nil {
			return 0, err
		}
		n, err := unix.Read(s.fd, data)
		if errors.Is(err, unix.EINTR) || errors.Is(err, unix.EAGAIN) {
			continue
		}
		if err != nil {
			return 0, errors.New("cannot read local input")
		}
		if n == 0 {
			return 0, io.EOF
		}
		return n, nil
	}
}

// Write delivers the entire buffer unless canceled or failed. No payload enters
// diagnostics, including when a downstream consumer disconnects.
func (s *Stream) Write(ctx context.Context, data []byte) error {
	if !s.write {
		return errors.New("local stream is not writable")
	}
	for len(data) > 0 {
		if err := s.wait(ctx, unix.POLLOUT); err != nil {
			return err
		}
		chunk := data
		if len(chunk) > 8192 {
			chunk = chunk[:8192]
		}
		n, err := unix.Write(s.fd, chunk)
		if errors.Is(err, unix.EINTR) || errors.Is(err, unix.EAGAIN) {
			continue
		}
		if err != nil || n <= 0 {
			return errors.New("cannot write local output")
		}
		data = data[n:]
	}
	return nil
}
