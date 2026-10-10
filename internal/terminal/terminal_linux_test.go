//go:build linux

package terminal

import (
	"context"
	"errors"
	"io"
	"os"
	"reflect"
	"strconv"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestActualPTYRawAndRestore(t *testing.T) {
	master, err := unix.Open("/dev/ptmx", unix.O_RDWR|unix.O_NOCTTY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Skipf("sandbox cannot open a test PTY: %v", err)
	}
	defer unix.Close(master)
	if err := unix.IoctlSetPointerInt(master, unix.TIOCSPTLCK, 0); err != nil {
		t.Fatal(err)
	}
	number, err := unix.IoctlGetInt(master, unix.TIOCGPTN)
	if err != nil {
		t.Fatal(err)
	}
	slave, err := unix.Open("/dev/pts/"+strconv.Itoa(number), unix.O_RDWR|unix.O_NOCTTY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(slave)
	original, err := unix.IoctlGetTermios(slave, unix.TCGETS)
	if err != nil {
		t.Fatal(err)
	}
	s, err := MakeRaw(slave)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Restore()
	state, err := unix.IoctlGetTermios(slave, unix.TCGETS)
	if err != nil {
		t.Fatal(err)
	}
	if state.Lflag&(unix.ECHO|unix.ICANON|unix.ISIG) != 0 {
		t.Fatal("PTY not raw")
	}
	if err := s.Restore(); err != nil {
		t.Fatal(err)
	}
	after, err := unix.IoctlGetTermios(slave, unix.TCGETS)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(after, original) {
		t.Fatal("PTY settings not restored exactly")
	}
	if err := unix.IoctlSetWinsize(slave, unix.TIOCSWINSZ, &unix.Winsize{Col: 132, Row: 42}); err != nil {
		t.Fatal(err)
	}
	cols, rows, err := Size(slave)
	if err != nil || cols != 132 || rows != 42 {
		t.Fatal("wrong PTY dimensions")
	}
}

type fakeControls struct {
	state unix.Termios
	fail  int
	sets  int
}

func (f *fakeControls) get(int) (*unix.Termios, error) { copy := f.state; return &copy, nil }
func (f *fakeControls) set(_ int, state *unix.Termios) error {
	f.sets++
	if f.fail > 0 {
		f.fail--
		return unix.EIO
	}
	f.state = *state
	return nil
}

func TestRawRestore(t *testing.T) {
	original := unix.Termios{Iflag: unix.ICRNL | unix.IXON | unix.INPCK, Oflag: unix.OPOST, Lflag: unix.ECHO | unix.ICANON | unix.ISIG | unix.IEXTEN, Cflag: unix.PARENB | unix.CS7, Ispeed: 9600, Ospeed: 9600}
	original.Cc[unix.VMIN] = 7
	f := &fakeControls{state: original}
	s, err := makeRaw(4, f)
	if err != nil {
		t.Fatal(err)
	}
	if f.state.Lflag&(unix.ECHO|unix.ICANON|unix.ISIG|unix.IEXTEN) != 0 || f.state.Iflag != 0 || f.state.Oflag != 0 || f.state.Cflag&unix.CSIZE != unix.CS8 || f.state.Cc[unix.VMIN] != 1 {
		t.Fatal("not raw")
	}
	f.fail = 1
	if s.Restore() == nil {
		t.Fatal("hidden restore failure")
	}
	if err := s.Restore(); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(f.state, original) {
		t.Fatal("incomplete restoration")
	}
	sets := f.sets
	if s.Restore() != nil || f.sets != sets {
		t.Fatal("restore not idempotent")
	}
}

func TestRawFailureAttemptsRestore(t *testing.T) {
	f := &fakeControls{fail: 1}
	if s, err := makeRaw(4, f); err == nil || s != nil || f.sets != 2 {
		t.Fatal("missing failed-change cleanup")
	}
}

func TestStreamCancellationAndFlags(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	defer w.Close()
	fd, err := fileDescriptor(r)
	if err != nil {
		t.Fatal(err)
	}
	before, err := unix.FcntlInt(uintptr(fd), unix.F_GETFL, 0)
	if err != nil {
		t.Fatal(err)
	}
	s, err := OpenStream(r, false)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	after, err := unix.FcntlInt(uintptr(fd), unix.F_GETFL, 0)
	if err != nil {
		t.Fatal(err)
	}
	if before&unix.O_NONBLOCK == 0 {
		t.Fatal("test pipe must initially be Go-managed nonblocking")
	}
	if before != after {
		t.Fatal("inherited flags modified")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	start := time.Now()
	if _, err = s.Read(ctx, make([]byte, 1024)); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("cancellation: %v", err)
	}
	if time.Since(start) > time.Second {
		t.Fatal("cancellation too slow")
	}
	if _, err := w.Write([]byte{0, 3, 4, 255}); err != nil {
		t.Fatal(err)
	}
	b := make([]byte, 1024)
	n, err := s.Read(context.Background(), b)
	if err != nil || !reflect.DeepEqual(b[:n], []byte{0, 3, 4, 255}) {
		t.Fatal("binary bytes changed")
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Read(context.Background(), b); !errors.Is(err, io.EOF) {
		t.Fatal("missing EOF")
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Stat(); err != nil {
		t.Fatal("closed inherited input")
	}
}

func TestBlockedOutputCancellation(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	defer w.Close()
	s, err := OpenStream(w, true)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	if err := s.Write(ctx, make([]byte, 1<<20)); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("blocked write: %v", err)
	}
}

func TestRegularStreamOffset(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "input")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err = f.WriteString("abcd"); err != nil {
		t.Fatal(err)
	}
	if _, err = f.Seek(2, io.SeekStart); err != nil {
		t.Fatal(err)
	}
	s, err := OpenStream(f, false)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	b := make([]byte, 4)
	n, err := s.Read(context.Background(), b)
	if err != nil || string(b[:n]) != "cd" {
		t.Fatal("offset not preserved")
	}
}
