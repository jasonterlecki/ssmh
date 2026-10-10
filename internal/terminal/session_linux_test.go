//go:build linux

package terminal

import (
	"bufio"
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	"ssmh/internal/transport/native"
)

type testInput struct {
	kind uint32
	data []byte
}

var _ Channel = (*native.Channel)(nil)

type testOutput struct {
	message native.Message
	err     error
}
type testChannel struct {
	sent     chan testInput
	out      chan testOutput
	closeErr error
	mu       sync.Mutex
	closed   bool
}

func newTestChannel() *testChannel {
	return &testChannel{sent: make(chan testInput, 20), out: make(chan testOutput, 10)}
}
func (c *testChannel) Send(ctx context.Context, kind uint32, data []byte) error {
	if len(data) > native.InputSize {
		return errors.New("oversized test send")
	}
	select {
	case c.sent <- testInput{kind, append([]byte(nil), data...)}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
func (c *testChannel) Receive(ctx context.Context) (native.Message, error) {
	select {
	case r := <-c.out:
		return r.message, r.err
	case <-ctx.Done():
		return native.Message{}, ctx.Err()
	}
}
func (c *testChannel) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.closed = true
	return c.closeErr
}
func (c *testChannel) isClosed() bool { c.mu.Lock(); defer c.mu.Unlock(); return c.closed }

func tempStream(t *testing.T) *os.File {
	t.Helper()
	file, err := os.CreateTemp(t.TempDir(), "stream")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { file.Close() })
	return file
}
func fileText(t *testing.T, file *os.File) string {
	t.Helper()
	info, err := file.Stat()
	if err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, info.Size())
	_, err = file.ReadAt(buf, 0)
	if err != nil && err != io.EOF {
		t.Fatal(err)
	}
	return string(buf)
}
func nextInput(t *testing.T, c *testChannel) testInput {
	t.Helper()
	select {
	case in := <-c.sent:
		return in
	case <-time.After(2 * time.Second):
		t.Fatal("missing native input")
		return testInput{}
	}
}
func waitRun(t *testing.T, done <-chan error) error {
	t.Helper()
	select {
	case err := <-done:
		return err
	case <-time.After(3 * time.Second):
		t.Fatal("terminal workers did not stop")
		return nil
	}
}

func TestSessionRedirectedInputAndOutput(t *testing.T) {
	input, output, stderr := tempStream(t), tempStream(t), tempStream(t)
	data := "~.\x00\x03\x04\xff"
	if _, err := input.WriteString(data); err != nil {
		t.Fatal(err)
	}
	if _, err := input.Seek(0, io.SeekStart); err != nil {
		t.Fatal(err)
	}
	c := newTestChannel()
	done := make(chan error, 1)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	go func() { done <- Run(ctx, c, input, output, stderr) }()
	in := nextInput(t, c)
	if in.kind != native.Output || string(in.data) != data {
		t.Fatal("redirected input changed or escapes applied")
	}
	in = nextInput(t, c)
	if string(in.data) != "\x04" {
		t.Fatal("input EOF did not send Ctrl+D")
	}
	c.out <- testOutput{message: native.Message{PayloadType: native.Output, Payload: []byte("out\x1b[0m\x00")}}
	c.out <- testOutput{message: native.Message{PayloadType: native.StdErr, Payload: []byte("stderr")}}
	c.out <- testOutput{err: io.EOF}
	if err := waitRun(t, done); err != nil {
		t.Fatal(err)
	}
	if fileText(t, output) != "out\x1b[0m\x00" || fileText(t, stderr) != "stderr" {
		t.Fatal("output changed or not drained")
	}
	if !c.isClosed() {
		t.Fatal("channel not closed")
	}
}

func testPTY(t *testing.T) (*os.File, *os.File) {
	t.Helper()
	fd, err := unix.Open("/dev/ptmx", unix.O_RDWR|unix.O_NOCTTY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Skipf("test PTY unavailable: %v", err)
	}
	master := os.NewFile(uintptr(fd), "test-pty-master")
	t.Cleanup(func() { master.Close() })
	if err := unix.IoctlSetPointerInt(fd, unix.TIOCSPTLCK, 0); err != nil {
		t.Fatal(err)
	}
	number, err := unix.IoctlGetInt(fd, unix.TIOCGPTN)
	if err != nil {
		t.Fatal(err)
	}
	slaveFD, err := unix.Open("/dev/pts/"+strconv.Itoa(number), unix.O_RDWR|unix.O_NOCTTY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	slave := os.NewFile(uintptr(slaveFD), "test-pty-slave")
	t.Cleanup(func() { slave.Close() })
	return master, slave
}

func TestSessionTTYResizeEscapeRestore(t *testing.T) {
	master, slave := testPTY(t)
	before, err := unix.IoctlGetTermios(int(slave.Fd()), unix.TCGETS)
	if err != nil {
		t.Fatal(err)
	}
	output, stderr := tempStream(t), tempStream(t)
	c := newTestChannel()
	resizes := make(chan os.Signal, 1)
	done := make(chan error, 1)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	go func() { done <- runSession(ctx, c, slave, output, stderr, resizes) }()
	in := nextInput(t, c)
	if in.kind != native.Size || string(in.data) != `{"cols":80,"rows":24}` {
		t.Fatal("wrong initial dimensions")
	}
	if err := unix.IoctlSetWinsize(int(slave.Fd()), unix.TIOCSWINSZ, &unix.Winsize{Col: 132, Row: 42}); err != nil {
		t.Fatal(err)
	}
	resizes <- syscall.SIGWINCH
	in = nextInput(t, c)
	if in.kind != native.Size || string(in.data) != `{"cols":132,"rows":42}` {
		t.Fatal("wrong resized dimensions")
	}
	if _, err := master.Write([]byte{3, 4, '\r'}); err != nil {
		t.Fatal(err)
	}
	in = nextInput(t, c)
	if !reflect.DeepEqual(in.data, []byte{3, 4, '\r'}) {
		t.Fatal("control input altered")
	}
	if _, err := master.WriteString("~."); err != nil {
		t.Fatal(err)
	}
	if err := waitRun(t, done); err != nil {
		t.Fatal(err)
	}
	if len(c.sent) != 0 {
		t.Fatal("local disconnect sent remotely")
	}
	after, err := unix.IoctlGetTermios(int(slave.Fd()), unix.TCGETS)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(before, after) {
		t.Fatal("terminal not restored")
	}
}

func TestSessionCancellationPreservesCloseFailure(t *testing.T) {
	_, slave := testPTY(t)
	before, err := unix.IoctlGetTermios(int(slave.Fd()), unix.TCGETS)
	if err != nil {
		t.Fatal(err)
	}
	c := newTestChannel()
	cleanup := errors.New("synthetic close failure")
	c.closeErr = errors.Join(context.Canceled, cleanup)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	output, stderr := tempStream(t), tempStream(t)
	go func() { done <- runSession(ctx, c, slave, output, stderr, nil) }()
	nextInput(t, c)
	cancel()
	err = waitRun(t, done)
	if !errors.Is(err, context.Canceled) || !errors.Is(err, cleanup) {
		t.Fatalf("cleanup failure lost: %v", err)
	}
	after, err := unix.IoctlGetTermios(int(slave.Fd()), unix.TCGETS)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(before, after) {
		t.Fatal("canceled terminal not restored")
	}
}

func TestSessionBadOutputAndSetupCleanup(t *testing.T) {
	for _, setup := range []bool{false, true} {
		input, output, stderr := tempStream(t), tempStream(t), tempStream(t)
		c := newTestChannel()
		if setup {
			output = nil
		} else {
			c.out <- testOutput{message: native.Message{PayloadType: native.ExitCode, Payload: []byte("not-an-interactive-exit")}}
		}
		err := runSession(context.Background(), c, input, output, stderr, nil)
		if err == nil || !c.isClosed() {
			t.Fatal("unsafe output or setup failure accepted")
		}
		if strings.Contains(err.Error(), "not-an-interactive-exit") {
			t.Fatal("payload exposed in error")
		}
	}
}

func TestPendingEscapeChunkBound(t *testing.T) {
	var e Escape
	e.Feed([]byte("~"))
	data, _ := e.Feed([]byte(strings.Repeat("x", native.InputSize)))
	c := newTestChannel()
	if err := sendChunks(context.Background(), c, data); err != nil {
		t.Fatal(err)
	}
	if len(c.sent) != 2 {
		t.Fatal("escape-expanded chunk not split")
	}
}

func TestSessionBlockedOutputCancellation(t *testing.T) {
	input, inputWriter, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer input.Close()
	defer inputWriter.Close()
	outputReader, output, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer outputReader.Close()
	defer output.Close()
	c := newTestChannel()
	c.out <- testOutput{message: native.Message{PayloadType: native.Output, Payload: make([]byte, native.MaxPayload)}}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	done := make(chan error, 1)
	stderr := tempStream(t)
	go func() { done <- runSession(ctx, c, input, output, stderr, nil) }()
	if err := waitRun(t, done); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("blocked output cancellation lost: %v", err)
	}
	if !c.isClosed() {
		t.Fatal("blocked channel not closed")
	}
	if _, err := output.Stat(); err != nil {
		t.Fatal("inherited output closed")
	}
}

type signalTestChannel struct {
	*testChannel
	ready sync.Once
}

func (c *signalTestChannel) Receive(ctx context.Context) (native.Message, error) {
	c.ready.Do(func() { _, _ = os.Stdout.WriteString("ready\n") })
	return c.testChannel.Receive(ctx)
}

// Run the termination signal in a subprocess, never in the test runner or the
// user's terminal. Readiness is emitted only after Run has registered signals.
func TestExternalSIGTERM(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestSignalHelper$")
	cmd.Env = append(os.Environ(), "SSMH_TERMINAL_SIGNAL_TEST=1")
	input, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	defer input.Close()
	output, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if cmd.ProcessState == nil {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
		}
	}()
	line, err := bufio.NewReader(output).ReadString('\n')
	if err != nil || line != "ready\n" {
		t.Fatalf("signal helper not ready: %v", err)
	}
	if err := cmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	if err := cmd.Wait(); err != nil {
		t.Fatalf("SIGTERM bypassed controlled cleanup: %v", err)
	}
}

func TestSignalHelper(t *testing.T) {
	if os.Getenv("SSMH_TERMINAL_SIGNAL_TEST") != "1" {
		return
	}
	c := &signalTestChannel{testChannel: newTestChannel()}
	err := Run(context.Background(), c, os.Stdin, tempStream(t), tempStream(t))
	if !errors.Is(err, context.Canceled) || !c.isClosed() {
		t.Fatal("signal failed to cancel and close channel")
	}
}
