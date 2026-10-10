//go:build linux

package integration

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"reflect"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	sdkaws "github.com/aws/aws-sdk-go-v2/aws"
	sdkssm "github.com/aws/aws-sdk-go-v2/service/ssm"
	"golang.org/x/sys/unix"
	"ssmh/internal/ssm"
	"ssmh/internal/terminal"
	"ssmh/internal/transport/native"
)

type livePTY struct {
	master, slave *os.File
	fd            int
	before        *unix.Termios
}

// A private test PTY, never the developer's controlling terminal. Opening the
// master nonblocking lets os.File supply bounded pollable I/O. Do not reopen
// /proc/self/fd for a PTY master: opening ptmx would allocate a different PTY.
func openLivePTY(t *testing.T) livePTY {
	t.Helper()
	fd, err := unix.Open("/dev/ptmx", unix.O_RDWR|unix.O_NOCTTY|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if err != nil {
		t.Fatal("private integration PTY unavailable")
	}
	master := os.NewFile(uintptr(fd), "private-live-pty-master")
	t.Cleanup(func() {
		if master.Close() != nil {
			t.Error("private integration PTY master cleanup failed")
		}
	})
	if unix.IoctlSetPointerInt(fd, unix.TIOCSPTLCK, 0) != nil {
		t.Fatal("cannot unlock private integration PTY")
	}
	number, err := unix.IoctlGetInt(fd, unix.TIOCGPTN)
	if err != nil {
		t.Fatal("cannot locate private integration PTY")
	}
	slaveFD, err := unix.Open("/dev/pts/"+strconv.Itoa(number), unix.O_RDWR|unix.O_NOCTTY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal("cannot open private integration PTY slave")
	}
	slave := os.NewFile(uintptr(slaveFD), "private-live-pty-slave")
	t.Cleanup(func() {
		if slave.Close() != nil {
			t.Error("private integration PTY slave cleanup failed")
		}
	})
	before, err := unix.IoctlGetTermios(slaveFD, unix.TCGETS)
	if err != nil || unix.IoctlSetWinsize(slaveFD, unix.TIOCSWINSZ, &unix.Winsize{Row: 30, Col: 90}) != nil {
		t.Fatal("cannot initialize private integration PTY state")
	}
	return livePTY{master, slave, slaveFD, before}
}

func (p livePTY) write(ctx context.Context, data string) error {
	deadline, ok := ctx.Deadline()
	if !ok || p.master.SetWriteDeadline(deadline) != nil {
		return errors.New("cannot bound private PTY input")
	}
	if _, err := io.WriteString(p.master, data); err != nil {
		return errors.New("private PTY input failed")
	}
	return nil
}

// readTTYLine retains at most the capture bound and never formats remote data.
// Markers are split in the submitted command, so input echo cannot satisfy this
// check. Each probe must be completed before the next command is submitted.
func readTTYLine(reader io.Reader, marker string) (string, error) {
	var retained []byte
	var chunk [1024]byte
	for len(retained) < captureLimit {
		n, err := reader.Read(chunk[:])
		if n > 0 {
			if len(retained)+n > captureLimit {
				return "", errors.New("private PTY output capture limit exceeded")
			}
			retained = append(retained, chunk[:n]...)
			if start := bytes.Index(retained, []byte(marker+":")); start >= 0 {
				line := retained[start+len(marker)+1:]
				if end := bytes.IndexByte(line, '\n'); end >= 0 {
					return strings.TrimSuffix(string(line[:end]), "\r"), nil
				}
			}
		}
		if err != nil || n == 0 {
			return "", errors.New("private PTY output probe failed")
		}
	}
	return "", errors.New("private PTY output capture limit exceeded")
}

func (p livePTY) probe(ctx context.Context, marker string) (string, error) {
	deadline, ok := ctx.Deadline()
	if !ok || p.master.SetReadDeadline(deadline) != nil {
		return "", errors.New("cannot bound private PTY output")
	}
	return readTTYLine(p.master, marker)
}

func splitTTYPrintf(marker, suffix string) string {
	middle := len(marker) / 2
	return "printf '%s%s:" + suffix + "' '" + marker[:middle] + "' '" + marker[middle:] + "'"
}

func awaitRawPTY(ctx context.Context, fd int) error {
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		if ctx.Err() != nil {
			return errors.New("private PTY did not enter raw mode")
		}
		state, err := unix.IoctlGetTermios(fd, unix.TCGETS)
		if err != nil {
			return errors.New("cannot inspect private PTY state")
		}
		if state.Lflag&(unix.ICANON|unix.ECHO|unix.ISIG) == 0 {
			return nil
		}
		select {
		case <-ctx.Done():
			return errors.New("private PTY did not enter raw mode")
		case <-ticker.C:
		}
	}
}

func TestLiveNativeShellTTY(t *testing.T) {
	o := liveGate(t, "shell-tty")
	// Fail missing PTY prerequisites before resolving credentials or starting AWS
	// sessions. A shell approval alone does not select this additional operation.
	p := openLivePTY(t)
	r := prepareLive(t, o)
	session, err := ssm.StartShell(r.setup, r.api, r.api, &sdkssm.StartSessionInput{Target: sdkaws.String(r.instance), Reason: sdkaws.String("Explicit ssmh native PTY integration test")}, r.cfg.Region)
	if session != nil {
		ownLiveSession(t, session)
	}
	if err != nil {
		t.Fatal("live PTY shell session creation failed")
	}
	channel, err := native.Connect(r.ctx, r.cfg, session, "Standard_Stream", remainingLive(t, r.setup))
	if channel != nil {
		ownLiveChannel(t, channel)
	}
	if err != nil {
		t.Fatal("live PTY shell channel establishment failed")
	}
	ctx, cancel := context.WithCancel(r.ctx)
	done := make(chan error, 1)
	go func() { done <- terminal.Run(ctx, channel, p.slave, p.slave, p.slave) }()
	joined := false
	defer func() {
		cancel()
		if !joined {
			if err := <-done; !onlyCancellation(err) {
				t.Error("live PTY terminal workers failed during cleanup:", liveFailureLabel(err, 0))
			}
		}
		after, err := unix.IoctlGetTermios(p.fd, unix.TCGETS)
		if err != nil || !reflect.DeepEqual(p.before, after) {
			t.Error("live PTY terminal state was not completely restored")
		}
	}()
	phase, stop := context.WithTimeout(ctx, 10*time.Second)
	if awaitRawPTY(phase, p.fd) != nil {
		stop()
		t.Fatal("live PTY raw mode failed")
	}
	stop()
	checkSize := func(rows, cols uint16) {
		t.Helper()
		phase, stop := context.WithTimeout(ctx, 10*time.Second)
		defer stop()
		for range 10 {
			marker := nonce(t)
			if p.write(phase, splitTTYPrintf(marker, "")+"; stty size\n") != nil {
				t.Fatal("live PTY size command failed")
			}
			line, err := p.probe(phase, marker)
			if err != nil {
				t.Fatal("live PTY size response failed; output omitted")
			}
			if line == strconv.Itoa(int(rows))+" "+strconv.Itoa(int(cols)) {
				return
			}
			timer := time.NewTimer(100 * time.Millisecond)
			select {
			case <-phase.Done():
				timer.Stop()
				t.Fatal("live PTY size propagation timed out")
			case <-timer.C:
			}
		}
		t.Fatal("live remote terminal dimensions did not match local PTY")
	}
	checkSize(30, 90)
	if unix.IoctlSetWinsize(p.fd, unix.TIOCSWINSZ, &unix.Winsize{Row: 41, Col: 105}) != nil || syscall.Kill(os.Getpid(), syscall.SIGWINCH) != nil {
		t.Fatal("cannot resize live test PTY")
	}
	checkSize(41, 105)
	phase, stop = context.WithTimeout(ctx, 10*time.Second)
	defer stop()
	ready, resumed := nonce(t), nonce(t)
	// The generated ASCII nonce is not user input. This remote child runs only
	// printf and a bounded sleep; Ctrl+C must interrupt it without closing ssmh.
	if p.write(phase, "sh -c \""+splitTTYPrintf(ready, "\\n")+"; sleep 30\"\n") != nil {
		t.Fatal("live PTY interrupt probe input failed")
	}
	if line, err := p.probe(phase, ready); err != nil || line != "" {
		t.Fatal("live PTY interrupt probe readiness failed")
	}
	if p.write(phase, "\x03"+splitTTYPrintf(resumed, "\\n")+"\n") != nil {
		t.Fatal("live PTY Ctrl+C input failed")
	}
	if line, err := p.probe(phase, resumed); err != nil || line != "" {
		t.Fatal("live remote Ctrl+C did not return to a usable shell")
	}
	if p.write(phase, "\x04") != nil {
		t.Fatal("live PTY Ctrl+D input failed")
	}
	select {
	case err := <-done:
		joined = true
		if err != nil {
			t.Fatal("live PTY Ctrl+D completion failed")
		}
		if channel.RemoteCompleted() {
			// Normal owned EOF is verified after terminal/channel workers join.
			// Every failed/interrupted probe retains best-effort API cleanup.
			session.ReleaseAfterRemoteCompletion()
		}
	case <-phase.Done():
		t.Fatal("live PTY Ctrl+D did not complete the shell")
	}
}

func TestTTYProbeLineBoundsAndRedaction(t *testing.T) {
	for _, suffix := range []string{"\n", "\r\n"} {
		line, err := readTTYLine(strings.NewReader("echo 'split' 'marker'\nnoise\n"+"splitmarker:41 105"+suffix), "splitmarker")
		if err != nil || line != "41 105" {
			t.Fatal("probe failed to extract actual remote line")
		}
	}
	for _, input := range []string{"echo 'split' 'marker'\n", "splitmarker:partial", strings.Repeat("SYNTHETIC-SECRET", captureLimit/16+1)} {
		if _, err := readTTYLine(strings.NewReader(input), "splitmarker"); err == nil || strings.Contains(err.Error(), "SYNTHETIC-SECRET") {
			t.Fatal("missing/bounded probe failure accepted or disclosed output")
		}
	}
}

func TestTTYProbeRealPrivatePTY(t *testing.T) {
	p := openLivePTY(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if _, err := p.slave.WriteString("SYNTHETIC-SECRET\nmarker:41 105\n"); err != nil {
		t.Fatal("private PTY fixture output failed")
	}
	if line, err := p.probe(ctx, "marker"); err != nil || line != "41 105" {
		t.Fatal("private PTY probe failed")
	}
	if awaitRawPTY(ctx, p.fd) == nil {
		t.Fatal("canonical PTY incorrectly treated as raw")
	}
}

type ttyHarnessChannel struct {
	sent chan native.Message
	out  chan native.Message
}

func (c *ttyHarnessChannel) Send(ctx context.Context, kind uint32, data []byte) error {
	select {
	case c.sent <- native.Message{PayloadType: kind, Payload: append([]byte(nil), data...)}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (c *ttyHarnessChannel) Receive(ctx context.Context) (native.Message, error) {
	select {
	case message, ok := <-c.out:
		if !ok {
			return native.Message{}, io.EOF
		}
		return message, nil
	case <-ctx.Done():
		return native.Message{}, ctx.Err()
	}
}

func (*ttyHarnessChannel) Close() error { return nil }

// This exercises only the test harness and production terminal runner, not AWS
// or the remote agent. Live interoperability must come from the opted-in case.
func TestTTYHarnessRawInputResizeAndRestore(t *testing.T) {
	p := openLivePTY(t)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	channel := &ttyHarnessChannel{make(chan native.Message, 8), make(chan native.Message, 8)}
	done := make(chan error, 1)
	go func() { done <- terminal.Run(ctx, channel, p.slave, p.slave, p.slave) }()
	joined := false
	defer func() {
		cancel()
		if !joined && !onlyCancellation(<-done) {
			t.Error("private PTY harness cleanup failed")
		}
		after, err := unix.IoctlGetTermios(p.fd, unix.TCGETS)
		if err != nil || !reflect.DeepEqual(p.before, after) {
			t.Error("private PTY harness did not restore state")
		}
	}()
	next := func() native.Message {
		t.Helper()
		select {
		case message := <-channel.sent:
			return message
		case <-ctx.Done():
			t.Fatal("private PTY harness input/resize missing")
			return native.Message{}
		}
	}
	if awaitRawPTY(ctx, p.fd) != nil {
		t.Fatal("private PTY harness raw mode failed")
	}
	message := next()
	if message.PayloadType != native.Size || string(message.Payload) != `{"cols":90,"rows":30}` {
		t.Fatal("private PTY initial size changed")
	}
	if unix.IoctlSetWinsize(p.fd, unix.TIOCSWINSZ, &unix.Winsize{Row: 41, Col: 105}) != nil || syscall.Kill(os.Getpid(), syscall.SIGWINCH) != nil {
		t.Fatal("private PTY harness resize failed")
	}
	message = next()
	if message.PayloadType != native.Size || string(message.Payload) != `{"cols":105,"rows":41}` {
		t.Fatal("private PTY resize did not reach channel")
	}
	if p.write(ctx, "\x03\x04") != nil {
		t.Fatal("private PTY harness control input failed")
	}
	var control []byte
	for len(control) < 2 {
		message = next()
		if message.PayloadType != native.Output {
			t.Fatal("private PTY control input changed type")
		}
		control = append(control, message.Payload...)
	}
	if !bytes.Equal(control, []byte{3, 4}) {
		t.Fatal("private PTY control input changed")
	}
	channel.out <- native.Message{PayloadType: native.Output, Payload: []byte("marker:41 105\r\n")}
	if line, err := p.probe(ctx, "marker"); err != nil || line != "41 105" {
		t.Fatal("private PTY channel output probe failed")
	}
	close(channel.out)
	select {
	case err := <-done:
		joined = true
		if err != nil {
			t.Fatal("private PTY harness completion failed")
		}
	case <-ctx.Done():
		t.Fatal("private PTY harness did not complete")
	}
}
