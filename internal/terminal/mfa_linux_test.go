//go:build linux

package terminal

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"os/signal"
	"reflect"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

type mfaResult struct {
	code string
	err  error
}

func readPTYPrompt(t *testing.T, master *os.File) string {
	t.Helper()
	fd, err := fileDescriptor(master)
	if err != nil {
		t.Fatal(err)
	}
	var out strings.Builder
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		fds := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}
		if _, err := unix.Poll(fds, 50); err != nil {
			t.Fatal(err)
		}
		if fds[0].Revents&unix.POLLIN == 0 {
			continue
		}
		var buffer [256]byte
		n, err := unix.Read(fd, buffer[:])
		if err != nil {
			t.Fatal(err)
		}
		out.Write(buffer[:n])
		if strings.Contains(out.String(), "input/typeahead cleared): ") {
			return out.String()
		}
	}
	t.Fatal("MFA prompt not ready")
	return ""
}

func TestMFAPromptPTYNoEchoRestorationAndQueueClear(t *testing.T) {
	for _, text := range []string{"123456\n", "12345\n", "12345678\n", "ABCDEF\n", "123456\n654321\n"} {
		master, slave := testPTY(t)
		fd, err := fileDescriptor(slave)
		if err != nil {
			t.Fatal(err)
		}
		before, err := unix.IoctlGetTermios(fd, unix.TCGETS)
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		done := make(chan mfaResult, 1)
		go func() { code, err := readMFACode(ctx, slave); done <- mfaResult{code, err} }()
		prompt := readPTYPrompt(t, master)
		if strings.Contains(prompt, "123456") {
			t.Fatal("code exposed in prompt")
		}
		during, err := unix.IoctlGetTermios(fd, unix.TCGETS)
		if err != nil {
			t.Fatal(err)
		}
		if during.Lflag&(unix.ECHO|unix.ECHONL) != 0 {
			t.Fatal("MFA echo enabled")
		}
		if _, err := master.WriteString(text); err != nil {
			t.Fatal(err)
		}
		var r mfaResult
		select {
		case r = <-done:
		case <-ctx.Done():
			t.Fatal("MFA read did not finish")
		}
		cancel()
		valid := text == "123456\n" || text == "123456\n654321\n"
		if valid && (r.err != nil || r.code != "123456") || !valid && (r.err == nil || r.code != "") {
			t.Fatal("incorrect code validation")
		}
		if r.err != nil && strings.Contains(r.err.Error(), strings.TrimSpace(text)) {
			t.Fatal("code in MFA error")
		}
		after, err := unix.IoctlGetTermios(fd, unix.TCGETS)
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(before, after) {
			t.Fatal("MFA terminal not restored")
		}
		queued, err := unix.IoctlGetInt(fd, unix.TIOCINQ)
		if err != nil || queued != 0 {
			t.Fatal("pasted code retained in terminal queue")
		}
		// Only a cosmetic newline may remain on the PTY output after a successful
		// read. No entered digit may have been echoed.
		masterFD, _ := fileDescriptor(master)
		fds := []unix.PollFd{{Fd: int32(masterFD), Events: unix.POLLIN}}
		if _, err := unix.Poll(fds, 10); err != nil {
			t.Fatal(err)
		}
		if fds[0].Revents&unix.POLLIN != 0 {
			var buffer [256]byte
			n, err := unix.Read(masterFD, buffer[:])
			if err != nil {
				t.Fatal(err)
			}
			if strings.ContainsAny(string(buffer[:n]), "0123456789ABCDEF") {
				t.Fatal("MFA characters echoed")
			}
		}
	}
}

func TestMFAPromptCancellationRestoresPTY(t *testing.T) {
	master, slave := testPTY(t)
	fd, _ := fileDescriptor(slave)
	before, err := unix.IoctlGetTermios(fd, unix.TCGETS)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan mfaResult, 1)
	go func() { code, err := readMFACode(ctx, slave); done <- mfaResult{code, err} }()
	readPTYPrompt(t, master)
	cancel()
	select {
	case r := <-done:
		if r.code != "" || !errors.Is(r.err, context.Canceled) {
			t.Fatal("canceled MFA accepted")
		}
	case <-time.After(time.Second):
		t.Fatal("MFA cancellation blocked")
	}
	after, err := unix.IoctlGetTermios(fd, unix.TCGETS)
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatal("canceled MFA settings not restored")
	}
}

func TestMFADoesNotReadRedirectedStdin(t *testing.T) {
	cmd := exec.Command(os.Args[0], "-test.run=^TestMFAWithoutTTYHelper$")
	cmd.Env = append(os.Environ(), "SSMH_MFA_NO_TTY_TEST=1")
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	cmd.Stdin = strings.NewReader("123456\n")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("no-TTY helper failed: %v %s", err, out)
	}
}
func TestMFAWithoutTTYHelper(t *testing.T) {
	if os.Getenv("SSMH_MFA_NO_TTY_TEST") != "1" {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	code, err := PromptMFA(ctx)
	if code != "" || err == nil || !strings.Contains(err.Error(), "controlling terminal") {
		t.Fatal("MFA consumed redirected stdin")
	}
}

func TestMFAControllingTTYAndKeyboardInterrupt(t *testing.T) {
	for _, interrupt := range []bool{false, true} {
		master, slave := testPTY(t)
		fd, _ := fileDescriptor(slave)
		before, err := unix.IoctlGetTermios(fd, unix.TCGETS)
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
		cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestMFAControllingTTYHelper$")
		mode := "code"
		if interrupt {
			mode = "interrupt"
		}
		cmd.Env = append(os.Environ(), "SSMH_MFA_TTY_TEST="+mode)
		cmd.Stdin = strings.NewReader("000000\n")
		cmd.ExtraFiles = []*os.File{slave}
		cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true, Setctty: true, Ctty: 3}
		if err := cmd.Start(); err != nil {
			cancel()
			t.Fatal(err)
		}
		readPTYPrompt(t, master)
		input := []byte("123456\n")
		if interrupt {
			input = []byte{3}
		}
		if _, err := master.Write(input); err != nil {
			cancel()
			t.Fatal(err)
		}
		err = cmd.Wait()
		cancel()
		if err != nil {
			t.Fatalf("controlling-TTY MFA failed: %v", err)
		}
		after, err := unix.IoctlGetTermios(fd, unix.TCGETS)
		if err != nil || !reflect.DeepEqual(before, after) {
			t.Fatal("controlling terminal not restored")
		}
	}
}

func TestMFAControllingTTYHelper(t *testing.T) {
	mode := os.Getenv("SSMH_MFA_TTY_TEST")
	if mode == "" {
		return
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT)
	defer stop()
	code, err := PromptMFA(ctx)
	if mode == "interrupt" {
		if code != "" || !errors.Is(err, context.Canceled) {
			t.Fatal("keyboard interrupt did not cancel MFA")
		}
	} else if code != "123456" || err != nil {
		t.Fatal("MFA used redirected stdin or failed terminal read")
	}
}
