//go:build linux

package terminal

import (
	"context"
	"errors"
	"os"

	"golang.org/x/sys/unix"
)

// PromptMFA reads one six-digit code from the controlling terminal, never stdin.
// The caller must exclude concurrent terminal/session readers. Echo is disabled,
// input is bounded, and settings are restored. Queued/typeahead input is cleared
// before and after the prompt so pasted codes cannot reach a later remote shell.
// No code is logged or persisted; Go/SDK string memory cannot be guaranteed erased.
func PromptMFA(ctx context.Context) (code string, result error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	fd, err := unix.Open("/dev/tty", unix.O_RDWR|unix.O_NONBLOCK|unix.O_NOCTTY|unix.O_CLOEXEC, 0)
	if err != nil {
		return "", errors.New("MFA requires a controlling terminal; use preauthenticated SDK credentials for unattended invocations")
	}
	file := os.NewFile(uintptr(fd), "MFA controlling terminal")
	defer func() {
		if file.Close() != nil {
			code = ""
			result = errors.Join(result, errors.New("cannot close MFA controlling terminal"))
		}
	}()
	return readMFACode(ctx, file)
}

func readMFACode(ctx context.Context, file *os.File) (code string, result error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	fd, err := fileDescriptor(file)
	if err != nil {
		return "", err
	}
	saved, err := (linuxControls{}).get(fd)
	if err != nil {
		return "", errors.New("cannot read MFA terminal settings")
	}
	state := &State{fd: fd, saved: *saved, control: linuxControls{}}
	defer func() {
		if unix.IoctlSetInt(fd, unix.TCFLSH, unix.TCIFLUSH) != nil {
			result = errors.Join(result, errors.New("cannot clear queued MFA terminal input"))
		}
		result = errors.Join(result, state.Restore())
		if result != nil {
			code = ""
		}
	}()
	noEcho := *saved
	noEcho.Lflag &^= unix.ECHO | unix.ECHONL | unix.ECHOE | unix.ECHOK | unix.ECHOCTL | unix.ECHOPRT | unix.ECHOKE
	noEcho.Lflag |= unix.ICANON | unix.ISIG
	noEcho.Iflag &^= unix.IGNCR | unix.INLCR
	noEcho.Iflag |= unix.ICRNL
	if (linuxControls{}).set(fd, &noEcho) != nil {
		return "", errors.New("cannot disable MFA terminal echo")
	}
	if unix.IoctlSetInt(fd, unix.TCFLSH, unix.TCIFLUSH) != nil {
		return "", errors.New("cannot clear stale MFA terminal input")
	}
	input, err := OpenStream(file, false)
	if err != nil {
		return "", err
	}
	defer func() {
		result = errors.Join(result, input.Close())
		if result != nil {
			code = ""
		}
	}()
	output, err := OpenStream(file, true)
	if err != nil {
		return "", err
	}
	defer func() {
		result = errors.Join(result, output.Close())
		if result != nil {
			code = ""
		}
	}()
	if err := output.Write(ctx, []byte("ssmh: MFA code (six digits; input/typeahead cleared): ")); err != nil {
		return "", err
	}
	var buffer [8]byte
	defer clear(buffer[:])
	n, err := input.Read(ctx, buffer[:])
	if err != nil {
		return "", err
	}
	if n != 7 || buffer[6] != '\n' {
		return "", errors.New("MFA code must contain exactly six digits followed by Enter")
	}
	for _, b := range buffer[:6] {
		if b < '0' || b > '9' {
			return "", errors.New("MFA code must contain exactly six digits")
		}
	}
	if err := output.Write(ctx, []byte("\n")); err != nil {
		return "", err
	}
	return string(buffer[:6]), nil
}
