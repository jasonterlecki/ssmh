package command

import "errors"

// AWS's shell plugin sendExitCode emits an ASCII prefix and canonical decimal
// value in payload type 12, not ordinary stdout. Linux exec.ExitError.ExitCode
// can be -1 for signal termination; that cannot be propagated as a process exit
// status without knowing the signal, so it remains an explicit unknown result.
func parseExitCode(payload []byte) (int, error) {
	const prefix = "EXIT_CODE: "
	invalid := errors.New("invalid or unavailable remote command exit status")
	if len(payload) <= len(prefix) || len(payload) > len(prefix)+3 {
		return 0, invalid
	}
	for i := range prefix {
		if payload[i] != prefix[i] {
			return 0, invalid
		}
	}
	digits := payload[len(prefix):]
	if len(digits) > 1 && digits[0] == '0' {
		return 0, invalid
	}
	code := 0
	for _, digit := range digits {
		if digit < '0' || digit > '9' {
			return 0, invalid
		}
		code = code*10 + int(digit-'0')
	}
	if code > 255 {
		return 0, invalid
	}
	return code, nil
}
