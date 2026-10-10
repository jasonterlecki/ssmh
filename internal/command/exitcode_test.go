package command

import (
	"fmt"
	"strings"
	"testing"
)

func TestExitCodeRangeAndCanonicalEncoding(t *testing.T) {
	for code := 0; code <= 255; code++ {
		got, err := parseExitCode([]byte(fmt.Sprintf("EXIT_CODE: %d", code)))
		if err != nil || got != code {
			t.Fatalf("status %d: %d, %v", code, got, err)
		}
	}
	for _, payload := range []string{"", "0", "EXIT_CODE: ", "EXIT_CODE: -1", "EXIT_CODE: -9", "EXIT_CODE: +1", "EXIT_CODE: 01", "EXIT_CODE: 00", "EXIT_CODE: 256", "EXIT_CODE: 999", "EXIT_CODE: 1000", "EXIT_CODE: 1\n", "EXIT_CODE:  1", "EXIT_CODE: 1\x00", "EXIT_CODE: ١", "exit_code: 1", "EXIT_CODE: secret", strings.Repeat("A", 1<<20)} {
		if _, err := parseExitCode([]byte(payload)); err == nil || strings.Contains(err.Error(), payload) && len(payload) > 20 {
			t.Fatal("invalid payload accepted or exposed")
		}
	}
}

func FuzzExitCode(f *testing.F) {
	for _, payload := range []string{"EXIT_CODE: 0", "EXIT_CODE: 255", "EXIT_CODE: -1", "EXIT_CODE: 00", "", "EXIT_CODE: 1\x00"} {
		f.Add([]byte(payload))
	}
	f.Fuzz(func(t *testing.T, payload []byte) {
		code, err := parseExitCode(payload)
		if err == nil && (code < 0 || code > 255 || string(payload) != fmt.Sprintf("EXIT_CODE: %d", code)) {
			t.Fatal("accepted noncanonical status")
		}
	})
}
