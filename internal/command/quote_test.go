package command

import (
	"strings"
	"testing"
)

// Independently decode the single-quoted argument grammar used by SerializeShell.
// Do not evaluate commands through a local shell, even to test serialization.
func decodeShellArgument(t *testing.T, encoded string) string {
	t.Helper()
	if !strings.HasPrefix(encoded, "/bin/sh -c ") {
		t.Fatal("unexpected remote executable")
	}
	encoded = strings.TrimPrefix(encoded, "/bin/sh -c ")
	var decoded strings.Builder
	for len(encoded) > 0 {
		if encoded[0] != '\'' {
			t.Fatal("unquoted remote command argument")
		}
		encoded = encoded[1:]
		end := strings.IndexByte(encoded, '\'')
		if end < 0 {
			t.Fatal("unterminated quoting")
		}
		decoded.WriteString(encoded[:end])
		encoded = encoded[end+1:]
		if encoded == "" {
			break
		}
		if !strings.HasPrefix(encoded, "\"'\"") {
			t.Fatal("unescaped argument boundary")
		}
		decoded.WriteByte('\'')
		encoded = encoded[3:]
	}
	return decoded.String()
}

func TestShellSerializationPreservesSemantics(t *testing.T) {
	for _, command := range []string{"uname -a", "printf '%s' \"$HOME\"; exit 42", "'", "''", "echo λ\ncat <<'EOF'\nquotes; $(ignored) `literal` \\\nEOF", "sudo explicitly-user-requested", "\tprintf \"spaces  \"\n"} {
		encoded, err := SerializeShell(command)
		if err != nil || decodeShellArgument(t, encoded) != command {
			t.Fatal("remote command altered")
		}
	}
	for _, command := range []string{"", "NUL\x00", "bad\xff", strings.Repeat("x", 32769), strings.Repeat("'", 8192)} {
		if encoded, err := SerializeShell(command); err == nil || encoded != "" {
			t.Fatal("invalid or oversized command serialized")
		}
	}
}

func FuzzShellSerialization(f *testing.F) {
	for _, command := range []string{"uname -a", "quote ' and λ", "\n$() ; `x`", "'", "\x00"} {
		f.Add(command)
	}
	f.Fuzz(func(t *testing.T, command string) {
		encoded, err := SerializeShell(command)
		if err == nil && (len(encoded) > 32768 || decodeShellArgument(t, encoded) != command) {
			t.Fatal("serialization changed command")
		}
	})
}
