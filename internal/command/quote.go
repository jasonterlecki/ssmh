package command

import (
	"errors"
	"strings"
	"unicode/utf8"
)

// SerializeShell preserves command as one argument to the remote /bin/sh -c.
// AWS's Linux NonInteractiveCommands executor tokenizes POSIX-style arguments;
// it does not itself interpret shell operators. Nothing is executed locally.
// The serialized parameter is bounded to 32 KiB, including quoting expansion.
func SerializeShell(command string) (string, error) {
	if command == "" || len(command) > 32768 || !utf8.ValidString(command) || strings.ContainsRune(command, 0) {
		return "", errors.New("invalid remote shell command")
	}
	serialized := "/bin/sh -c '" + strings.ReplaceAll(command, "'", "'\"'\"'") + "'"
	if len(serialized) > 32768 {
		return "", errors.New("remote command exceeds size limit after quoting")
	}
	return serialized, nil
}
