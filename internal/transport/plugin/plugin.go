// Package plugin supplies executable preflight and an owned session-response
// handoff primitive for the official Session Manager executable.
// Session launch and CLI integration are not implemented yet.
package plugin

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const probeTimeout = 3 * time.Second

// Executable identifies a successfully probed plugin, not an authenticated session.
// A version string does not establish binary provenance or security correctness.
type Executable struct {
	path    string
	version [4]uint16
}

// String deliberately omits the installation path and any subprocess output.
func (e *Executable) String() string { return "Session Manager plugin [installation path redacted]" }

// GoString provides the same safe representation for Go-syntax formatting.
func (e *Executable) GoString() string { return e.String() }

// Version returns the validated four-component version, or empty for a nil handle.
func (e *Executable) Version() string {
	if e == nil {
		return ""
	}
	return fmt.Sprintf("%d.%d.%d.%d", e.version[0], e.version[1], e.version[2], e.version[3])
}

// Inspect finds session-manager-plugin on trusted PATH and probes its version.
// It never installs a program, invokes a shell, loads AWS credentials or starts a
// session. The probe inherits no environment or input and its output is bounded
// and never included in errors. The caller must trust the executable and PATH.
func Inspect(ctx context.Context) (*Executable, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	path, err := exec.LookPath("session-manager-plugin")
	if err != nil {
		return nil, errors.New("Session Manager plugin is unavailable; install a reviewed official version 1.2.764.0 or later on trusted PATH")
	}
	// LookPath refuses implicit current-directory discovery. Also reject relative
	// PATH entries explicitly: a later working-directory change must not retarget
	// the executable selected by preflight.
	if !filepath.IsAbs(path) {
		return nil, errors.New("Session Manager plugin must be installed on an absolute trusted PATH entry")
	}
	info, err := os.Stat(path)
	if err != nil || !safeExecutableMode(info.Mode()) {
		return nil, errors.New("Session Manager plugin must be a regular executable without set-ID or group/world-write permissions")
	}
	probe, cancel := context.WithTimeout(ctx, probeTimeout)
	defer cancel()
	command := exec.CommandContext(probe, path, "--version")
	command.Env = []string{"LANG=C", "LC_ALL=C"}
	// If a trusted program accidentally leaves inherited output pipes open in a
	// descendant, do not let pipe draining outlive the probe indefinitely.
	command.WaitDelay = 250 * time.Millisecond
	var output versionOutput
	command.Stdout = &output
	if err := command.Run(); err != nil {
		return nil, errors.Join(probe.Err(), errors.New("cannot probe Session Manager plugin version"))
	}
	if err := probe.Err(); err != nil {
		return nil, err
	}
	version, ok := parseVersion(string(output.data[:output.used]))
	if output.overflow || !ok {
		return nil, errors.New("Session Manager plugin returned an invalid version")
	}
	if !supportedVersion(version) {
		return nil, errors.New("Session Manager plugin is outdated; install a reviewed official version 1.2.764.0 or later")
	}
	return &Executable{path: path, version: version}, nil
}

// versionOutput discards excess bytes without allocating in response to output.
// An excessive writer still remains subject to the probe deadline.
type versionOutput struct {
	data     [64]byte
	used     int
	overflow bool
}

func (o *versionOutput) Write(p []byte) (int, error) {
	n := copy(o.data[o.used:], p)
	o.used += n
	o.overflow = o.overflow || n != len(p)
	return len(p), nil
}

func parseVersion(output string) (version [4]uint16, ok bool) {
	if len(output) > 64 {
		return version, false
	}
	if strings.HasSuffix(output, "\r\n") {
		output = strings.TrimSuffix(output, "\r\n")
	} else {
		output = strings.TrimSuffix(output, "\n")
	}
	parts := strings.Split(output, ".")
	if len(parts) != len(version) {
		return version, false
	}
	for i, part := range parts {
		if len(part) == 0 || len(part) > 5 || len(part) > 1 && part[0] == '0' {
			return [4]uint16{}, false
		}
		for _, b := range []byte(part) {
			if b < '0' || b > '9' {
				return [4]uint16{}, false
			}
		}
		value, err := strconv.ParseUint(part, 10, 16)
		if err != nil {
			return [4]uint16{}, false
		}
		version[i] = uint16(value)
	}
	return version, true
}

func supportedVersion(version [4]uint16) bool {
	minimum := [4]uint16{1, 2, 764, 0}
	for i, value := range version {
		if value != minimum[i] {
			return value > minimum[i]
		}
	}
	return true
}

func safeExecutableMode(mode os.FileMode) bool {
	return mode.IsRegular() && mode.Perm()&0111 != 0 && mode.Perm()&0022 == 0 && mode&(os.ModeSetuid|os.ModeSetgid) == 0
}
