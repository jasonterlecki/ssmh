package plugin

import (
	"bytes"
	"context"
	"encoding/xml"
	"errors"
	"io"
	"os"
	"syscall"

	"golang.org/x/sys/unix"
)

const pluginLogConfig = "/usr/local/sessionmanagerplugin/seelog.xml"
const maxLogConfigBytes = 1024

// inspectLogging is a prerequisite for a future launch, not launch permission.
// The reviewed Linux plugin reads this installation-wide path and reloads it.
// Root administrators remain trusted throughout the child's lifetime. This
// function neither edits their configuration nor locks it against their changes.
func inspectLogging(ctx context.Context) (result error) {
	if err := ctx.Err(); err != nil {
		return err
	}
	invalid := errors.New("plugin logging requires a root-owned protected installation and disabled seelog configuration")
	for _, directory := range []string{"/", "/usr", "/usr/local", "/usr/local/sessionmanagerplugin"} {
		info, err := os.Lstat(directory)
		if err != nil || !protectedLogPath(info, true) {
			return invalid
		}
	}
	before, err := os.Lstat(pluginLogConfig)
	if err != nil || !protectedLogPath(before, false) {
		return invalid
	}
	// Nonblocking open avoids waiting on a substituted special file. NOFOLLOW
	// refuses a leaf symlink; protected root-owned ancestors refuse symlinks too.
	fd, err := unix.Open(pluginLogConfig, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return invalid
	}
	file := os.NewFile(uintptr(fd), "plugin logging configuration")
	defer func() {
		if file.Close() != nil {
			result = errors.Join(result, errors.New("cannot close plugin logging configuration"))
		}
	}()
	after, err := file.Stat()
	if err != nil || !protectedLogPath(after, false) || !os.SameFile(before, after) || after.Size() > maxLogConfigBytes {
		return invalid
	}
	if err := readDisabledLogging(file); err != nil {
		return err
	}
	return ctx.Err()
}

func protectedLogPath(info os.FileInfo, directory bool) bool {
	if info == nil || info.Mode().Perm()&0022 != 0 || info.Mode()&(os.ModeSymlink|os.ModeSetuid|os.ModeSetgid) != 0 {
		return false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != 0 {
		return false
	}
	if directory {
		return info.IsDir()
	}
	return info.Mode().IsRegular()
}

// readDisabledLogging deliberately accepts a tiny subset of the pinned seelog
// grammar: <seelog type="sync" minlevel="off"/> with XML whitespace. No outputs,
// exceptions, namespaces, directives, comments, declarations or extra attributes
// are accepted. A minlevel="off" substring alone does not disable exceptions.
// The parser has a fixed input bound and never exposes file contents/errors.
func readDisabledLogging(reader io.Reader) error {
	invalid := errors.New("plugin logging configuration must contain only seelog type=sync minlevel=off without outputs or exceptions")
	data, err := io.ReadAll(io.LimitReader(reader, maxLogConfigBytes+1))
	if err != nil || len(data) > maxLogConfigBytes {
		return invalid
	}
	decoder := xml.NewDecoder(bytes.NewReader(data))
	state := 0
	for {
		token, err := decoder.Token()
		if err == io.EOF {
			if state == 2 {
				return nil
			}
			return invalid
		}
		if err != nil {
			return invalid
		}
		switch token := token.(type) {
		case xml.StartElement:
			if state != 0 || token.Name.Space != "" || token.Name.Local != "seelog" || len(token.Attr) != 2 {
				return invalid
			}
			seen := map[string]bool{}
			for _, attribute := range token.Attr {
				name := attribute.Name.Local
				if attribute.Name.Space != "" || seen[name] || !(name == "type" && attribute.Value == "sync" || name == "minlevel" && attribute.Value == "off") {
					return invalid
				}
				seen[name] = true
			}
			state = 1
		case xml.EndElement:
			if state != 1 || token.Name.Space != "" || token.Name.Local != "seelog" {
				return invalid
			}
			state = 2
		case xml.CharData:
			for _, b := range token {
				if b != ' ' && b != '\t' && b != '\r' && b != '\n' {
					return invalid
				}
			}
		default:
			return invalid
		}
	}
}
