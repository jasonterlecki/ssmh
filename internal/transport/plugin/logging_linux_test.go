package plugin

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestDisabledLoggingGrammar(t *testing.T) {
	for _, input := range []string{
		`<seelog type="sync" minlevel="off"/>`,
		" \n<seelog minlevel='off' type='sync'>\t\r\n</seelog> \n",
	} {
		if err := readDisabledLogging(strings.NewReader(input)); err != nil {
			t.Fatal("disabled configuration refused")
		}
	}
	for name, input := range map[string]string{
		"empty": "", "missing type": `<seelog minlevel="off"/>`,
		"enabled":       `<seelog type="sync" minlevel="debug"/>`,
		"async":         `<seelog type="asyncloop" minlevel="off"/>`,
		"exception":     `<seelog type="sync" minlevel="off"><exceptions><exception minlevel="error"/></exceptions></seelog>`,
		"file output":   `<seelog type="sync" minlevel="off"><outputs><file path="SYNTHETIC-SECRET"/></outputs></seelog>`,
		"extra level":   `<seelog type="sync" minlevel="off" maxlevel="critical"/>`,
		"duplicate":     `<seelog type="sync" type="sync"/>`,
		"duplicate off": `<seelog minlevel="off" minlevel="off"/>`,
		"namespace":     `<seelog xmlns="urn:test" type="sync" minlevel="off"/>`,
		"prefixed attr": `<seelog xmlns:a="urn:test" a:type="sync" minlevel="off"/>`,
		"unknown attr":  `<seelog type="sync" minlevel="off" secret="SYNTHETIC-SECRET"/>`,
		"root text":     `SYNTHETIC-SECRET<seelog type="sync" minlevel="off"/>`,
		"child text":    `<seelog type="sync" minlevel="off">SYNTHETIC-SECRET</seelog>`,
		"second root":   `<seelog type="sync" minlevel="off"/><seelog type="sync" minlevel="off"/>`,
		"comment":       `<!-- SYNTHETIC-SECRET --><seelog type="sync" minlevel="off"/>`,
		"declaration":   `<?xml version="1.0"?><seelog type="sync" minlevel="off"/>`,
		"directive":     `<!DOCTYPE seelog><seelog type="sync" minlevel="off"/>`,
		"malformed":     `<seelog type="sync" minlevel="off">`,
		"invalid UTF8":  "\xff<seelog type=\"sync\" minlevel=\"off\"/>",
		"oversized":     strings.Repeat(" ", maxLogConfigBytes) + `<seelog type="sync" minlevel="off"/>`,
	} {
		t.Run(name, func(t *testing.T) {
			err := readDisabledLogging(strings.NewReader(input))
			if err == nil || strings.Contains(err.Error(), "SYNTHETIC-SECRET") {
				t.Fatal("unsafe configuration accepted or contents exposed")
			}
		})
	}
}

type infiniteLoggingRead struct{ bytes int }

func (r *infiniteLoggingRead) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = ' '
	}
	r.bytes += len(p)
	return len(p), nil
}

func TestDisabledLoggingReadBound(t *testing.T) {
	r := &infiniteLoggingRead{}
	if readDisabledLogging(r) == nil || r.bytes != maxLogConfigBytes+1 {
		t.Fatal("logging input not bounded")
	}
}

type errorLoggingRead struct{}

func (errorLoggingRead) Read([]byte) (int, error) {
	return 0, errors.New("SYNTHETIC-SECRET read failure")
}

func TestDisabledLoggingReadFailureAndExactBound(t *testing.T) {
	if err := readDisabledLogging(errorLoggingRead{}); err == nil || strings.Contains(err.Error(), "SYNTHETIC-SECRET") {
		t.Fatal("read error ignored or exposed")
	}
	config := `<seelog type="sync" minlevel="off"/>`
	input := config + strings.Repeat(" ", maxLogConfigBytes-len(config))
	if readDisabledLogging(strings.NewReader(input)) != nil {
		t.Fatal("exact input bound refused")
	}
	if readDisabledLogging(strings.NewReader(input+" ")) == nil {
		t.Fatal("input beyond bound accepted")
	}
}

type logPathInfo struct {
	mode os.FileMode
	stat any
}

func (i logPathInfo) Name() string       { return "synthetic" }
func (i logPathInfo) Size() int64        { return 0 }
func (i logPathInfo) Mode() os.FileMode  { return i.mode }
func (i logPathInfo) ModTime() time.Time { return time.Time{} }
func (i logPathInfo) IsDir() bool        { return i.mode.IsDir() }
func (i logPathInfo) Sys() any           { return i.stat }

func TestProtectedLoggingPaths(t *testing.T) {
	for _, directory := range []bool{false, true} {
		mode := os.FileMode(0644)
		if directory {
			mode = os.ModeDir | 0755
		}
		good := logPathInfo{mode, &syscall.Stat_t{Uid: 0}}
		if !protectedLogPath(good, directory) {
			t.Fatal("protected path refused")
		}
		for _, bad := range []os.FileInfo{
			nil,
			logPathInfo{mode, nil},
			logPathInfo{mode, &syscall.Stat_t{Uid: 1000}},
			logPathInfo{mode | 0020, good.stat},
			logPathInfo{mode | 0002, good.stat},
			logPathInfo{mode | os.ModeSymlink, good.stat},
			logPathInfo{mode | os.ModeSetuid, good.stat},
			logPathInfo{mode | os.ModeSetgid, good.stat},
			logPathInfo{os.ModeNamedPipe | 0600, good.stat},
		} {
			if protectedLogPath(bad, directory) {
				t.Fatal("unprotected path accepted")
			}
		}
		if protectedLogPath(good, !directory) {
			t.Fatal("wrong path type accepted")
		}
	}
}

func TestInspectLoggingCanceledBeforeFilesystem(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := inspectLogging(ctx); !errors.Is(err, context.Canceled) {
		t.Fatal("canceled preflight continued")
	}
}

func TestProtectedLoggingRealLocalFiles(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "seelog.xml")
	if err := os.WriteFile(path, []byte(`<seelog type="sync" minlevel="off"/>`), 0600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(directory, "link.xml")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(link)
	if err != nil || protectedLogPath(info, false) {
		t.Fatal("real symlink accepted")
	}
	if os.Getuid() != 0 {
		info, err = os.Lstat(path)
		if err != nil || protectedLogPath(info, false) {
			t.Fatal("real non-root-owned config accepted")
		}
	}
}

func FuzzDisabledLogging(f *testing.F) {
	f.Add(`<seelog type="sync" minlevel="off"/>`)
	f.Add(`<seelog minlevel="off"><exceptions/></seelog>`)
	f.Fuzz(func(t *testing.T, input string) {
		if err := readDisabledLogging(strings.NewReader(input)); err != nil && err.Error() != "plugin logging configuration must contain only seelog type=sync minlevel=off without outputs or exceptions" {
			t.Fatal("unexpected diagnostic")
		}
	})
}
