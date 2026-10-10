//go:build linux

package buildcheck

import (
	"bytes"
	"context"
	"crypto/sha256"
	"debug/buildinfo"
	"debug/elf"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"
)

const releaseVersion = "v0.0.0-repro-test"

// This deliberately tests the release recipe, not a second copy of its flags.
// It is opt-in because four cross-builds can be expensive on an empty build cache.
func TestReleaseReproducibility(t *testing.T) {
	enabled, err := buildGate(os.Getenv("SSMH_TEST_BUILD"))
	if err != nil {
		t.Fatal(err)
	}
	if !enabled {
		t.Skip("set SSMH_TEST_BUILD=1 to verify offline release builds")
	}
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	goBinary := filepath.Join(runtime.GOROOT(), "bin", "go")
	if info, err := os.Stat(goBinary); err != nil || !info.Mode().IsRegular() {
		t.Fatal("test toolchain executable is unavailable")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Minute)
	defer cancel()
	var previous [2][sha256.Size]byte
	for copyIndex := 0; copyIndex < 2; copyIndex++ {
		copyRoot := t.TempDir()
		copyBuildInputs(t, root, copyRoot)
		// Quoting is for Make's recipe shell; GO remains one structured make argument.
		quotedGo := "'" + strings.ReplaceAll(goBinary, "'", "'\\''") + "'"
		cmd := exec.CommandContext(ctx, "make", "GO="+quotedGo, "VERSION="+releaseVersion, "release")
		cmd.Dir = copyRoot
		cmd.Env = buildEnvironment(os.Environ())
		ownBuildProcess(cmd)
		// No inherited output or credential-bearing diagnostics are retained.
		if err := cmd.Run(); err != nil {
			t.Fatal("offline Makefile release failed; ensure make and all dependencies are cached")
		}
		if copyIndex == 0 {
			verifyRootBuild(t, ctx, goBinary, copyRoot)
		}
		for archIndex, arch := range []string{"amd64", "arm64"} {
			binary := filepath.Join(copyRoot, "dist", "ssmh-linux-"+arch)
			verifyReleaseBinary(t, binary, arch)
			content, err := os.ReadFile(binary)
			if err != nil {
				t.Fatal("cannot read release artifact")
			}
			if bytes.Contains(content, []byte(copyRoot)) || bytes.Contains(content, []byte(root)) {
				t.Fatal("release artifact contains a source-directory path")
			}
			if !bytes.Contains(content, []byte(releaseVersion)) {
				t.Fatal("release version marker is missing")
			}
			digest := sha256.Sum256(content)
			if copyIndex == 0 {
				previous[archIndex] = digest
			} else if digest != previous[archIndex] {
				t.Fatalf("Linux %s release differs across source directories", arch)
			} else {
				t.Logf("Linux %s identical SHA-256: %x", arch, digest)
			}
			if copyIndex == 0 && arch == runtime.GOARCH {
				probe := exec.CommandContext(ctx, binary, "--version")
				probe.Env = buildEnvironment(os.Environ())
				probe.WaitDelay = time.Second
				output, err := probe.Output()
				want := "ssmh " + releaseVersion + " (" + runtime.Version() + "; linux/" + arch + ")\n"
				if err != nil || string(output) != want {
					t.Fatal("native release version metadata is incorrect")
				}
			}
		}
	}
}

func buildGate(value string) (bool, error) {
	switch value {
	case "":
		return false, nil
	case "1":
		return true, nil
	default:
		return false, fmt.Errorf("SSMH_TEST_BUILD must be absent or exactly 1")
	}
}

func ownBuildProcess(cmd *exec.Cmd) {
	// Cancellation owns only this newly created process group, including
	// recipe shells/compiler children, not the caller's process group.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		err := syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		if errors.Is(err, syscall.ESRCH) {
			return os.ErrProcessDone
		}
		return err
	}
	cmd.WaitDelay = time.Second
}

// Keep only ordinary tool locations/cache configuration, not host credentials,
// workspaces, per-user Go settings, build flags or executable injection hooks.
func buildEnvironment(inherited []string) []string {
	env := make([]string, 0, 16)
	for _, entry := range inherited {
		key, _, _ := strings.Cut(entry, "=")
		switch key {
		case "PATH", "HOME", "TMPDIR", "GOCACHE", "GOMODCACHE", "GOPATH":
			env = append(env, entry)
		}
	}
	return append(env, "GOENV=off", "GOWORK=off", "GOTOOLCHAIN=local", "GOPROXY=off",
		"GOFLAGS=-mod=readonly", "GOAMD64=v1", "GOARM64=v8.0", "AWS_EC2_METADATA_DISABLED=true")
}

func copyBuildInputs(t *testing.T, root, destination string) {
	t.Helper()
	for _, name := range []string{"Makefile", "go.mod", "go.sum", "main.go", "cmd", "internal"} {
		err := filepath.WalkDir(filepath.Join(root, name), func(path string, entry fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if entry.Type()&os.ModeSymlink != 0 {
				return fmt.Errorf("build inputs must not be symbolic links")
			}
			relative, err := filepath.Rel(root, path)
			if err != nil {
				return err
			}
			target := filepath.Join(destination, relative)
			if entry.IsDir() {
				return os.MkdirAll(target, 0700)
			}
			// No tests, Git files, local configuration, artifacts or credentials.
			if relative != "Makefile" && relative != "go.mod" && relative != "go.sum" &&
				(!strings.HasSuffix(relative, ".go") || strings.HasSuffix(relative, "_test.go")) {
				return nil
			}
			info, err := entry.Info()
			if err != nil || !info.Mode().IsRegular() {
				return fmt.Errorf("build input must be a regular file")
			}
			data, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			return os.WriteFile(target, data, 0600)
		})
		if err != nil {
			t.Fatal("cannot prepare isolated build inputs")
		}
	}
}

// Exercise the exact root go-build command, not go build ./cmd/ssmh. The
// temporary root owns the resulting ./ssmh; workspace binaries are untouched.
func verifyRootBuild(t *testing.T, ctx context.Context, goBinary, root string) {
	t.Helper()
	cmd := exec.CommandContext(ctx, goBinary, "build")
	cmd.Dir = root
	cmd.Env = append(buildEnvironment(os.Environ()), "CGO_ENABLED=0")
	ownBuildProcess(cmd)
	if err := cmd.Run(); err != nil {
		t.Fatal("plain go build at the repository root failed")
	}
	rootBinary := filepath.Join(root, "ssmh")
	version := exec.CommandContext(ctx, rootBinary, "--version")
	version.Env = buildEnvironment(os.Environ())
	version.WaitDelay = time.Second
	output, err := version.Output()
	want := "ssmh dev (" + runtime.Version() + "; linux/" + runtime.GOARCH + ")\n"
	if err != nil || string(output) != want {
		t.Fatal("root executable default version is incorrect")
	}
	// Both compiled entry points must expose the same help, not just compile.
	var expected []byte
	for _, binary := range []string{rootBinary, filepath.Join(root, "dist", "ssmh-linux-"+runtime.GOARCH)} {
		probe := exec.CommandContext(ctx, binary, "--help")
		probe.Env = buildEnvironment(os.Environ())
		probe.WaitDelay = time.Second
		output, err := probe.Output()
		if err != nil || len(output) == 0 {
			t.Fatal("compiled executable help failed")
		}
		if expected == nil {
			expected = output
		} else if !bytes.Equal(expected, output) {
			t.Fatal("root and cmd/ssmh executables expose different CLI help")
		}
	}
}

func verifyReleaseBinary(t *testing.T, path, arch string) {
	t.Helper()
	image, err := elf.Open(path)
	if err != nil {
		t.Fatal("release artifact is not ELF")
	}
	machine := elf.EM_X86_64
	if arch == "arm64" {
		machine = elf.EM_AARCH64
	}
	valid := image.Class == elf.ELFCLASS64 && image.Machine == machine
	for _, program := range image.Progs {
		if program.Type == elf.PT_INTERP || program.Type == elf.PT_DYNAMIC {
			valid = false
		}
	}
	for _, section := range image.Sections {
		if section.Type == elf.SHT_SYMTAB || strings.HasPrefix(section.Name, ".debug_") || strings.HasPrefix(section.Name, ".zdebug_") {
			valid = false
		}
	}
	if err := image.Close(); err != nil {
		t.Fatal("cannot close ELF inspection")
	}
	if !valid {
		t.Fatal("release artifact has the wrong architecture, dynamic linking or unstripped debug/symbol sections")
	}
	metadata, err := buildinfo.ReadFile(path)
	if err != nil || metadata.Path != "ssmh/cmd/ssmh" || metadata.GoVersion != runtime.Version() {
		t.Fatal("release build metadata is missing or incorrect")
	}
	settings := make(map[string]string)
	for _, setting := range metadata.Settings {
		if strings.HasPrefix(setting.Key, "vcs") {
			t.Fatal("release artifact embeds VCS metadata")
		}
		settings[setting.Key] = setting.Value
	}
	if settings["CGO_ENABLED"] != "0" || settings["GOOS"] != "linux" ||
		settings["GOARCH"] != arch || settings["-trimpath"] != "true" {
		t.Fatal("release build metadata does not match the static, trimmed contract")
	}
}

func TestBuildGate(t *testing.T) {
	for _, value := range []string{"", "1", "true", "0", "synthetic-secret"} {
		enabled, err := buildGate(value)
		if enabled != (value == "1") || (err != nil) != (value != "" && value != "1") {
			t.Fatal("incorrect build-test gate")
		}
		if err != nil && strings.Contains(err.Error(), value) {
			t.Fatal("invalid opt-in value exposed")
		}
	}
}

func TestBuildEnvironment(t *testing.T) {
	env := buildEnvironment([]string{"PATH=/tools", "HOME=/synthetic-home", "GOCACHE=/cache",
		"AWS_SECRET_ACCESS_KEY=synthetic-secret", "AWS_PROFILE=host-profile", "GOFLAGS=-toolexec=unsafe",
		"GOWORK=/host/workspace", "GOENV=/host/config", "MAKEFLAGS=unsafe", "LD_PRELOAD=unsafe"})
	settings := make(map[string]string)
	for _, entry := range env {
		key, value, _ := strings.Cut(entry, "=")
		settings[key] = value
		if strings.Contains(entry, "synthetic-secret") || strings.Contains(entry, "unsafe") || strings.Contains(entry, "/host/") {
			t.Fatal("host credentials or execution settings reached build environment")
		}
	}
	if settings["PATH"] != "/tools" || settings["GOCACHE"] != "/cache" || settings["GOPROXY"] != "off" ||
		settings["GOFLAGS"] != "-mod=readonly" || settings["GOWORK"] != "off" || settings["GOTOOLCHAIN"] != "local" {
		t.Fatal("offline isolated build environment is incomplete")
	}
}
