package plugin

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// The test executable doubles as a synthetic installed plugin. No shell or real
// plugin is run. A private cwd fixture selects behavior without inheriting env.
func TestMain(m *testing.M) {
	if len(os.Args) == 3 && os.Args[1] == "--verify-child-environment" {
		verifyChildEnvironment(os.Args[2])
		os.Exit(0)
	}
	if len(os.Args) == 2 && os.Args[1] == responseVariable {
		verifyChildHandoff()
		os.Exit(0)
	}
	if len(os.Args) == 2 && os.Args[1] == "--version" {
		mode, err := os.ReadFile("probe-mode")
		if err != nil {
			os.Exit(90)
		}
		switch string(mode) {
		case "success":
			if len(os.Environ()) != 2 || os.Getenv("LANG") != "C" || os.Getenv("LC_ALL") != "C" {
				os.Exit(91)
			}
			// The probe must not consume the invoking application's stdin.
			input, err := io.ReadAll(os.Stdin)
			if err != nil || len(input) != 0 {
				os.Exit(92)
			}
			fmt.Print("1.2.835.0\n")
		case "minimum":
			fmt.Print("1.2.764.0\r\n")
		case "old":
			fmt.Print("1.2.763.65535\n")
		case "malformed":
			fmt.Print("SYNTHETIC-SECRET\x1b[31m\n")
		case "overflow":
			fmt.Print("1.2.835.0\n" + strings.Repeat("SYNTHETIC-SECRET", 1000))
		case "failure":
			fmt.Fprint(os.Stderr, "SYNTHETIC-SECRET")
			fmt.Print("SYNTHETIC-SECRET")
			os.Exit(9)
		case "hang":
			time.Sleep(time.Minute)
		default:
			os.Exit(93)
		}
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func helperInstallation(t *testing.T, mode string) string {
	t.Helper()
	directory := t.TempDir()
	t.Chdir(directory)
	if err := os.WriteFile(filepath.Join(directory, "probe-mode"), []byte(mode), 0600); err != nil {
		t.Fatal(err)
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "session-manager-plugin")
	if err := os.Symlink(executable, path); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", directory)
	return path
}

func TestInspectRealSubprocess(t *testing.T) {
	for _, test := range []struct {
		mode, version string
	}{
		{"success", "1.2.835.0"},
		{"minimum", "1.2.764.0"},
		{"old", ""}, {"malformed", ""}, {"overflow", ""}, {"failure", ""},
	} {
		t.Run(test.mode, func(t *testing.T) {
			path := helperInstallation(t, test.mode)
			t.Setenv("AWS_SECRET_ACCESS_KEY", "SYNTHETIC-SECRET")
			t.Setenv("AWS_SESSION_TOKEN", "SYNTHETIC-SECRET")
			t.Setenv("AWS_SSM_START_SESSION_RESPONSE", "SYNTHETIC-SECRET")
			plugin, err := Inspect(context.Background())
			if test.version == "" {
				if err == nil || plugin != nil || strings.Contains(err.Error(), "SYNTHETIC-SECRET") || strings.Contains(err.Error(), path) {
					t.Fatal("failed probe exposed output/path or returned an executable")
				}
				return
			}
			if err != nil || plugin == nil || plugin.Version() != test.version || plugin.path != path {
				t.Fatalf("probe did not return expected validated version: %v", err)
			}
			if strings.Contains(fmt.Sprintf("%v %#v", plugin, plugin), path) {
				t.Fatal("formatted plugin exposed installation path")
			}
		})
	}
}

func TestInspectMissingAndRelativePath(t *testing.T) {
	t.Run("missing", func(t *testing.T) {
		t.Setenv("PATH", t.TempDir())
		plugin, err := Inspect(context.Background())
		if plugin != nil || err == nil || !strings.Contains(err.Error(), "install") {
			t.Fatal("missing plugin did not provide installation guidance")
		}
	})
	t.Run("relative", func(t *testing.T) {
		helperInstallation(t, "success")
		t.Setenv("PATH", ".")
		if plugin, err := Inspect(context.Background()); err == nil || plugin != nil {
			t.Fatal("implicit current directory executable accepted")
		}
	})
	t.Run("relative entry", func(t *testing.T) {
		helperInstallation(t, "success")
		if err := os.Mkdir("nested", 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink("../session-manager-plugin", "nested/session-manager-plugin"); err != nil {
			t.Fatal(err)
		}
		t.Setenv("PATH", "nested")
		if plugin, err := Inspect(context.Background()); err == nil || plugin != nil {
			t.Fatal("relative PATH executable accepted")
		}
	})
}

func TestInspectCancellation(t *testing.T) {
	t.Run("before lookup", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		plugin, err := Inspect(ctx)
		if plugin != nil || !errors.Is(err, context.Canceled) {
			t.Fatal("initial cancellation lost")
		}
	})
	t.Run("caller deadline", func(t *testing.T) {
		helperInstallation(t, "hang")
		ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
		defer cancel()
		started := time.Now()
		plugin, err := Inspect(ctx)
		if plugin != nil || !errors.Is(err, context.DeadlineExceeded) || time.Since(started) > time.Second {
			t.Fatal("version probe ignored caller deadline")
		}
	})
	t.Run("probe deadline", func(t *testing.T) {
		helperInstallation(t, "hang")
		started := time.Now()
		plugin, err := Inspect(context.Background())
		if plugin != nil || !errors.Is(err, context.DeadlineExceeded) || time.Since(started) > probeTimeout+time.Second {
			t.Fatal("version probe was not independently bounded")
		}
	})
}

func TestVersionParsing(t *testing.T) {
	for _, test := range []struct {
		input            string
		valid, supported bool
	}{
		{"1.2.764.0", true, true}, {"1.2.835.0\n", true, true}, {"1.2.764.0\r\n", true, true},
		{"1.2.763.65535", true, false}, {"1.1.65535.65535", true, false}, {"1.3.0.0", true, true},
		{"2.0.0.0", true, true}, {"1.2.764.1", true, true},
		{"", false, false}, {"1.2.764", false, false}, {"1.2.764.0.0", false, false},
		{"1.2.764.0\n\n", false, false}, {"1.2.764.0\r", false, false},
		{" 1.2.764.0", false, false}, {"01.2.764.0", false, false}, {"+1.2.764.0", false, false},
		{"1.2.65536.0", false, false}, {"1.2.764.0\x00", false, false}, {"１.2.764.0", false, false},
	} {
		t.Run(test.input, func(t *testing.T) {
			version, ok := parseVersion(test.input)
			if ok != test.valid || ok && supportedVersion(version) != test.supported {
				t.Fatal("unexpected version acceptance")
			}
		})
	}
	if (*Executable)(nil).Version() != "" {
		t.Fatal("nil executable reports a version")
	}
}

func TestVersionOutputBound(t *testing.T) {
	var output versionOutput
	if n, err := output.Write([]byte(strings.Repeat("x", 63))); n != 63 || err != nil || output.overflow {
		t.Fatal("output rejected before bound")
	}
	if n, err := output.Write([]byte("yz")); n != 2 || err != nil || !output.overflow || output.used != 64 {
		t.Fatal("output overflow was not retained safely")
	}
	if n, err := output.Write([]byte("more")); n != 4 || err != nil || output.used != 64 {
		t.Fatal("overflow grew output storage")
	}
}

func TestExecutableModes(t *testing.T) {
	for _, test := range []struct {
		mode  os.FileMode
		valid bool
	}{
		{0755, true}, {0500, true}, {0644, false}, {0775, false}, {0757, false},
		{0755 | os.ModeSetuid, false}, {0755 | os.ModeSetgid, false},
		{0755 | os.ModeDir, false}, {0755 | os.ModeNamedPipe, false},
	} {
		if safeExecutableMode(test.mode) != test.valid {
			t.Fatalf("unexpected executable mode acceptance: %v", test.mode)
		}
	}
}

func FuzzVersion(f *testing.F) {
	for _, seed := range []string{"1.2.764.0", "1.2.835.0\n", "1.2.763.65535", "", "1.2.764.0\x00"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, input string) {
		version, ok := parseVersion(input)
		if !ok {
			return
		}
		executable := &Executable{version: version}
		parsed, valid := parseVersion(executable.Version())
		if !valid || parsed != version {
			t.Fatal("accepted version does not round-trip canonically")
		}
	})
}
