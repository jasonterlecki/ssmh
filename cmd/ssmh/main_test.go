package main

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestExecutableHelpAndErrors(t *testing.T) {
	for _, tc := range []struct {
		args   []string
		code   int
		output bool
	}{
		{[]string{"--help"}, 0, true},
		{[]string{"--version"}, 0, true},
		{[]string{"--mfa-token=synthetic-private-code"}, 2, false},
		{[]string{"--list", "--tag", "Env=a", "--tag", "Env=b"}, 2, false},
	} {
		args := append([]string{"-test.run=^TestExecuteHelper$", "--"}, tc.args...)
		cmd := exec.Command(os.Args[0], args...)
		cmd.Env = offlineExecuteEnv(t)
		var stdout, stderr bytes.Buffer
		cmd.Stdout = &stdout
		cmd.Stderr = &stderr
		err := cmd.Run()
		code := 0
		if err != nil {
			if exit, ok := err.(*exec.ExitError); ok {
				code = exit.ExitCode()
			} else {
				t.Fatal(err)
			}
		}
		if code != tc.code || (stdout.Len() > 0) != tc.output {
			t.Fatalf("incorrect exit or stdout: %d %q", code, stdout.String())
		}
		if tc.code == 0 && stderr.Len() != 0 || tc.code != 0 && stderr.Len() == 0 {
			t.Fatal("diagnostic stream separation failed")
		}
		if strings.Contains(stdout.String()+stderr.String(), "synthetic-private-code") {
			t.Fatal("argument secret exposed")
		}
	}
}

// Child CLI tests must never inherit real provider configuration or credentials.
// Invalid/help invocations should not authenticate; isolation also prevents a
// routing regression from finding host profiles, container providers or IMDS.
func offlineExecuteEnv(t *testing.T) []string {
	t.Helper()
	env := make([]string, 0)
	for _, entry := range os.Environ() {
		key, _, _ := strings.Cut(entry, "=")
		upper := strings.ToUpper(key)
		if strings.HasPrefix(upper, "AWS_") || upper == "SSMH_EXECUTE_TEST" {
			continue
		}
		env = append(env, entry)
	}
	dir := t.TempDir()
	return append(env, "SSMH_EXECUTE_TEST=1", "AWS_EC2_METADATA_DISABLED=true", "AWS_CONFIG_FILE="+filepath.Join(dir, "missing-config"), "AWS_SHARED_CREDENTIALS_FILE="+filepath.Join(dir, "missing-credentials"))
}

func TestExecutableEnvironmentExcludesHostAWSProviders(t *testing.T) {
	for _, key := range []string{"AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN", "AWS_PROFILE", "AWS_REGION", "AWS_CONTAINER_CREDENTIALS_FULL_URI", "AWS_ENDPOINT_URL", "aws_custom_provider"} {
		t.Setenv(key, "synthetic-private-value")
	}
	seen := make(map[string]string)
	for _, entry := range offlineExecuteEnv(t) {
		key, value, _ := strings.Cut(entry, "=")
		if strings.HasPrefix(strings.ToUpper(key), "AWS_") {
			switch key {
			case "AWS_EC2_METADATA_DISABLED", "AWS_CONFIG_FILE", "AWS_SHARED_CREDENTIALS_FILE":
			default:
				t.Fatal("host AWS provider configuration reached child")
			}
			seen[key] = value
		}
	}
	if len(seen) != 3 || seen["AWS_EC2_METADATA_DISABLED"] != "true" || !filepath.IsAbs(seen["AWS_CONFIG_FILE"]) || !filepath.IsAbs(seen["AWS_SHARED_CREDENTIALS_FILE"]) {
		t.Fatal("offline provider isolation missing")
	}
}

func TestExecuteHelper(t *testing.T) {
	if os.Getenv("SSMH_EXECUTE_TEST") != "1" {
		return
	}
	for i, arg := range os.Args {
		if arg == "--" {
			os.Args = append([]string{"ssmh"}, os.Args[i+1:]...)
			os.Exit(execute())
		}
	}
	t.Fatal("missing helper invocation")
}

func TestBrokenHelpPipeReturnsControlledError(t *testing.T) {
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := reader.Close(); err != nil {
		t.Fatal(err)
	}
	defer writer.Close()
	cmd := exec.Command(os.Args[0], "-test.run=^TestExecuteHelper$", "--", "--help")
	cmd.Env = offlineExecuteEnv(t)
	cmd.Stdout = writer
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	err = cmd.Run()
	exit, ok := err.(*exec.ExitError)
	if !ok || exit.ExitCode() != 1 || !strings.Contains(stderr.String(), "cannot write CLI help") {
		t.Fatalf("broken pipe bypassed error handling: %v", err)
	}
}
