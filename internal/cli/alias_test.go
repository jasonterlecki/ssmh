package cli

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

func aliasTestHome(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	if err := os.Mkdir(filepath.Join(home, ".aws"), 0700); err != nil {
		t.Fatal(err)
	}
	return filepath.Join(home, ".aws", "alias.yaml")
}

func writeAliasTest(t *testing.T, path, contents string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(contents), 0600); err != nil {
		t.Fatal(err)
	}
}

func TestAliasParsingAndOverrides(t *testing.T) {
	path := aliasTestHome(t)
	writeAliasTest(t, path, "version: 1\naliases:\n  prod:\n    instance: i-0123456789abcdef0\n    region: ca-central-1\n    profile: production\n    arn: arn:aws:iam::123456789012:role/Example\n    timeout: 45s\n")
	for _, flag := range []string{"--alias", "-a"} {
		o, err := Parse([]string{flag, "prod", "--profile", "override", "-r", "us-east-1"})
		if err != nil || o.Instance != "i-0123456789abcdef0" || o.Profile != "override" || o.Region != "us-east-1" || o.RoleARN == "" || o.Timeout.Seconds() != 45 {
			t.Fatalf("alias application: %+v, %v", o, err)
		}
	}
	if _, err := Parse([]string{"--alias", "missing"}); err == nil {
		t.Fatal("missing alias accepted")
	}
	if _, err := Parse([]string{"--alias", "../bad"}); err == nil {
		t.Fatal("unsafe name accepted")
	}
}

func TestAliasExampleIsValid(t *testing.T) {
	data, err := os.ReadFile("../../alias.example.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := decodeAliases(data); err != nil {
		t.Fatal(err)
	}
}

func TestAliasStrictYAMLAndPrivateFile(t *testing.T) {
	path := aliasTestHome(t)
	for _, text := range []string{
		"version: 1\nversion: 1\naliases: {}\n",
		"version: 1\naliases:\n  x:\n    instance: i-0123456789abcdef0\n    unknown: value\n",
		"version: 1\naliases: {}\n---\nversion: 1\naliases: {}\n",
		"version: 1\naliases:\n  x: &x\n    instance: i-0123456789abcdef0\n  y: *x\n",
		"version: 1\naliases:\n  x:\n    instance: i-0123456789abcdef0\n    instance: i-0123456789abcdef0\n",
		"version: 1\naliases:\n  x:\n    instance: i-123\n",
		"version: 1\naliases:\n  x:\n    instance: i-0123456789abcdef0\n    profile: true\n",
		"version: 1\naliases:\n  x:\n    instance: i-0123456789abcdef0\n    profile: null\n",
		"version: 1\naliases:\n  x:\n    instance: i-0123456789abcdef0\n    backend: plugin\n",
	} {
		writeAliasTest(t, path, text)
		if _, err := Parse([]string{"--alias", "x"}); err == nil {
			t.Fatal("unsafe YAML accepted")
		}
	}
	writeAliasTest(t, path, "version: 1\naliases:\n  x:\n    instance: i-0123456789abcdef0\n")
	if err := os.Chmod(path, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := Parse([]string{"--alias", "x"}); err == nil {
		t.Fatal("public alias file accepted")
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(t.TempDir(), "target"), path); err != nil {
		t.Fatal(err)
	}
	if _, err := Parse([]string{"--alias", "x"}); err == nil {
		t.Fatal("symlink alias file accepted")
	}
}

func TestAliasInitCreateAndOverwrite(t *testing.T) {
	path := aliasTestHome(t)
	var output bytes.Buffer
	answers := "i-0123456789abcdef0\nca-central-1\nproduction\n" + strings.Repeat("\n", 10)
	if err := initAlias("prod", strings.NewReader(answers), &output); err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(path)
	if err != nil || st.Mode().Perm() != 0600 {
		t.Fatal("alias file missing or not private")
	}
	file, err := loadAliases(path)
	if err != nil || file.Aliases["prod"].Profile != "production" {
		t.Fatalf("saved alias: %v", err)
	}
	before, _ := os.ReadFile(path)
	if err := initAlias("prod", strings.NewReader("n\n"), &output); err == nil {
		t.Fatal("overwrite refusal ignored")
	}
	after, _ := os.ReadFile(path)
	if !bytes.Equal(before, after) {
		t.Fatal("refused overwrite changed file")
	}
	if err := initAlias("prod", strings.NewReader("yes\n"+strings.Repeat("\n", 13)), &output); err != nil {
		t.Fatal(err)
	}
	if err := initAlias("", strings.NewReader("second\ni-0123456789abcdef0\nca-central-1\n"+strings.Repeat("\n", 11)), &output); err != nil {
		t.Fatal(err)
	}
	if err := initAlias("prod", strings.NewReader("yes\n\n\n-\n"+strings.Repeat("\n", 10)), &output); err != nil {
		t.Fatal(err)
	}
	file, err = loadAliases(path)
	if err != nil || file.Aliases["prod"].Instance != "i-0123456789abcdef0" || file.Aliases["prod"].Profile != "" || file.Aliases["second"].Instance != "i-0123456789abcdef0" {
		t.Fatal("existing alias lost")
	}
	if _, err := Parse([]string{"--aliasinit", "prod"}); err != nil {
		t.Fatal(err)
	}
	if _, err := Parse([]string{"--aliasinit"}); err != nil {
		t.Fatal(err)
	}
	if _, err := Parse([]string{"--aliasinit", "prod", "--region", "us-east-1"}); err == nil {
		t.Fatal("mixed init invocation accepted")
	}
	if _, err := Parse([]string{"--aliasinit", "--aliasinit"}); err == nil {
		t.Fatal("duplicate init accepted")
	}
}

func TestAliasInitRunUsesOnlyLocalFiles(t *testing.T) {
	path := aliasTestHome(t)
	in, out, stderr := cliFiles(t)
	_, _ = in.WriteString("i-0123456789abcdef0\nca-central-1\n" + strings.Repeat("\n", 11))
	_, _ = in.Seek(0, 0)
	d := dependencies{}
	if err := run(context.Background(), []string{"--aliasinit", "unit"}, in, out, stderr, d); err != nil {
		t.Fatal(err)
	}
	if cliText(t, out) != "" {
		t.Fatal("alias questionnaire polluted stdout")
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatal(err)
	}
	if _, err := Parse([]string{"-a", "unit"}); err != nil {
		t.Fatal(err)
	}
}

func TestAliasInitRejectsOverLimitWithoutChangingFile(t *testing.T) {
	path := aliasTestHome(t)
	file := aliasFile{Version: 1, Aliases: map[string]aliasEntry{}}
	for i := 0; i < 100; i++ {
		file.Aliases[fmt.Sprintf("alias%d", i)] = aliasEntry{Instance: "i-0123456789abcdef0"}
	}
	data, err := yaml.Marshal(file)
	if err != nil {
		t.Fatal(err)
	}
	writeAliasTest(t, path, string(data))
	answers := "i-0123456789abcdef0\n" + strings.Repeat("\n", 12)
	if err := initAlias("newalias", strings.NewReader(answers), &bytes.Buffer{}); err == nil {
		t.Fatal("101st alias accepted")
	}
	after, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(after, data) {
		t.Fatal("over-limit write changed file")
	}
}
