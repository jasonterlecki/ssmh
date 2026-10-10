package cli

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"time"

	"go.yaml.in/yaml/v3"
	"ssmh/internal/config"
)

const maxAliasFile = 64 << 10

var aliasName = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_-]{0,63}$`)

func validAliasName(s string) bool { return aliasName.MatchString(s) }

type aliasEntry struct {
	Instance    string `yaml:"instance"`
	Region      string `yaml:"region,omitempty"`
	Profile     string `yaml:"profile,omitempty"`
	RoleARN     string `yaml:"arn,omitempty"`
	ExternalID  string `yaml:"external-id,omitempty"`
	SessionName string `yaml:"session-name,omitempty"`
	MFASerial   string `yaml:"mfa-serial,omitempty"`
	CACert      string `yaml:"ca-cert,omitempty"`
	Document    string `yaml:"document,omitempty"`
	Reason      string `yaml:"reason,omitempty"`
	Backend     string `yaml:"backend,omitempty"`
	Timeout     string `yaml:"timeout,omitempty"`
	Duration    string `yaml:"duration,omitempty"`
}

type aliasFile struct {
	Version int                   `yaml:"version"`
	Aliases map[string]aliasEntry `yaml:"aliases"`
}

func aliasPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return "", errors.New("cannot locate home directory for aliases")
	}
	return filepath.Join(home, ".aws", "alias.yaml"), nil
}

func safeAliasDir(dir string, create bool) error {
	if create {
		if err := os.Mkdir(dir, 0700); err != nil && !os.IsExist(err) {
			return errors.New("cannot create alias directory")
		}
	}
	st, err := os.Lstat(dir)
	if err != nil || !st.IsDir() || st.Mode().Perm()&0022 != 0 {
		return errors.New("alias directory must be a private directory")
	}
	if sys, ok := st.Sys().(*syscall.Stat_t); !ok || sys.Uid != uint32(os.Getuid()) {
		return errors.New("alias directory must be owned by the current user")
	}
	return nil
}

func loadAliases(path string) (aliasFile, error) {
	var result aliasFile
	if err := safeAliasDir(filepath.Dir(path), false); err != nil {
		return result, err
	}
	st, err := os.Lstat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return result, errors.New("alias file not found; run ssmh --aliasinit")
		}
		return result, errors.New("cannot inspect alias file")
	}
	if !st.Mode().IsRegular() || st.Size() > maxAliasFile || st.Mode().Perm()&0077 != 0 {
		return result, errors.New("alias file must be a private regular file of at most 64 KiB")
	}
	if sys, ok := st.Sys().(*syscall.Stat_t); !ok || sys.Uid != uint32(os.Getuid()) {
		return result, errors.New("alias file must be owned by the current user")
	}
	f, err := os.Open(path)
	if err != nil {
		return result, errors.New("cannot open alias file")
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil || !opened.Mode().IsRegular() || !os.SameFile(st, opened) {
		return result, errors.New("alias file changed during open")
	}
	data, err := io.ReadAll(io.LimitReader(f, maxAliasFile+1))
	if err != nil || len(data) > maxAliasFile {
		return result, errors.New("cannot read bounded alias file")
	}
	return decodeAliases(data)
}

func decodeAliases(data []byte) (aliasFile, error) {
	var file aliasFile
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&file); err != nil {
		return aliasFile{}, errors.New("invalid alias YAML: unknown, duplicate, or malformed field")
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		return aliasFile{}, errors.New("alias YAML must contain exactly one document")
	}
	var node yaml.Node
	if err := yaml.Unmarshal(data, &node); err != nil || !plainAliasTree(&node) || !strictAliasShape(&node) {
		return aliasFile{}, errors.New("alias YAML cannot use anchors, aliases, merges, or custom tags")
	}
	if file.Version != 1 || file.Aliases == nil || len(file.Aliases) > 100 {
		return aliasFile{}, errors.New("alias YAML requires version 1 and at most 100 aliases")
	}
	for name, entry := range file.Aliases {
		if !validAliasName(name) || entry.validate() != nil {
			return aliasFile{}, errors.New("alias YAML contains an invalid name or connection setting")
		}
	}
	return file, nil
}

func plainAliasTree(n *yaml.Node) bool {
	if n.Kind == yaml.AliasNode || n.Anchor != "" || n.Tag == "!!merge" || strings.HasPrefix(n.Tag, "!") && !strings.HasPrefix(n.Tag, "!!") {
		return false
	}
	for _, child := range n.Content {
		if !plainAliasTree(child) {
			return false
		}
	}
	return true
}

func strictAliasShape(doc *yaml.Node) bool {
	if doc.Kind != yaml.DocumentNode || len(doc.Content) != 1 {
		return false
	}
	root := doc.Content[0]
	if root.Kind != yaml.MappingNode {
		return false
	}
	for i := 0; i < len(root.Content); i += 2 {
		key, value := root.Content[i], root.Content[i+1]
		if key.Tag != "!!str" {
			return false
		}
		switch key.Value {
		case "version":
			if value.Kind != yaml.ScalarNode || value.Tag != "!!int" {
				return false
			}
		case "aliases":
			if value.Kind != yaml.MappingNode {
				return false
			}
			for j := 0; j < len(value.Content); j += 2 {
				name, entry := value.Content[j], value.Content[j+1]
				if name.Tag != "!!str" || entry.Kind != yaml.MappingNode {
					return false
				}
				for k := 0; k < len(entry.Content); k += 2 {
					field, setting := entry.Content[k], entry.Content[k+1]
					if field.Tag != "!!str" || setting.Kind != yaml.ScalarNode || setting.Tag != "!!str" {
						return false
					}
				}
			}
		}
	}
	return true
}

func (e aliasEntry) validate() error {
	if e.Backend == "plugin" {
		return errors.New("plugin backend is not available")
	}
	o := config.Options{Instance: e.Instance, Region: e.Region, Profile: e.Profile, RoleARN: e.RoleARN, ExternalID: e.ExternalID, SessionName: e.SessionName, MFASerial: e.MFASerial, CACert: e.CACert, Document: e.Document, Reason: e.Reason, Backend: e.Backend, Timeout: 30 * time.Second}
	if o.Backend == "" {
		o.Backend = "auto"
	}
	if e.Timeout != "" {
		var err error
		o.Timeout, err = time.ParseDuration(e.Timeout)
		if err != nil {
			return err
		}
	}
	if e.Duration != "" {
		var err error
		o.Duration, err = time.ParseDuration(e.Duration)
		if err != nil {
			return err
		}
	}
	return o.Validate()
}

func (e aliasEntry) apply(o *config.Options, seen map[string]bool) {
	set := func(names []string, target *string, value string) {
		for _, name := range names {
			if seen[name] {
				return
			}
		}
		if value != "" {
			*target = value
		}
	}
	set([]string{"instance", "i"}, &o.Instance, e.Instance)
	set([]string{"region", "r"}, &o.Region, e.Region)
	set([]string{"profile", "p"}, &o.Profile, e.Profile)
	set([]string{"arn"}, &o.RoleARN, e.RoleARN)
	set([]string{"external-id"}, &o.ExternalID, e.ExternalID)
	set([]string{"session-name"}, &o.SessionName, e.SessionName)
	set([]string{"mfa-serial"}, &o.MFASerial, e.MFASerial)
	set([]string{"ca-cert", "ca"}, &o.CACert, e.CACert)
	set([]string{"document"}, &o.Document, e.Document)
	set([]string{"reason"}, &o.Reason, e.Reason)
	set([]string{"backend"}, &o.Backend, e.Backend)
	if !seen["timeout"] && e.Timeout != "" {
		o.Timeout, _ = time.ParseDuration(e.Timeout)
	}
	if !seen["duration"] && e.Duration != "" {
		o.Duration, _ = time.ParseDuration(e.Duration)
	}
}

func initAlias(name string, input io.Reader, output io.Writer) error {
	path, err := aliasPath()
	if err != nil {
		return err
	}
	if err := safeAliasDir(filepath.Dir(path), true); err != nil {
		return err
	}
	file := aliasFile{Version: 1, Aliases: map[string]aliasEntry{}}
	if _, err := os.Lstat(path); err == nil {
		file, err = loadAliases(path)
		if err != nil {
			return err
		}
	} else if !os.IsNotExist(err) {
		return errors.New("cannot inspect alias file")
	}
	scan := bufio.NewScanner(input)
	scan.Buffer(make([]byte, 4096), 4096)
	ask := func(label, current string) (string, error) {
		if _, err := fmt.Fprintf(output, "%s", label); err != nil {
			return "", errors.New("cannot write alias prompt")
		}
		if !scan.Scan() {
			return "", errors.New("alias questionnaire ended before completion")
		}
		value := strings.TrimSpace(scan.Text())
		if value == "" {
			value = current
		} else if value == "-" {
			value = ""
		}
		return value, nil
	}
	if name == "" {
		name, err = ask("Alias name: ", "")
		if err != nil {
			return err
		}
	}
	if !validAliasName(name) {
		return errors.New("invalid alias name")
	}
	entry, exists := file.Aliases[name]
	if exists {
		answer, err := ask("Alias exists. Overwrite? [y/N]: ", "")
		if err != nil {
			return err
		}
		if answer != "y" && answer != "yes" {
			return errors.New("alias overwrite declined")
		}
		if _, err := fmt.Fprintln(output, "Leave a field blank to keep its value; enter - to clear it."); err != nil {
			return errors.New("cannot write alias prompt")
		}
	}
	fields := []struct {
		label string
		p     *string
	}{
		{"Instance ID or exact Name (required): ", &entry.Instance},
		{"AWS region (blank uses SDK region): ", &entry.Region},
		{"AWS profile (optional): ", &entry.Profile},
		{"Role ARN (optional): ", &entry.RoleARN},
		{"STS external ID (optional; stored privately): ", &entry.ExternalID},
		{"STS session name (optional): ", &entry.SessionName},
		{"MFA device ARN (optional): ", &entry.MFASerial},
		{"CA bundle path (optional): ", &entry.CACert},
		{"SSM shell document (optional): ", &entry.Document},
		{"Session reason (optional): ", &entry.Reason},
		{"Backend: auto or native (blank auto): ", &entry.Backend},
		{"Connection timeout (blank 30s): ", &entry.Timeout},
		{"Maximum session duration (optional): ", &entry.Duration},
	}
	for _, field := range fields {
		value, err := ask(field.label, *field.p)
		if err != nil {
			return err
		}
		*field.p = value
	}
	if err := entry.validate(); err != nil {
		return errors.New("invalid alias connection settings: " + err.Error())
	}
	file.Aliases[name] = entry
	if len(file.Aliases) > 100 {
		return errors.New("alias file supports at most 100 aliases")
	}
	data, err := yaml.Marshal(file)
	if err != nil || len(data) > maxAliasFile {
		return errors.New("alias file exceeds limit")
	}
	return saveAliases(path, data)
}

func saveAliases(path string, data []byte) error {
	dir := filepath.Dir(path)
	f, err := os.CreateTemp(dir, ".alias-*")
	if err != nil {
		return errors.New("cannot create private alias file")
	}
	defer os.Remove(f.Name())
	if err := f.Chmod(0600); err != nil {
		f.Close()
		return errors.New("cannot protect alias file")
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return errors.New("cannot write alias file")
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return errors.New("cannot sync alias file")
	}
	if err := f.Close(); err != nil {
		return errors.New("cannot close alias file")
	}
	if err := os.Rename(f.Name(), path); err != nil {
		return errors.New("cannot save alias file")
	}
	return nil
}
