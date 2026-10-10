// Package cli parses GNU-style options without printing argument values.
package cli

import (
	"errors"
	"flag"
	"io"
	"strings"
	"time"

	"ssmh/internal/config"
)

type tags []string

func (t *tags) String() string     { return "" }
func (t *tags) Set(s string) error { *t = append(*t, s); return nil }

// Flags constructs the supported flags. It writes help only to the supplied writer.
func Flags(o *config.Options, out io.Writer) *flag.FlagSet {
	f := flag.NewFlagSet("ssmh", flag.ContinueOnError)
	f.SetOutput(out)
	for _, v := range []struct {
		p           *string
		names       []string
		value, help string
	}{
		{&o.Instance, []string{"instance", "i"}, "", "EC2 instance ID or exact Name tag"},
		{&o.Alias, []string{"alias", "a"}, "", "load a named connection from ~/.aws/alias.yaml"},
		{&o.AliasInitName, []string{"aliasinit"}, "", "interactively create or update an alias (optional name)"},
		{&o.Profile, []string{"profile", "p"}, "", "AWS shared profile"},
		{&o.Region, []string{"region", "r"}, "", "AWS region (no implicit default)"},
		{&o.CACert, []string{"ca-cert", "ca"}, "", "PEM CA bundle path (overrides AWS_CA_BUNDLE and profile ca_bundle)"},
		{&o.RoleARN, []string{"arn"}, "", "IAM role ARN to assume"},
		{&o.SessionName, []string{"session-name"}, "", "STS role session name"},
		{&o.ExternalID, []string{"external-id"}, "", "STS external ID"},
		{&o.MFASerial, []string{"mfa-serial"}, "", "MFA device ARN"},
		{&o.MFAToken, []string{"mfa-token"}, "", "MFA code (prefer an interactive prompt)"},
		{&o.Command, []string{"command", "c"}, "", "remote shell command"},
		{&o.Document, []string{"document"}, "", "SSM session document"},
		{&o.Reason, []string{"reason"}, "", "session reason"},
		{&o.Backend, []string{"backend"}, "auto", "native, plugin, or auto"},
		{&o.Forward, []string{"forward", "L"}, "", "LOCAL_PORT:REMOTE_PORT"},
		{&o.ForwardHost, []string{"forward-host"}, "", "LOCAL_PORT:REMOTE_HOST:REMOTE_PORT"},
		{&o.Name, []string{"name"}, "", "Name tag filter for --list"},
		{&o.State, []string{"state"}, "", "EC2 state filter for --list"},
	} {
		for _, n := range v.names {
			f.StringVar(v.p, n, v.value, v.help)
		}
	}
	for _, v := range []struct {
		p     *bool
		names []string
		help  string
	}{
		{&o.List, []string{"list"}, "list SSM-managed instances"}, {&o.Check, []string{"check"}, "check readiness without starting a session"},
		{&o.JSON, []string{"json"}, "machine-readable discovery/check output"}, {&o.Verbose, []string{"verbose", "v"}, "verbose diagnostics on stderr"},
		{&o.Debug, []string{"debug"}, "allowlisted debug diagnostics on stderr"}, {&o.Quiet, []string{"quiet", "q"}, "suppress informational diagnostics"},
		{&o.Help, []string{"help", "h"}, "display help"}, {&o.Version, []string{"version"}, "display version"},
	} {
		for _, n := range v.names {
			f.BoolVar(v.p, n, false, v.help)
		}
	}
	f.DurationVar(&o.Timeout, "timeout", 30*time.Second, "connection establishment timeout")
	f.DurationVar(&o.Duration, "duration", 0, "maximum local session duration (0: unlimited)")
	f.Var((*tags)(&o.Tags), "tag", "KEY=VALUE filter for --list (repeatable)")
	return f
}

// Parse rejects positional arguments and redacts parser errors, including MFA values.
func Parse(args []string) (config.Options, error) {
	var o config.Options
	f := Flags(&o, io.Discard)
	for _, a := range args {
		if len(a) > 65536 {
			return o, errors.New("command-line argument exceeds 65536 bytes")
		}
	}
	if len(args) > 256 {
		return o, errors.New("too many command-line arguments")
	}
	normalized, err := normalize(args, f)
	if err != nil {
		return config.Options{}, err
	}
	if err := f.Parse(normalized); err != nil {
		return config.Options{}, errors.New("invalid command-line options; run ssmh --help")
	}
	if f.NArg() != 0 {
		return config.Options{}, errors.New("unexpected positional arguments; use named options")
	}
	f.Visit(func(v *flag.Flag) {
		if v.Name == "aliasinit" {
			o.AliasInit = true
		}
	})
	if o.AliasInit {
		count := 0
		f.Visit(func(v *flag.Flag) { count++ })
		formOK := len(args) == 1 && (args[0] == "--aliasinit" || strings.HasPrefix(args[0], "--aliasinit=")) ||
			len(args) == 2 && args[0] == "--aliasinit" && !strings.HasPrefix(args[1], "-")
		if count != 1 || !formOK {
			return config.Options{}, errors.New("--aliasinit must be used alone with an optional alias name")
		}
		if o.AliasInitName != "" && !validAliasName(o.AliasInitName) {
			return config.Options{}, errors.New("invalid alias name")
		}
		return o, nil
	}
	// An explicit empty command must not silently select an interactive shell.
	for _, a := range args {
		if a == "--command=" || a == "-c=" {
			return o, errors.New("--command must not be empty")
		}
	}
	f.Visit(func(v *flag.Flag) {
		if (v.Name == "ca-cert" || v.Name == "ca") && o.CACert == "" {
			o.CACert = "\x00"
		}
		if (v.Name == "command" || v.Name == "c") && strings.TrimSpace(o.Command) == "" {
			o.Command = "\x00"
		}
	})
	if o.Alias != "" && !o.Help && !o.Version {
		if !validAliasName(o.Alias) {
			return config.Options{}, errors.New("invalid alias name")
		}
		path, err := aliasPath()
		if err != nil {
			return config.Options{}, err
		}
		file, err := loadAliases(path)
		if err != nil {
			return config.Options{}, err
		}
		entry, ok := file.Aliases[o.Alias]
		if !ok {
			return config.Options{}, errors.New("alias not found")
		}
		seen := map[string]bool{}
		f.Visit(func(v *flag.Flag) { seen[v.Name] = true })
		entry.apply(&o, seen)
	}
	return o, o.Validate()
}

// normalize supports grouped boolean short flags and attached short values while
// preserving argument text, including commands whose first character is a dash.
func normalize(args []string, f *flag.FlagSet) ([]string, error) {
	var result []string
	valueNext := false
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if valueNext {
			result = append(result, arg)
			valueNext = false
			continue
		}
		if arg == "--" {
			result = append(result, arg)
			continue
		}
		if arg == "--aliasinit" {
			if i+1 < len(args) && !strings.HasPrefix(args[i+1], "-") {
				result = append(result, "--aliasinit="+args[i+1])
				i++
			} else {
				result = append(result, "--aliasinit=")
			}
			continue
		}
		if !strings.HasPrefix(arg, "-") || arg == "-" {
			result = append(result, arg)
			continue
		}
		name, _, hasValue := strings.Cut(strings.TrimLeft(arg, "-"), "=")
		if option := f.Lookup(name); option != nil {
			result = append(result, arg)
			valueNext = !hasValue && !boolean(option)
			continue
		}
		if strings.HasPrefix(arg, "--") {
			return nil, errors.New("unknown command-line option; run ssmh --help")
		}
		for i := 1; i < len(arg); i++ {
			if len(result) >= 1024 {
				return nil, errors.New("too many expanded short options")
			}
			name := arg[i : i+1]
			option := f.Lookup(name)
			if option == nil {
				return nil, errors.New("unknown command-line option; run ssmh --help")
			}
			if boolean(option) {
				result = append(result, "-"+name)
				continue
			}
			if i+1 < len(arg) {
				result = append(result, "-"+name+"="+strings.TrimPrefix(arg[i+1:], "="))
			} else {
				result = append(result, "-"+name)
				valueNext = true
			}
			break
		}
	}
	return result, nil
}

func boolean(option *flag.Flag) bool {
	v, ok := option.Value.(interface{ IsBoolFlag() bool })
	return ok && v.IsBoolFlag()
}
