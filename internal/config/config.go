// Package config holds and validates invocation options. It never persists them.
package config

import (
	"errors"
	"net"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

// Options describes one invocation. MFA tokens must never be serialized or logged.
type Options struct {
	Instance, Profile, Region, RoleARN, SessionName, ExternalID string
	MFASerial, MFAToken                                         string
	Command, Document, Reason, Backend                          string
	Forward, ForwardHost                                        string
	Name, State                                                 string
	Tags                                                        []string
	Timeout, Duration                                           time.Duration
	List, Check, JSON, Verbose, Debug, Quiet, Help, Version     bool
}

var (
	instanceID  = regexp.MustCompile(`^i-(?:[0-9a-f]{8}|[0-9a-f]{17})$`)
	region      = regexp.MustCompile(`^[a-z]{2}(?:-[a-z0-9]+)+-[0-9]+$`)
	roleARN     = regexp.MustCompile(`^arn:aws(?:-[a-z0-9-]+)?:iam::[0-9]{12}:role/[A-Za-z0-9_+=,.@/-]+$`)
	mfaARN      = regexp.MustCompile(`^arn:aws(?:-[a-z0-9-]+)?:iam::[0-9]{12}:mfa/[A-Za-z0-9_+=,.@/-]+$`)
	sessionName = regexp.MustCompile(`^[A-Za-z0-9_+=,.@-]{2,64}$`)
	externalID  = regexp.MustCompile(`^[A-Za-z0-9_+=,.@:/-]+$`)
	document    = regexp.MustCompile(`^(?:[A-Za-z0-9_.-]{3,128}|arn:aws(?:-[a-z0-9-]+)?:ssm:[a-z0-9-]+:[0-9]{12}:document/[A-Za-z0-9_.-]{3,128})$`)
	mfaToken    = regexp.MustCompile(`^[0-9]{6}$`)
	dnsLabel    = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$`)
)

// InstanceID reports whether value is a supported EC2 instance identifier.
func InstanceID(value string) bool { return instanceID.MatchString(value) }

// Region validates an explicit or SDK-resolved region without selecting a default.
func Region(value string) error {
	if !region.MatchString(value) || len(value) > 64 {
		return errors.New("missing or invalid AWS region; use --region or configure the AWS SDK region")
	}
	return nil
}

// Text rejects terminal controls and invalid Unicode in metadata and options.
func Text(value string, max int) bool {
	if len(value) > max || !utf8.ValidString(value) {
		return false
	}
	for _, r := range value {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}

// Validate checks all options before any AWS operation.
func (o Options) Validate() error {
	if o.Help || o.Version {
		return nil
	}
	if o.Timeout <= 0 || o.Timeout > 10*time.Minute {
		return errors.New("--timeout must be greater than zero and at most 10m")
	}
	if o.Duration < 0 {
		return errors.New("--duration must not be negative")
	}
	if o.Backend != "auto" && o.Backend != "native" && o.Backend != "plugin" {
		return errors.New("--backend must be auto, native, or plugin")
	}
	if o.List && o.Check {
		return errors.New("--list and --check cannot be combined")
	}
	if !o.List && o.Instance == "" {
		return errors.New("missing required instance; use --instance INSTANCE_ID or an exact Name tag")
	}
	if !Text(o.Instance, 256) || strings.HasPrefix(o.Instance, "i-") && !InstanceID(o.Instance) {
		return errors.New("invalid instance ID or Name tag")
	}
	if o.Region != "" {
		if err := Region(o.Region); err != nil {
			return err
		}
	}
	if !Text(o.Profile, 256) {
		return errors.New("invalid AWS profile name")
	}
	if o.RoleARN != "" && (len(o.RoleARN) > 2048 || !roleARN.MatchString(o.RoleARN) || strings.Contains(o.RoleARN, "//")) {
		return errors.New("invalid IAM role ARN")
	}
	if o.RoleARN == "" && (o.SessionName != "" || o.ExternalID != "" || o.MFASerial != "" || o.MFAToken != "") {
		return errors.New("role options require --arn")
	}
	if o.SessionName != "" && !sessionName.MatchString(o.SessionName) {
		return errors.New("invalid STS session name; expected 2–64 IAM session-name characters")
	}
	if o.ExternalID != "" && (len(o.ExternalID) < 2 || len(o.ExternalID) > 1224 || !externalID.MatchString(o.ExternalID)) {
		return errors.New("invalid STS external ID")
	}
	if o.MFASerial != "" && (!mfaARN.MatchString(o.MFASerial) || len(o.MFASerial) > 2048) {
		return errors.New("invalid MFA device ARN")
	}
	if o.MFAToken != "" && (o.MFASerial == "" || !mfaToken.MatchString(o.MFAToken)) {
		return errors.New("--mfa-token requires --mfa-serial and exactly six digits")
	}
	if o.Document != "" && !document.MatchString(o.Document) {
		return errors.New("invalid SSM document name or ARN")
	}
	if !Text(o.Reason, 256) {
		return errors.New("--reason must be at most 256 bytes without control characters")
	}
	if len(o.Command) > 32768 || !utf8.ValidString(o.Command) || strings.ContainsRune(o.Command, 0) {
		return errors.New("invalid remote command: maximum 32768 bytes, valid UTF-8, no NUL")
	}
	modes := 0
	for _, used := range []bool{o.Command != "", o.Forward != "", o.ForwardHost != ""} {
		if used {
			modes++
		}
	}
	if modes > 1 {
		return errors.New("--command, --forward, and --forward-host are mutually exclusive")
	}
	if (o.List || o.Check) && (modes > 0 || o.Document != "" || o.Reason != "" || o.Duration != 0) {
		return errors.New("session options cannot be combined with --list or --check")
	}
	if o.List && o.Instance != "" {
		return errors.New("--list cannot be combined with --instance")
	}
	if !o.List && (o.Name != "" || o.State != "" || len(o.Tags) > 0) {
		return errors.New("--name, --state, and --tag require --list")
	}
	if o.JSON && !o.List && !o.Check {
		return errors.New("--json requires --list or --check")
	}
	if o.Quiet && (o.Verbose || o.Debug) {
		return errors.New("--quiet cannot be combined with --verbose or --debug")
	}
	if !Text(o.Name, 256) {
		return errors.New("invalid Name tag filter")
	}
	if o.State != "" {
		switch o.State {
		case "pending", "running", "shutting-down", "terminated", "stopping", "stopped":
		default:
			return errors.New("invalid EC2 state filter")
		}
	}
	if len(o.Tags) > 50 {
		return errors.New("at most 50 --tag filters are supported")
	}
	for _, tag := range o.Tags {
		k, v, ok := strings.Cut(tag, "=")
		if !ok || k == "" || !Text(k, 128) || !Text(v, 256) {
			return errors.New("--tag requires KEY=VALUE without control characters")
		}
	}
	if o.Forward != "" {
		if _, err := ParseForward(o.Forward, false); err != nil {
			return err
		}
	}
	if o.ForwardHost != "" {
		if _, err := ParseForward(o.ForwardHost, true); err != nil {
			return err
		}
	}
	if (o.Forward != "" || o.ForwardHost != "") && o.Document != "" {
		return errors.New("forwarding selects the AWS port-forwarding document; do not combine with --document")
	}
	return nil
}

// ForwardTarget describes a destination. Revalidate exported fields at resource
// boundaries with Validate; local listeners must use Address.
type ForwardTarget struct {
	LocalPort, RemotePort int
	Host                  string
}

// Validate checks a programmatically constructed destination without rewriting
// its host or resolving it locally. An empty host means the instance-local port.
func (f ForwardTarget) Validate() error {
	if f.LocalPort < 1 || f.LocalPort > 65535 || f.RemotePort < 1 || f.RemotePort > 65535 || (f.Host != "" && !validHost(f.Host)) {
		return errors.New("invalid forwarding destination")
	}
	return nil
}

// Address returns the only supported local bind address.
func (f ForwardTarget) Address() string {
	return net.JoinHostPort("127.0.0.1", strconv.Itoa(f.LocalPort))
}

// ParseForward accepts LOCAL:REMOTE or LOCAL:HOST:REMOTE (bracket IPv6 hosts).
func ParseForward(value string, hostMode bool) (ForwardTarget, error) {
	f := ForwardTarget{}
	first := strings.IndexByte(value, ':')
	last := strings.LastIndexByte(value, ':')
	if first <= 0 || hostMode && first == last || !hostMode && first != last {
		return f, errors.New("invalid forwarding syntax; use LOCAL:REMOTE or LOCAL:HOST:REMOTE")
	}
	port := func(s string) (int, error) {
		if len(s) == 0 || len(s) > 5 {
			return 0, errors.New("port must be an integer from 1 to 65535")
		}
		for _, r := range s {
			if r < '0' || r > '9' {
				return 0, errors.New("port must be an integer from 1 to 65535")
			}
		}
		n, e := strconv.Atoi(s)
		if e != nil || n < 1 || n > 65535 {
			return 0, errors.New("port must be an integer from 1 to 65535")
		}
		return n, nil
	}
	var err error
	if f.LocalPort, err = port(value[:first]); err != nil {
		return f, err
	}
	if f.RemotePort, err = port(value[last+1:]); err != nil {
		return f, err
	}
	if hostMode {
		f.Host = value[first+1 : last]
		if strings.HasPrefix(f.Host, "[") && strings.HasSuffix(f.Host, "]") {
			f.Host = f.Host[1 : len(f.Host)-1]
			if net.ParseIP(f.Host) == nil {
				return f, errors.New("invalid bracketed forwarding IP address")
			}
		}
		if !validHost(f.Host) {
			return f, errors.New("invalid forwarding destination host")
		}
	}
	return f, nil
}

func validHost(s string) bool {
	if s == "" || len(s) > 253 {
		return false
	}
	if net.ParseIP(s) != nil {
		return true
	}
	if strings.ContainsAny(s, ":[]") {
		return false
	}
	// Reject strings resembling malformed IPv4 rather than interpreting them as DNS.
	if strings.Trim(s, "0123456789.") == "" {
		return false
	}
	for _, label := range strings.Split(strings.TrimSuffix(s, "."), ".") {
		if !dnsLabel.MatchString(label) {
			return false
		}
	}
	return true
}
