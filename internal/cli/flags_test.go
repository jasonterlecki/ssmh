package cli

import (
	"strings"
	"testing"
)

func TestParse(t *testing.T) {
	o, err := Parse([]string{"-i", "web-prod", "--profile=production", "-r", "ca-central-1", "--arn", "arn:aws:iam::123456789012:role/Admin", "--external-id", "customer", "--timeout", "45s"})
	if err != nil {
		t.Fatal(err)
	}
	if o.Instance != "web-prod" || o.Profile != "production" || o.Region != "ca-central-1" || o.Timeout.Seconds() != 45 {
		t.Fatal("flags lost")
	}
	o, err = Parse([]string{"--list", "--json", "--tag", "Env=prod", "--tag=Team=ops"})
	if err != nil || !o.List || !o.JSON || len(o.Tags) != 2 {
		t.Fatalf("list parse: %v", err)
	}
	for _, args := range [][]string{{}, {"-i", "i-123"}, {"-i", "web", "-c", ""}, {"--list", "unexpected"}, {"--timeout=very-secret-value"}, {"--mfa-token=very-secret-value"}, {"--unknown=very-secret-value"}, {"-i", "web", "--command="}} {
		_, err := Parse(args)
		if err == nil {
			t.Errorf("accepted %q", args)
		} else if strings.Contains(err.Error(), "very-secret-value") {
			t.Fatal("parser leaked value")
		}
	}
	for _, flag := range []string{"--help", "-h", "--version"} {
		if _, err := Parse([]string{flag}); err != nil {
			t.Fatal(err)
		}
	}
}

func TestCACertFlags(t *testing.T) {
	for _, flag := range []string{"-ca", "--ca-cert", "-ca-cert", "--ca"} {
		for _, args := range [][]string{{"-i", "web", flag, "path with spaces/ca-bundle.pem"}, {"--list", flag + "=path with spaces/ca-bundle.pem"}} {
			o, err := Parse(args)
			if err != nil || o.CACert != "path with spaces/ca-bundle.pem" {
				t.Fatal("CA path/alias not preserved")
			}
		}
		for _, args := range [][]string{{"-i", "web", flag}, {"-i", "web", flag, ""}, {"-i", "web", flag + "="}, {"-i", "web", flag, "synthetic-secret\x00path"}, {"-i", "web", flag, strings.Repeat("x", 4097)}} {
			if _, err := Parse(args); err == nil || strings.Contains(err.Error(), "synthetic-secret") {
				t.Fatal("invalid CA option accepted or leaked")
			}
		}
	}
}

func TestGNUShortFlagsAndCommandPreservation(t *testing.T) {
	o, err := Parse([]string{"-viweb", "-pproduction", "-rca-central-1", "-L8080:80"})
	if err != nil || !o.Verbose || o.Instance != "web" || o.Profile != "production" || o.Forward != "8080:80" {
		t.Fatalf("GNU short flags: %v", err)
	}
	command := "-v 'quoted' ; $HOME \n printf '非ASCII'"
	o, err = Parse([]string{"-iweb", "-c", command})
	if err != nil || o.Command != command {
		t.Fatal("command argument was altered")
	}
	if _, err := Parse([]string{"-iweb", "-c"}); err == nil {
		t.Fatal("missing command value accepted")
	}
	if _, err := Parse([]string{"-iweb", "-" + strings.Repeat("v", 2000)}); err == nil {
		t.Fatal("unbounded short-option expansion")
	}
}
