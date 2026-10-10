package config

import (
	"strings"
	"testing"
	"time"
)

func valid() Options {
	return Options{Instance: "i-0123456789abcdef0", Backend: "auto", Timeout: 30 * time.Second}
}

func TestValidation(t *testing.T) {
	tests := []struct {
		name string
		edit func(*Options)
	}{
		{"missing instance", func(o *Options) { o.Instance = "" }},
		{"malformed ID", func(o *Options) { o.Instance = "i-123" }},
		{"terminal injection", func(o *Options) { o.Instance = "web\x1b[2J" }},
		{"missing role", func(o *Options) { o.ExternalID = "customer" }},
		{"non-role ARN", func(o *Options) { o.RoleARN = "arn:aws:iam::123456789012:user/admin" }},
		{"MFA without device", func(o *Options) { o.RoleARN = "arn:aws:iam::123456789012:role/admin"; o.MFAToken = "123456" }},
		{"MFA malformed", func(o *Options) {
			o.RoleARN = "arn:aws:iam::123456789012:role/admin"
			o.MFASerial = "arn:aws:iam::123456789012:mfa/test"
			o.MFAToken = "secret"
		}},
		{"timeout", func(o *Options) { o.Timeout = 0 }},
		{"negative duration", func(o *Options) { o.Duration = -time.Second }},
		{"region", func(o *Options) { o.Region = "https://attacker.invalid" }},
		{"backend", func(o *Options) { o.Backend = "ssh" }},
		{"mode conflict", func(o *Options) { o.Command = "hostname"; o.Forward = "8080:80" }},
		{"document forwarding", func(o *Options) { o.Document = "custom"; o.Forward = "8080:80" }},
		{"list command", func(o *Options) { o.List = true; o.Command = "hostname" }},
		{"check duration", func(o *Options) { o.Check = true; o.Duration = time.Hour }},
		{"tag nonlist", func(o *Options) { o.Tags = []string{"Env=prod"} }},
		{"invalid command", func(o *Options) { o.Command = "x\x00y" }},
		{"large command", func(o *Options) { o.Command = strings.Repeat("x", 32769) }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			o := valid()
			tt.edit(&o)
			if o.Validate() == nil {
				t.Fatal("accepted invalid invocation")
			}
		})
	}
	for _, partition := range []string{"aws", "aws-cn", "aws-us-gov"} {
		o := valid()
		o.RoleARN = "arn:" + partition + ":iam::123456789012:role/path/Admin"
		if err := o.Validate(); err != nil {
			t.Fatal(err)
		}
	}
}

func TestForward(t *testing.T) {
	for _, tt := range []struct {
		value string
		host  bool
	}{{"8080:80", false}, {"15432:database.internal:5432", true}, {"8080:[::1]:80", true}, {"8080:127.0.0.1:80", true}} {
		f, err := ParseForward(tt.value, tt.host)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.HasPrefix(f.Address(), "127.0.0.1:") {
			t.Fatal("non-loopback bind")
		}
	}
	for _, v := range []string{"0:80", "65536:80", "+80:80", " 80:80", "80:0", "80:999999999999", "0.0.0.0:80:80"} {
		if _, err := ParseForward(v, false); err == nil {
			t.Errorf("accepted %q", v)
		}
	}
	for _, v := range []string{"80::80", "80:host;evil:80", "80:host\n:80", "80:-host:80", "80:999.1.1.1:80", "80:[oops]:80", "80:https://host:80", "80:host%zone:80"} {
		if _, err := ParseForward(v, true); err == nil {
			t.Errorf("accepted %q", v)
		}
	}
}

func FuzzForward(f *testing.F) {
	for _, s := range []string{"8080:80", "15432:db.internal:5432", "8080:[::1]:80", ""} {
		f.Add(s, true)
	}
	f.Fuzz(func(t *testing.T, s string, host bool) {
		result, err := ParseForward(s, host)
		if err == nil && (result.LocalPort < 1 || result.LocalPort > 65535 || !strings.HasPrefix(result.Address(), "127.0.0.1:")) {
			t.Fatal("invalid accepted target")
		}
	})
}
