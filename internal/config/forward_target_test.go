package config

import (
	"strings"
	"testing"
)

func TestForwardTargetValidate(t *testing.T) {
	for _, spec := range []struct {
		value string
		host  bool
	}{{"1:65535", false}, {"65535:1", false}, {"8080:database.internal:5432", true}, {"8080:[::1]:80", true}, {"8080:Example.COM.:80", true}} {
		target, err := ParseForward(spec.value, spec.host)
		if err != nil || target.Validate() != nil {
			t.Fatalf("parsed target rejected: %s", spec.value)
		}
	}
	for _, target := range []ForwardTarget{
		{}, {LocalPort: -1, RemotePort: 80}, {LocalPort: 65536, RemotePort: 80},
		{LocalPort: 80, RemotePort: 0}, {LocalPort: 80, RemotePort: 65536},
		{LocalPort: 80, RemotePort: 80, Host: "[::1]"},
		{LocalPort: 80, RemotePort: 80, Host: "::1%lo"},
		{LocalPort: 80, RemotePort: 80, Host: "bad\nsecret"},
		{LocalPort: 80, RemotePort: 80, Host: "999.1.1.1"},
		{LocalPort: 80, RemotePort: 80, Host: strings.Repeat("a", 254)},
	} {
		if err := target.Validate(); err == nil || strings.Contains(err.Error(), "secret") {
			t.Fatal("invalid target accepted or disclosed")
		}
	}
}
