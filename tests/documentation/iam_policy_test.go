// These tests guard documentation examples, not effective AWS authorization.
package doccheck

import (
	"encoding/json"
	"io"
	"os"
	"reflect"
	"strings"
	"testing"
)

type policy struct {
	Version   string
	Statement []statement
}

type statement struct {
	Sid       string
	Effect    string
	Action    string
	Resource  any
	Condition map[string]map[string]string
}

func TestIAMPolicyExamples(t *testing.T) {
	content, err := os.ReadFile("../../docs/iam-policy.md")
	if err != nil {
		t.Fatal(err)
	}
	var examples []policy
	remaining := string(content)
	for {
		_, after, found := strings.Cut(remaining, "```json\n")
		if !found {
			break
		}
		block, rest, closed := strings.Cut(after, "\n```")
		if !closed {
			t.Fatal("unterminated JSON policy example")
		}
		checkUniqueKeys(t, json.NewDecoder(strings.NewReader(block)))
		decoder := json.NewDecoder(strings.NewReader(block))
		decoder.DisallowUnknownFields()
		var example policy
		if err := decoder.Decode(&example); err != nil {
			t.Fatal(err)
		}
		if decoder.Decode(new(any)) != io.EOF {
			t.Fatal("extra data after policy")
		}
		examples = append(examples, example)
		remaining = rest
	}
	const doc = "arn:aws:ssm:ca-central-1:123456789012:document/SSM-SessionManagerRunShell"
	const target = "i-0123456789abcdef0"
	want := []policy{
		{"2012-10-17", []statement{
			{"ResolveTargetState", "Allow", "ec2:DescribeInstances", "*", map[string]map[string]string{"StringEquals": {"aws:RequestedRegion": "ca-central-1"}}},
			{"ReadRegistration", "Allow", "ssm:DescribeInstanceInformation", "*", map[string]map[string]string{"StringEquals": {"aws:RequestedRegion": "ca-central-1"}}},
			{"ReadApprovedShellDocument", "Allow", "ssm:GetDocument", doc, nil},
			{"StartApprovedShell", "Allow", "ssm:StartSession", []any{"arn:aws:ec2:ca-central-1:123456789012:instance/" + target, doc}, map[string]map[string]string{"Bool": {"ssm:SessionDocumentAccessCheck": "true"}}},
			{"OpenOwnDataChannel", "Allow", "ssmmessages:OpenDataChannel", "arn:aws:ssm:ca-central-1:123456789012:session/${aws:userid}-*", nil},
			{"EndOwnTargetSessions", "Allow", "ssm:TerminateSession", "arn:aws:ssm:ca-central-1:123456789012:session/${aws:username}-*", map[string]map[string]string{"StringEquals": {
				"ssm:resourceTag/aws:ssmmessages:session-id": "${aws:userid}",
				"ssm:resourceTag/aws:ssmmessages:target-id":  target,
			}}},
		}},
		{"2012-10-17", []statement{
			{"AssumeApprovedRemoteAccessRole", "Allow", "sts:AssumeRole", "arn:aws:iam::123456789012:role/RemoteAccess", nil},
		}},
	}
	if !reflect.DeepEqual(examples, want) {
		t.Fatal("policy example scope changed: review API requirements, action/resource restrictions and ownership conditions")
	}
}

// Reject duplicate keys instead of accepting JSON's last-value interpretation.
func checkUniqueKeys(t *testing.T, decoder *json.Decoder) {
	t.Helper()
	token, err := decoder.Token()
	if err != nil {
		t.Fatal(err)
	}
	delim, nested := token.(json.Delim)
	if !nested {
		return
	}
	keys := map[string]bool{}
	for decoder.More() {
		if delim == '{' {
			key, err := decoder.Token()
			if err != nil {
				t.Fatal(err)
			}
			name, ok := key.(string)
			if !ok || keys[name] {
				t.Fatal("duplicate or invalid JSON key")
			}
			keys[name] = true
		}
		checkUniqueKeys(t, decoder)
	}
	if _, err := decoder.Token(); err != nil {
		t.Fatal(err)
	}
}
