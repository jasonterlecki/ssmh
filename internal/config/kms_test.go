package config

import "testing"

func TestKMSLiteralReferences(t *testing.T) {
	key := "12345678-1234-1234-1234-123456789abc"
	for _, item := range []struct{ region, partition string }{{"ca-central-1", "aws"}, {"cn-north-1", "aws-cn"}, {"us-gov-west-1", "aws-us-gov"}} {
		for _, value := range []string{key, "alias/Reviewed-Key", "mrk-0123456789abcdef0123456789abcdef", "arn:" + item.partition + ":kms:" + item.region + ":123456789012:key/" + key, "arn:" + item.partition + ":kms:" + item.region + ":123456789012:alias/Reviewed"} {
			if !KMSKeyReference(value, item.region) || !KMSKeyReference(value, "") {
				t.Fatal("valid literal KMS reference rejected")
			}
		}
	}
	for _, value := range []string{"", "{{key}}", "{{ssm:key}}", "alias/", "secret\nkey", "arn:aws:kms:us-east-1:123456789012:key/" + key, "arn:aws-cn:kms:ca-central-1:123456789012:key/" + key, "arn:aws:kms:ca-central-1:123:key/" + key} {
		if KMSKeyReference(value, "ca-central-1") {
			t.Fatal("invalid/mismatched KMS reference accepted")
		}
	}
}
