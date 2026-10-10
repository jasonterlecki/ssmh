package config

import (
	"regexp"
	"strings"
)

var kmsKeyID = regexp.MustCompile(`^(?:[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}|mrk-[a-f0-9]{32})$`)
var kmsAlias = regexp.MustCompile(`^alias/[A-Za-z0-9/_-]{1,250}$`)
var kmsAccount = regexp.MustCompile(`^[0-9]{12}$`)

// KMSKeyReference validates a literal key ID/alias or an ARN matching the
// selected region/partition. It does not resolve aliases, retrieve credentials
// or prove permission. Empty selected region validates an ARN's own region.
func KMSKeyReference(key, selectedRegion string) bool {
	if len(key) == 0 || len(key) > 2048 || selectedRegion != "" && Region(selectedRegion) != nil {
		return false
	}
	if kmsKeyID.MatchString(key) || kmsAlias.MatchString(key) {
		return true
	}
	parts := strings.SplitN(key, ":", 6)
	if len(parts) != 6 || parts[0] != "arn" || parts[2] != "kms" || Region(parts[3]) != nil || selectedRegion != "" && parts[3] != selectedRegion || !kmsAccount.MatchString(parts[4]) {
		return false
	}
	partition := "aws"
	if strings.HasPrefix(parts[3], "cn-") {
		partition = "aws-cn"
	}
	if strings.HasPrefix(parts[3], "us-gov-") {
		partition = "aws-us-gov"
	}
	return parts[1] == partition && (strings.HasPrefix(parts[5], "key/") && kmsKeyID.MatchString(strings.TrimPrefix(parts[5], "key/")) || kmsAlias.MatchString(parts[5]))
}
