// Package logging exposes only allowlisted error information, never raw SDK errors.
package logging

import (
	"context"
	"errors"
	"strings"
	"unicode"

	"github.com/aws/smithy-go"
)

// SafeText escapes untrusted metadata for diagnostic terminal display.
func SafeText(s string) string {
	var b strings.Builder
	for _, r := range s {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			b.WriteRune('�')
		} else {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// Failure returns actionable messages without retaining or exposing secret-bearing causes.
func Failure(operation string, err error) error {
	if errors.Is(err, context.Canceled) {
		return errors.New(operation + ": canceled")
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return errors.New(operation + ": timed out; check network connectivity and --timeout")
	}
	var api smithy.APIError
	if errors.As(err, &api) {
		switch api.ErrorCode() {
		case "AccessDenied", "AccessDeniedException", "UnauthorizedOperation":
			return errors.New(operation + ": access denied; check IAM permissions, session policies, and role trust")
		case "ExpiredToken", "ExpiredTokenException", "InvalidClientTokenId", "UnrecognizedClientException":
			return errors.New(operation + ": authentication failed; refresh your AWS credentials or IAM Identity Center login")
		case "TargetNotConnected":
			return errors.New(operation + ": target is not connected to SSM; check agent status and endpoint connectivity")
		case "Throttling", "ThrottlingException", "TooManyRequestsException":
			return errors.New(operation + ": AWS request throttled after bounded retries; retry later")
		case "InvalidDocument":
			return errors.New(operation + ": invalid or unavailable SSM document")
		}
	}
	return errors.New(operation + ": operation failed; check AWS configuration, credentials, TLS certificates, and network connectivity")
}
