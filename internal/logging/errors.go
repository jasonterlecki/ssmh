// Package logging exposes only allowlisted error information, never raw SDK errors.
package logging

import (
	"context"
	"errors"
	"net"
	"strconv"
	"strings"
	"unicode"

	"github.com/aws/smithy-go"
	smithyhttp "github.com/aws/smithy-go/transport/http"
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
	message := failureMessage(operation, err)
	category, code := "unclassified", ""
	var api smithy.APIError
	var network *net.OpError
	switch {
	case errors.Is(err, context.Canceled):
		category = "canceled"
	case errors.Is(err, context.DeadlineExceeded):
		category = "timeout"
	case errors.As(err, &api) && api != nil:
		category = "aws-service"
		// Codes are untrusted response text. Only exact reviewed literals may
		// enter diagnostics; neither messages nor arbitrary codes are printed.
		selectedCode := api.ErrorCode()
		switch selectedCode {
		case "AccessDenied", "AccessDeniedException", "UnauthorizedOperation",
			"ExpiredToken", "ExpiredTokenException", "InvalidClientTokenId", "UnrecognizedClientException",
			"TargetNotConnected", "Throttling", "ThrottlingException", "TooManyRequestsException",
			"InvalidDocument", "InternalServerError", "InternalServerException",
			"InvalidSessionId", "DoesNotExistException", "ValidationException", "ValidationError",
			"InvalidParameters", "ResourceNotFoundException", "SerializationException":
			code = selectedCode
		default:
			code = "unrecognized"
		}
	case errors.As(err, &network) && network != nil:
		category = "network"
	}
	details := "category=" + category
	if code != "" {
		details += " aws_code=" + code
	}
	var response *smithyhttp.ResponseError
	if errors.As(err, &response) && response != nil && response.Response != nil && response.Response.Response != nil {
		status := response.Response.StatusCode
		if status >= 100 && status <= 599 {
			details += " http_status=" + strconv.Itoa(status)
		}
	}
	// Return a fresh text-only error: no retained cause, URL, response, header,
	// request ID, provider output or credential-bearing object.
	return errors.New(message.Error() + " (" + details + ")")
}

func failureMessage(operation string, err error) error {
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
