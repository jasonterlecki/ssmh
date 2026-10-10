package logging

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"testing"

	sdkhttp "github.com/aws/aws-sdk-go-v2/aws/transport/http"
	"github.com/aws/smithy-go"
	smithyhttp "github.com/aws/smithy-go/transport/http"
)

func TestFailureNeverLeaksCause(t *testing.T) {
	for _, err := range []error{errors.New("token=secret"), &smithy.GenericAPIError{Code: "AccessDeniedException", Message: "secret"}, &smithy.GenericAPIError{Code: "secret", Message: "secret"}, context.Canceled, context.DeadlineExceeded} {
		got := Failure("start session", err)
		if strings.Contains(got.Error(), "secret") {
			t.Fatal(got)
		}
	}
}

func TestFailureSafeClassification(t *testing.T) {
	for _, code := range []string{"InternalServerError", "InvalidSessionId", "DoesNotExistException", "ValidationException", "AccessDeniedException", "synthetic-secret-code"} {
		cause := &smithy.GenericAPIError{Code: code, Message: "synthetic-secret-message"}
		wrapped := &sdkhttp.ResponseError{ResponseError: &smithyhttp.ResponseError{Response: &smithyhttp.Response{Response: &http.Response{StatusCode: 400, Header: http.Header{"Authorization": {"synthetic-secret-header"}}}}, Err: cause}, RequestID: "synthetic-secret-request-id"}
		got := Failure("terminate owned session", &smithy.OperationError{ServiceID: "SSM", OperationName: "TerminateSession", Err: wrapped})
		want := code
		if code == "synthetic-secret-code" {
			want = "unrecognized"
		}
		if !strings.Contains(got.Error(), "category=aws-service aws_code="+want+" http_status=400") || strings.Contains(got.Error(), "synthetic-secret") || errors.Unwrap(got) != nil {
			t.Fatal("classification omitted reviewed metadata or retained sensitive cause")
		}
	}
	for _, status := range []int{-1, 0, 99, 600, 999999} {
		got := Failure("operation", &smithyhttp.ResponseError{Response: &smithyhttp.Response{Response: &http.Response{StatusCode: status}}, Err: errors.New("synthetic-secret")})
		if strings.Contains(got.Error(), "http_status=") || strings.Contains(got.Error(), "synthetic-secret") {
			t.Fatal("invalid status entered diagnostics")
		}
	}
	for _, response := range []*smithyhttp.Response{nil, {}} {
		got := Failure("operation", &smithyhttp.ResponseError{Response: response, Err: errors.New("synthetic-secret")})
		if strings.Contains(got.Error(), "synthetic-secret") {
			t.Fatal("partial response leaked cause")
		}
	}
	for _, tc := range []struct {
		cause    error
		category string
	}{
		{context.Canceled, "canceled"}, {context.DeadlineExceeded, "timeout"},
		{&net.OpError{Op: "synthetic-secret", Net: "tcp", Err: errors.New("synthetic-secret")}, "network"},
		{errors.New("synthetic-secret"), "unclassified"},
	} {
		got := Failure("operation", fmt.Errorf("synthetic-secret wrapper: %w", tc.cause))
		if !strings.Contains(got.Error(), "category="+tc.category) || strings.Contains(got.Error(), "synthetic-secret") {
			t.Fatal("local category missing or raw cause leaked")
		}
	}
}
func TestSafeText(t *testing.T) {
	if got := SafeText("web\x1b[2J\r\n\u202eprod"); strings.ContainsAny(got, "\x1b\r\n\u202e") {
		t.Fatal("unsafe metadata")
	}
}
