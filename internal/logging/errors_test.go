package logging

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/aws/smithy-go"
)

func TestFailureNeverLeaksCause(t *testing.T) {
	for _, err := range []error{errors.New("token=secret"), &smithy.GenericAPIError{Code: "AccessDeniedException", Message: "secret"}, &smithy.GenericAPIError{Code: "secret", Message: "secret"}, context.Canceled, context.DeadlineExceeded} {
		got := Failure("start session", err)
		if strings.Contains(got.Error(), "secret") {
			t.Fatal(got)
		}
	}
}
func TestSafeText(t *testing.T) {
	if got := SafeText("web\x1b[2J\r\n\u202eprod"); strings.ContainsAny(got, "\x1b\r\n\u202e") {
		t.Fatal("unsafe metadata")
	}
}
