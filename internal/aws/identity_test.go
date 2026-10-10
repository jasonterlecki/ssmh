package aws

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/aws/smithy-go"
)

type identityHTTP func(*http.Request) (*http.Response, error)

func (f identityHTTP) Do(request *http.Request) (*http.Response, error) { return f(request) }

func TestReadIdentityThroughAuthenticatedSDK(t *testing.T) {
	calls := 0
	client := sts.NewFromConfig(aws.Config{Region: "ca-central-1", Credentials: credentials.NewStaticCredentialsProvider("synthetic-key", "synthetic-secret", ""), HTTPClient: identityHTTP(func(request *http.Request) (*http.Response, error) {
		calls++
		if request.Method != "POST" || request.URL.Scheme != "https" || request.URL.Host != "sts.ca-central-1.amazonaws.com" || !strings.HasPrefix(request.Header.Get("Authorization"), "AWS4-HMAC-SHA256 ") {
			t.Fatal("identity request escaped the authenticated selected STS endpoint")
		}
		body, err := io.ReadAll(request.Body)
		if err != nil {
			t.Fatal(err)
		}
		query, err := url.ParseQuery(string(body))
		if err != nil || query.Get("Action") != "GetCallerIdentity" {
			t.Fatal("identity request changed operation")
		}
		response := `<GetCallerIdentityResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/"><GetCallerIdentityResult><Account>123456789012</Account><Arn>arn:aws:sts::123456789012:assumed-role/ReviewedRole/session</Arn><UserId>synthetic-secret-ignored-user-id</UserId></GetCallerIdentityResult><ResponseMetadata><RequestId>synthetic-request</RequestId></ResponseMetadata></GetCallerIdentityResponse>`
		return &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Type": {"text/xml"}}, Body: io.NopCloser(strings.NewReader(response)), Request: request}, nil
	})})
	i, err := ReadIdentity(context.Background(), client)
	if err != nil || calls != 1 || i.Account() != "123456789012" || i.ARN() != "arn:aws:sts::123456789012:assumed-role/ReviewedRole/session" || strings.Contains(fmt.Sprint(i), "synthetic-secret") {
		t.Fatalf("SDK identity response not safely interpreted: %v", err)
	}
}

type identityAPI struct {
	response *sts.GetCallerIdentityOutput
	err      error
	calls    int
	cancel   context.CancelFunc
}

func (i *identityAPI) GetCallerIdentity(context.Context, *sts.GetCallerIdentityInput, ...func(*sts.Options)) (*sts.GetCallerIdentityOutput, error) {
	i.calls++
	if i.cancel != nil {
		i.cancel()
	}
	return i.response, i.err
}

func TestReadIdentityMetadata(t *testing.T) {
	for _, principal := range []string{"arn:aws:iam::123456789012:root", "arn:aws-cn:iam::123456789012:user/team/operator", "arn:aws-us-gov:sts::123456789012:assumed-role/ReviewedRole/unit-session", "arn:aws:sts::123456789012:federated-user/operator", "arn:aws:iam::123456789012:role/team/ReviewedRole", "arn:aws:iam::123456789012:user/team:+*%/operator", "arn:aws:iam::123456789012:user/team//operator"} {
		api := &identityAPI{response: &sts.GetCallerIdentityOutput{Account: aws.String("123456789012"), Arn: aws.String(principal), UserId: aws.String("synthetic-secret-ignored-user-id")}}
		i, err := ReadIdentity(context.Background(), api)
		if err != nil || api.calls != 1 || i.Account() != "123456789012" || i.ARN() != principal {
			t.Fatalf("caller identity changed: %v", err)
		}
	}
	for _, principal := range []string{"", "synthetic-secret", "arn:aws:sts::000000000000:assumed-role/ReviewedRole/session", "arn:aws:sts:ca-central-1:123456789012:assumed-role/ReviewedRole/session", "arn:aws:sts::123456789012:assumed-role//session", "arn:aws:sts::123456789012:assumed-role/ReviewedRole/", "arn:aws:sts::123456789012:assumed-role/ReviewedRole/session\n", "arn:aws:sts::123456789012:assumed-role/ReviewedRole/sess\x1b[2J", "arn:aws:sts::123456789012:federated-user/", "arn:aws:ssm::123456789012:session/synthetic-secret", strings.Repeat("x", 2049)} {
		api := &identityAPI{response: &sts.GetCallerIdentityOutput{Account: aws.String("123456789012"), Arn: aws.String(principal)}}
		i, err := ReadIdentity(context.Background(), api)
		if err == nil || i != (Identity{}) || strings.Contains(err.Error(), "synthetic-secret") {
			t.Fatal("invalid identity leaked or returned partially")
		}
	}
	for _, account := range []string{"", "1234", "123456789012\n", "synthetic-secret"} {
		api := &identityAPI{response: &sts.GetCallerIdentityOutput{Account: aws.String(account), Arn: aws.String("arn:aws:iam::123456789012:user/operator")}}
		if i, err := ReadIdentity(context.Background(), api); err == nil || i != (Identity{}) {
			t.Fatal("invalid account accepted")
		}
	}
}

func TestReadIdentityFailureAndCancellation(t *testing.T) {
	for _, api := range []*identityAPI{{}, {err: errors.New("synthetic-secret-api-error")}} {
		i, err := ReadIdentity(context.Background(), api)
		if err == nil || i != (Identity{}) || strings.Contains(err.Error(), "synthetic-secret") || api.calls != 1 {
			t.Fatal("API failure ignored, leaked or retried")
		}
	}
	if i, err := ReadIdentity(context.Background(), nil); err == nil || i != (Identity{}) {
		t.Fatal("nil client accepted")
	}
	for _, duringRead := range []bool{false, true} {
		ctx, cancel := context.WithCancel(context.Background())
		api := &identityAPI{cancel: cancel, response: &sts.GetCallerIdentityOutput{Account: aws.String("123456789012"), Arn: aws.String("arn:aws:iam::123456789012:user/operator")}}
		if !duringRead {
			cancel()
		}
		i, err := ReadIdentity(ctx, api)
		if !errors.Is(err, context.Canceled) || i != (Identity{}) || !duringRead && api.calls != 0 {
			t.Fatal("canceled identity request returned metadata")
		}
	}
}

func TestCallerIdentityPathAndSubjectBounds(t *testing.T) {
	for _, principal := range []string{"arn:aws:iam::123456789012:user/team/", "arn:aws:iam::123456789012:user/team/operator:invalid", "arn:aws:sts::123456789012:federated-user/team/operator", "arn:aws:iam::123456789012:user/" + strings.Repeat("x", 512) + "/operator", "arn:aws:iam::123456789012:user/" + strings.Repeat("x", 65)} {
		api := &identityAPI{response: &sts.GetCallerIdentityOutput{Account: aws.String("123456789012"), Arn: aws.String(principal)}}
		if i, err := ReadIdentity(context.Background(), api); err == nil || i != (Identity{}) {
			t.Fatal("invalid identity path or subject accepted")
		}
	}
}

func FuzzCallerIdentity(f *testing.F) {
	f.Add("123456789012", "arn:aws:sts::123456789012:assumed-role/ReviewedRole/session")
	f.Fuzz(func(t *testing.T, account, principal string) {
		api := &identityAPI{response: &sts.GetCallerIdentityOutput{Account: aws.String(account), Arn: aws.String(principal)}}
		_, _ = ReadIdentity(context.Background(), api)
	})
}

func TestIdentityDenialClassificationDoesNotHideAuthenticationFailures(t *testing.T) {
	for _, code := range []string{"AccessDenied", "AccessDeniedException", "ExpiredToken", "InvalidClientTokenId", "UnrecognizedClientException", "Forbidden", "Unknown"} {
		api := &identityAPI{err: &smithy.GenericAPIError{Code: code, Message: "synthetic-secret"}}
		identity, err := ReadIdentity(context.Background(), api)
		denied := code == "AccessDenied" || code == "AccessDeniedException"
		if identity != (Identity{}) || err == nil || errors.Is(err, ErrIdentityDenied) != denied || strings.Contains(err.Error(), "synthetic-secret") {
			t.Fatal("identity denial misclassified or raw error retained")
		}
		var raw smithy.APIError
		if errors.As(err, &raw) {
			t.Fatal("raw identity API error retained")
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	api := &identityAPI{cancel: cancel, err: &smithy.GenericAPIError{Code: "AccessDenied", Message: "synthetic-secret"}}
	if identity, err := ReadIdentity(ctx, api); identity != (Identity{}) || !errors.Is(err, context.Canceled) {
		t.Fatal("cancellation hidden by denial classification")
	}
}
