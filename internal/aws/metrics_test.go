package aws

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	sdk "github.com/aws/aws-sdk-go-v2/aws"
	awsmiddleware "github.com/aws/aws-sdk-go-v2/aws/middleware"
	"github.com/aws/aws-sdk-go-v2/aws/retry"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/aws/smithy-go/middleware"

	"ssmh/internal/config"
)

func metricConfig(t *testing.T, debug bool, ctx context.Context) sdk.Config {
	t.Helper()
	isolate(t)
	t.Setenv("AWS_ENDPOINT_URL_EC2", "")
	t.Setenv("AWS_ACCESS_KEY_ID", "synthetic-key")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "synthetic-secret")
	cfg, err := Load(ctx, config.Options{Instance: "i-0123456789abcdef0", Region: "ca-central-1", Backend: "auto", Timeout: time.Second, Debug: debug}, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { Close(cfg) })
	return cfg
}

func TestAPIMetricsThroughSDKRetries(t *testing.T) {
	for _, test := range []struct {
		name     string
		failures int
		status   int
		attempts int
		success  bool
	}{
		{"success", 0, 0, 1, true},
		{"transient", 1, 503, 2, true},
		{"denied", 10, 400, 1, false},
		{"exhausted", 10, 503, 3, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			ctx, metrics := WithAPIMetrics(context.Background())
			cfg := metricConfig(t, true, ctx)
			calls := 0
			cfg.HTTPClient = identityHTTP(func(request *http.Request) (*http.Response, error) {
				calls++
				if request.Header.Get("X-Amz-Target") != "AmazonSSM.StartSession" || !strings.HasPrefix(request.Header.Get("Authorization"), "AWS4-HMAC-SHA256 ") {
					t.Fatal("SDK request changed authentication/operation")
				}
				status, body := 200, `{"SessionId":"unit-owned","TokenValue":"synthetic-secret-token","StreamUrl":"wss://synthetic-secret-url"}`
				if calls <= test.failures {
					status = test.status
					code := "InternalServerError"
					if status == 400 {
						code = "AccessDeniedException"
					}
					body = fmt.Sprintf(`{"__type":%q,"Message":"synthetic-secret-api-error"}`, code)
				}
				return &http.Response{StatusCode: status, Header: http.Header{"Content-Type": {"application/x-amz-json-1.1"}}, Body: io.NopCloser(strings.NewReader(body)), Request: request}, nil
			})
			client := ssm.NewFromConfig(cfg, func(o *ssm.Options) {
				o.Retryer = retry.NewStandard(func(o *retry.StandardOptions) {
					o.MaxAttempts = 3
					o.Backoff = retry.BackoffDelayerFunc(func(int, error) (time.Duration, error) { return 0, nil })
				})
			})
			out, err := client.StartSession(ctx, &ssm.StartSessionInput{Target: sdk.String("i-0123456789abcdef0"), Reason: sdk.String("synthetic-secret-reason")})
			if (err == nil) != test.success || calls != test.attempts {
				t.Fatalf("SDK operation/retries changed: calls=%d success=%v", calls, err == nil)
			}
			if test.success && (out == nil || sdk.ToString(out.TokenValue) != "synthetic-secret-token") {
				t.Fatal("metrics altered successful owned-session response")
			}
			events, omitted := metrics.Drain()
			if omitted || len(events) != 1 {
				t.Fatal("metrics did not summarize exactly one SDK operation")
			}
			count, known := events[0].Attempts()
			if !known || count != test.attempts || events[0].Service() != "SSM" || events[0].Operation() != "StartSession" || events[0].Success() != test.success || events[0].Elapsed() < 0 || strings.Contains(fmt.Sprint(events), "synthetic-secret") {
				t.Fatal("SDK summaries leaked data or misreported retries")
			}
		})
	}
}

func TestEC2APIMetricsThroughSignedSDKRetries(t *testing.T) {
	for _, test := range []struct {
		name                       string
		debug                      bool
		failures, status, attempts int
		success                    bool
	}{
		{"default", false, 0, 0, 1, true},
		{"success", true, 0, 0, 1, true},
		{"transient", true, 1, 503, 2, true},
		{"denied", true, 10, 403, 1, false},
		{"exhausted", true, 10, 503, 3, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			ctx, metrics := WithAPIMetrics(context.Background())
			cfg := metricConfig(t, test.debug, ctx)
			calls := 0
			cfg.HTTPClient = identityHTTP(func(request *http.Request) (*http.Response, error) {
				calls++
				if request.URL.Scheme != "https" || request.URL.Host != "ec2.ca-central-1.amazonaws.com" || !strings.HasPrefix(request.Header.Get("Authorization"), "AWS4-HMAC-SHA256 ") || request.ParseForm() != nil || request.Form.Get("Action") != "DescribeInstances" || request.Form.Get("Filter.1.Value.1") != "synthetic-secret-name" {
					t.Fatal("EC2 metrics changed the selected signed SDK operation")
				}
				status := 200
				body := `<DescribeInstancesResponse xmlns="http://ec2.amazonaws.com/doc/2016-11-15/"><nextToken>synthetic-secret-page-token</nextToken><reservationSet><item><instancesSet><item><instanceId>i-0123456789abcdef0</instanceId><instanceState><name>running</name></instanceState></item></instancesSet></item></reservationSet></DescribeInstancesResponse>`
				if calls <= test.failures {
					status = test.status
					code := "InternalError"
					if status == 403 {
						code = "UnauthorizedOperation"
					}
					body = fmt.Sprintf(`<Response><Errors><Error><Code>%s</Code><Message>synthetic-secret-error</Message></Error></Errors><RequestID>synthetic-secret-request-id</RequestID></Response>`, code)
				}
				return &http.Response{StatusCode: status, Header: http.Header{"Content-Type": {"text/xml"}}, Body: io.NopCloser(strings.NewReader(body)), Request: request}, nil
			})
			client := ec2.NewFromConfig(cfg, func(o *ec2.Options) {
				o.Retryer = retry.NewStandard(func(o *retry.StandardOptions) {
					o.MaxAttempts = 3
					o.Backoff = retry.BackoffDelayerFunc(func(int, error) (time.Duration, error) { return 0, nil })
				})
			})
			out, err := client.DescribeInstances(ctx, &ec2.DescribeInstancesInput{MaxResults: sdk.Int32(100), Filters: []ec2types.Filter{{Name: sdk.String("tag:Name"), Values: []string{"synthetic-secret-name"}}}})
			if (err == nil) != test.success || calls != test.attempts {
				t.Fatal("EC2 observation changed retry/result behavior")
			}
			if test.success && (out == nil || sdk.ToString(out.NextToken) != "synthetic-secret-page-token" || len(out.Reservations) != 1) {
				t.Fatal("EC2 observation changed response metadata")
			}
			events, omitted := metrics.Drain()
			if omitted || !test.debug && len(events) != 0 || test.debug && len(events) != 1 {
				t.Fatal("EC2 debug gating or summary cardinality changed")
			}
			if test.debug {
				event := events[0]
				attempts, known := event.Attempts()
				if event.Service() != "EC2" || event.Operation() != "DescribeInstances" || event.Success() != test.success || event.Elapsed() < 0 || !known || attempts != test.attempts || strings.Contains(fmt.Sprint(event), "synthetic-secret") {
					t.Fatal("EC2 summary disclosed data or misreported timing/retries")
				}
			}
		})
	}
}

func TestKMSAPIMetricsThroughSignedSDKRetries(t *testing.T) {
	for _, test := range []struct {
		name                       string
		debug                      bool
		failures, status, attempts int
		success                    bool
	}{
		{"default", false, 0, 0, 1, true},
		{"success", true, 0, 0, 1, true},
		{"transient", true, 1, 503, 2, true},
		{"denied", true, 10, 400, 1, false},
		{"exhausted", true, 10, 503, 3, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			ctx, metrics := WithAPIMetrics(context.Background())
			cfg := metricConfig(t, test.debug, ctx)
			calls := 0
			cfg.HTTPClient = identityHTTP(func(request *http.Request) (*http.Response, error) {
				calls++
				var input struct {
					KeyID             string `json:"KeyId"`
					NumberOfBytes     int
					EncryptionContext map[string]string
				}
				if request.URL.Scheme != "https" || request.URL.Host != "kms.ca-central-1.amazonaws.com" || !strings.Contains(request.Header.Get("Authorization"), "/ca-central-1/kms/aws4_request") || request.Header.Get("X-Amz-Target") != "TrentService.GenerateDataKey" || json.NewDecoder(request.Body).Decode(&input) != nil || input.KeyID != "alias/synthetic-secret-key" || input.NumberOfBytes != 64 || input.EncryptionContext["aws:ssm:RandomChallenge"] != "synthetic-secret-challenge" {
					t.Fatal("KMS metrics changed signed request or encryption context")
				}
				status := 200
				body := `{"KeyId":"synthetic-secret-key-id","Plaintext":"c3ludGhldGljLXNlY3JldC1rZXk=","CiphertextBlob":"c3ludGhldGljLXNlY3JldC1ibG9i"}`
				if calls <= test.failures {
					status = test.status
					code := "KMSInternalException"
					if status == 400 {
						code = "AccessDeniedException"
					}
					body = fmt.Sprintf(`{"__type":%q,"message":"synthetic-secret-error"}`, code)
				}
				return &http.Response{StatusCode: status, Header: http.Header{"Content-Type": {"application/x-amz-json-1.1"}}, Body: io.NopCloser(strings.NewReader(body)), Request: request}, nil
			})
			client := kms.NewFromConfig(cfg, func(o *kms.Options) {
				o.ClientLogMode = 0
				o.Retryer = retry.NewStandard(func(o *retry.StandardOptions) {
					o.MaxAttempts = 3
					o.Backoff = retry.BackoffDelayerFunc(func(int, error) (time.Duration, error) { return 0, nil })
				})
			})
			out, err := client.GenerateDataKey(context.Background(), &kms.GenerateDataKeyInput{KeyId: sdk.String("alias/synthetic-secret-key"), NumberOfBytes: sdk.Int32(64), EncryptionContext: map[string]string{"aws:ssm:RandomChallenge": "synthetic-secret-challenge"}})
			if (err == nil) != test.success || calls != test.attempts {
				t.Fatal("KMS observation changed result/retries")
			}
			if test.success && (out == nil || string(out.Plaintext) != "synthetic-secret-key" || string(out.CiphertextBlob) != "synthetic-secret-blob" || sdk.ToString(out.KeyId) != "synthetic-secret-key-id") {
				t.Fatal("KMS observation changed key response")
			}
			events, omitted := metrics.Drain()
			if omitted || !test.debug && len(events) != 0 || test.debug && len(events) != 1 {
				t.Fatal("KMS debug gating or cardinality changed")
			}
			if test.debug {
				event := events[0]
				attempts, known := event.Attempts()
				if event.Service() != "KMS" || event.Operation() != "GenerateDataKey" || event.Success() != test.success || event.Elapsed() < 0 || !known || attempts != test.attempts || strings.Contains(fmt.Sprint(event), "synthetic-secret") {
					t.Fatal("KMS summary leaked data or misreported attempts")
				}
			}
		})
	}
	for _, pair := range [][2]string{{"KMS", "Decrypt"}, {"KMS", "GenerateDataKey\x1b[2J"}, {"SSM", "GenerateDataKey"}} {
		if _, _, allowed := metricLabels(pair[0], pair[1]); allowed {
			t.Fatal("unexpected KMS metric label accepted")
		}
	}
}

func TestAPIMetricsAreDebugOptIn(t *testing.T) {
	for _, debug := range []bool{false, true} {
		t.Run(fmt.Sprint(debug), func(t *testing.T) {
			ctx, metrics := WithAPIMetrics(context.Background())
			deadline, cancel := context.WithTimeout(ctx, time.Minute)
			defer cancel()
			cfg := metricConfig(t, debug, deadline)
			if (len(cfg.APIOptions) != 0) != debug {
				t.Fatal("default client instrumentation changed")
			}
			cfg.HTTPClient = identityHTTP(func(request *http.Request) (*http.Response, error) {
				return &http.Response{StatusCode: 200, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(`{}`)), Request: request}, nil
			})
			if _, err := ssm.NewFromConfig(cfg).TerminateSession(deadline, &ssm.TerminateSessionInput{SessionId: sdk.String("unit-owned")}); err != nil {
				t.Fatal(err)
			}
			events, omitted := metrics.Drain()
			if omitted || (len(events) == 1) != debug {
				t.Fatal("nondebug client collected API summaries")
			}
		})
	}
}

func TestRoleRefreshMetricsSurviveDifferentContexts(t *testing.T) {
	ctx, metrics := WithAPIMetrics(context.Background())
	cfg := metricConfig(t, true, ctx)
	cfg.HTTPClient = identityHTTP(func(request *http.Request) (*http.Response, error) {
		body := `<AssumeRoleResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/"><AssumeRoleResult><Credentials><AccessKeyId>synthetic-key</AccessKeyId><SecretAccessKey>synthetic-secret</SecretAccessKey><SessionToken>synthetic-secret-token</SessionToken><Expiration>2099-01-01T00:00:00Z</Expiration></Credentials></AssumeRoleResult></AssumeRoleResponse>`
		return &http.Response{StatusCode: 200, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(body)), Request: request}, nil
	})
	o := options()
	o.MFASerial, o.MFAToken = "", ""
	assumed, err := Assume(ctx, cfg, sts.NewFromConfig(cfg), o, nil)
	if err != nil {
		t.Fatal(err)
	}
	assumed.Credentials.(*sdk.CredentialsCache).Invalidate()
	if _, err := assumed.Credentials.Retrieve(context.Background()); err != nil {
		t.Fatal(err)
	}
	events, omitted := metrics.Drain()
	if omitted || len(events) != 2 {
		t.Fatal("refresh from an independent context lost its captured collector")
	}
	for _, event := range events {
		if event.Service() != "STS" || event.Operation() != "AssumeRole" || !event.Success() || strings.Contains(fmt.Sprint(event), "synthetic-secret") {
			t.Fatal("role refresh summary was incorrect or exposed credentials")
		}
	}
}

func TestMetricsPreserveOpaqueResultErrorAndSkipUnknownLabels(t *testing.T) {
	for _, service := range []string{"SSM", "synthetic-secret-service\x1b[2J"} {
		metrics := &APIMetrics{}
		stack := middleware.NewStack("unit", func() any { return nil })
		if err := metrics.middleware(stack); err != nil {
			t.Fatal(err)
		}
		observer, ok := stack.Initialize.Get("ssmhAPIMetrics")
		if !ok {
			t.Fatal("missing metrics middleware")
		}
		secret := errors.New("synthetic-secret-error")
		result := new(int)
		var metadata middleware.Metadata
		metadata.Set("unit", "synthetic-secret-metadata")
		register := awsmiddleware.RegisterServiceMetadata{ServiceID: service, OperationName: "StartSession"}
		out, meta, err := register.HandleInitialize(context.Background(), middleware.InitializeInput{Parameters: "synthetic-secret-input"}, middleware.InitializeHandlerFunc(func(ctx context.Context, in middleware.InitializeInput) (middleware.InitializeOutput, middleware.Metadata, error) {
			return observer.HandleInitialize(ctx, in, middleware.InitializeHandlerFunc(func(_ context.Context, in middleware.InitializeInput) (middleware.InitializeOutput, middleware.Metadata, error) {
				if in.Parameters != "synthetic-secret-input" {
					t.Fatal("input altered")
				}
				return middleware.InitializeOutput{Result: result}, metadata, secret
			}))
		}))
		if err != secret || out.Result != result || meta.Get("unit") != "synthetic-secret-metadata" {
			t.Fatal("metrics altered opaque SDK results")
		}
		events, _ := metrics.Drain()
		if (len(events) == 1) != (service == "SSM") || strings.Contains(fmt.Sprint(events), "synthetic-secret") {
			t.Fatal("untrusted metadata leaked into summaries")
		}
		if len(events) == 1 {
			if _, known := events[0].Attempts(); known {
				t.Fatal("missing retry metadata fabricated an attempt count")
			}
		}
	}
	for _, pair := range [][2]string{{"SSM", "synthetic-secret-operation"}, {"STS", "StartSession"}, {"SSM", "AssumeRole"}, {"EC2", "StartSession"}, {"EC2", "DescribeInstances\x1b[2J"}, {"SSM", "DescribeInstances"}, {"EC2", "TerminateInstances"}} {
		if _, _, allowed := metricLabels(pair[0], pair[1]); allowed {
			t.Fatal("unreviewed service/operation labels accepted")
		}
	}
}

func TestAPIMetricsBoundAndConcurrentDrain(t *testing.T) {
	metrics := &APIMetrics{}
	var workers sync.WaitGroup
	for range 8 {
		workers.Go(func() {
			for range maxAPIMetrics {
				metrics.record(APIMetric{service: "STS", operation: "AssumeRole"})
			}
		})
	}
	workers.Wait()
	events, omitted := metrics.Drain()
	if len(events) != maxAPIMetrics || !omitted {
		t.Fatal("API metrics grew beyond the buffer limit")
	}
	if events, omitted := metrics.Drain(); len(events) != 0 || omitted {
		t.Fatal("drained summaries retained")
	}
	for range 8 {
		workers.Go(func() {
			for range maxAPIMetrics {
				metrics.record(APIMetric{service: "SSM", operation: "GetDocument"})
				metrics.Drain()
			}
		})
	}
	workers.Wait()
	if events, _ := metrics.Drain(); len(events) > maxAPIMetrics {
		t.Fatal("concurrent collector was unbounded")
	}
}
