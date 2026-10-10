package cli

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	sdkaws "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/retry"
	sdkssm "github.com/aws/aws-sdk-go-v2/service/ssm"
	"ssmh/internal/aws"
	"ssmh/internal/config"
	"ssmh/internal/ssm"
	"ssmh/internal/terminal"
)

type diagnosticSDKHTTP struct {
	t                          *testing.T
	starts, ends, availability int
	breakAfterStart            func()
	exactName                  string
	ec2Pages                   int
}

func (h *diagnosticSDKHTTP) Do(request *http.Request) (*http.Response, error) {
	if request.URL.Scheme != "https" || !strings.HasPrefix(request.Header.Get("Authorization"), "AWS4-HMAC-SHA256 ") {
		h.t.Fatal("diagnostic test lost SDK authentication")
	}
	status, body := 200, ""
	switch request.Header.Get("X-Amz-Target") {
	case "":
		if request.URL.Host == "ec2.ca-central-1.amazonaws.com" {
			h.ec2Pages++
			filter, value := "instance-id", cliTarget
			if h.exactName != "" {
				filter, value = "tag:Name", h.exactName
			}
			if err := request.ParseForm(); err != nil || request.Form.Get("Action") != "DescribeInstances" || request.Form.Get("Filter.1.Name") != filter || request.Form.Get("Filter.1.Value.1") != value || request.Form.Get("MaxResults") != "100" {
				h.t.Fatal("unexpected SDK target resolution")
			}
			if h.exactName != "" && h.ec2Pages == 1 {
				body = `<DescribeInstancesResponse xmlns="http://ec2.amazonaws.com/doc/2016-11-15/"><nextToken>next</nextToken></DescribeInstancesResponse>`
			} else {
				if h.exactName != "" && request.Form.Get("NextToken") != "next" {
					h.t.Fatal("SDK Name resolution lost pagination")
				}
				body = `<DescribeInstancesResponse xmlns="http://ec2.amazonaws.com/doc/2016-11-15/"><reservationSet><item><instancesSet><item><instanceId>i-0123456789abcdef0</instanceId><instanceState><name>running</name></instanceState><tagSet><item><key>Name</key><value>web-prod</value></item></tagSet></item></instancesSet></item></reservationSet></DescribeInstancesResponse>`
			}
			break
		}
		if request.URL.Host != "sts.ca-central-1.amazonaws.com" {
			h.t.Fatal("unexpected SDK identity host")
		}
		body = `<GetCallerIdentityResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/"><GetCallerIdentityResult><Account>123456789012</Account><Arn>arn:aws:iam::123456789012:user/unit</Arn><UserId>synthetic-secret-id</UserId></GetCallerIdentityResult></GetCallerIdentityResponse>`
	case "AmazonSSM.DescribeInstanceInformation":
		h.availability++
		if h.availability == 1 {
			status, body = 503, `{"__type":"InternalServerError","Message":"synthetic-secret-error"}`
		} else {
			body = `{"InstanceInformationList":[{"InstanceId":"i-0123456789abcdef0","PingStatus":"Online","PlatformType":"Linux","ResourceType":"EC2Instance"}]}`
		}
	case "AmazonSSM.GetDocument":
		data, err := json.Marshal(map[string]string{
			"Name": "SSM-SessionManagerRunShell", "DocumentType": "Session", "DocumentFormat": "JSON", "Status": "Active",
			"Content": `{"schemaVersion":"1.0","sessionType":"Standard_Stream","inputs":{"kmsKeyId":""}}`,
		})
		if err != nil {
			h.t.Fatal(err)
		}
		body = string(data)
	case "AmazonSSM.StartSession":
		var input sdkssm.StartSessionInput
		if json.NewDecoder(request.Body).Decode(&input) != nil || sdkaws.ToString(input.Target) != cliTarget || h.ec2Pages == 0 || h.exactName != "" && h.ec2Pages != 2 {
			h.t.Fatal("SDK session started before complete EC2 resolution or targeted Name")
		}
		h.starts++
		if h.breakAfterStart != nil {
			h.breakAfterStart()
		}
		body = `{"SessionId":"unit-owned","TokenValue":"synthetic-secret-token","StreamUrl":"wss://ssmmessages.ca-central-1.amazonaws.com/v1/data-channel/unit-owned?role=publish_subscribe"}`
	case "AmazonSSM.TerminateSession":
		h.ends++
		if request.Context().Err() != nil {
			h.t.Fatal("cleanup used a canceled context")
		}
		body = `{}`
	default:
		h.t.Fatal("unexpected SDK operation")
	}
	return &http.Response{StatusCode: status, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(body)), Request: request}, nil
}

func diagnosticSDKDependencies(t *testing.T, httpClient *diagnosticSDKHTTP, channel *cliChannel) dependencies {
	t.Helper()
	for _, key := range []string{"AWS_PROFILE", "AWS_DEFAULT_PROFILE", "AWS_ROLE_ARN", "AWS_WEB_IDENTITY_TOKEN_FILE", "AWS_CONTAINER_CREDENTIALS_FULL_URI", "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI", "AWS_ENDPOINT_URL", "AWS_ENDPOINT_URL_STS", "AWS_ENDPOINT_URL_SSM", "AWS_ENDPOINT_URL_EC2", "AWS_CA_BUNDLE", "AWS_SESSION_TOKEN"} {
		t.Setenv(key, "")
	}
	t.Setenv("AWS_EC2_METADATA_DISABLED", "true")
	t.Setenv("AWS_ACCESS_KEY_ID", "synthetic-key")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "synthetic-secret")
	t.Setenv("AWS_CONFIG_FILE", filepath.Join(t.TempDir(), "absent-config"))
	t.Setenv("AWS_SHARED_CREDENTIALS_FILE", filepath.Join(t.TempDir(), "absent-credentials"))
	d := production()
	d.load = func(ctx context.Context, o config.Options, prompt aws.TokenProvider) (sdkaws.Config, error) {
		cfg, err := aws.Load(ctx, o, prompt)
		if err != nil {
			return sdkaws.Config{}, err
		}
		aws.Close(cfg)
		cfg.HTTPClient = httpClient // Only the network boundary is synthetic.
		cfg.Retryer = func() sdkaws.Retryer {
			return retry.NewStandard(func(o *retry.StandardOptions) {
				o.MaxAttempts = 3
				o.Backoff = retry.BackoffDelayerFunc(func(int, error) (time.Duration, error) { return 0, nil })
			})
		}
		return cfg, nil
	}
	d.connect = cliDeps(nil, channel, nil).connect
	d.run = func(_ context.Context, c terminal.Channel, _, _, _ *os.File) error { return c.Close() }
	return d
}

func TestDebugAPISummariesThroughSDKAndCLI(t *testing.T) {
	for _, mode := range []string{"-v", "--debug"} {
		t.Run(mode, func(t *testing.T) {
			in, out, stderr := cliFiles(t)
			httpClient := &diagnosticSDKHTTP{t: t}
			channel := &cliChannel{}
			d := diagnosticSDKDependencies(t, httpClient, channel)
			err := run(context.Background(), []string{"-i", cliTarget, "-r", "ca-central-1", "--reason", "synthetic-secret-reason", mode}, in, out, stderr, d)
			if err != nil || httpClient.starts != 1 || httpClient.ends != 1 || !channel.closed {
				t.Fatalf("SDK diagnostic lifecycle failed: %v", err)
			}
			text := cliText(t, stderr)
			if !strings.Contains(text, "SDK credential sources: environment\n") {
				t.Fatal("actual SDK provider metadata not reported")
			}
			if cliText(t, out) != "" || strings.Contains(text, "synthetic-secret") {
				t.Fatal("SDK metrics leaked payloads/secrets or polluted stdout")
			}
			if mode == "-v" {
				if strings.Contains(text, "AWS API") {
					t.Fatal("verbose enabled debug API tracing")
				}
				return
			}
			for _, operation := range []string{"STS.GetCallerIdentity", "EC2.DescribeInstances", "SSM.DescribeInstanceInformation", "SSM.GetDocument", "SSM.StartSession", "SSM.TerminateSession"} {
				if strings.Count(text, "AWS API "+operation+": completed") != 1 {
					t.Fatalf("missing or repeated API summary %s", operation)
				}
			}
			if !strings.Contains(text, "attempts=2 retries=1") || !strings.Contains(text, "attempts=1 retries=0") {
				t.Fatal("actual SDK retry counts not reported")
			}
		})
	}
}

func TestNameConnectionThroughActualSDKBoundaries(t *testing.T) {
	in, out, stderr := cliFiles(t)
	httpClient := &diagnosticSDKHTTP{t: t, exactName: "web-prod"}
	channel := &cliChannel{}
	d := diagnosticSDKDependencies(t, httpClient, channel)
	if err := run(context.Background(), []string{"-i", "web-prod", "-r", "ca-central-1", "--quiet"}, in, out, stderr, d); err != nil {
		t.Fatal(err)
	}
	if httpClient.ec2Pages != 2 || httpClient.availability != 2 || httpClient.starts != 1 || httpClient.ends != 1 || !channel.closed || cliText(t, out) != "" || cliText(t, stderr) != "" {
		t.Fatal("SDK exact Name resolution/session cleanup failed")
	}
}

func TestPostStartAPIDiagnosticFailureStillCleansUp(t *testing.T) {
	in, out, _ := cliFiles(t)
	reader, stderr, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	defer stderr.Close()
	httpClient := &diagnosticSDKHTTP{t: t, breakAfterStart: func() {
		if err := reader.Close(); err != nil {
			t.Fatal(err)
		}
	}}
	d := diagnosticSDKDependencies(t, httpClient, &cliChannel{})
	d.connect = func(context.Context, sdkaws.Config, *ssm.Session, string, time.Duration) (terminal.Channel, error) {
		t.Fatal("channel establishment continued after diagnostic failure")
		return nil, nil
	}
	err = run(context.Background(), []string{"-i", cliTarget, "-r", "ca-central-1", "--debug"}, in, out, stderr, d)
	if err == nil || httpClient.starts != 1 || httpClient.ends != 1 || strings.Contains(err.Error(), "synthetic-secret") {
		t.Fatal("post-Start reporting failure masked ownership or skipped cleanup")
	}
}

func TestAPIDiagnosticOverflowIsExplicitAndBounded(t *testing.T) {
	in, out, stderr := cliFiles(t)
	httpClient := &diagnosticSDKHTTP{t: t}
	channel := &cliChannel{}
	d := diagnosticSDKDependencies(t, httpClient, channel)
	load := d.load
	var cfg sdkaws.Config
	d.load = func(ctx context.Context, o config.Options, prompt aws.TokenProvider) (sdkaws.Config, error) {
		var err error
		cfg, err = load(ctx, o, prompt)
		return cfg, err
	}
	d.run = func(ctx context.Context, c terminal.Channel, _, _, _ *os.File) error {
		client := sdkssm.NewFromConfig(cfg)
		for range 100 {
			if _, err := client.GetDocument(ctx, &sdkssm.GetDocumentInput{Name: sdkaws.String("SSM-SessionManagerRunShell")}); err != nil {
				return err
			}
		}
		return c.Close()
	}
	if err := run(context.Background(), []string{"-i", cliTarget, "-r", "ca-central-1", "--debug"}, in, out, stderr, d); err != nil {
		t.Fatal(err)
	}
	text := cliText(t, stderr)
	// One preflight document read, plus at most 64 pending remote-stage summaries.
	if strings.Count(text, "AWS API SSM.GetDocument:") != 65 || strings.Count(text, "additional AWS API diagnostics omitted") != 1 || httpClient.ends != 1 || cliText(t, out) != "" {
		t.Fatal("overflow was silent, unbounded, or prevented cleanup")
	}
}
