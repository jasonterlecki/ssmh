package cli

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"

	sdkaws "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	sdkec2 "github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	sdkssm "github.com/aws/aws-sdk-go-v2/service/ssm"
	"github.com/aws/aws-sdk-go-v2/service/ssm/types"
	"ssmh/internal/aws"
	"ssmh/internal/config"
	"ssmh/internal/ec2"
	"ssmh/internal/ssm"
)

func checkDependencies(t *testing.T, state string, ping types.PingStatus, platform types.PlatformType) (dependencies, *idleClient, *cliAPI) {
	t.Helper()
	e := listEC2(func(ctx context.Context, in *sdkec2.DescribeInstancesInput) (*sdkec2.DescribeInstancesOutput, error) {
		if _, ok := ctx.Deadline(); !ok {
			t.Fatal("check lacks setup budget")
		}
		if sdkaws.ToInt32(in.MaxResults) != 100 || len(in.Filters) != 1 || len(in.InstanceIds) != 0 {
			t.Fatal("unbounded or unexpected EC2 query")
		}
		return &sdkec2.DescribeInstancesOutput{Reservations: []ec2types.Reservation{{Instances: []ec2types.Instance{listInstance(cliTarget, "生产😀\u202e", state)}}}}, nil
	})
	s := listSSM(func(ctx context.Context, in *sdkssm.DescribeInstanceInformationInput) (*sdkssm.DescribeInstanceInformationOutput, error) {
		if ctx.Err() != nil || len(in.Filters) != 1 || sdkaws.ToString(in.Filters[0].Key) != "InstanceIds" || len(in.Filters[0].Values) != 1 || in.Filters[0].Values[0] != cliTarget {
			t.Fatal("SSM check not exact resolved ID")
		}
		return &sdkssm.DescribeInstanceInformationOutput{InstanceInformationList: []types.InstanceInformation{listRegistration(cliTarget, ping, platform)}}, nil
	})
	d, idle := listDependencies(t, e, s)
	doc := &cliAPI{}
	d.documentClient = func(cfg sdkaws.Config) ssm.DocumentAPI {
		if cfg.HTTPClient != idle {
			t.Fatal("document config changed")
		}
		return doc
	}
	return d, idle, doc
}

func TestCheckReadOnlyPrerequisitesAndOutput(t *testing.T) {
	for _, mode := range []string{"default", "json", "verbose", "debug", "quiet"} {
		for _, target := range []string{cliTarget, "生产😀\u202e"} {
			_, out, stderr := cliFiles(t)
			d, idle, doc := checkDependencies(t, "running", types.PingStatusOnline, types.PlatformTypeLinux)
			args := []string{"--check", "-i", target, "--profile", "production"}
			if mode != "default" {
				args = append(args, "--"+mode)
			}
			if err := run(context.Background(), args, nil, out, stderr, d); err != nil {
				t.Fatal(err)
			}
			text := cliText(t, out)
			if !idle.closed || doc.starts != 0 || doc.terminates != 0 || sdkaws.ToString(doc.documentRequest.Name) != "SSM-SessionManagerRunShell" || strings.Contains(text, "\u202e") || strings.Contains(text, "ignored-secret") {
				t.Fatal("check ownership, document or redaction failed")
			}
			if mode == "json" {
				var report checkReport
				if json.Unmarshal([]byte(text), &report) != nil || !report.Ready || report.SessionPermissionsVerified || report.Backend != "native" || report.Profile != "production" || report.Account != "123456789012" || report.Instance.ID != cliTarget || report.Instance.Name != "生产😀\u202e" || report.Instance.State != "running" || report.IdentityStatus != "available" {
					t.Fatal("incorrect readiness JSON")
				}
			} else if !strings.Contains(text, "Prerequisites passed") || !strings.Contains(text, "not verified") || !strings.Contains(text, "SSM Status: Online") {
				t.Fatal("missing actionable prerequisite/permission distinction")
			}
			if strings.Contains(text, "ssmh:") || (mode == "verbose" || mode == "debug") != (cliText(t, stderr) != "") {
				t.Fatal("check stream separation failed")
			}
		}
	}
}

func TestCheckFailuresNeverStartOrReportReady(t *testing.T) {
	for _, failure := range []string{"auth", "identity", "malformed identity", "expired", "stopped", "offline", "unregistered", "windows", "kms", "document", "ambiguous", "ec2 error", "late ssm error", "canceled"} {
		t.Run(failure, func(t *testing.T) {
			_, out, stderr := cliFiles(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			d, idle, doc := checkDependencies(t, "running", types.PingStatusOnline, types.PlatformTypeLinux)
			switch failure {
			case "auth":
				d.load = func(context.Context, config.Options, aws.TokenProvider) (sdkaws.Config, error) {
					return sdkaws.Config{}, errors.New("authentication failed")
				}
			case "identity", "expired":
				d.identity = func(context.Context, sdkaws.Config) (aws.Identity, error) {
					return aws.Identity{}, errors.New("authentication or identity failed")
				}
			case "malformed identity":
				d.identity = func(context.Context, sdkaws.Config) (aws.Identity, error) { return aws.Identity{}, nil }
			case "stopped":
				d, idle, doc = checkDependencies(t, "stopped", types.PingStatusOnline, types.PlatformTypeLinux)
			case "offline":
				d, idle, doc = checkDependencies(t, "running", types.PingStatusConnectionLost, types.PlatformTypeLinux)
			case "windows":
				d, idle, doc = checkDependencies(t, "running", types.PingStatusOnline, types.PlatformTypeWindows)
			case "unregistered":
				d.statusClient = func(sdkaws.Config) ssm.StatusAPI {
					return listSSM(func(context.Context, *sdkssm.DescribeInstanceInformationInput) (*sdkssm.DescribeInstanceInformationOutput, error) {
						return &sdkssm.DescribeInstanceInformationOutput{}, nil
					})
				}
			case "kms":
				doc.documentContent = `{"schemaVersion":"1.0","sessionType":"Standard_Stream","inputs":{"kmsKeyId":"synthetic-secret"}}`
			case "document":
				doc.documentErr = errors.New("synthetic-secret")
			case "ambiguous":
				d.ec2Client = func(sdkaws.Config) ec2.API {
					return listEC2(func(context.Context, *sdkec2.DescribeInstancesInput) (*sdkec2.DescribeInstancesOutput, error) {
						return &sdkec2.DescribeInstancesOutput{Reservations: []ec2types.Reservation{{Instances: []ec2types.Instance{listInstance(cliTarget, "name", "running"), listInstance("i-00000000000000001", "name", "stopped")}}}}, nil
					})
				}
			case "ec2 error":
				d.ec2Client = func(sdkaws.Config) ec2.API {
					return listEC2(func(context.Context, *sdkec2.DescribeInstancesInput) (*sdkec2.DescribeInstancesOutput, error) {
						return nil, errors.New("synthetic-secret")
					})
				}
			case "late ssm error":
				calls := 0
				d.statusClient = func(sdkaws.Config) ssm.StatusAPI {
					return listSSM(func(context.Context, *sdkssm.DescribeInstanceInformationInput) (*sdkssm.DescribeInstanceInformationOutput, error) {
						calls++
						if calls == 2 {
							return nil, errors.New("synthetic-secret")
						}
						return &sdkssm.DescribeInstanceInformationOutput{InstanceInformationList: []types.InstanceInformation{listRegistration(cliTarget, types.PingStatusOnline, types.PlatformTypeLinux)}, NextToken: sdkaws.String("next")}, nil
					})
				}
			case "canceled":
				cancel()
			}
			args := []string{"--check", "--json", "-i", cliTarget}
			if failure == "ambiguous" {
				args[3] = "name"
			}
			err := run(ctx, args, nil, out, stderr, d)
			if err == nil || cliText(t, out) != "" || doc.starts != 0 || doc.terminates != 0 || strings.Contains(err.Error(), "synthetic-secret") || failure != "auth" && !idle.closed {
				t.Fatalf("unsafe or incomplete readiness accepted: %v", err)
			}
		})
	}
}

func TestCheckIdentityDeniedPreservesSelectedProvider(t *testing.T) {
	_, out, stderr := cliFiles(t)
	d, idle, _ := checkDependencies(t, "running", types.PingStatusOnline, types.PlatformTypeLinux)
	d.identity = func(_ context.Context, cfg sdkaws.Config) (aws.Identity, error) {
		if cfg.HTTPClient != idle {
			t.Fatal("identity config changed")
		}
		return aws.Identity{}, aws.ErrIdentityDenied
	}
	load := d.load
	d.load = func(ctx context.Context, o config.Options, token aws.TokenProvider) (sdkaws.Config, error) {
		if o.RoleARN != "arn:aws:iam::123456789012:role/ReviewedRole" || o.Profile != "production" {
			t.Fatal("selected role/profile changed")
		}
		return load(ctx, o, token)
	}
	if err := run(context.Background(), []string{"--check", "--json", "-i", cliTarget, "--profile", "production", "--arn", "arn:aws:iam::123456789012:role/ReviewedRole"}, nil, out, stderr, d); err != nil {
		t.Fatal(err)
	}
	var report checkReport
	if json.Unmarshal([]byte(cliText(t, out)), &report) != nil || !report.Ready || report.IdentityStatus != "unavailable_access_denied" || report.Account != "" || report.Identity != "" || report.SessionPermissionsVerified || !idle.closed {
		t.Fatal("identity denial was masked or changed readiness claims")
	}
}

func TestCheckDeadlineBrokenOutputAndMFAClosure(t *testing.T) {
	for _, mode := range []string{"deadline", "broken output"} {
		_, out, stderr := cliFiles(t)
		d, idle, _ := checkDependencies(t, "running", types.PingStatusOnline, types.PlatformTypeLinux)
		var callback aws.TokenProvider
		load := d.load
		d.load = func(ctx context.Context, o config.Options, token aws.TokenProvider) (sdkaws.Config, error) {
			callback = token
			return load(ctx, o, token)
		}
		if mode == "deadline" {
			d.identity = func(ctx context.Context, _ sdkaws.Config) (aws.Identity, error) {
				<-ctx.Done()
				return aws.Identity{}, errors.Join(ctx.Err(), aws.ErrIdentityDenied)
			}
		} else {
			r, w, err := os.Pipe()
			if err != nil {
				t.Fatal(err)
			}
			r.Close()
			defer w.Close()
			out = w
		}
		err := run(context.Background(), []string{"--check", "--json", "-i", cliTarget, "--timeout", "30ms"}, nil, out, stderr, d)
		if err == nil || !idle.closed || mode == "deadline" && !errors.Is(err, context.DeadlineExceeded) {
			t.Fatal("check cancellation or output failure hidden")
		}
		if token, err := callback(); token != "" || err == nil {
			t.Fatal("MFA allowed after check")
		}
	}
}

func TestCheckThroughSDKReadsOnly(t *testing.T) {
	for _, denied := range []bool{false, true} {
		_, out, stderr := cliFiles(t)
		calls := 0
		cfg := sdkaws.Config{Region: "ca-central-1", Credentials: sdkaws.NewCredentialsCache(credentials.NewStaticCredentialsProvider("synthetic-selected-key", "synthetic-secret", "")), HTTPClient: listHTTP(func(r *http.Request) (*http.Response, error) {
			calls++
			if r.URL.Scheme != "https" || !strings.Contains(r.Header.Get("Authorization"), "Credential=synthetic-selected-key/") {
				t.Fatal("SDK changed selected identity or TLS endpoint")
			}
			code := 200
			var body string
			switch calls {
			case 1:
				if r.URL.Host != "sts.ca-central-1.amazonaws.com" {
					t.Fatal("identity read not regional STS")
				}
				body = `<GetCallerIdentityResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/"><GetCallerIdentityResult><Account>123456789012</Account><Arn>arn:aws:iam::123456789012:user/operator</Arn></GetCallerIdentityResult></GetCallerIdentityResponse>`
				if denied {
					code = 403
					body = `<ErrorResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/"><Error><Code>AccessDenied</Code><Message>synthetic-secret</Message></Error></ErrorResponse>`
				}
			case 2:
				if r.URL.Host != "ec2.ca-central-1.amazonaws.com" {
					t.Fatal("EC2 read region changed")
				}
				body = `<DescribeInstancesResponse xmlns="http://ec2.amazonaws.com/doc/2016-11-15/"><reservationSet><item><instancesSet><item><instanceId>i-0123456789abcdef0</instanceId><instanceState><name>running</name></instanceState></item></instancesSet></item></reservationSet></DescribeInstancesResponse>`
			case 3:
				if r.Header.Get("X-Amz-Target") != "AmazonSSM.DescribeInstanceInformation" {
					t.Fatal("unexpected SSM operation")
				}
				body = `{"InstanceInformationList":[{"InstanceId":"i-0123456789abcdef0","ResourceType":"EC2Instance","PingStatus":"Online","PlatformType":"Linux"}]}`
			case 4:
				if r.Header.Get("X-Amz-Target") != "AmazonSSM.GetDocument" {
					t.Fatal("unexpected document or session operation")
				}
				body = `{"Name":"SSM-SessionManagerRunShell","DocumentType":"Session","DocumentFormat":"JSON","Status":"Active","Content":"{\"schemaVersion\":\"1.0\",\"sessionType\":\"Standard_Stream\",\"inputs\":{\"kmsKeyId\":\"\"}}"}`
			default:
				t.Fatal("check started a session or retried another identity")
			}
			return &http.Response{StatusCode: code, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(body)), Request: r}, nil
		})}
		d := production()
		d.load = func(context.Context, config.Options, aws.TokenProvider) (sdkaws.Config, error) { return cfg, nil }
		if err := run(context.Background(), []string{"--check", "--json", "-i", cliTarget}, nil, out, stderr, d); err != nil {
			t.Fatal(err)
		}
		if calls != 4 || strings.Contains(cliText(t, out)+cliText(t, stderr), "synthetic-secret") {
			t.Fatal("read-only SDK check or redaction failed")
		}
	}
}
