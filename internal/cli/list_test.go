package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

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
	"ssmh/internal/terminal"
)

type listEC2 func(context.Context, *sdkec2.DescribeInstancesInput) (*sdkec2.DescribeInstancesOutput, error)

func (f listEC2) DescribeInstances(ctx context.Context, in *sdkec2.DescribeInstancesInput, _ ...func(*sdkec2.Options)) (*sdkec2.DescribeInstancesOutput, error) {
	return f(ctx, in)
}

type listSSM func(context.Context, *sdkssm.DescribeInstanceInformationInput) (*sdkssm.DescribeInstanceInformationOutput, error)

func (f listSSM) DescribeInstanceInformation(ctx context.Context, in *sdkssm.DescribeInstanceInformationInput, _ ...func(*sdkssm.Options)) (*sdkssm.DescribeInstanceInformationOutput, error) {
	return f(ctx, in)
}

func listInstance(id, name, state string) ec2types.Instance {
	return ec2types.Instance{InstanceId: sdkaws.String(id), State: &ec2types.InstanceState{Name: ec2types.InstanceStateName(state)}, PrivateIpAddress: sdkaws.String("10.0.0.10"), Tags: []ec2types.Tag{{Key: sdkaws.String("Name"), Value: sdkaws.String(name)}}}
}
func listRegistration(id string, ping types.PingStatus, platform types.PlatformType) types.InstanceInformation {
	return types.InstanceInformation{InstanceId: sdkaws.String(id), ResourceType: types.ResourceTypeEc2Instance, PingStatus: ping, PlatformType: platform, Name: sdkaws.String("ignored-secret"), IPAddress: sdkaws.String("ignored-secret")}
}
func listDependencies(t *testing.T, e ec2.API, s ssm.StatusAPI) (dependencies, *idleClient) {
	t.Helper()
	idle := &idleClient{}
	d := dependencies{
		load: func(ctx context.Context, _ config.Options, _ aws.TokenProvider) (sdkaws.Config, error) {
			if _, ok := ctx.Deadline(); !ok {
				t.Fatal("unbounded listing authentication")
			}
			return sdkaws.Config{Region: "ca-central-1", HTTPClient: idle}, nil
		},
		ec2Client: func(cfg sdkaws.Config) ec2.API {
			if cfg.HTTPClient != idle {
				t.Fatal("EC2 identity/config replaced")
			}
			return e
		},
		statusClient: func(cfg sdkaws.Config) ssm.StatusAPI {
			if cfg.HTTPClient != idle {
				t.Fatal("SSM identity/config replaced")
			}
			return s
		},
		identity: func(ctx context.Context, _ sdkaws.Config) (aws.Identity, error) {
			return aws.ReadIdentity(ctx, cliIdentityAPI{})
		},
		client: func(sdkaws.Config) ssm.API { t.Fatal("listing constructed a session-control client"); return nil },
	}
	return d, idle
}

func TestListJoinsCompleteInventoriesAndKeepsStreamsSeparate(t *testing.T) {
	for _, mode := range []string{"default", "json", "verbose", "debug", "quiet"} {
		t.Run(mode, func(t *testing.T) {
			_, out, stderr := cliFiles(t)
			ecalls, scalls := 0, 0
			e := listEC2(func(ctx context.Context, in *sdkec2.DescribeInstancesInput) (*sdkec2.DescribeInstancesOutput, error) {
				ecalls++
				if ctx.Err() != nil || sdkaws.ToInt32(in.MaxResults) != 100 || len(in.Filters) != 1 || sdkaws.ToString(in.Filters[0].Name) != "instance-state-name" || in.Filters[0].Values[0] != "running" {
					t.Fatal("default query changed")
				}
				if ecalls == 1 {
					return &sdkec2.DescribeInstancesOutput{NextToken: sdkaws.String("ec2-next")}, nil
				}
				if ecalls != 2 || sdkaws.ToString(in.NextToken) != "ec2-next" {
					t.Fatal("EC2 pagination not completed")
				}
				return &sdkec2.DescribeInstancesOutput{Reservations: []ec2types.Reservation{{Instances: []ec2types.Instance{
					listInstance("i-00000000000000003", "offline", "running"), listInstance("i-00000000000000002", "windows", "running"), listInstance(cliTarget, "unregistered", "running"), listInstance("i-00000000000000001", "生产😀\u202e", "running"), listInstance("i-00000000000000004", "stopped", "stopped"),
				}}}}, nil
			})
			s := listSSM(func(ctx context.Context, in *sdkssm.DescribeInstanceInformationInput) (*sdkssm.DescribeInstanceInformationOutput, error) {
				scalls++
				if ctx.Err() != nil || len(in.Filters) != 1 || sdkaws.ToString(in.Filters[0].Key) != "ResourceType" || in.Filters[0].Values[0] != "EC2Instance" {
					t.Fatal("SSM discovery query changed")
				}
				if scalls == 1 {
					return &sdkssm.DescribeInstanceInformationOutput{NextToken: sdkaws.String("ssm-next")}, nil
				}
				if scalls != 2 || sdkaws.ToString(in.NextToken) != "ssm-next" {
					t.Fatal("SSM pagination not completed")
				}
				return &sdkssm.DescribeInstanceInformationOutput{InstanceInformationList: []types.InstanceInformation{
					listRegistration("i-00000000000000001", types.PingStatusOnline, types.PlatformTypeLinux), listRegistration("i-00000000000000002", types.PingStatusOnline, types.PlatformTypeWindows), listRegistration("i-00000000000000003", types.PingStatusConnectionLost, types.PlatformTypeLinux), listRegistration("i-00000000000000009", types.PingStatusOnline, types.PlatformTypeLinux),
				}}, nil
			})
			d, idle := listDependencies(t, e, s)
			identities := 0
			identity := d.identity
			d.identity = func(ctx context.Context, cfg sdkaws.Config) (aws.Identity, error) {
				identities++
				return identity(ctx, cfg)
			}
			args := []string{"--list"}
			if mode != "default" {
				args = append(args, "--"+mode)
			}
			if err := run(context.Background(), args, nil, out, stderr, d); err != nil {
				t.Fatal(err)
			}
			text := cliText(t, out)
			if !idle.closed || ecalls != 2 || scalls != 2 || strings.Contains(text, "ignored-secret") || strings.Contains(text, "unregistered") || strings.Contains(text, "offline") || strings.Contains(text, "stopped") || strings.Contains(text, "\u202e") {
				t.Fatal("join, redaction or cleanup failed")
			}
			if mode == "json" {
				var rows []listRow
				if json.Unmarshal([]byte(text), &rows) != nil || len(rows) != 2 || rows[0].ID != "i-00000000000000001" || rows[0].Name != "生产😀\u202e" || rows[0].Region != "ca-central-1" || rows[1].Platform != "Windows" {
					t.Fatal("JSON schema, exact Unicode or sorting changed")
				}
			} else if !strings.Contains(text, "INSTANCE ID") || !strings.Contains(text, "PRIVATE IP") || !strings.Contains(text, "Windows") {
				t.Fatal("missing listing columns")
			}
			verbose := mode == "verbose" || mode == "debug"
			if verbose && (identities != 1 || !strings.Contains(cliText(t, stderr), "EC2 discovery")) || !verbose && (identities != 0 || cliText(t, stderr) != "") {
				t.Fatal("diagnostics or identity not opt-in")
			}
			if strings.Contains(text, "ssmh:") || strings.Contains(text, "AWS authentication") {
				t.Fatal("diagnostics contaminated listing")
			}
		})
	}
}

func TestListInvalidFiltersDoNotAuthenticate(t *testing.T) {
	for _, args := range [][]string{{"--list", "--tag", "key=a", "--tag", "key=b"}, {"--list", "--name", "a", "--tag", "Name=b"}, {"--list", "--name", strings.Repeat("*", 128)}} {
		_, out, stderr := cliFiles(t)
		d := dependencies{load: func(context.Context, config.Options, aws.TokenProvider) (sdkaws.Config, error) {
			t.Fatal("invalid query authenticated")
			return sdkaws.Config{}, nil
		}}
		if err := run(context.Background(), args, nil, out, stderr, d); err == nil || ExitCode(err) != 2 || cliText(t, out) != "" {
			t.Fatal("invalid filters accepted")
		}
	}
}

func TestListDiscardsResultsAfterLaterFailures(t *testing.T) {
	for _, failure := range []string{"ec2", "ssm", "identity", "canceled"} {
		t.Run(failure, func(t *testing.T) {
			_, out, stderr := cliFiles(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			e := listEC2(func(context.Context, *sdkec2.DescribeInstancesInput) (*sdkec2.DescribeInstancesOutput, error) {
				if failure == "ec2" {
					return nil, errors.New("synthetic-secret")
				}
				return &sdkec2.DescribeInstancesOutput{Reservations: []ec2types.Reservation{{Instances: []ec2types.Instance{listInstance(cliTarget, "name", "running")}}}}, nil
			})
			calls := 0
			s := listSSM(func(context.Context, *sdkssm.DescribeInstanceInformationInput) (*sdkssm.DescribeInstanceInformationOutput, error) {
				calls++
				if failure == "canceled" {
					cancel()
				}
				if calls == 2 {
					return nil, errors.New("synthetic-secret")
				}
				return &sdkssm.DescribeInstanceInformationOutput{InstanceInformationList: []types.InstanceInformation{listRegistration(cliTarget, types.PingStatusOnline, types.PlatformTypeLinux)}, NextToken: sdkaws.String("next")}, nil
			})
			d, idle := listDependencies(t, e, s)
			args := []string{"--list", "--json"}
			if failure == "identity" {
				args = append(args, "--verbose")
				d.identity = func(context.Context, sdkaws.Config) (aws.Identity, error) {
					return aws.Identity{}, errors.New("identity unavailable")
				}
			}
			err := run(ctx, args, nil, out, stderr, d)
			if err == nil || cliText(t, out) != "" || !idle.closed || strings.Contains(err.Error(), "synthetic-secret") || strings.Contains(cliText(t, stderr), "synthetic-secret") {
				t.Fatal("partial result or raw error exposed, or cleanup missed")
			}
		})
	}
}

func TestListSelectedOptionsAndDeadlinePreserved(t *testing.T) {
	_, out, stderr := cliFiles(t)
	e := listEC2(func(ctx context.Context, in *sdkec2.DescribeInstancesInput) (*sdkec2.DescribeInstancesOutput, error) {
		if len(in.Filters) != 3 || in.Filters[0].Values[0] != `prod\*` || in.Filters[1].Values[0] != "stopped" || in.Filters[2].Values[0] != "Production" {
			t.Fatal("explicit filters changed")
		}
		<-ctx.Done()
		return nil, ctx.Err()
	})
	d, idle := listDependencies(t, e, nil)
	load := d.load
	d.load = func(ctx context.Context, o config.Options, token aws.TokenProvider) (sdkaws.Config, error) {
		if o.Profile != "production" || o.RoleARN != "arn:aws:iam::123456789012:role/ReviewedRole" || o.Region != "ca-central-1" {
			t.Fatal("selected identity options changed")
		}
		return load(ctx, o, token)
	}
	err := run(context.Background(), []string{"--list", "--json", "--name", "prod*", "--state", "stopped", "--tag", "Environment=Production", "--profile", "production", "--arn", "arn:aws:iam::123456789012:role/ReviewedRole", "--region", "ca-central-1", "--timeout", "20ms"}, nil, out, stderr, d)
	if !errors.Is(err, context.DeadlineExceeded) || !idle.closed || cliText(t, out) != "" {
		t.Fatalf("setup budget not preserved: %v", err)
	}
}

func TestListEmptyAndBrokenOutput(t *testing.T) {
	for _, broken := range []bool{false, true} {
		_, out, stderr := cliFiles(t)
		e := listEC2(func(context.Context, *sdkec2.DescribeInstancesInput) (*sdkec2.DescribeInstancesOutput, error) {
			return &sdkec2.DescribeInstancesOutput{}, nil
		})
		s := listSSM(func(context.Context, *sdkssm.DescribeInstanceInformationInput) (*sdkssm.DescribeInstanceInformationOutput, error) {
			return &sdkssm.DescribeInstanceInformationOutput{}, nil
		})
		d, idle := listDependencies(t, e, s)
		if broken {
			r, w, err := os.Pipe()
			if err != nil {
				t.Fatal(err)
			}
			r.Close()
			defer w.Close()
			out = w
		}
		err := run(context.Background(), []string{"--list", "--json"}, nil, out, stderr, d)
		if broken {
			if err == nil {
				t.Fatal("broken listing writer succeeded")
			}
		} else if err != nil || cliText(t, out) != "[]\n" {
			t.Fatal("empty inventory not JSON array")
		}
		if !idle.closed {
			t.Fatal("output failure leaked HTTP pool")
		}
	}
}

type listHTTP func(*http.Request) (*http.Response, error)

func (f listHTTP) Do(r *http.Request) (*http.Response, error) { return f(r) }
func TestListThroughActualSDKClients(t *testing.T) {
	_, out, stderr := cliFiles(t)
	calls := 0
	cfg := sdkaws.Config{Region: "ca-central-1", Credentials: credentials.NewStaticCredentialsProvider("synthetic-key", "synthetic-secret", ""), HTTPClient: listHTTP(func(r *http.Request) (*http.Response, error) {
		calls++
		if r.URL.Scheme != "https" || !strings.HasPrefix(r.Header.Get("Authorization"), "AWS4-HMAC-SHA256 ") {
			t.Fatal("unsigned listing API request")
		}
		body := `{"InstanceInformationList":[{"InstanceId":"i-0123456789abcdef0","ResourceType":"EC2Instance","PingStatus":"Online","PlatformType":"Linux"}]}`
		if calls == 1 {
			if r.URL.Host != "ec2.ca-central-1.amazonaws.com" {
				t.Fatal("EC2 region changed")
			}
			body = `<DescribeInstancesResponse xmlns="http://ec2.amazonaws.com/doc/2016-11-15/"><reservationSet><item><instancesSet><item><instanceId>i-0123456789abcdef0</instanceId><instanceState><name>running</name></instanceState><tagSet><item><key>Name</key><value>prod</value></item></tagSet></item></instancesSet></item></reservationSet></DescribeInstancesResponse>`
		} else if calls != 2 || r.URL.Host != "ssm.ca-central-1.amazonaws.com" || r.Header.Get("X-Amz-Target") != "AmazonSSM.DescribeInstanceInformation" {
			t.Fatal("unexpected API request or session operation")
		}
		return &http.Response{StatusCode: 200, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(body)), Request: r}, nil
	})}
	d := production()
	d.load = func(context.Context, config.Options, aws.TokenProvider) (sdkaws.Config, error) { return cfg, nil }
	if err := run(context.Background(), []string{"--list", "--json"}, nil, out, stderr, d); err != nil {
		t.Fatal(err)
	}
	var rows []listRow
	if json.Unmarshal([]byte(cliText(t, out)), &rows) != nil || calls != 2 || len(rows) != 1 || rows[0].Name != "prod" || rows[0].SSM != "Online" {
		t.Fatal("actual SDK join failed")
	}
}

func TestFormatListASCIIJSONPreservesUnicode(t *testing.T) {
	name := "生产😀\u202e\U000e0001"
	data, err := formatList([]listRow{{Name: name}}, true)
	if err != nil {
		t.Fatal(err)
	}
	for _, b := range data {
		if b > 127 {
			t.Fatal("non-ASCII JSON wire data")
		}
	}
	var rows []listRow
	if json.Unmarshal(data, &rows) != nil || rows[0].Name != name {
		t.Fatal("Unicode JSON semantics changed")
	}
	data, err = formatList([]listRow{{Name: name}}, false)
	if err != nil || strings.Contains(string(data), "\u202e") || strings.Contains(string(data), "\U000e0001") {
		t.Fatal("unsafe terminal formatting retained")
	}
}

func TestListBlockedOutputIsBoundedAndDisablesMFA(t *testing.T) {
	_, _, stderr := cliFiles(t)
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	defer w.Close()
	stream, err := terminal.OpenStream(w, true)
	if err != nil {
		t.Fatal(err)
	}
	fill, stopFill := context.WithTimeout(context.Background(), 100*time.Millisecond)
	err = stream.Write(fill, bytes.Repeat([]byte("x"), 1<<20))
	stopFill()
	if closeErr := stream.Close(); err == nil || closeErr != nil {
		t.Fatal("test pipe could not be filled safely")
	}
	e := listEC2(func(context.Context, *sdkec2.DescribeInstancesInput) (*sdkec2.DescribeInstancesOutput, error) {
		return &sdkec2.DescribeInstancesOutput{}, nil
	})
	s := listSSM(func(context.Context, *sdkssm.DescribeInstanceInformationInput) (*sdkssm.DescribeInstanceInformationOutput, error) {
		return &sdkssm.DescribeInstanceInformationOutput{}, nil
	})
	d, idle := listDependencies(t, e, s)
	var callback aws.TokenProvider
	load := d.load
	d.load = func(ctx context.Context, o config.Options, token aws.TokenProvider) (sdkaws.Config, error) {
		callback = token
		return load(ctx, o, token)
	}
	started := time.Now()
	err = run(context.Background(), []string{"--list", "--json", "--timeout", "30ms"}, nil, w, stderr, d)
	if err == nil || !errors.Is(err, context.DeadlineExceeded) || time.Since(started) > 3*time.Second || !idle.closed {
		t.Fatalf("blocked output not bounded/cleaned: %v", err)
	}
	if callback == nil {
		t.Fatal("selected-provider callback missing")
	}
	if token, err := callback(); err == nil || token != "" {
		t.Fatal("MFA prompt allowed after listing")
	}
}
