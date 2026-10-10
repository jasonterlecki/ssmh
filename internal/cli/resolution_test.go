package cli

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	sdkaws "github.com/aws/aws-sdk-go-v2/aws"
	sdkec2 "github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	sdkssm "github.com/aws/aws-sdk-go-v2/service/ssm"
	"github.com/aws/aws-sdk-go-v2/service/ssm/types"
	"ssmh/internal/aws"
	"ssmh/internal/config"
	"ssmh/internal/ec2"
	"ssmh/internal/ssm"
	"ssmh/internal/terminal"
	"ssmh/internal/transport/native"
)

type resolvedSessionAPI struct {
	*cliAPI
	t *testing.T
}

func (a resolvedSessionAPI) DescribeInstanceInformation(ctx context.Context, in *sdkssm.DescribeInstanceInformationInput, options ...func(*sdkssm.Options)) (*sdkssm.DescribeInstanceInformationOutput, error) {
	if len(in.Filters) != 1 || sdkaws.ToString(in.Filters[0].Key) != "InstanceIds" || len(in.Filters[0].Values) != 1 || in.Filters[0].Values[0] != cliTarget {
		a.t.Fatal("unresolved Name reached SSM availability")
	}
	return a.cliAPI.DescribeInstanceInformation(ctx, in, options...)
}

func TestAllSessionModesResolveExactTargetUsingSelectedConfig(t *testing.T) {
	const name = "生产*?\\\u202e"
	for _, mode := range []string{"shell", "command", "forward", "forward-host"} {
		for _, target := range []string{cliTarget, name} {
			t.Run(mode+"/"+target, func(t *testing.T) {
				in, out, stderr := cliFiles(t)
				a := &cliAPI{platform: types.PlatformTypeLinux}
				c, idle := &cliChannel{}, &idleClient{}
				l := &cliForwardListener{port: 8080}
				d := cliDeps(a, c, idle)
				args := []string{"-i", target, "--profile", "selected", "--arn", "arn:aws:iam::123456789012:role/ReviewedRole", "--reason", "selected reason", "--debug"}
				switch mode {
				case "command":
					a.documentContent = cliCommandDocument
					args = append(args, "-c", "printf '生产'", "--document", "SafeCommand")
					commandOutput := &commandChannel{messages: []native.Message{{PayloadType: native.ExitCode, Payload: []byte("EXIT_CODE: 0")}}}
					d.connect = func(_ context.Context, _ sdkaws.Config, _ *ssm.Session, kind string, _ time.Duration) (terminal.Channel, error) {
						if kind != "NonInteractiveCommands" {
							t.Fatal("command type changed")
						}
						return commandOutput, nil
					}
				case "forward", "forward-host":
					d = forwardDeps(t, a, c, l, idle)
					if mode == "forward" {
						args = append(args, "-L", "8080:80")
					} else {
						args = append(args, "--forward-host", "8080:database.internal:5432")
					}
				}
				loads, pages, clients := 0, 0, 0
				d.load = func(ctx context.Context, o config.Options, _ aws.TokenProvider) (sdkaws.Config, error) {
					loads++
					if o.Profile != "selected" || o.RoleARN != "arn:aws:iam::123456789012:role/ReviewedRole" || ctx.Err() != nil {
						t.Fatal("authentication selection changed")
					}
					return sdkaws.Config{Region: "ca-central-1", HTTPClient: idle}, nil
				}
				d.ec2Client = func(cfg sdkaws.Config) ec2.API {
					if cfg.HTTPClient != idle || cfg.Region != "ca-central-1" {
						t.Fatal("EC2 config replaced")
					}
					return listEC2(func(ctx context.Context, request *sdkec2.DescribeInstancesInput) (*sdkec2.DescribeInstancesOutput, error) {
						pages++
						filter, value := "instance-id", target
						if target == name {
							filter, value = "tag:Name", "生产\\*\\?\\\\\u202e"
						}
						if ctx.Err() != nil || sdkaws.ToInt32(request.MaxResults) != 100 || len(request.Filters) != 1 || sdkaws.ToString(request.Filters[0].Name) != filter || len(request.Filters[0].Values) != 1 || request.Filters[0].Values[0] != value || len(request.InstanceIds) != 0 {
							t.Fatal("exact paginated filter changed")
						}
						if pages == 1 {
							return &sdkec2.DescribeInstancesOutput{NextToken: sdkaws.String("next")}, nil
						}
						if pages != 2 || sdkaws.ToString(request.NextToken) != "next" {
							t.Fatal("resolution pagination incomplete")
						}
						return &sdkec2.DescribeInstancesOutput{Reservations: []ec2types.Reservation{{Instances: []ec2types.Instance{listInstance(cliTarget, name, "running")}}}}, nil
					})
				}
				d.client = func(cfg sdkaws.Config) ssm.API {
					clients++
					if pages != 2 || cfg.HTTPClient != idle {
						t.Fatal("SSM constructed before complete selected-config resolution")
					}
					return resolvedSessionAPI{a, t}
				}
				if err := run(context.Background(), args, in, out, stderr, d); err != nil {
					t.Fatal(err)
				}
				if loads != 1 || clients != 1 || a.checks != 1 || a.starts != 1 || a.terminates != 1 || !idle.closed || sdkaws.ToString(a.request.Target) != cliTarget || sdkaws.ToString(a.request.Reason) != "selected reason" {
					t.Fatal("resolved lifecycle/cleanup changed")
				}
				if strings.Contains(cliText(t, stderr), name) || !strings.Contains(cliText(t, stderr), cliTarget) || !strings.Contains(cliText(t, stderr), "EC2 discovery: completed") {
					t.Fatal("Name leaked or resolution diagnostic missing")
				}
				if mode != "command" && cliText(t, out) != "" {
					t.Fatal("resolution polluted stdout")
				}
			})
		}
	}
}

func TestResolutionFailuresNeverConstructSessionClient(t *testing.T) {
	for _, mode := range []string{"shell", "command", "forward", "forward-host"} {
		for _, failure := range []string{"missing", "ambiguous", "stopped", "malformed", "later-error", "later-duplicate", "cycle", "timeout", "cancel"} {
			t.Run(mode+"/"+failure, func(t *testing.T) {
				in, out, stderr := cliFiles(t)
				a, c, idle := &cliAPI{platform: types.PlatformTypeLinux}, &cliChannel{}, &idleClient{}
				l := &cliForwardListener{port: 8080}
				d := cliDeps(a, c, idle)
				args := []string{"-i", "exact-name", "--quiet"}
				if mode == "command" {
					args = append(args, "-c", "uname -a")
				}
				if mode == "forward" || mode == "forward-host" {
					d = forwardDeps(t, a, c, l, idle)
					if mode == "forward" {
						args = append(args, "-L", "8080:80")
					} else {
						args = append(args, "--forward-host", "8080:database.internal:5432")
					}
				}
				if failure == "timeout" {
					args = append(args, "--timeout", "20ms")
				}
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				pages := 0
				d.ec2Client = func(sdkaws.Config) ec2.API {
					return listEC2(func(ctx context.Context, _ *sdkec2.DescribeInstancesInput) (*sdkec2.DescribeInstancesOutput, error) {
						pages++
						response := &sdkec2.DescribeInstancesOutput{Reservations: []ec2types.Reservation{{Instances: []ec2types.Instance{listInstance(cliTarget, "exact-name", "running")}}}}
						switch failure {
						case "missing":
							response.Reservations = nil
						case "ambiguous":
							response.Reservations[0].Instances = append(response.Reservations[0].Instances, listInstance("i-00000000000000002", "exact-name", "stopped"))
						case "stopped":
							response.Reservations[0].Instances[0].State.Name = ec2types.InstanceStateNameStopped
						case "malformed":
							response.Reservations[0].Instances[0].InstanceId = sdkaws.String("unsafe-secret")
						case "timeout":
							<-ctx.Done()
							return nil, ctx.Err()
						case "cancel":
							cancel()
						case "later-error", "later-duplicate", "cycle":
							response.NextToken = sdkaws.String("next")
							if pages == 2 {
								if failure == "later-error" {
									return nil, errors.New("unsafe-secret")
								}
								if failure == "later-duplicate" {
									response.NextToken = nil
									response.Reservations[0].Instances[0] = listInstance("i-00000000000000002", "exact-name", "stopped")
								} else {
									response.Reservations = nil
								}
							}
						}
						return response, nil
					})
				}
				d.client = func(sdkaws.Config) ssm.API {
					t.Fatal("failed resolution constructed session-control client")
					return nil
				}
				err := run(ctx, args, in, out, stderr, d)
				if err == nil || a.starts != 0 || a.terminates != 0 || a.checks != 0 || c.closed || !idle.closed || cliText(t, out) != "" || strings.Contains(err.Error(), "unsafe-secret") {
					t.Fatal("resolution failure escaped ownership/redaction boundary")
				}
				if (mode == "forward" || mode == "forward-host") && l.closed != 1 {
					t.Fatal("reserved listener leaked")
				}
				if failure == "timeout" && !errors.Is(err, context.DeadlineExceeded) || failure == "cancel" && !errors.Is(err, context.Canceled) {
					t.Fatal("resolution cancellation lost")
				}
			})
		}
	}
}

func TestNameFilterLimitsFailBeforeAuthentication(t *testing.T) {
	_, out, stderr := cliFiles(t)
	d := dependencies{load: func(context.Context, config.Options, aws.TokenProvider) (sdkaws.Config, error) {
		t.Fatal("invalid exact filter authenticated")
		return sdkaws.Config{}, nil
	}}
	err := run(context.Background(), []string{"-i", strings.Repeat("*", 128), "-c", "uname -a"}, nil, out, stderr, d)
	if err == nil || ExitCode(err) != 2 {
		t.Fatal("escaped filter bound bypassed")
	}
}
