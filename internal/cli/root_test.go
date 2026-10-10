package cli

import (
	"context"
	"errors"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	sdkaws "github.com/aws/aws-sdk-go-v2/aws"
	sdkec2 "github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	sdkssm "github.com/aws/aws-sdk-go-v2/service/ssm"
	"github.com/aws/aws-sdk-go-v2/service/ssm/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"ssmh/internal/aws"
	"ssmh/internal/config"
	"ssmh/internal/ec2"
	"ssmh/internal/ssm"
	"ssmh/internal/terminal"
	"ssmh/internal/transport/native"
)

const cliTarget = "i-0123456789abcdef0"

type cliIdentityAPI struct{}

func (cliIdentityAPI) GetCallerIdentity(context.Context, *sts.GetCallerIdentityInput, ...func(*sts.Options)) (*sts.GetCallerIdentityOutput, error) {
	return &sts.GetCallerIdentityOutput{Account: sdkaws.String("123456789012"), Arn: sdkaws.String("arn:aws:sts::123456789012:assumed-role/ReviewedRole/unit-session")}, nil
}

type cliAPI struct {
	onCleanup                      func()
	starts, terminates, checks     int
	startErr, cleanupErr, checkErr error
	request                        *sdkssm.StartSessionInput
	cleanupActive                  bool
	platform                       types.PlatformType
	documentErr                    error
	documentContent                string
	documentRequest                *sdkssm.GetDocumentInput
}

func (a *cliAPI) GetDocument(_ context.Context, in *sdkssm.GetDocumentInput, _ ...func(*sdkssm.Options)) (*sdkssm.GetDocumentOutput, error) {
	a.documentRequest = in
	content := a.documentContent
	if content == "" {
		content = `{"schemaVersion":"1.0","sessionType":"Standard_Stream","inputs":{"kmsKeyId":""}}`
	}
	name := sdkaws.ToString(in.Name)
	name = name[strings.LastIndex(name, "/")+1:]
	return &sdkssm.GetDocumentOutput{Name: sdkaws.String(name), Content: sdkaws.String(content), DocumentType: types.DocumentTypeSession, DocumentFormat: types.DocumentFormatJson, Status: types.DocumentStatusActive}, a.documentErr
}

func (a *cliAPI) StartSession(_ context.Context, in *sdkssm.StartSessionInput, _ ...func(*sdkssm.Options)) (*sdkssm.StartSessionOutput, error) {
	a.starts++
	a.request = in
	if a.startErr != nil {
		return nil, a.startErr
	}
	return &sdkssm.StartSessionOutput{SessionId: sdkaws.String("unit-owned"), StreamUrl: sdkaws.String("wss://ssmmessages.ca-central-1.amazonaws.com/v1/data-channel/unit-owned?role=publish_subscribe"), TokenValue: sdkaws.String("synthetic-token")}, nil
}
func (a *cliAPI) TerminateSession(ctx context.Context, in *sdkssm.TerminateSessionInput, _ ...func(*sdkssm.Options)) (*sdkssm.TerminateSessionOutput, error) {
	if a.onCleanup != nil {
		a.onCleanup()
	}
	a.terminates++
	a.cleanupActive = ctx.Err() == nil && sdkaws.ToString(in.SessionId) == "unit-owned"
	return &sdkssm.TerminateSessionOutput{}, a.cleanupErr
}
func (a *cliAPI) DescribeInstanceInformation(_ context.Context, _ *sdkssm.DescribeInstanceInformationInput, _ ...func(*sdkssm.Options)) (*sdkssm.DescribeInstanceInformationOutput, error) {
	a.checks++
	if a.checkErr != nil {
		return nil, a.checkErr
	}
	return &sdkssm.DescribeInstanceInformationOutput{InstanceInformationList: []types.InstanceInformation{{InstanceId: sdkaws.String(cliTarget), PingStatus: types.PingStatusOnline, PlatformType: a.platform, ResourceType: types.ResourceTypeEc2Instance}}}, nil
}

type cliChannel struct{ closed bool }

func (c *cliChannel) Send(context.Context, uint32, []byte) error { return nil }
func (c *cliChannel) Receive(context.Context) (native.Message, error) {
	return native.Message{}, io.EOF
}
func (c *cliChannel) Close() error { c.closed = true; return nil }

type idleClient struct{ closed bool }

func (*idleClient) Do(*http.Request) (*http.Response, error) {
	return nil, errors.New("unexpected HTTP request")
}
func (c *idleClient) CloseIdleConnections() { c.closed = true }

func cliFiles(t *testing.T) (*os.File, *os.File, *os.File) {
	t.Helper()
	files := make([]*os.File, 3)
	for i := range files {
		f, err := os.CreateTemp(t.TempDir(), "stdio")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { f.Close() })
		files[i] = f
	}
	return files[0], files[1], files[2]
}
func cliText(t *testing.T, f *os.File) string {
	t.Helper()
	stat, err := f.Stat()
	if err != nil {
		t.Fatal(err)
	}
	b := make([]byte, stat.Size())
	_, err = f.ReadAt(b, 0)
	if err != nil && err != io.EOF {
		t.Fatal(err)
	}
	return string(b)
}
func cliDeps(api *cliAPI, channel *cliChannel, httpClient *idleClient) dependencies {
	return dependencies{
		identity: func(ctx context.Context, _ sdkaws.Config) (aws.Identity, error) {
			return aws.ReadIdentity(ctx, cliIdentityAPI{})
		},
		load: func(context.Context, config.Options, aws.TokenProvider) (sdkaws.Config, error) {
			return sdkaws.Config{Region: "ca-central-1", HTTPClient: httpClient}, nil
		},
		client: func(sdkaws.Config) ssm.API { return api },
		ec2Client: func(sdkaws.Config) ec2.API {
			return listEC2(func(context.Context, *sdkec2.DescribeInstancesInput) (*sdkec2.DescribeInstancesOutput, error) {
				return &sdkec2.DescribeInstancesOutput{Reservations: []ec2types.Reservation{{Instances: []ec2types.Instance{listInstance(cliTarget, "unit", "running")}}}}, nil
			})
		},
		connect: func(context.Context, sdkaws.Config, *ssm.Session, string, time.Duration) (terminal.Channel, error) {
			return channel, nil
		},
		run: func(_ context.Context, c terminal.Channel, _, _, _ *os.File) error { return c.Close() },
	}
}

func TestHelpVersionAndUnsupportedDoNotAuthenticate(t *testing.T) {
	for _, args := range [][]string{{"--help"}, {"--version"}, {"--list", "--backend", "plugin"}, {"-i", cliTarget, "--check", "--backend", "plugin"}, {"-i", "server-name", "--backend", "plugin"}, {"-i", cliTarget, "--backend", "plugin"}, {"-i", cliTarget, "-L", "8080:80", "--backend", "plugin"}} {
		in, out, stderr := cliFiles(t)
		d := dependencies{load: func(context.Context, config.Options, aws.TokenProvider) (sdkaws.Config, error) {
			t.Fatal("unsupported/help invoked AWS")
			return sdkaws.Config{}, nil
		}}
		err := run(context.Background(), args, in, out, stderr, d)
		if args[0] == "--help" || args[0] == "--version" {
			if err != nil || cliText(t, out) == "" || cliText(t, stderr) != "" {
				t.Fatalf("help/version: %v", err)
			}
		} else if err == nil || ExitCode(err) != 2 || cliText(t, out) != "" {
			t.Fatal("unsupported operation not explicitly refused")
		}
	}
}

func TestLifecycleSuccessAndRequestPreservation(t *testing.T) {
	in, out, stderr := cliFiles(t)
	api := &cliAPI{platform: types.PlatformTypeLinux}
	channel := &cliChannel{}
	httpClient := &idleClient{}
	d := cliDeps(api, channel, httpClient)
	err := run(context.Background(), []string{"-i", cliTarget, "--document", "CustomShell", "--reason", "Unit check", "-v"}, in, out, stderr, d)
	if err != nil {
		t.Fatal(err)
	}
	if api.starts != 1 || api.terminates != 1 || !api.cleanupActive || !channel.closed || !httpClient.closed {
		t.Fatal("incomplete owned cleanup")
	}
	if sdkaws.ToString(api.request.DocumentName) != "CustomShell" || sdkaws.ToString(api.request.Reason) != "Unit check" {
		t.Fatal("request altered")
	}
	if cliText(t, out) != "" || !strings.Contains(cliText(t, stderr), "native SSM shell") {
		t.Fatal("stdout polluted or diagnostics missing")
	}
}

func TestLifecycleFailureStages(t *testing.T) {
	for _, stage := range []string{"auth", "availability", "start", "handshake", "terminal"} {
		t.Run(stage, func(t *testing.T) {
			in, out, stderr := cliFiles(t)
			api := &cliAPI{platform: types.PlatformTypeLinux}
			channel := &cliChannel{}
			httpClient := &idleClient{}
			d := cliDeps(api, channel, httpClient)
			errSynthetic := errors.New("synthetic failure")
			switch stage {
			case "auth":
				d.load = func(context.Context, config.Options, aws.TokenProvider) (sdkaws.Config, error) {
					return sdkaws.Config{}, errSynthetic
				}
			case "availability":
				api.checkErr = errSynthetic
			case "start":
				api.startErr = errSynthetic
			case "handshake":
				d.connect = func(context.Context, sdkaws.Config, *ssm.Session, string, time.Duration) (terminal.Channel, error) {
					return nil, errSynthetic
				}
			case "terminal":
				d.run = func(_ context.Context, c terminal.Channel, _, _, _ *os.File) error {
					return errors.Join(errSynthetic, c.Close())
				}
			}
			if err := run(context.Background(), []string{"-i", cliTarget, "-q"}, in, out, stderr, d); err == nil {
				t.Fatal("failure accepted")
			}
			owned := stage == "handshake" || stage == "terminal"
			if owned && (api.terminates != 1 || !api.cleanupActive) || !owned && api.terminates != 0 {
				t.Fatal("incorrect cleanup ownership")
			}
			if stage != "auth" && !httpClient.closed {
				t.Fatal("idle HTTP connections leaked")
			}
			if cliText(t, out) != "" || cliText(t, stderr) != "" {
				t.Fatal("quiet diagnostics contaminated streams")
			}
		})
	}
}

func TestDurationAndCanceledCleanup(t *testing.T) {
	for _, duration := range []bool{false, true} {
		in, out, stderr := cliFiles(t)
		api := &cliAPI{platform: types.PlatformTypeLinux}
		channel := &cliChannel{}
		httpClient := &idleClient{}
		d := cliDeps(api, channel, httpClient)
		ctx, cancel := context.WithCancel(context.Background())
		args := []string{"-i", cliTarget, "-q"}
		if duration {
			args = append(args, "--duration", "10ms")
		}
		d.run = func(lifetime context.Context, c terminal.Channel, _, _, _ *os.File) error {
			if !duration {
				cancel()
			}
			<-lifetime.Done()
			return errors.Join(lifetime.Err(), c.Close())
		}
		err := run(ctx, args, in, out, stderr, d)
		cancel()
		if err == nil || api.terminates != 1 || !api.cleanupActive {
			t.Fatal("cancellation prevented owned cleanup")
		}
		if duration && !errors.Is(err, context.DeadlineExceeded) || !duration && ExitCode(err) != 130 {
			t.Fatal("incorrect cancellation classification")
		}
	}
}

func TestCleanupFailureVisibleAndRedacted(t *testing.T) {
	in, out, stderr := cliFiles(t)
	api := &cliAPI{platform: types.PlatformTypeLinux, cleanupErr: errors.New("synthetic-secret-token")}
	err := run(context.Background(), []string{"-i", cliTarget, "-q"}, in, out, stderr, cliDeps(api, &cliChannel{}, &idleClient{}))
	if err == nil || !strings.Contains(err.Error(), "cleanup is best effort") || strings.Contains(err.Error(), "synthetic-secret-token") {
		t.Fatal("cleanup error hidden or unsafe")
	}
}

func TestNonLinuxRefusedBeforeStart(t *testing.T) {
	in, out, stderr := cliFiles(t)
	api := &cliAPI{platform: types.PlatformTypeWindows}
	if err := run(context.Background(), []string{"-i", cliTarget, "-q"}, in, out, stderr, cliDeps(api, &cliChannel{}, &idleClient{})); err == nil || api.starts != 0 {
		t.Fatal("unsupported platform started")
	}
}

func TestEstablishmentContextDoesNotOwnSessionLifetime(t *testing.T) {
	in, out, stderr := cliFiles(t)
	api := &cliAPI{platform: types.PlatformTypeLinux}
	d := cliDeps(api, &cliChannel{}, &idleClient{})
	var setup context.Context
	d.load = func(ctx context.Context, o config.Options, _ aws.TokenProvider) (sdkaws.Config, error) {
		setup = ctx
		return sdkaws.Config{Region: "ca-central-1"}, nil
	}
	d.connect = func(ctx context.Context, _ sdkaws.Config, _ *ssm.Session, sessionType string, budget time.Duration) (terminal.Channel, error) {
		if sessionType != "Standard_Stream" {
			t.Fatal("shell session type changed")
		}
		if ctx.Err() != nil || budget <= 0 || budget > 30*time.Second {
			t.Fatal("invalid establishment budget")
		}
		return &cliChannel{}, nil
	}
	d.run = func(ctx context.Context, c terminal.Channel, _, _, _ *os.File) error {
		if setup.Err() != context.Canceled || ctx.Err() != nil {
			t.Fatal("setup cancellation killed established socket lifetime")
		}
		return c.Close()
	}
	if err := run(context.Background(), []string{"-i", cliTarget, "-q"}, in, out, stderr, d); err != nil {
		t.Fatal(err)
	}
	if api.request.DocumentName != nil {
		t.Fatal("default session document overridden")
	}
}

func TestLifecycleWithActualTerminalLoop(t *testing.T) {
	in, out, stderr := cliFiles(t)
	api := &cliAPI{platform: types.PlatformTypeLinux}
	channel := &cliChannel{}
	d := cliDeps(api, channel, &idleClient{})
	d.run = terminal.Run
	if err := run(context.Background(), []string{"-i", cliTarget, "-q"}, in, out, stderr, d); err != nil {
		t.Fatal(err)
	}
	if !channel.closed || api.terminates != 1 || !api.cleanupActive {
		t.Fatal("terminal/owned-session composition leaked")
	}
}
