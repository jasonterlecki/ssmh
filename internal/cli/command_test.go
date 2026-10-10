package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	sdkaws "github.com/aws/aws-sdk-go-v2/aws"
	sdkssm "github.com/aws/aws-sdk-go-v2/service/ssm"
	"github.com/aws/aws-sdk-go-v2/service/ssm/types"
	"ssmh/internal/aws"
	"ssmh/internal/command"
	"ssmh/internal/config"
	"ssmh/internal/ssm"
	"ssmh/internal/terminal"
	"ssmh/internal/transport/native"
)

const cliCommandDocument = `{"schemaVersion":"1.0","sessionType":"NonInteractiveCommands","parameters":{"command":{"type":"String"}},"properties":{"linux":{"commands":"{{ command }}","runAsElevated":false,"separateOutputStream":true}}}`

type commandAPI struct {
	*cliAPI
	content    string
	docErr     error
	docRequest *sdkssm.GetDocumentInput
}

func (a *commandAPI) GetDocument(_ context.Context, in *sdkssm.GetDocumentInput, _ ...func(*sdkssm.Options)) (*sdkssm.GetDocumentOutput, error) {
	a.docRequest = in
	content := a.content
	if content == "" {
		content = cliCommandDocument
	}
	return &sdkssm.GetDocumentOutput{Name: in.Name, Content: sdkaws.String(content), DocumentType: types.DocumentTypeSession, DocumentFormat: types.DocumentFormatJson, Status: types.DocumentStatusActive}, a.docErr
}

type commandChannel struct {
	messages []native.Message
	end      error
	closed   bool
}

func (*commandChannel) Send(context.Context, uint32, []byte) error {
	return errors.New("command mode must never send input")
}
func (c *commandChannel) Receive(ctx context.Context) (native.Message, error) {
	if len(c.messages) > 0 {
		m := c.messages[0]
		c.messages = c.messages[1:]
		return m, nil
	}
	if c.end != nil {
		return native.Message{}, c.end
	}
	return native.Message{}, io.EOF
}
func (c *commandChannel) Close() error { c.closed = true; return nil }

func commandDeps(t *testing.T, api *commandAPI, channel *commandChannel) dependencies {
	t.Helper()
	d := cliDeps(api.cliAPI, &cliChannel{}, &idleClient{})
	d.client = func(sdkaws.Config) ssm.API { return api }
	d.connect = func(ctx context.Context, cfg sdkaws.Config, session *ssm.Session, sessionType string, timeout time.Duration) (terminal.Channel, error) {
		if sessionType != "NonInteractiveCommands" || api.docRequest == nil || timeout <= 0 || session.HandshakeOptional() {
			t.Fatal("command bypassed validated session type/document")
		}
		return channel, nil
	}
	d.run = func(context.Context, terminal.Channel, *os.File, *os.File, *os.File) error {
		t.Fatal("command invoked interactive terminal loop")
		return nil
	}
	return d
}

func TestCommandLifecycleSerializationOutputAndStatus(t *testing.T) {
	for _, code := range []int{0, 1, 42, 130, 255} {
		for _, custom := range []bool{false, true} {
			_, out, stderr := cliFiles(t)
			api := &commandAPI{cliAPI: &cliAPI{platform: types.PlatformTypeLinux}}
			channel := &commandChannel{messages: []native.Message{
				{PayloadType: native.Output, Payload: []byte("remote stdout\nEXIT_CODE: 255\n")},
				{PayloadType: native.StdErr, Payload: []byte("remote stderr\n")},
				{PayloadType: native.ExitCode, Payload: []byte(fmt.Sprintf("EXIT_CODE: %d", code))},
			}}
			requested := "printf '%s' \"λ; $HOME\"\nfalse; exit 42"
			args := []string{"-i", cliTarget, "-c", requested, "--reason", "Unit command", "-q"}
			name := "AWS-StartNonInteractiveCommand"
			if custom {
				name = "SafeCommand"
				args = append(args, "--document", name)
			}
			err := run(context.Background(), args, nil, out, stderr, commandDeps(t, api, channel))
			if ExitCode(err) != code || (err == nil) != (code == 0) || !channel.closed || api.terminates != 1 || !api.cleanupActive {
				t.Fatalf("status %d: %v", code, err)
			}
			serialized, _ := command.SerializeShell(requested)
			if sdkaws.ToString(api.request.DocumentName) != name || sdkaws.ToString(api.docRequest.Name) != name || sdkaws.ToString(api.request.Reason) != "Unit command" || len(api.request.Parameters) != 1 || len(api.request.Parameters["command"]) != 1 || api.request.Parameters["command"][0] != serialized {
				t.Fatal("command/document/reason changed")
			}
			if cliText(t, out) != "remote stdout\nEXIT_CODE: 255\n" || cliText(t, stderr) != "remote stderr\n" {
				t.Fatal("command output changed or mixed with diagnostics")
			}
			if err != nil && strings.Contains(err.Error(), requested) {
				t.Fatal("command leaked into diagnostics")
			}
		}
	}
}

func TestCommandPreflightRefusesUnsafeDocumentsBeforeStart(t *testing.T) {
	for _, content := range []string{
		"{",
		strings.Replace(cliCommandDocument, "false", "true", 1),
		strings.Replace(cliCommandDocument, `"separateOutputStream":true`, `"separateOutputStream":false`, 1),
		strings.Replace(cliCommandDocument, "{{ command }}", "sudo {{ command }}", 1),
		strings.Replace(cliCommandDocument, `"runAsElevated"`, `"RunAsElevated"`, 1),
		strings.Replace(cliCommandDocument, `"commands"`, `"Commands"`, 1),
		strings.Replace(cliCommandDocument, `"separateOutputStream":true`, `"separateOutputStream":true,"stdErrSeparatorPrefix":null`, 1),
	} {
		_, out, stderr := cliFiles(t)
		api := &commandAPI{cliAPI: &cliAPI{platform: types.PlatformTypeLinux}, content: content}
		channel := &commandChannel{}
		err := run(context.Background(), []string{"-i", cliTarget, "-c", "synthetic-secret", "-q"}, nil, out, stderr, commandDeps(t, api, channel))
		if err == nil || api.starts != 0 || api.terminates != 0 || channel.closed || strings.Contains(err.Error(), "synthetic-secret") {
			t.Fatal("unsafe document executed or command exposed")
		}
	}
	_, out, stderr := cliFiles(t)
	api := &commandAPI{cliAPI: &cliAPI{platform: types.PlatformTypeLinux}, docErr: errors.New("synthetic-secret")}
	err := run(context.Background(), []string{"-i", cliTarget, "-c", "uname -a", "-q"}, nil, out, stderr, commandDeps(t, api, &commandChannel{}))
	if err == nil || api.starts != 0 || strings.Contains(err.Error(), "synthetic-secret") {
		t.Fatal("document read failure ignored or exposed")
	}
}

func TestCommandCleanupFailureOverridesRemoteStatus(t *testing.T) {
	for _, code := range []int{0, 42} {
		_, out, stderr := cliFiles(t)
		api := &commandAPI{cliAPI: &cliAPI{platform: types.PlatformTypeLinux, cleanupErr: errors.New("synthetic cleanup failure")}}
		channel := &commandChannel{messages: []native.Message{{PayloadType: native.ExitCode, Payload: []byte(fmt.Sprintf("EXIT_CODE: %d", code))}}}
		err := run(context.Background(), []string{"-i", cliTarget, "-c", "uname -a", "-q"}, nil, out, stderr, commandDeps(t, api, channel))
		if err == nil || ExitCode(err) != 1 || !strings.Contains(err.Error(), "terminate owned SSM session") || api.terminates != 1 || !channel.closed {
			t.Fatal("cleanup failure hidden by command status")
		}
	}
}

func TestCommandInterruptionNeverPropagatesReceivedStatus(t *testing.T) {
	for _, end := range []error{io.ErrUnexpectedEOF, context.Canceled, context.DeadlineExceeded} {
		_, out, stderr := cliFiles(t)
		api := &commandAPI{cliAPI: &cliAPI{platform: types.PlatformTypeLinux}}
		channel := &commandChannel{messages: []native.Message{{PayloadType: native.ExitCode, Payload: []byte("EXIT_CODE: 42")}}, end: end}
		err := run(context.Background(), []string{"-i", cliTarget, "-c", "uname -a", "-q"}, nil, out, stderr, commandDeps(t, api, channel))
		if err == nil || ExitCode(err) == 42 || !errors.Is(err, end) || api.terminates != 1 || !api.cleanupActive || !channel.closed {
			t.Fatal("interruption lost or leaked session")
		}
	}
}

func TestQuotedCommandSizeRejectedBeforeAuthentication(t *testing.T) {
	_, out, stderr := cliFiles(t)
	d := dependencies{load: func(context.Context, config.Options, aws.TokenProvider) (sdkaws.Config, error) {
		t.Fatal("oversized serialized command reached authentication")
		return sdkaws.Config{}, nil
	}}
	err := run(context.Background(), []string{"-i", cliTarget, "-c", strings.Repeat("'", 8192)}, nil, out, stderr, d)
	if err == nil || ExitCode(err) != 2 {
		t.Fatal("quoting expansion bypassed validation")
	}
}

func TestCommandKMSCapabilityAndOwnedCleanup(t *testing.T) {
	key := "arn:aws:kms:ca-central-1:123456789012:key/12345678-1234-1234-1234-123456789abc"
	for _, failSetup := range []bool{false, true} {
		_, out, stderr := cliFiles(t)
		api := &commandAPI{cliAPI: &cliAPI{platform: types.PlatformTypeLinux}, content: strings.Replace(cliCommandDocument, `"parameters":`, `"inputs":{"kmsKeyId":"`+key+`"},"parameters":`, 1)}
		channel := &commandChannel{messages: []native.Message{{PayloadType: native.Output, Payload: []byte("reply")}, {PayloadType: native.StdErr, Payload: []byte("error")}, {PayloadType: native.ExitCode, Payload: []byte("EXIT_CODE: 37")}}}
		d := commandDeps(t, api, channel)
		calls := 0
		d.connect = func(_ context.Context, cfg sdkaws.Config, session *ssm.Session, kind string, _ time.Duration) (terminal.Channel, error) {
			calls++
			selectedType, selectedKey := session.DocumentKMSContext()
			if cfg.Region != "ca-central-1" || kind != "NonInteractiveCommands" || selectedType != kind || selectedKey != key || session.HandshakeOptional() || session.ShellKMSKey() != "" || api.docRequest == nil {
				t.Fatal("command document/identity capability changed")
			}
			if failSetup {
				return nil, errors.New("synthetic encrypted command setup failure")
			}
			return channel, nil
		}
		err := run(context.Background(), []string{"-i", cliTarget, "-c", "exit 37", "--document", "ReviewedCommand", "-q"}, nil, out, stderr, d)
		if calls != 1 || api.starts != 1 || api.terminates != 1 || !api.cleanupActive {
			t.Fatal("encrypted command ownership cleanup missing")
		}
		if failSetup {
			if err == nil || ExitCode(err) == 37 {
				t.Fatal("setup failure reported remote status")
			}
		} else if ExitCode(err) != 37 || cliText(t, out) != "reply" || cliText(t, stderr) != "error" {
			t.Fatal("encrypted command result/streams changed")
		}
	}
}
