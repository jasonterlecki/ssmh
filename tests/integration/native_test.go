//go:build linux

// Package integration contains explicitly opted-in tests against existing AWS
// targets. Default runs skip every live operation before credential resolution.
package integration

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"os"
	"sync"
	"testing"
	"time"

	sdkaws "github.com/aws/aws-sdk-go-v2/aws"
	sdkec2 "github.com/aws/aws-sdk-go-v2/service/ec2"
	sdkssm "github.com/aws/aws-sdk-go-v2/service/ssm"
	"github.com/aws/aws-sdk-go-v2/service/ssm/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"ssmh/internal/aws"
	"ssmh/internal/cli"
	"ssmh/internal/command"
	"ssmh/internal/config"
	"ssmh/internal/ec2"
	"ssmh/internal/forward"
	"ssmh/internal/ssm"
	"ssmh/internal/terminal"
	"ssmh/internal/transport/native"
)

type liveOptions struct {
	options config.Options
	account string
	target  config.ForwardTarget
}

// Configuration is validated before credentials, network, listeners or sessions.
// A single operation is authorized, not a blanket switch for all live tests.
func readLiveOptions(get func(string) string, operation string) (liveOptions, bool, error) {
	mode := get("SSMH_TEST_AWS")
	if mode == "" {
		return liveOptions{}, false, nil
	}
	switch mode {
	case "check", "shell", "shell-tty", "command", "forward", "forward-host":
	default:
		return liveOptions{}, false, errors.New("SSMH_TEST_AWS must select one documented live operation")
	}
	if mode != operation {
		return liveOptions{}, false, nil
	}
	id, region, account := get("SSMH_LIVE_INSTANCE"), get("SSMH_LIVE_REGION"), get("SSMH_LIVE_ACCOUNT")
	if !config.InstanceID(id) || config.Region(region) != nil || len(account) != 12 {
		return liveOptions{}, false, errors.New("live tests require an explicit EC2 instance ID, region and twelve-digit expected account")
	}
	for _, digit := range account {
		if digit < '0' || digit > '9' {
			return liveOptions{}, false, errors.New("invalid expected live account")
		}
	}
	args := []string{"-i", id, "-r", region, "--backend", "native", "--timeout", "30s", "--quiet"}
	if profile := get("SSMH_LIVE_PROFILE"); profile != "" {
		args = append(args, "--profile", profile)
	}
	if role := get("SSMH_LIVE_ROLE_ARN"); role != "" {
		args = append(args, "--arn", role)
	}
	if mode == "command" {
		document := get("SSMH_LIVE_COMMAND_DOCUMENT")
		if document == "" {
			return liveOptions{}, false, errors.New("command test requires an approved separate-output session document")
		}
		args = append(args, "--command", "true", "--document", document)
	}
	var target config.ForwardTarget
	if mode == "forward" || mode == "forward-host" {
		var err error
		target, err = config.ParseForward(get("SSMH_LIVE_FORWARD"), mode == "forward-host")
		if err != nil || target.LocalPort < 1024 {
			return liveOptions{}, false, errors.New("forwarding tests require a validated nonprivileged loopback port and approved echo destination")
		}
		flag := "--forward"
		if mode == "forward-host" {
			flag = "--forward-host"
		}
		args = append(args, flag, get("SSMH_LIVE_FORWARD"))
	}
	o, err := cli.Parse(args)
	if err != nil {
		return liveOptions{}, false, errors.New("invalid live test profile, role, document or destination options")
	}
	return liveOptions{o, account, target}, true, nil
}

func liveGate(t *testing.T, operation string) liveOptions {
	t.Helper()
	o, enabled, err := readLiveOptions(os.Getenv, operation)
	if err != nil {
		t.Fatal(err)
	}
	if !enabled {
		t.Skip("live AWS operation not explicitly selected")
	}
	return o
}

type liveRun struct {
	ctx, setup context.Context
	cfg        sdkaws.Config
	api        *sdkssm.Client
	instance   string
}

// One selected SDK configuration is retained for identity, EC2, SSM and native
// transport. A changed expected account fails before any StartSession.
func prepareLive(t *testing.T, o liveOptions) liveRun {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	t.Cleanup(cancel)
	setup, stopSetup := context.WithTimeout(ctx, 30*time.Second)
	t.Cleanup(stopSetup)
	cfg, err := aws.Load(setup, o.options, nil)
	if err != nil {
		t.Fatal("live SDK authentication failed (no raw credential diagnostics)")
	}
	t.Cleanup(func() { aws.Close(cfg) })
	if err := verifyLiveAccount(setup, sts.NewFromConfig(cfg), o.account); err != nil {
		t.Fatal(err)
	}
	instance, err := ec2.Resolve(setup, sdkec2.NewFromConfig(cfg), cfg.Region, o.options.Instance)
	if err != nil || instance.State != "running" {
		t.Fatal("live target resolution/running-state prerequisite failed")
	}
	api := sdkssm.NewFromConfig(cfg)
	status, err := ssm.Online(setup, api, instance.ID)
	if err != nil || status.PlatformType != types.PlatformTypeLinux {
		t.Fatal("live Linux/Online SSM prerequisite failed")
	}
	return liveRun{ctx, setup, cfg, api, instance.ID}
}

func verifyLiveAccount(ctx context.Context, client aws.IdentityAPI, expected string) error {
	identity, err := aws.ReadIdentity(ctx, client)
	if err != nil || identity.Account() != expected {
		// Unlike CLI --check, unavailable identity must not pass the live account
		// safety guard. Never echo either identity or a raw provider/API failure.
		return errors.New("live identity unavailable or outside the explicitly expected account; no session started")
	}
	return nil
}

func ownLiveSession(t *testing.T, session *ssm.Session) {
	t.Helper()
	if session == nil {
		t.Fatal("live session creation returned no ownership")
	}
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if session.Terminate(cleanup) != nil {
			t.Error("owned live session termination failed; use approved AWS tooling to inspect residual sessions")
		}
	})
}

func remainingLive(t *testing.T, setup context.Context) time.Duration {
	t.Helper()
	deadline, ok := setup.Deadline()
	remaining := time.Until(deadline)
	if !ok || remaining <= 0 || setup.Err() != nil {
		t.Fatal("live setup budget exhausted before native channel connection")
	}
	return remaining
}

func ownLiveChannel(t *testing.T, channel *native.Channel) {
	t.Helper()
	if channel == nil {
		t.Fatal("live native connection returned no channel")
	}
	t.Cleanup(func() {
		if !onlyCancellation(channel.Close()) {
			t.Error("live channel cleanup failed (payloads omitted)")
		}
	})
}

// Cancellation never masks an independent or wrapped cleanup failure.
func onlyCancellation(err error) bool {
	if err == nil || err == context.Canceled {
		return true
	}
	if joined, ok := err.(interface{ Unwrap() []error }); ok {
		for _, leaf := range joined.Unwrap() {
			if !onlyCancellation(leaf) {
				return false
			}
		}
		return true
	}
	return false
}

func nonce(t *testing.T) string {
	t.Helper()
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		t.Fatal("cannot generate live test nonce")
	}
	return "ssmh_" + hex.EncodeToString(raw[:])
}

func TestLiveNativeCheck(t *testing.T) {
	o := liveGate(t, "check")
	r := prepareLive(t, o)
	if ssm.ValidateShellDocument(r.setup, r.api, "", r.cfg.Region) != nil {
		t.Fatal("live default shell document compatibility failed")
	}
	// Read APIs only. No StartSession/permission proof is inferred from success.
}

func TestLiveNativeShell(t *testing.T) {
	o := liveGate(t, "shell")
	r := prepareLive(t, o)
	session, err := ssm.StartShell(r.setup, r.api, r.api, &sdkssm.StartSessionInput{Target: sdkaws.String(r.instance), Reason: sdkaws.String("Explicit ssmh native shell integration test")}, r.cfg.Region)
	if session != nil {
		ownLiveSession(t, session)
	}
	if err != nil {
		t.Fatal("live shell session creation failed (authentication material omitted)")
	}
	channel, err := native.Connect(r.ctx, r.cfg, session, "Standard_Stream", remainingLive(t, r.setup))
	if channel != nil {
		ownLiveChannel(t, channel)
	}
	if err != nil {
		t.Fatal("live shell data-channel establishment failed")
	}
	marker := nonce(t)
	// The input echo cannot contain the complete marker: printf concatenates two
	// separate arguments. Observing it therefore requires remote command output.
	middle := len(marker) / 2
	script := "printf '%s%s\\n' '" + marker[:middle] + "' '" + marker[middle:] + "'\nexit\n"
	stdout, _, err := captureOperation(r.ctx, script, func(ctx context.Context, input, output, stderr *os.File) error {
		return terminal.Run(ctx, channel, input, output, stderr)
	})
	if err != nil || !bytes.Contains(stdout, []byte(marker)) {
		t.Fatal("live shell nonce/owned completion failed; remote output omitted")
	}
}

func TestLiveNativeCommand(t *testing.T) {
	o := liveGate(t, "command")
	r := prepareLive(t, o)
	stdoutMarker, stderrMarker := nonce(t), nonce(t)
	text := "printf '%s' '" + stdoutMarker + "'; printf '%s' '" + stderrMarker + "' >&2; exit 37"
	serialized, err := command.SerializeShell(text)
	if err != nil {
		t.Fatal("cannot serialize fixed live command probe")
	}
	session, err := ssm.StartCommand(r.setup, r.api, r.api, &sdkssm.StartSessionInput{Target: sdkaws.String(r.instance), DocumentName: sdkaws.String(o.options.Document), Parameters: map[string][]string{"command": {serialized}}, Reason: sdkaws.String("Explicit ssmh native command integration test")}, r.cfg.Region)
	if session != nil {
		ownLiveSession(t, session)
	}
	if err != nil {
		t.Fatal("live command session creation failed")
	}
	channel, err := native.Connect(r.ctx, r.cfg, session, "NonInteractiveCommands", remainingLive(t, r.setup))
	if channel != nil {
		ownLiveChannel(t, channel)
	}
	if err != nil {
		t.Fatal("live command data-channel establishment failed")
	}
	var result command.Result
	stdout, stderr, err := captureOperation(r.ctx, "", func(ctx context.Context, _ *os.File, output, stderr *os.File) error {
		var operationErr error
		result, operationErr = command.Run(ctx, channel, output, stderr)
		return operationErr
	})
	code, known := result.ExitCode()
	if err != nil || !known || code != 37 || string(stdout) != stdoutMarker || string(stderr) != stderrMarker {
		t.Fatal("live separate stdout/stderr or verified exit-code assertion failed; output omitted")
	}
}

func TestLiveNativeForward(t *testing.T)     { testLiveForward(t, "forward") }
func TestLiveNativeForwardHost(t *testing.T) { testLiveForward(t, "forward-host") }

type liveListener struct {
	net.Listener
	once sync.Once
	err  error
}

func (l *liveListener) Close() error {
	l.once.Do(func() { l.err = l.Listener.Close() })
	return l.err
}

func testLiveForward(t *testing.T, operation string) {
	t.Helper()
	o := liveGate(t, operation)
	// Reserve the exact approved local port before any AWS authentication.
	bind, stopBind := context.WithTimeout(context.Background(), 5*time.Second)
	bound, err := forward.Listen(bind, o.target)
	stopBind()
	if err != nil {
		t.Fatal("approved live loopback port unavailable; no AWS session started")
	}
	listener := &liveListener{Listener: bound}
	defer func() {
		if listener.Close() != nil {
			t.Error("owned live listener cleanup failed")
		}
	}()
	r := prepareLive(t, o)
	session, err := ssm.StartForward(r.setup, r.api, r.instance, r.cfg.Region, "Explicit ssmh native echo-forwarding integration test", o.target)
	if session != nil {
		ownLiveSession(t, session)
	}
	if err != nil {
		t.Fatal("live forwarding session creation failed")
	}
	channel, err := native.ConnectForward(r.ctx, r.cfg, session, o.target, remainingLive(t, r.setup))
	if channel != nil {
		ownLiveChannel(t, channel)
	}
	if err != nil {
		t.Fatal("live forwarding data-channel establishment failed")
	}
	serving, cancel := context.WithCancel(r.ctx)
	done := make(chan error, 1)
	go func() { done <- native.ServeForward(serving, channel, listener) }()
	// Join socket/channel workers before owned AWS cleanup, including Fatal paths.
	defer func() {
		cancel()
		if !onlyCancellation(<-done) {
			t.Error("live forwarding/cleanup failed; forwarded data omitted")
		}
	}()
	connections := make([]net.Conn, 0, 3)
	payloads := make([][]byte, 0, 3)
	for range 3 {
		conn, err := (&net.Dialer{Timeout: 5 * time.Second}).DialContext(serving, "tcp4", o.target.Address())
		if err != nil {
			t.Fatal("cannot connect to approved live loopback tunnel")
		}
		connections = append(connections, conn)
		defer func() {
			if conn.Close() != nil {
				t.Error("owned live client socket cleanup failed")
			}
		}()
		if conn.SetDeadline(time.Now().Add(10*time.Second)) != nil {
			t.Fatal("cannot bound live echo I/O")
		}
		payload := []byte(nonce(t))
		payloads = append(payloads, payload)
		for pending := payload; len(pending) > 0; {
			n, err := conn.Write(pending)
			if err != nil || n == 0 {
				t.Fatal("live echo tunnel write failed")
			}
			pending = pending[n:]
		}
	}
	for i, conn := range connections {
		data := make([]byte, len(payloads[i]))
		if _, err := io.ReadFull(conn, data); err != nil || !bytes.Equal(data, payloads[i]) {
			t.Fatal("live echo response/stream-isolation assertion failed; payload omitted")
		}
	}
}

const captureLimit = 1 << 20

type captured struct {
	data []byte
	err  error
}

// No transcripts are written to disk or diagnostics. Collectors are joined;
// overflow cancels the operation instead of retaining unbounded remote output.
func captureOperation(parent context.Context, input string, operation func(context.Context, *os.File, *os.File, *os.File) error) (stdout, stderr []byte, result error) {
	if len(input) > 512 {
		return nil, nil, errors.New("live probe input exceeds fixed bound")
	}
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	var files []*os.File
	defer func() {
		for _, file := range files {
			if err := file.Close(); err != nil && !errors.Is(err, os.ErrClosed) {
				result = errors.Join(result, errors.New("private live test pipe cleanup failed"))
			}
		}
	}()
	pipes := make([][2]*os.File, 3)
	for i := range pipes {
		r, w, err := os.Pipe()
		if err != nil {
			return nil, nil, errors.New("cannot create private live test pipes")
		}
		files = append(files, r, w)
		pipes[i] = [2]*os.File{r, w}
	}
	if _, err := io.WriteString(pipes[0][1], input); err != nil {
		return nil, nil, errors.New("cannot supply fixed live probe input")
	}
	if err := pipes[0][1].Close(); err != nil {
		return nil, nil, errors.New("cannot close live probe input")
	}
	results := make([]chan captured, 2)
	for i := range results {
		results[i] = make(chan captured, 1)
		reader, done := pipes[i+1][0], results[i]
		go func() {
			stop := context.AfterFunc(ctx, func() { reader.Close() })
			defer stop()
			data, err := io.ReadAll(io.LimitReader(reader, captureLimit+1))
			if len(data) > captureLimit {
				cancel()
				data, err = nil, errors.New("live output capture limit exceeded")
			}
			if err != nil {
				data, err = nil, errors.New("live output collection failed")
			}
			done <- captured{data, err}
		}()
	}
	operationErr := operation(ctx, pipes[0][0], pipes[1][1], pipes[2][1])
	closeErr := errors.Join(pipes[1][1].Close(), pipes[2][1].Close())
	outCapture, errCapture := <-results[0], <-results[1]
	return outCapture.data, errCapture.data, errors.Join(operationErr, closeErr, outCapture.err, errCapture.err)
}
