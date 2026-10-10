package plugin

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	sdk "github.com/aws/aws-sdk-go-v2/service/ssm"
	"ssmh/internal/ssm"
)

const syntheticToken = "SYNTHETIC-TOKEN-\"\\\n\x00☃"

type handoffAPI struct{}

func (handoffAPI) StartSession(context.Context, *sdk.StartSessionInput, ...func(*sdk.Options)) (*sdk.StartSessionOutput, error) {
	return &sdk.StartSessionOutput{
		SessionId:  aws.String("synthetic-owned-session"),
		StreamUrl:  aws.String("wss://ssmmessages.ca-central-1.amazonaws.com/v1/data-channel/synthetic-owned-session?role=publish_subscribe"),
		TokenValue: aws.String(syntheticToken),
	}, nil
}
func (handoffAPI) TerminateSession(context.Context, *sdk.TerminateSessionInput, ...func(*sdk.Options)) (*sdk.TerminateSessionOutput, error) {
	return &sdk.TerminateSessionOutput{}, nil
}
func (handoffAPI) DescribeInstanceInformation(context.Context, *sdk.DescribeInstanceInformationInput, ...func(*sdk.Options)) (*sdk.DescribeInstanceInformationOutput, error) {
	return &sdk.DescribeInstanceInformationOutput{}, nil
}

func ownedHandoffSession(t *testing.T, client ssm.API) *ssm.Session {
	t.Helper()
	session, err := ssm.Start(context.Background(), client, &sdk.StartSessionInput{Target: aws.String("i-0123456789abcdef0")}, "ca-central-1")
	if err != nil {
		t.Fatal("cannot create synthetic owned session")
	}
	return session
}

// Mirrors only the verified official environment lookup, unset and SDK JSON
// decode contract. It is not an official plugin or a transport emulator.
func verifyChildHandoff() {
	response := os.Getenv(os.Args[1])
	if response == "" || os.Unsetenv(os.Args[1]) != nil || os.Getenv(os.Args[1]) != "" {
		os.Exit(94)
	}
	for _, entry := range os.Environ() {
		if strings.HasPrefix(entry, responsePrefix) {
			os.Exit(95)
		}
	}
	var decoded sdk.StartSessionOutput
	if json.Unmarshal([]byte(response), &decoded) != nil || aws.ToString(decoded.TokenValue) != syntheticToken || aws.ToString(decoded.SessionId) != "synthetic-owned-session" || aws.ToString(decoded.StreamUrl) == "" {
		os.Exit(96)
	}
	fmt.Print("handoff verified")
}

func TestHandoffActualChildEnvironment(t *testing.T) {
	session := ownedHandoffSession(t, handoffAPI{})
	handoff, err := prepareHandoff(session)
	if err != nil {
		t.Fatal(err)
	}
	defer handoff.clear()
	base := []string{"LANG=C", responseVariable + "=OLD-SYNTHETIC-TOKEN", responsePrefix + "_ALIAS=OLD-SYNTHETIC-TOKEN"}
	environment, err := handoff.environment(base)
	if err != nil || !reflect.DeepEqual(base, []string{"LANG=C", responseVariable + "=OLD-SYNTHETIC-TOKEN", responsePrefix + "_ALIAS=OLD-SYNTHETIC-TOKEN"}) {
		t.Fatal("handoff changed the supplied environment")
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	child := exec.CommandContext(ctx, executable, responseVariable)
	child.Env = environment
	for _, argument := range child.Args {
		if strings.Contains(argument, "SYNTHETIC-TOKEN") || strings.Contains(argument, "wss://") || strings.Contains(argument, "synthetic-owned-session") {
			t.Fatal("authentication material entered argv")
		}
	}
	output, err := child.Output()
	if err != nil || string(output) != "handoff verified" {
		t.Fatal("child did not decode the environment response contract")
	}
	if text := fmt.Sprintf("%v %+v %#v", handoff, handoff, handoff); strings.Contains(text, "SYNTHETIC-TOKEN") || strings.Contains(text, "wss://") {
		t.Fatal("formatted handoff exposed authentication material")
	}
}

func TestHandoffOwnershipAndRelease(t *testing.T) {
	for _, session := range []*ssm.Session{nil, {}} {
		if handoff, err := prepareHandoff(session); handoff != nil || err == nil {
			t.Fatal("unavailable ownership accepted")
		}
	}
	session := ownedHandoffSession(t, handoffAPI{})
	if err := session.Terminate(context.Background()); err != nil {
		t.Fatal(err)
	}
	if handoff, err := prepareHandoff(session); handoff != nil || err == nil {
		t.Fatal("terminated session accepted")
	}
	handoff, err := prepareHandoff(ownedHandoffSession(t, handoffAPI{}))
	if err != nil {
		t.Fatal(err)
	}
	handoff.clear()
	if environment, err := handoff.environment([]string{}); environment != nil || err == nil {
		t.Fatal("cleared handoff remained usable")
	}
	(*responseHandoff)(nil).clear()
}

type tokenAPI struct {
	handoffAPI
	token string
}

func (a tokenAPI) StartSession(ctx context.Context, input *sdk.StartSessionInput, options ...func(*sdk.Options)) (*sdk.StartSessionOutput, error) {
	output, err := a.handoffAPI.StartSession(ctx, input, options...)
	output.TokenValue = aws.String(a.token)
	return output, err
}

func TestHandoffEncodingLimits(t *testing.T) {
	for _, test := range []struct {
		token string
		valid bool
	}{
		{strings.Repeat("x", 65536), true},
		{strings.Repeat("\x00", 65536), false}, // JSON escaping can exceed one environment entry.
		{string([]byte{0xff}), false},          // JSON must not silently replace token bytes.
	} {
		session := ownedHandoffSession(t, tokenAPI{token: test.token})
		handoff, err := prepareHandoff(session)
		if (err == nil) != test.valid || (handoff != nil) != test.valid {
			t.Fatal("unexpected handoff encoding acceptance")
		}
		if err != nil && strings.Contains(err.Error(), test.token) {
			t.Fatal("encoding failure exposed the token")
		}
		if handoff != nil {
			if len(handoff.entry) > maxResponseEntry || strings.IndexByte(handoff.entry, 0) >= 0 {
				t.Fatal("unsafe environment entry generated")
			}
			handoff.clear()
		}
	}
}

func TestHandoffExplicitEnvironmentBounds(t *testing.T) {
	handoff, err := prepareHandoff(ownedHandoffSession(t, handoffAPI{}))
	if err != nil {
		t.Fatal(err)
	}
	defer handoff.clear()
	for _, base := range [][]string{nil, {""}, {"NO_EQUALS"}, {"=value"}, {"KEY=\x00SYNTHETIC-SECRET"}, make([]string, 257), {"KEY=" + strings.Repeat("x", maxResponseEntry)}, {"A=" + strings.Repeat("x", 100*1024), "B=" + strings.Repeat("x", 100*1024), "C=" + strings.Repeat("x", 100*1024)}} {
		if environment, err := handoff.environment(base); environment != nil || err == nil || strings.Contains(err.Error(), "SYNTHETIC-SECRET") {
			t.Fatal("unsafe child environment accepted or exposed")
		}
	}
	environment, err := handoff.environment([]string{})
	if err != nil || len(environment) != 1 || environment[0] != handoff.entry {
		t.Fatal("explicit empty child environment refused")
	}
}
