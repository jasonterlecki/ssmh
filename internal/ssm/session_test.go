package ssm

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	sdk "github.com/aws/aws-sdk-go-v2/service/ssm"
	"github.com/aws/aws-sdk-go-v2/service/ssm/types"
)

const testID = "synthetic-user-0123456789abcdef0"

func TestReleaseAfterVerifiedRemoteCompletion(t *testing.T) {
	f := api()
	s, err := Start(context.Background(), f, input(), "ca-central-1")
	if err != nil {
		t.Fatal(err)
	}
	s.kmsKey, s.kmsType = "synthetic-key", "Standard_Stream"
	s.ReleaseAfterRemoteCompletion()
	if _, _, _, live := s.OwnedContext(); live {
		t.Fatal("remote-completed ownership retained")
	}
	_, stream, token := s.TransportMaterial()
	if stream != "" || token != "" {
		t.Fatal("remote-completed transport references retained")
	}
	if kind, key := s.DocumentKMSContext(); kind != "" || key != "" {
		t.Fatal("remote-completed KMS capability retained")
	}
	if err := s.Terminate(context.Background()); err != nil || f.terminates != 0 {
		t.Fatal("remote-completed session terminated redundantly")
	}
}

func TestOwnedContextLifetimeAndImmutableTarget(t *testing.T) {
	for _, s := range []*Session{nil, {}} {
		if id, target, region, live := s.OwnedContext(); live || id != "" || target != "" || region != "" {
			t.Fatal("unowned session granted context")
		}
	}
	f := api()
	input := &sdk.StartSessionInput{Target: aws.String("i-0123456789abcdef0")}
	s, err := Start(context.Background(), f, input, "ca-central-1")
	if err != nil {
		t.Fatal(err)
	}
	input.Target = aws.String("i-fedcba98765432100")
	if id, target, region, live := s.OwnedContext(); !live || id != testID || target != "i-0123456789abcdef0" || region != "ca-central-1" {
		t.Fatal("owned target/context changed with caller input")
	}
	f.terminateErr = errors.New("synthetic cleanup failure")
	if err := s.Terminate(context.Background()); err == nil {
		t.Fatal("cleanup unexpectedly succeeded")
	}
	if _, _, _, live := s.OwnedContext(); !live {
		t.Fatal("failed cleanup falsely ended ownership")
	}
	f.terminateErr = nil
	if err := s.Terminate(context.Background()); err != nil {
		t.Fatal(err)
	}
	if id, target, region, live := s.OwnedContext(); live || id != "" || target != "" || region != "" {
		t.Fatal("terminated session retained context capability")
	}
}

type fakeAPI struct {
	output                 *sdk.StartSessionOutput
	startErr, terminateErr error
	starts, terminates     int
	terminatedID           string
	pages                  []*sdk.DescribeInstanceInformationOutput
	page                   int
}

func (f *fakeAPI) StartSession(context.Context, *sdk.StartSessionInput, ...func(*sdk.Options)) (*sdk.StartSessionOutput, error) {
	f.starts++
	return f.output, f.startErr
}
func (f *fakeAPI) TerminateSession(_ context.Context, in *sdk.TerminateSessionInput, _ ...func(*sdk.Options)) (*sdk.TerminateSessionOutput, error) {
	f.terminates++
	f.terminatedID = aws.ToString(in.SessionId)
	return &sdk.TerminateSessionOutput{}, f.terminateErr
}
func (f *fakeAPI) DescribeInstanceInformation(context.Context, *sdk.DescribeInstanceInformationInput, ...func(*sdk.Options)) (*sdk.DescribeInstanceInformationOutput, error) {
	p := f.pages[f.page]
	if f.page < len(f.pages)-1 {
		f.page++
	}
	return p, nil
}
func api() *fakeAPI {
	return &fakeAPI{output: &sdk.StartSessionOutput{SessionId: aws.String(testID), TokenValue: aws.String("synthetic-token"), StreamUrl: aws.String("wss://ssmmessages.ca-central-1.amazonaws.com/v1/data-channel/" + testID + "?role=publish_subscribe")}}
}
func input() *sdk.StartSessionInput {
	return &sdk.StartSessionInput{Target: aws.String("i-0123456789abcdef0")}
}

func TestOwnedCleanupConcurrentAndRetry(t *testing.T) {
	f := api()
	s, err := Start(context.Background(), f, input(), "ca-central-1")
	if err != nil {
		t.Fatal(err)
	}
	for _, format := range []string{"%v", "%+v", "%#v", "%s"} {
		if strings.Contains(fmt.Sprintf(format, s), "synthetic-token") {
			t.Fatal("formatted session leaked token")
		}
	}
	f.terminateErr = errors.New("synthetic-token")
	if err = s.Terminate(context.Background()); err == nil || strings.Contains(err.Error(), "synthetic-token") {
		t.Fatal("cleanup failure missing or leaked")
	}
	f.terminateErr = nil
	var wg sync.WaitGroup
	for range 20 {
		wg.Go(func() {
			if err := s.Terminate(context.Background()); err != nil {
				t.Error(err)
			}
		})
	}
	wg.Wait()
	if f.terminates != 2 || f.terminatedID != testID {
		t.Fatal("cleanup was not idempotent, retryable, or owned")
	}
}

func TestMalformedStartAndAuthenticationFailure(t *testing.T) {
	for _, url := range []string{"ws://ssmmessages.ca-central-1.amazonaws.com/", "wss://attacker.invalid/v1/data-channel/" + testID + "?role=publish_subscribe", "wss://ssmmessages.ca-central-1.amazonaws.com/v1/data-channel/unrelated?role=publish_subscribe", "wss://ssmmessages.ca-central-1.amazonaws.com/v1/data-channel/" + testID + "?role=wrong"} {
		f := api()
		f.output.StreamUrl = aws.String(url)
		if s, err := Start(context.Background(), f, input(), "ca-central-1"); err == nil || s != nil || f.terminates != 1 {
			t.Fatal("malformed response accepted or not cleaned up")
		}
	}
	f := api()
	f.startErr = errors.New("synthetic-token")
	if _, err := Start(context.Background(), f, input(), "ca-central-1"); err == nil || strings.Contains(err.Error(), "synthetic-token") || f.terminates != 0 {
		t.Fatal("failed start ownership")
	}
	f = api()
	f.output.SessionId = aws.String("invalid\nID")
	if _, err := Start(context.Background(), f, input(), "ca-central-1"); err == nil || f.terminates != 0 {
		t.Fatal("unsafe session identifier used for cleanup")
	}
}

func TestOnlinePaginationAndStatus(t *testing.T) {
	id := "i-0123456789abcdef0"
	f := api()
	f.pages = []*sdk.DescribeInstanceInformationOutput{{NextToken: aws.String("page2")}, {InstanceInformationList: []types.InstanceInformation{{InstanceId: aws.String(id), PingStatus: types.PingStatusOnline, ResourceType: types.ResourceTypeEc2Instance, PlatformType: types.PlatformTypeLinux}}}}
	if _, err := Online(context.Background(), f, id); err != nil {
		t.Fatal(err)
	}
	if f.starts != 0 || f.terminates != 0 {
		t.Fatal("readiness started a session")
	}
	f.pages = []*sdk.DescribeInstanceInformationOutput{{NextToken: aws.String("repeated")}}
	f.page = 0
	if _, err := Online(context.Background(), f, id); err == nil {
		t.Fatal("pagination cycle accepted")
	}
	for _, status := range []types.PingStatus{types.PingStatusConnectionLost, types.PingStatusInactive} {
		f.pages = []*sdk.DescribeInstanceInformationOutput{{InstanceInformationList: []types.InstanceInformation{{InstanceId: aws.String(id), PingStatus: status, ResourceType: types.ResourceTypeEc2Instance, PlatformType: types.PlatformTypeLinux}}}}
		f.page = 0
		if _, err := Online(context.Background(), f, id); err == nil {
			t.Fatal("offline accepted")
		}
	}
}

func FuzzStreamValidation(f *testing.F) {
	f.Add("wss://ssmmessages.ca-central-1.amazonaws.com/v1/data-channel/" + testID + "?role=publish_subscribe")
	f.Add("")
	f.Fuzz(func(t *testing.T, s string) { _ = validateStream(s, testID, "ca-central-1") })
}
