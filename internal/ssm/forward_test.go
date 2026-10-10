package ssm

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"reflect"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	sdk "github.com/aws/aws-sdk-go-v2/service/ssm"
	"ssmh/internal/config"
)

type forwardAPI struct {
	*fakeAPI
	request *sdk.StartSessionInput
	ctx     context.Context
	started func()
}

func (f *forwardAPI) StartSession(ctx context.Context, in *sdk.StartSessionInput, options ...func(*sdk.Options)) (*sdk.StartSessionOutput, error) {
	f.ctx, f.request = ctx, in
	if f.started != nil {
		f.started()
	}
	return f.fakeAPI.StartSession(ctx, in, options...)
}

func TestStartForwardExactDocumentsAndOwnership(t *testing.T) {
	for _, host := range []string{"", "database.internal", "2001:db8::1", "Example.COM."} {
		f := &forwardAPI{fakeAPI: api()}
		target := config.ForwardTarget{LocalPort: 15432, RemotePort: 5432, Host: host}
		ctx := context.WithValue(context.Background(), struct{}{}, "context-marker")
		session, err := StartForward(ctx, f, aws.ToString(input().Target), "ca-central-1", "maintenance reason", target)
		if err != nil || session == nil || session.HandshakeOptional() || f.starts != 1 || f.ctx != ctx {
			t.Fatal("session ownership or strict handshake lost")
		}
		document := "AWS-StartPortForwardingSession"
		want := map[string][]string{"portNumber": {"5432"}, "localPortNumber": {"15432"}}
		if host != "" {
			document += "ToRemoteHost"
			want["host"] = []string{host}
		}
		if aws.ToString(f.request.DocumentName) != document || aws.ToString(f.request.Target) != aws.ToString(input().Target) || aws.ToString(f.request.Reason) != "maintenance reason" || !reflect.DeepEqual(f.request.Parameters, want) {
			t.Fatal("forward destination, document or reason changed")
		}
		if err := session.Terminate(context.Background()); err != nil || f.terminates != 1 || f.terminatedID != testID {
			t.Fatal("owned cleanup failed")
		}
	}
}

func TestStartForwardInvalidSetup(t *testing.T) {
	valid := config.ForwardTarget{LocalPort: 8080, RemotePort: 80}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	for _, tc := range []struct {
		ctx                      context.Context
		instance, region, reason string
		target                   config.ForwardTarget
	}{
		{nil, aws.ToString(input().Target), "ca-central-1", "", valid},
		{canceled, aws.ToString(input().Target), "ca-central-1", "", valid},
		{context.Background(), "name-secret", "ca-central-1", "", valid},
		{context.Background(), aws.ToString(input().Target), "region-secret", "", valid},
		{context.Background(), aws.ToString(input().Target), "ca-central-1", "secret\nreason", valid},
		{context.Background(), aws.ToString(input().Target), "ca-central-1", strings.Repeat("x", 257), valid},
		{context.Background(), aws.ToString(input().Target), "ca-central-1", "", config.ForwardTarget{LocalPort: 8080, RemotePort: 0}},
		{context.Background(), aws.ToString(input().Target), "ca-central-1", "", config.ForwardTarget{LocalPort: 8080, RemotePort: 80, Host: "bad\nsecret"}},
	} {
		f := &forwardAPI{fakeAPI: api()}
		s, err := StartForward(tc.ctx, f, tc.instance, tc.region, tc.reason, tc.target)
		if s != nil || err == nil || f.starts != 0 || f.terminates != 0 || strings.Contains(err.Error(), "secret") {
			t.Fatal("invalid setup attempted AWS or leaked input")
		}
		if tc.ctx == canceled && !errors.Is(err, context.Canceled) {
			t.Fatal("setup cancellation lost")
		}
	}
	if s, err := StartForward(context.Background(), nil, aws.ToString(input().Target), "ca-central-1", "", valid); s != nil || err == nil {
		t.Fatal("nil client accepted")
	}
}

func TestStartForwardFailureAndCancellationOwnership(t *testing.T) {
	target := config.ForwardTarget{LocalPort: 8080, RemotePort: 80}
	f := &forwardAPI{fakeAPI: api()}
	f.startErr = errors.New("secret-token")
	s, err := StartForward(context.Background(), f, aws.ToString(input().Target), "ca-central-1", "", target)
	if s != nil || err == nil || strings.Contains(err.Error(), "secret") || f.terminates != 0 || f.starts != 1 {
		t.Fatal("start failure leaked or acquired ownership")
	}
	f = &forwardAPI{fakeAPI: api()}
	f.output.StreamUrl = aws.String("wss://secret.invalid/")
	s, err = StartForward(context.Background(), f, aws.ToString(input().Target), "ca-central-1", "", target)
	if s != nil || err == nil || strings.Contains(err.Error(), "secret") || f.terminates != 1 || f.terminatedID != testID {
		t.Fatal("malformed response not safely cleaned")
	}
	ctx, cancel := context.WithCancel(context.Background())
	f = &forwardAPI{fakeAPI: api(), started: cancel}
	s, err = StartForward(ctx, f, aws.ToString(input().Target), "ca-central-1", "", target)
	if err != nil || s == nil || f.request.Reason != nil {
		t.Fatal("cancellation dropped successful owned response or empty reason supplied")
	}
	if err := s.Terminate(context.Background()); err != nil || f.terminates != 1 {
		t.Fatal("canceled response cleanup failed")
	}
}

func TestStartForwardThroughActualSDK(t *testing.T) {
	for _, host := range []string{"", "database.internal", "2001:db8::1"} {
		calls := 0
		client := sdk.NewFromConfig(aws.Config{Region: "ca-central-1", Credentials: credentials.NewStaticCredentialsProvider("synthetic-key", "synthetic-secret", "synthetic-session"), HTTPClient: inventoryHTTP(func(request *http.Request) (*http.Response, error) {
			calls++
			if request.Method != "POST" || request.URL.Scheme != "https" || request.URL.Host != "ssm.ca-central-1.amazonaws.com" || !strings.HasPrefix(request.Header.Get("Authorization"), "AWS4-HMAC-SHA256 ") {
				t.Fatal("not authenticated regional SSM")
			}
			body := `{}`
			if calls == 1 {
				if request.Header.Get("X-Amz-Target") != "AmazonSSM.StartSession" {
					t.Fatal("wrong API for forwarding")
				}
				var wire map[string]json.RawMessage
				if json.NewDecoder(request.Body).Decode(&wire) != nil || len(wire) != 4 {
					t.Fatal("unexpected serialized request fields")
				}
				var target, document, reason string
				var params map[string][]string
				if json.Unmarshal(wire["Target"], &target) != nil || json.Unmarshal(wire["DocumentName"], &document) != nil || json.Unmarshal(wire["Reason"], &reason) != nil || json.Unmarshal(wire["Parameters"], &params) != nil {
					t.Fatal("invalid SDK JSON")
				}
				wantDoc := "AWS-StartPortForwardingSession"
				want := map[string][]string{"localPortNumber": {"8080"}, "portNumber": {"80"}}
				if host != "" {
					wantDoc += "ToRemoteHost"
					want["host"] = []string{host}
				}
				if target != aws.ToString(input().Target) || document != wantDoc || reason != "maintenance" || !reflect.DeepEqual(params, want) {
					t.Fatal("SDK changed forwarding request")
				}
				body = `{"SessionId":"` + testID + `","TokenValue":"synthetic-token","StreamUrl":"wss://ssmmessages.ca-central-1.amazonaws.com/v1/data-channel/` + testID + `?role=publish_subscribe"}`
			} else if calls == 2 {
				if request.Header.Get("X-Amz-Target") != "AmazonSSM.TerminateSession" {
					t.Fatal("wrong cleanup API")
				}
				var in sdk.TerminateSessionInput
				if json.NewDecoder(request.Body).Decode(&in) != nil || aws.ToString(in.SessionId) != testID {
					t.Fatal("cleanup targeted unrelated session")
				}
			} else {
				t.Fatal("unexpected API or fallback")
			}
			return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": {"application/x-amz-json-1.1"}}, Body: io.NopCloser(strings.NewReader(body)), Request: request}, nil
		})})
		s, err := StartForward(context.Background(), client, aws.ToString(input().Target), "ca-central-1", "maintenance", config.ForwardTarget{LocalPort: 8080, RemotePort: 80, Host: host})
		if err != nil || s == nil || s.HandshakeOptional() {
			t.Fatal("SDK response did not establish strict owned session")
		}
		if err := s.Terminate(context.Background()); err != nil || calls != 2 {
			t.Fatal("SDK owned cleanup failed")
		}
	}
}
