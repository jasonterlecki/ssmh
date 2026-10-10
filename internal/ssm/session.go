// Package ssm owns authenticated session control and process-created session cleanup.
package ssm

import (
	"context"
	"errors"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	sdk "github.com/aws/aws-sdk-go-v2/service/ssm"

	"ssmh/internal/config"
	"ssmh/internal/logging"
)

// API is the session ownership and readiness boundary used by SDK clients and tests.
type API interface {
	StartSession(context.Context, *sdk.StartSessionInput, ...func(*sdk.Options)) (*sdk.StartSessionOutput, error)
	TerminateSession(context.Context, *sdk.TerminateSessionInput, ...func(*sdk.Options)) (*sdk.TerminateSessionOutput, error)
	DescribeInstanceInformation(context.Context, *sdk.DescribeInstanceInformationInput, ...func(*sdk.Options)) (*sdk.DescribeInstanceInformationOutput, error)
}

// Session contains sensitive transport material. Never serialize it into diagnostics.
// Fields are private so callers cannot manufacture ownership of unrelated sessions.
type Session struct {
	client            API
	id, stream, token string
	target, region    string
	mu                sync.Mutex
	terminated        bool
	handshakeOptional bool
	kmsKey, kmsType   string
}

// String and GoString prevent accidental formatted logging of authentication material.
func (s *Session) String() string   { return "SSM session [authentication material redacted]" }
func (s *Session) GoString() string { return s.String() }

var sessionID = regexp.MustCompile(`^[A-Za-z0-9_.@-]{1,128}$`)

// Start starts and validates one owned session. Malformed responses trigger cleanup.
func Start(ctx context.Context, client API, input *sdk.StartSessionInput, region string) (*Session, error) {
	if input == nil || !config.InstanceID(aws.ToString(input.Target)) {
		return nil, errors.New("StartSession requires a validated EC2 instance ID")
	}
	if err := config.Region(region); err != nil {
		return nil, err
	}
	target := aws.ToString(input.Target)
	output, err := client.StartSession(ctx, input)
	if err != nil {
		return nil, logging.Failure("start SSM session", err)
	}
	if output == nil || !sessionID.MatchString(aws.ToString(output.SessionId)) {
		return nil, errors.New("SSM returned an invalid session identifier; cleanup could not be attempted safely")
	}
	s := &Session{client: client, id: aws.ToString(output.SessionId), stream: aws.ToString(output.StreamUrl), token: aws.ToString(output.TokenValue), target: target, region: region}
	if err = validateStream(s.stream, s.id, region); err != nil || s.token == "" || len(s.token) > 65536 {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		cleanupErr := s.Terminate(cleanupCtx)
		return nil, errors.Join(errors.New("SSM returned invalid data-channel authentication material"), cleanupErr)
	}
	return s, nil
}

func validateStream(raw, id, region string) error {
	if len(raw) > 8192 {
		return errors.New("invalid SSM stream endpoint")
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "wss" || u.User != nil || u.Fragment != "" || u.Port() != "" {
		return errors.New("invalid SSM stream endpoint")
	}
	// Exact regional service hosts prevent sending tokens to attacker-selected hosts.
	suffix := "amazonaws.com"
	if strings.HasPrefix(region, "cn-") {
		suffix = "amazonaws.com.cn"
	}
	if u.Host != "ssmmessages."+region+"."+suffix {
		return errors.New("unsupported SSM stream endpoint")
	}
	if u.Path != "/v1/data-channel/"+id {
		return errors.New("invalid SSM stream path")
	}
	q, err := url.ParseQuery(u.RawQuery)
	if err != nil || len(q["role"]) != 1 || q.Get("role") != "publish_subscribe" {
		return errors.New("invalid SSM stream role")
	}
	return nil
}

// TransportMaterial returns material solely for authenticated transport setup.
func (s *Session) TransportMaterial() (id, stream, token string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.id, s.stream, s.token
}

// OwnedContext returns validated non-secret identifiers for a live process-owned
// session. It grants no document, credential or encryption authorization.
// Termination is checked under the ownership lock; a later concurrent termination
// can still race a caller's operation and must be handled by its lifetime context.
func (s *Session) OwnedContext() (id, target, region string, live bool) {
	if s == nil {
		return "", "", "", false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.terminated || s.client == nil || s.token == "" || s.stream == "" || !sessionID.MatchString(s.id) || !config.InstanceID(s.target) || config.Region(s.region) != nil {
		return "", "", "", false
	}
	return s.id, s.target, s.region, true
}

// HandshakeOptional is true only for a live owned shell whose selected document
// was authenticated and verified non-KMS by StartShell. It is not a user override.
func (s *Session) HandshakeOptional() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.handshakeOptional && !s.terminated
}

// ShellKMSKey returns the literal key authenticated by StartShell's document
// preflight for this live owned session. Ordinary Start never grants it.
// Document/alias administrators remain trusted; no version can be pinned.
func (s *Session) ShellKMSKey() string {
	kind, key := s.DocumentKMSContext()
	if kind != "Standard_Stream" {
		return ""
	}
	return key
}

// DocumentKMSContext binds a literal document-selected key to the session type
// validated by StartShell or StartCommand. Ordinary Start grants no capability.
func (s *Session) DocumentKMSContext() (sessionType, key string) {
	if s == nil {
		return "", ""
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.terminated {
		return "", ""
	}
	return s.kmsType, s.kmsKey
}

// ReleaseAfterRemoteCompletion releases ownership and transport references without
// an API call. The caller must first verify authenticated owned-session closure
// and successful local shutdown; socket EOF or cancellation alone is insufficient.
func (s *Session) ReleaseAfterRemoteCompletion() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.terminated = true
	s.stream, s.token = "", ""
	s.kmsKey, s.kmsType = "", ""
}

// Terminate performs idempotent owned-session cleanup. Failed cleanup may be retried.
func (s *Session) Terminate(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.terminated {
		return nil
	}
	_, err := s.client.TerminateSession(ctx, &sdk.TerminateSessionInput{SessionId: aws.String(s.id)})
	if err != nil {
		return logging.Failure("terminate owned SSM session (cleanup is best effort)", err)
	}
	s.terminated = true
	s.stream, s.token = "", ""
	s.kmsKey, s.kmsType = "", ""
	return nil
}
