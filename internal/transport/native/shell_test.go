package native

import (
	"context"
	"crypto/sha1"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	sdk "github.com/aws/aws-sdk-go-v2/service/ssm"
	"github.com/aws/aws-sdk-go-v2/service/ssm/types"
	"ssmh/internal/ssm"
)

type shellDocumentAPI struct{}

func (shellDocumentAPI) GetDocument(_ context.Context, input *sdk.GetDocumentInput, _ ...func(*sdk.Options)) (*sdk.GetDocumentOutput, error) {
	return &sdk.GetDocumentOutput{Name: input.Name, Content: aws.String(`{"schemaVersion":"1.0","sessionType":"Standard_Stream","inputs":{"kmsKeyId":""}}`), DocumentType: types.DocumentTypeSession, DocumentFormat: types.DocumentFormatJson, Status: types.DocumentStatusActive}, nil
}

// This crosses the real Connect/StartShell capability boundary and uses real
// TLS, SigV4 and token exchange over an in-memory network (no live AWS access).
func TestConnectAuthenticatedHandshakeFreeShell(t *testing.T) {
	for _, mode := range []string{"verified-shell", "ordinary-start", "command", "required-kms", "required-kms-challenge"} {
		t.Run(mode, func(t *testing.T) {
			agentDone := make(chan error, 1)
			server := newTLSServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				var result error
				defer func() { agentDone <- result }()
				if !strings.HasPrefix(r.Header.Get("Authorization"), "AWS4-HMAC-SHA256 ") || !strings.Contains(r.Header.Get("Authorization"), "/ssmmessages/") {
					result = errors.New("missing authenticated upgrade")
					return
				}
				key := r.Header.Get("Sec-WebSocket-Key")
				sum := sha1.Sum([]byte(key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))
				conn, buf, err := w.(http.Hijacker).Hijack()
				if err != nil {
					result = err
					return
				}
				defer conn.Close()
				_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
				if _, err = fmt.Fprintf(buf, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: %s\r\n\r\n", base64.StdEncoding.EncodeToString(sum[:])); err != nil {
					result = err
					return
				}
				if err = buf.Flush(); err != nil {
					result = err
					return
				}
				op, data, err := readClientFrame(buf)
				var opened struct{ TokenValue, ClientVersion string }
				if err != nil || op != wsText || json.Unmarshal(data, &opened) != nil || opened.TokenValue != "synthetic-ssm-token" || opened.ClientVersion != "1.2.339.0" {
					result = errors.New("missing authenticated token exchange")
					return
				}
				kind, payload := Output, []byte("initial prompt\x00\xff")
				if mode == "required-kms" || mode == "required-kms-challenge" {
					kind = HandshakeRequest
					payload = []byte(`{"RequestedClientActions":[{"ActionType":"SessionType","ActionParameters":{"SessionType":"Standard_Stream"}},{"ActionType":"KMSEncryption","ActionParameters":{"KMSKeyId":"synthetic"}}]}`)
					if mode == "required-kms-challenge" {
						payload = []byte(`{"RequestedClientActions":[{"ActionType":"SessionType","ActionParameters":{"SessionType":"Standard_Stream"}},{"ActionType":"KMSEncryption","ActionParameters":{"KMSKeyId":"synthetic-key","Challenge":"AAECAwQFBgcICQoLDA0ODw=="}}]}`)
					}
				}
				if err = sendRemote(t, conn, outputStream, kind, 0, payload); err != nil {
					result = err
					return
				}
				if mode != "verified-shell" {
					// Invalid first output/KMS negotiation must close, never send input.
					for {
						m, err := clientMessage(conn)
						if err != nil {
							return
						}
						if m.Type == inputStream && m.PayloadType != HandshakeResponse {
							result = errors.New("application input sent on unverified channel")
							return
						}
					}
				}
				m, err := clientMessage(conn)
				if err != nil || m.Type != acknowledge {
					result = errors.New("first shell output was not acknowledged")
					return
				}
				m, err = clientMessage(conn)
				if err != nil || m.Type != inputStream || m.PayloadType != Size || m.Sequence != 0 || string(m.Payload) != `{"cols":80,"rows":24}` {
					result = errors.New("initial resize changed or handshake response invented")
					return
				}
				if err = acknowledgeInput(t, conn, m); err != nil {
					result = err
					return
				}
				if err = sendRemote(t, conn, outputStream, Output, 1, []byte("reply")); err != nil {
					result = err
					return
				}
				m, err = clientMessage(conn)
				if err != nil || m.Type != acknowledge {
					result = errors.New("second shell output not acknowledged")
					return
				}
				payload, _ = json.Marshal(map[string]string{"SessionId": ownedID})
				result = sendRemote(t, conn, channelClosed, 0, 0, payload)
				if result == nil {
					// Let the client finish its TLS close_notify before closing the
					// peer; premature server shutdown is a real cleanup failure.
					_, _ = conn.Read(make([]byte, 1))
				}
			}))
			defer server.Close()
			destination, _ := url.Parse(server.URL)
			client := server.Client()
			client.Transport = redirectTransport{client.Transport, destination}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			ctx, trace := WithTrace(ctx)
			request := &sdk.StartSessionInput{Target: aws.String("i-0123456789abcdef0")}
			var session *ssm.Session
			var err error
			if mode == "ordinary-start" {
				session, err = ssm.Start(ctx, startAPI{}, request, "ca-central-1")
			} else {
				session, err = ssm.StartShell(ctx, startAPI{}, shellDocumentAPI{}, request, "ca-central-1")
			}
			if err != nil {
				t.Fatal(err)
			}
			defer session.Terminate(context.Background())
			cfg := aws.Config{Region: "ca-central-1", HTTPClient: client, Credentials: credentials.NewStaticCredentialsProvider("synthetic-key", "synthetic-secret", "")}
			sessionType := "Standard_Stream"
			if mode == "command" {
				sessionType = "NonInteractiveCommands"
			}
			channel, err := Connect(ctx, cfg, session, sessionType, 3*time.Second)
			if mode != "verified-shell" {
				if err == nil || channel != nil {
					t.Fatal("unverified shell or required KMS bypassed handshake")
				}
				if strings.HasPrefix(mode, "required-kms") && (!strings.Contains(err.Error(), kmsUnsupportedMessage) || strings.Contains(err.Error(), "synthetic-key") || strings.Contains(err.Error(), "AAECAwQFBgcICQoLDA0ODw==")) {
					t.Fatal("KMS setup failure concealed the unsupported feature or exposed handshake material")
				}
			} else {
				if err != nil {
					t.Fatal(err)
				}
				defer channel.Close()
				m, err := channel.Receive(ctx)
				if err != nil || string(m.Payload) != "initial prompt\x00\xff" {
					t.Fatal("initial output not preserved through establishment")
				}
				if err = channel.Send(ctx, Size, []byte(`{"cols":80,"rows":24}`)); err != nil {
					t.Fatal(err)
				}
				m, err = channel.Receive(ctx)
				if err != nil || string(m.Payload) != "reply" {
					t.Fatal("subsequent output not delivered")
				}
				if _, err = channel.Receive(ctx); err != io.EOF {
					t.Fatalf("owned close missing: %v", err)
				}
				if err = channel.Close(); err != nil {
					t.Fatal(err)
				}
			}
			select {
			case err := <-agentDone:
				if err != nil {
					t.Fatal(err)
				}
			case <-ctx.Done():
				t.Fatal("synthetic agent failed to shut down")
			}
			labels := strings.Join(traceLabels(t, trace), "\n")
			if !strings.HasPrefix(labels, "WebSocket opening\nWebSocket authenticated; token submitted\nprotocol readiness pending\n") || strings.Contains(labels, "synthetic") || strings.Contains(labels, "initial prompt") || strings.Contains(labels, ownedID) {
				t.Fatal("real native trace lost state order or retained remote/authentication data")
			}
			if mode == "verified-shell" {
				if !strings.Contains(labels, "document-authorized shell output verified\nowned-session EOF verified\nWebSocket closed") || strings.Contains(labels, "handshake verified") || strings.Contains(labels, "channel failed") {
					t.Fatal("shell readiness/owned close mislabeled")
				}
			} else if !strings.Contains(labels, "channel failed") || strings.Contains(labels, "output verified") || strings.Contains(labels, "handshake verified") || strings.Contains(labels, "EOF verified") {
				t.Fatal("failed native negotiation fabricated readiness/completion")
			}
		})
	}
}
