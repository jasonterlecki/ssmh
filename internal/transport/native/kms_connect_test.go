package native

import (
	"bytes"
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
	"sync/atomic"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	sdk "github.com/aws/aws-sdk-go-v2/service/ssm"
	"github.com/aws/aws-sdk-go-v2/service/ssm/types"
	"ssmh/internal/ssm"
)

type encryptedDocument struct{ kind string }

func (d encryptedDocument) GetDocument(_ context.Context, in *sdk.GetDocumentInput, _ ...func(*sdk.Options)) (*sdk.GetDocumentOutput, error) {
	content := `{"schemaVersion":"1.0","sessionType":"Standard_Stream","inputs":{"kmsKeyId":"` + dataKeyARN + `"}}`
	if d.kind == "NonInteractiveCommands" {
		content = `{"schemaVersion":"1.0","sessionType":"NonInteractiveCommands","inputs":{"kmsKeyId":"` + dataKeyARN + `"},"parameters":{"command":{"type":"String"}},"properties":{"linux":{"commands":"{{ command }}","runAsElevated":false,"separateOutputStream":true}}}`
	}
	return &sdk.GetDocumentOutput{Name: in.Name, Content: aws.String(content), DocumentType: types.DocumentTypeSession, DocumentFormat: types.DocumentFormatJson, Status: types.DocumentStatusActive}, nil
}

func TestConnectDocumentOwnedKMSShellTLS(t *testing.T) {
	testConnectDocumentOwnedKMS(t, "Standard_Stream")
}

func TestConnectDocumentOwnedKMSCommandTLS(t *testing.T) {
	testConnectDocumentOwnedKMS(t, "NonInteractiveCommands")
}

func testConnectDocumentOwnedKMS(t *testing.T, kind string) {
	for _, mode := range []string{"success", "key mismatch", "early completion", "KMS denied", "KMS timeout", "plaintext"} {
		t.Run(mode, func(t *testing.T) {
			var keyCalls atomic.Int32
			agentDone := make(chan error, 1)
			challenge := challengePayload(t, bytes.Repeat([]byte{0x62}, 64))
			output := referencePayload(t, syntheticSessionMaterial()[:32], []byte("encrypted reply"))
			server := newTLSServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Header.Get("X-Amz-Target") == "TrentService.GenerateDataKey" {
					keyCalls.Add(1)
					var in struct {
						KeyId             string
						NumberOfBytes     int
						EncryptionContext map[string]string
					}
					if !strings.Contains(r.Header.Get("Authorization"), "/ca-central-1/kms/aws4_request") || json.NewDecoder(r.Body).Decode(&in) != nil || in.KeyId != dataKeyARN || in.NumberOfBytes != 64 || in.EncryptionContext["aws:ssm:SessionId"] != ownedID || in.EncryptionContext["aws:ssm:TargetId"] != dataKeyTarget || in.EncryptionContext["aws:ssm:RandomChallenge"] != testKMSChallenge {
						t.Error("selected KMS identity/context changed")
						w.WriteHeader(400)
						return
					}
					if mode == "KMS timeout" {
						<-r.Context().Done()
						return
					}
					if mode == "KMS denied" {
						w.WriteHeader(403)
						_, _ = io.WriteString(w, `{"__type":"AccessDeniedException","message":"SYNTHETIC-SECRET-ERROR"}`)
						return
					}
					w.Header().Set("Content-Type", "application/x-amz-json-1.1")
					_ = json.NewEncoder(w).Encode(map[string]any{"KeyId": dataKeyARN, "Plaintext": syntheticSessionMaterial(), "CiphertextBlob": []byte("synthetic-kms-ciphertext")})
					return
				}
				result := func() error {
					if !strings.Contains(r.Header.Get("Authorization"), "/ssmmessages/") {
						return errors.New("missing signed channel upgrade")
					}
					key := r.Header.Get("Sec-WebSocket-Key")
					sum := sha1.Sum([]byte(key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))
					conn, buf, err := w.(http.Hijacker).Hijack()
					if err != nil {
						return err
					}
					defer conn.Close()
					_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
					if _, err := fmt.Fprintf(buf, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: %s\r\n\r\n", base64.StdEncoding.EncodeToString(sum[:])); err != nil {
						return err
					}
					if err := buf.Flush(); err != nil {
						return err
					}
					op, data, err := readClientFrame(buf)
					var opened struct{ TokenValue string }
					if err != nil || op != wsText || json.Unmarshal(data, &opened) != nil || opened.TokenValue != "synthetic-ssm-token" {
						return errors.New("token exchange failed")
					}
					request := strings.Replace(string(kmsHandshake(kind, testKMSChallenge)), testKMSKey, dataKeyARN, 1)
					if mode == "key mismatch" {
						request = strings.Replace(request, dataKeyARN, dataKeyID, 1)
					}
					if err := sendRemote(t, conn, outputStream, HandshakeRequest, 0, []byte(request)); err != nil {
						return err
					}
					m, err := clientMessage(conn)
					if err != nil || m.Type != acknowledge {
						return errors.New("handshake ACK missing")
					}
					m, err = clientMessage(conn)
					if err != nil || m.PayloadType != HandshakeResponse {
						return errors.New("handshake response missing")
					}
					if mode == "key mismatch" || mode == "KMS denied" {
						_, _ = conn.Read(make([]byte, 1))
						return nil
					}
					if err := acknowledgeInput(t, conn, m); err != nil {
						return err
					}
					seq := int64(1)
					if mode != "early completion" {
						if err := sendRemote(t, conn, outputStream, EncryptionChallenge, seq, challenge); err != nil {
							return err
						}
						m, err = clientMessage(conn)
						if err != nil || m.Type != acknowledge {
							return errors.New("challenge ACK missing")
						}
						m, err = clientMessage(conn)
						if err != nil || m.PayloadType != EncryptionResponse {
							return errors.New("challenge response missing")
						}
						var answer struct{ Challenge []byte }
						if json.Unmarshal(m.Payload, &answer) != nil || !bytes.Equal(decodeClientCipher(t, answer.Challenge), bytes.Repeat([]byte{0x62}, 64)) {
							return errors.New("challenge authentication failed")
						}
						if err := acknowledgeInput(t, conn, m); err != nil {
							return err
						}
						seq++
					}
					if err := sendRemote(t, conn, outputStream, HandshakeComplete, seq, []byte(`{}`)); err != nil {
						return err
					}
					seq++
					m, err = clientMessage(conn)
					if err != nil || m.Type != acknowledge {
						return errors.New("completion ACK missing")
					}
					if mode == "early completion" {
						_, _ = conn.Read(make([]byte, 1))
						return nil
					}
					if mode == "plaintext" {
						return sendRemote(t, conn, outputStream, Output, seq, []byte("SYNTHETIC-PRIVATE-PLAINTEXT"))
					}
					if kind == "Standard_Stream" {
						m, err = clientMessage(conn)
						if err != nil || m.PayloadType != Output || string(decodeClientCipher(t, m.Payload)) != "encrypted input" {
							return errors.New("client input not independently authenticated")
						}
						if err := acknowledgeInput(t, conn, m); err != nil {
							return err
						}
					}
					if err := sendRemote(t, conn, outputStream, Output, seq, output); err != nil {
						return err
					}
					m, err = clientMessage(conn)
					if err != nil || m.Type != acknowledge {
						return errors.New("output ACK missing")
					}
					if kind == "NonInteractiveCommands" {
						for i, extra := range []struct {
							payloadType uint32
							text        string
						}{{StdErr, "encrypted stderr"}, {ExitCode, "EXIT_CODE: 37"}} {
							if err := sendRemote(t, conn, outputStream, extra.payloadType, seq+int64(i)+1, referencePayload(t, syntheticSessionMaterial()[:32], []byte(extra.text))); err != nil {
								return err
							}
							m, err = clientMessage(conn)
							if err != nil || m.Type != acknowledge {
								return errors.New("command data ACK missing")
							}
						}
					}
					if err := sendRemote(t, conn, channelClosed, 0, 0, []byte(`{"SessionId":"`+ownedID+`"}`)); err != nil {
						return err
					}
					_, _ = conn.Read(make([]byte, 1))
					return nil
				}()
				agentDone <- result
			}))
			defer server.Close()
			destination, _ := url.Parse(server.URL)
			client := server.Client()
			client.Transport = redirectTransport{client.Transport, destination}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			var s *ssm.Session
			var err error
			if kind == "Standard_Stream" {
				s, err = ssm.StartShell(ctx, startAPI{}, encryptedDocument{}, &sdk.StartSessionInput{Target: aws.String(dataKeyTarget)}, "ca-central-1")
			} else {
				s, err = ssm.StartCommand(ctx, startAPI{}, encryptedDocument{kind: kind}, &sdk.StartSessionInput{Target: aws.String(dataKeyTarget), DocumentName: aws.String("ReviewedCommand"), Parameters: map[string][]string{"command": {"/bin/sh -c 'exit 37'"}}}, "ca-central-1")
			}
			if err != nil || s == nil || s.HandshakeOptional() {
				t.Fatal("encrypted document capability missing")
			}
			defer s.Terminate(context.Background())
			if selectedType, selectedKey := s.DocumentKMSContext(); selectedType != kind || selectedKey != dataKeyARN {
				t.Fatal("document capability type/key changed")
			}
			cfg := aws.Config{Region: "ca-central-1", HTTPClient: client, Credentials: credentials.NewStaticCredentialsProvider("synthetic-key", "synthetic-secret", ""), RetryMaxAttempts: 1}
			otherType := "NonInteractiveCommands"
			if kind == otherType {
				otherType = "Standard_Stream"
			}
			if other, err := Connect(ctx, cfg, s, otherType, time.Second); err == nil || other != nil || keyCalls.Load() != 0 {
				t.Fatal("document KMS capability authorized another session type or key side effect")
			}
			timeout := 3 * time.Second
			if mode == "KMS timeout" {
				timeout = 150 * time.Millisecond
			}
			c, err := Connect(ctx, cfg, s, kind, timeout)
			if mode != "success" && (mode != "plaintext" || err != nil) {
				if err == nil || c != nil || strings.Contains(err.Error(), "SYNTHETIC-SECRET") || strings.Contains(err.Error(), testKMSChallenge) {
					t.Fatal("encrypted setup failed open or disclosed data")
				}
			} else {
				if err != nil || c == nil {
					t.Fatal("encrypted TLS setup failed")
				}
				defer c.Close()
				if mode == "success" && kind == "Standard_Stream" {
					if err := c.Send(ctx, Output, []byte("encrypted input")); err != nil {
						t.Fatal("encrypted TLS send failed")
					}
				}
				m, err := c.Receive(ctx)
				if mode == "plaintext" {
					if err == nil || len(m.Payload) != 0 || strings.Contains(err.Error(), "SYNTHETIC-PRIVATE") {
						t.Fatal("plaintext emitted or disclosed")
					}
				} else {
					if err != nil || string(m.Payload) != "encrypted reply" {
						t.Fatal("encrypted TLS output lost")
					}
					if kind == "NonInteractiveCommands" {
						for _, want := range []struct {
							payloadType uint32
							text        string
						}{{StdErr, "encrypted stderr"}, {ExitCode, "EXIT_CODE: 37"}} {
							m, err := c.Receive(ctx)
							if err != nil || m.PayloadType != want.payloadType || string(m.Payload) != want.text {
								t.Fatal("encrypted command stderr/status changed")
							}
						}
					}
					if _, err := c.Receive(ctx); !errors.Is(err, io.EOF) {
						t.Fatal("encrypted TLS owned EOF lost")
					}
					if err := c.Close(); err != nil {
						t.Fatal("encrypted TLS cleanup failed")
					}
				}
			}
			select {
			case agentErr := <-agentDone:
				if mode == "success" && agentErr != nil {
					t.Fatal("synthetic encrypted TLS agent failed")
				}
			case <-ctx.Done():
				t.Fatal("synthetic encrypted TLS agent did not join")
			}
			wanted := int32(1)
			if mode == "key mismatch" {
				wanted = 0
			}
			if keyCalls.Load() != wanted {
				t.Fatal("key generation occurred before validation or repeated")
			}
		})
	}
}
