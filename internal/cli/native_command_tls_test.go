package cli

import (
	"bufio"
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha1"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	sdkaws "github.com/aws/aws-sdk-go-v2/aws"
	"ssmh/internal/aws"
	"ssmh/internal/command"
	"ssmh/internal/config"
	"ssmh/internal/transport/native"
)

// This crosses the real CLI/SDK/native/result/cleanup composition. Only network
// routing is replaced; all credentials, payloads and API replies are synthetic.
func TestNativeCommandTLSComposition(t *testing.T) {
	testNativeTLSComposition(t, false, nil)
}

func TestNativeShellTLSComposition(t *testing.T) {
	testNativeTLSComposition(t, true, nil)
}

func testNativeTLSComposition(t *testing.T, shell bool, executable *compositionExecutable) {
	if testing.Short() || os.Getenv("SSMH_TEST_TCP") != "1" {
		t.Skip("set SSMH_TEST_TCP=1 to exercise the CLI against synthetic OS TLS sockets")
	}
	modes := []string{"plain", "encrypted", "key-denied", "corrupt-output", "missing-status", "cleanup-denied", "upgrade-denied"}
	if shell {
		modes = []string{"plain", "network-drop", "cleanup-denied", "upgrade-denied"}
		if executable != nil {
			modes = append(modes, "tty-sigterm")
		}
	}
	for _, mode := range modes {
		t.Run(mode, func(t *testing.T) {
			encrypted := !shell && mode != "plain"
			const keyARN = "arn:aws:kms:ca-central-1:123456789012:key/12345678-1234-1234-1234-123456789abc"
			material := append(bytes.Repeat([]byte{0x31}, 32), bytes.Repeat([]byte{0x72}, 32)...)
			var starts, ends, keys atomic.Int32
			peerDone := make(chan error, 1)
			ttyReady := make(chan struct{})
			server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if executable != nil && !compositionSignedRequest(r) {
					t.Error("compiled invocation lost signed selected-service routing")
					w.WriteHeader(400)
					return
				}
				if r.Header.Get("Upgrade") == "websocket" {
					if mode == "upgrade-denied" {
						w.WriteHeader(http.StatusForbidden)
						_, _ = io.WriteString(w, "synthetic-secret-upgrade-error")
						peerDone <- nil
						return
					}
					if shell {
						peerDone <- composedPlainShellPeer(r, w, mode, ttyReady)
					} else {
						peerDone <- composedCommandPeer(r, w, encrypted, mode, material, keyARN)
					}
					return
				}
				w.Header().Set("Content-Type", "application/x-amz-json-1.1")
				switch r.Header.Get("X-Amz-Target") {
				case "AmazonSSM.GetDocument":
					content := cliCommandDocument
					name := "ReviewedCommand"
					if shell {
						name = "SSM-SessionManagerRunShell"
						content = `{"schemaVersion":"1.0","sessionType":"Standard_Stream","inputs":{"kmsKeyId":""}}`
					}
					if encrypted {
						content = strings.Replace(content, `"parameters":`, `"inputs":{"kmsKeyId":"`+keyARN+`"},"parameters":`, 1)
					}
					var request struct {
						Name            string
						DocumentVersion string
					}
					if json.NewDecoder(r.Body).Decode(&request) != nil || request.Name != name || request.DocumentVersion != "$DEFAULT" {
						t.Error("composed document selection changed")
						w.WriteHeader(400)
						return
					}
					_ = json.NewEncoder(w).Encode(map[string]string{"Name": name, "DocumentType": "Session", "DocumentFormat": "JSON", "Status": "Active", "Content": content})
				case "AmazonSSM.StartSession":
					var input struct {
						Target, DocumentName string
						Parameters           map[string][]string
					}
					expected, _ := command.SerializeShell("printf 'synthetic command'; exit 37")
					invalid := json.NewDecoder(r.Body).Decode(&input) != nil || input.Target != cliTarget
					if shell {
						invalid = invalid || input.DocumentName != "" || len(input.Parameters) != 0
					} else {
						invalid = invalid || input.DocumentName != "ReviewedCommand" || len(input.Parameters["command"]) != 1
						if !invalid {
							invalid = input.Parameters["command"][0] != expected
						}
					}
					if invalid {
						t.Error("composed command request changed")
						w.WriteHeader(400)
						return
					}
					starts.Add(1)
					_, _ = io.WriteString(w, `{"SessionId":"unit-owned","TokenValue":"synthetic-secret-token","StreamUrl":"wss://ssmmessages.ca-central-1.amazonaws.com/v1/data-channel/unit-owned?role=publish_subscribe"}`)
				case "AmazonSSM.TerminateSession":
					var input struct {
						SessionID string `json:"SessionId"`
					}
					if json.NewDecoder(r.Body).Decode(&input) != nil || input.SessionID != "unit-owned" || r.Context().Err() != nil {
						t.Error("composed cleanup lost ownership/context")
						w.WriteHeader(400)
						return
					}
					ends.Add(1)
					if mode == "cleanup-denied" {
						w.WriteHeader(400)
						_, _ = io.WriteString(w, `{"__type":"AccessDeniedException","Message":"synthetic-secret-cleanup"}`)
					} else {
						_, _ = io.WriteString(w, `{}`)
					}
				case "TrentService.GenerateDataKey":
					keys.Add(1)
					var input struct {
						KeyID             string `json:"KeyId"`
						NumberOfBytes     int
						EncryptionContext map[string]string
					}
					if json.NewDecoder(r.Body).Decode(&input) != nil || input.KeyID != keyARN || input.NumberOfBytes != 64 || input.EncryptionContext["aws:ssm:SessionId"] != "unit-owned" || input.EncryptionContext["aws:ssm:TargetId"] != cliTarget || input.EncryptionContext["aws:ssm:RandomChallenge"] != "AAECAwQFBgcICQoLDA0ODw==" {
						t.Error("composed KMS context changed")
						w.WriteHeader(400)
						return
					}
					if mode == "key-denied" {
						w.WriteHeader(400)
						_, _ = io.WriteString(w, `{"__type":"AccessDeniedException","message":"synthetic-secret-key-error"}`)
						return
					}
					_ = json.NewEncoder(w).Encode(map[string]any{"KeyId": keyARN, "Plaintext": material, "CiphertextBlob": []byte("synthetic-secret-key-blob")})
				case "AmazonSSM.DescribeInstanceInformation":
					_, _ = io.WriteString(w, `{"InstanceInformationList":[{"InstanceId":"i-0123456789abcdef0","PingStatus":"Online","PlatformType":"Linux","ResourceType":"EC2Instance"}]}`)
				case "":
					if r.ParseForm() != nil || r.Form.Get("Action") != "DescribeInstances" || r.Form.Get("Filter.1.Value.1") != cliTarget {
						t.Error("composed EC2 resolution changed")
						w.WriteHeader(400)
						return
					}
					w.Header().Set("Content-Type", "text/xml")
					_, _ = io.WriteString(w, `<DescribeInstancesResponse xmlns="http://ec2.amazonaws.com/doc/2016-11-15/"><reservationSet><item><instancesSet><item><instanceId>i-0123456789abcdef0</instanceId><instanceState><name>running</name></instanceState></item></instancesSet></item></reservationSet></DescribeInstancesResponse>`)
				default:
					t.Error("unexpected composed SDK operation")
					w.WriteHeader(400)
				}
			}))
			if executable != nil {
				server.TLS = &tls.Config{Certificates: []tls.Certificate{executable.certificate}, MinVersion: tls.VersionTLS12}
			}
			server.StartTLS()
			defer server.Close()
			destination, _ := url.Parse(server.URL)
			client := server.Client()
			client.Transport = compositionTransport{base: client.Transport, destination: destination, t: t}
			d := diagnosticSDKDependencies(t, nil, nil)
			t.Setenv("AWS_ENDPOINT_URL_KMS", "")
			load := d.load
			d.load = func(ctx context.Context, o config.Options, prompt aws.TokenProvider) (sdkaws.Config, error) {
				cfg, err := load(ctx, o, prompt)
				cfg.HTTPClient = client
				return cfg, err
			}
			d.connect = production().connect
			d.run = production().run
			_, out, stderr := cliFiles(t)
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			args := []string{"-i", cliTarget, "-r", "ca-central-1", "-c", "printf 'synthetic command'; exit 37", "--document", "ReviewedCommand", "-q"}
			var input *os.File
			if shell {
				args = []string{"-i", cliTarget, "-r", "ca-central-1", "-q"}
			}
			if shell && mode != "tty-sigterm" {
				read, write, err := os.Pipe()
				if err != nil {
					t.Fatal("cannot create synthetic shell input")
				}
				input = read
				defer read.Close()
				if _, err = io.WriteString(write, "synthetic shell input\n\x03"); err != nil {
					_ = write.Close()
					t.Fatal("cannot prepare synthetic shell input")
				}
				if write.Close() != nil {
					t.Fatal("cannot close synthetic shell input")
				}
			}
			var err error
			code := 0
			if executable == nil {
				err = run(ctx, args, input, out, stderr, d)
				code = ExitCode(err)
			} else {
				args = append(args, "--ca-cert", executable.roots)
				proxy := compositionProxy(t, server.Listener.Addr().String())
				defer proxy.Close()
				cmd := exec.CommandContext(ctx, executable.path, args...)
				cmd.Env = executable.environment(proxy.URL)
				cmd.Stdout = out
				cmd.Stderr = stderr
				cmd.Stdin = input
				cmd.WaitDelay = time.Second
				if mode == "tty-sigterm" {
					err = compositionTTYSignal(t, ctx, cmd, ttyReady)
				} else {
					err = cmd.Run()
				}
				if err != nil {
					var exit *exec.ExitError
					if errors.As(err, &exit) {
						code = exit.ExitCode()
					} else {
						t.Fatal("cannot execute composed compiled client")
					}
				}
			}
			wantKeys := int32(0)
			if encrypted && mode != "upgrade-denied" {
				wantKeys = 1
			}
			wantEnds := int32(1)
			if shell && mode == "plain" {
				wantEnds = 0
			}
			if starts.Load() != 1 || ends.Load() != wantEnds || keys.Load() != wantKeys {
				t.Fatal("composed ownership/key call count changed")
			}
			if mode == "plain" || mode == "encrypted" {
				wantedCode, wantedOut, wantedErr := 37, "synthetic stdout", "synthetic stderr"
				if shell {
					wantedCode = 0
					wantedOut = compositionShellOutput
					wantedErr = ""
				}
				if executable != nil && !shell {
					wantedErr += "ssmh: remote command exited with status 37\n"
				}
				if code != wantedCode || cliText(t, out) != wantedOut || cliText(t, stderr) != wantedErr {
					t.Fatal("composed command streams/status changed")
				}
			} else if err == nil || code == 37 || strings.Contains(err.Error(), "synthetic-secret") || strings.Contains(cliText(t, stderr), "synthetic-secret") {
				t.Fatal("composed failure passed through as remote success/status or leaked data")
			}
			if mode == "key-denied" || mode == "corrupt-output" || mode == "upgrade-denied" {
				if cliText(t, out) != "" || executable == nil && cliText(t, stderr) != "" {
					t.Fatal("failed encrypted input emitted application bytes")
				}
			}
			if mode == "upgrade-denied" && (code != 1 || ctx.Err() != nil) {
				t.Fatal("authorization denial did not fail promptly with local failure status")
			}
			if mode == "tty-sigterm" && (code != 130 || ctx.Err() != nil) {
				t.Fatal("compiled TTY SIGTERM did not return controlled cancellation after cleanup")
			}
			if mode == "cleanup-denied" {
				diagnostic := err.Error()
				if executable != nil {
					diagnostic = cliText(t, stderr)
				}
				if !strings.Contains(diagnostic, "category=aws-service aws_code=AccessDeniedException http_status=400") {
					t.Fatal("cleanup lost safe SDK service/HTTP classification")
				}
			}
			select {
			case peerErr := <-peerDone:
				if peerErr != nil {
					t.Fatal("composed synthetic agent failed")
				}
			case <-ctx.Done():
				t.Fatal("composed peer did not join")
			}
		})
	}
}

const compositionShellOutput = "synthetic shell λ\x1b[32mcolor\x1b[0m\r\n"

func composedPlainShellPeer(r *http.Request, w http.ResponseWriter, mode string, ttyReady chan<- struct{}) error {
	conn, buffer, err := w.(http.Hijacker).Hijack()
	if err != nil {
		return err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(8 * time.Second))
	sum := sha1.Sum([]byte(r.Header.Get("Sec-WebSocket-Key") + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))
	if _, err = fmt.Fprintf(buffer, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: %s\r\n\r\n", base64.StdEncoding.EncodeToString(sum[:])); err != nil {
		return err
	}
	if err = buffer.Flush(); err != nil {
		return err
	}
	op, data, err := compositionReadWS(buffer)
	var opened struct{ TokenValue string }
	if err != nil || op != 1 || json.Unmarshal(data, &opened) != nil || opened.TokenValue != "synthetic-secret-token" {
		return errors.New("composed shell token exchange failed")
	}
	send := func(kind string, payload uint32, sequence int64, body []byte) error {
		m := native.Message{Type: kind, Created: 1, Sequence: sequence, ID: native.UUID{1, 2, 3, byte(sequence + 1)}, PayloadType: payload, Payload: body}
		if sequence == 0 && kind == "output_stream_data" {
			m.Flags = 1
		}
		raw, err := native.Encode(m)
		if err != nil {
			return err
		}
		return compositionWriteWS(conn, raw)
	}
	// The document-owned non-KMS shell must become ready on first output,
	// without an invented handshake or a timer-driven downgrade.
	if err = send("output_stream_data", native.Output, 0, []byte(compositionShellOutput)); err != nil {
		return err
	}
	op, data, err = compositionReadWS(buffer)
	m, decodeErr := native.Decode(data)
	if err != nil || op != 2 || decodeErr != nil || m.Type != "acknowledge" {
		return errors.New("composed shell first-output ACK missing")
	}
	if mode == "tty-sigterm" {
		op, data, err = compositionReadWS(buffer)
		m, decodeErr = native.Decode(data)
		var size struct{ Cols, Rows int }
		if err != nil || op != 2 || decodeErr != nil || m.Type != "input_stream_data" || m.PayloadType != native.Size || json.Unmarshal(m.Payload, &size) != nil || size.Cols != 80 || size.Rows != 24 {
			return errors.New("compiled TTY initial dimensions changed")
		}
		ack, _ := json.Marshal(map[string]any{"AcknowledgedMessageType": m.Type, "AcknowledgedMessageId": m.ID.String(), "AcknowledgedMessageSequenceNumber": m.Sequence, "IsSequentialMessage": true})
		if err = send("acknowledge", 0, 0, ack); err != nil {
			return err
		}
		close(ttyReady)
		op, _, err = compositionReadWS(buffer)
		if err == io.EOF || err == io.ErrUnexpectedEOF || err == nil && op == 8 {
			return nil
		}
		return errors.New("compiled TTY signal did not close the channel")
	}
	var received []byte
	for len(received) < len("synthetic shell input\n\x03\x04") {
		op, data, err = compositionReadWS(buffer)
		m, decodeErr = native.Decode(data)
		if err != nil || op != 2 || decodeErr != nil || m.Type != "input_stream_data" || m.PayloadType != native.Output || len(received)+len(m.Payload) > 256 {
			return errors.New("composed shell input changed")
		}
		received = append(received, m.Payload...)
		ack, _ := json.Marshal(map[string]any{"AcknowledgedMessageType": m.Type, "AcknowledgedMessageId": m.ID.String(), "AcknowledgedMessageSequenceNumber": m.Sequence, "IsSequentialMessage": true})
		if err = send("acknowledge", 0, 0, ack); err != nil {
			return err
		}
	}
	if string(received) != "synthetic shell input\n\x03\x04" {
		return errors.New("composed shell input/EOF/control bytes changed")
	}
	if mode == "network-drop" || mode == "cleanup-denied" {
		return nil
	}
	if err = send("channel_closed", 0, 0, []byte(`{"SessionId":"unit-owned"}`)); err != nil {
		return err
	}
	_, _ = conn.Read(make([]byte, 1))
	return nil
}

type compositionTransport struct {
	base        http.RoundTripper
	destination *url.URL
	t           *testing.T
}

func (tr compositionTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	service := ""
	switch r.URL.Host {
	case "ec2.ca-central-1.amazonaws.com":
		service = "ec2"
	case "ssm.ca-central-1.amazonaws.com":
		service = "ssm"
	case "ssmmessages.ca-central-1.amazonaws.com":
		service = "ssmmessages"
	case "kms.ca-central-1.amazonaws.com":
		service = "kms"
	}
	if r.URL.Scheme != "https" || service == "" || !strings.Contains(r.Header.Get("Authorization"), "/ca-central-1/"+service+"/aws4_request") {
		tr.t.Error("composed SDK request lost selected region/service/signature")
		return nil, errors.New("invalid synthetic routing")
	}
	copy := r.Clone(r.Context())
	address := *r.URL
	address.Scheme = tr.destination.Scheme
	address.Host = tr.destination.Host
	copy.URL = &address
	return tr.base.RoundTrip(copy)
}

func composedCommandPeer(r *http.Request, w http.ResponseWriter, encrypted bool, mode string, material []byte, key string) error {
	conn, buffer, err := w.(http.Hijacker).Hijack()
	if err != nil {
		return err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(8 * time.Second))
	sum := sha1.Sum([]byte(r.Header.Get("Sec-WebSocket-Key") + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))
	if _, err = fmt.Fprintf(buffer, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: %s\r\n\r\n", base64.StdEncoding.EncodeToString(sum[:])); err != nil {
		return err
	}
	if err = buffer.Flush(); err != nil {
		return err
	}
	op, data, err := compositionReadWS(buffer)
	var opened struct{ TokenValue string }
	if err != nil || op != 1 || json.Unmarshal(data, &opened) != nil || opened.TokenValue != "synthetic-secret-token" {
		return errors.New("composed token exchange failed")
	}
	seq := int64(0)
	send := func(kind string, payload uint32, data []byte) error {
		id := native.UUID{1, 2, 3}
		id[15] = byte(seq + 1)
		m := native.Message{Type: kind, Created: 1, Sequence: seq, ID: id, PayloadType: payload, Payload: data}
		if seq == 0 && kind == "output_stream_data" {
			m.Flags = 1
		}
		raw, err := native.Encode(m)
		if err != nil {
			return err
		}
		seq++
		return compositionWriteWS(conn, raw)
	}
	read := func() (native.Message, error) {
		op, raw, err := compositionReadWS(buffer)
		if err != nil {
			return native.Message{}, err
		}
		if op != 2 {
			return native.Message{}, errors.New("unexpected composed peer opcode")
		}
		return native.Decode(raw)
	}
	actions := []any{map[string]any{"ActionType": "SessionType", "ActionParameters": map[string]string{"SessionType": "NonInteractiveCommands"}}}
	if encrypted {
		actions = append(actions, map[string]any{"ActionType": "KMSEncryption", "ActionParameters": map[string]string{"KMSKeyId": key, "Challenge": "AAECAwQFBgcICQoLDA0ODw=="}})
	}
	request, _ := json.Marshal(map[string]any{"RequestedClientActions": actions})
	if err = send("output_stream_data", native.HandshakeRequest, request); err != nil {
		return err
	}
	m, err := read()
	if err != nil || m.Type != "acknowledge" {
		return errors.New("composed handshake ACK missing")
	}
	m, err = read()
	if err != nil || m.PayloadType != native.HandshakeResponse {
		return errors.New("composed handshake response missing")
	}
	if mode == "key-denied" {
		var response struct {
			ProcessedClientActions []struct {
				ActionType   string
				ActionStatus int
			}
		}
		if json.Unmarshal(m.Payload, &response) != nil || len(response.ProcessedClientActions) != 2 || response.ProcessedClientActions[1].ActionType != "KMSEncryption" || response.ProcessedClientActions[1].ActionStatus != 2 {
			return errors.New("composed KMS denial was not a failed action")
		}
		_, _ = conn.Read(make([]byte, 1))
		return nil
	}
	ack := func(m native.Message) error {
		data, _ := json.Marshal(map[string]any{"AcknowledgedMessageType": m.Type, "AcknowledgedMessageId": m.ID.String(), "AcknowledgedMessageSequenceNumber": m.Sequence, "IsSequentialMessage": true})
		return send("acknowledge", 0, data)
	}
	// ACKs do not occupy the remote application's sequence space.
	ackSend := func(m native.Message) error { saved := seq; err := ack(m); seq = saved; return err }
	if err = ackSend(m); err != nil {
		return err
	}
	agentCipher, _ := aes.NewCipher(material[:32])
	agentGCM, _ := cipher.NewGCM(agentCipher)
	seal := func(data []byte) []byte {
		nonce := bytes.Repeat([]byte{byte(seq + 1)}, agentGCM.NonceSize())
		return agentGCM.Seal(nonce, nonce, data, nil)
	}
	if encrypted {
		challenge := bytes.Repeat([]byte{0x43}, 64)
		data, _ := json.Marshal(map[string][]byte{"Challenge": seal(challenge)})
		if err = send("output_stream_data", native.EncryptionChallenge, data); err != nil {
			return err
		}
		m, err = read()
		if err != nil || m.Type != "acknowledge" {
			return errors.New("composed challenge ACK missing")
		}
		m, err = read()
		if err != nil || m.PayloadType != native.EncryptionResponse {
			return errors.New("composed encryption response missing")
		}
		var reply struct{ Challenge []byte }
		if json.Unmarshal(m.Payload, &reply) != nil || len(reply.Challenge) < 28 {
			return errors.New("invalid composed challenge answer")
		}
		block, _ := aes.NewCipher(material[32:])
		gcm, _ := cipher.NewGCM(block)
		answer, err := gcm.Open(nil, reply.Challenge[:12], reply.Challenge[12:], nil)
		if err != nil || !bytes.Equal(answer, challenge) {
			return errors.New("composed challenge authentication failed")
		}
		if err = ackSend(m); err != nil {
			return err
		}
	}
	if err = send("output_stream_data", native.HandshakeComplete, []byte(`{}`)); err != nil {
		return err
	}
	m, err = read()
	if err != nil || m.Type != "acknowledge" {
		return errors.New("composed completion ACK missing")
	}
	for _, entry := range []struct {
		kind uint32
		text string
	}{{native.Output, "synthetic stdout"}, {native.StdErr, "synthetic stderr"}, {native.ExitCode, "EXIT_CODE: 37"}} {
		if mode == "missing-status" && entry.kind == native.ExitCode {
			continue
		}
		data := []byte(entry.text)
		if encrypted {
			data = seal(data)
		}
		if mode == "corrupt-output" {
			data[len(data)-1] ^= 1
		}
		if err = send("output_stream_data", entry.kind, data); err != nil {
			return err
		}
		if mode == "corrupt-output" {
			// A rejected frame need not receive an ACK; readiness/challenge were
			// already verified above. Wait only for the client's bounded shutdown.
			_, _ = conn.Read(make([]byte, 1))
			return nil
		}
		m, err = read()
		if err != nil || m.Type != "acknowledge" {
			return errors.New("composed output ACK missing")
		}
	}
	if err = send("channel_closed", 0, []byte(`{"SessionId":"unit-owned"}`)); err != nil {
		return err
	}
	_, _ = conn.Read(make([]byte, 1))
	return nil
}

func compositionReadWS(reader *bufio.ReadWriter) (byte, []byte, error) {
	var head [2]byte
	if _, err := io.ReadFull(reader, head[:]); err != nil {
		return 0, nil, err
	}
	if head[0]&0x80 == 0 || head[1]&0x80 == 0 {
		return 0, nil, errors.New("invalid synthetic client WebSocket frame")
	}
	n := uint64(head[1] & 127)
	if n == 126 {
		var size [2]byte
		if _, err := io.ReadFull(reader, size[:]); err != nil {
			return 0, nil, err
		}
		n = uint64(binary.BigEndian.Uint16(size[:]))
	} else if n == 127 {
		var size [8]byte
		if _, err := io.ReadFull(reader, size[:]); err != nil {
			return 0, nil, err
		}
		n = binary.BigEndian.Uint64(size[:])
	}
	if n > 65536 {
		return 0, nil, errors.New("oversized synthetic client frame")
	}
	var mask [4]byte
	if _, err := io.ReadFull(reader, mask[:]); err != nil {
		return 0, nil, err
	}
	data := make([]byte, int(n))
	if _, err := io.ReadFull(reader, data); err != nil {
		return 0, nil, err
	}
	for i := range data {
		data[i] ^= mask[i%4]
	}
	return head[0] & 15, data, nil
}

func compositionWriteWS(conn net.Conn, data []byte) error {
	header := []byte{0x82}
	if len(data) < 126 {
		header = append(header, byte(len(data)))
	} else {
		header = append(header, 126, byte(len(data)>>8), byte(len(data)))
	}
	_, err := io.Copy(conn, bytes.NewReader(append(header, data...)))
	return err
}
