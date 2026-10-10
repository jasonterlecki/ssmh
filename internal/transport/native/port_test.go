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
	"net"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	sdk "github.com/aws/aws-sdk-go-v2/service/ssm"
	"ssmh/internal/config"
	"ssmh/internal/ssm"
)

func portRequest(t *testing.T, target config.ForwardTarget, version string) []byte {
	t.Helper()
	properties := map[string]string{"type": "LocalPortForwarding", "localPortNumber": fmt.Sprint(target.LocalPort), "portNumber": fmt.Sprint(target.RemotePort)}
	if target.Host != "" {
		properties["host"] = target.Host
	}
	data, err := json.Marshal(map[string]any{"AgentVersion": version, "RequestedClientActions": []any{map[string]any{"ActionType": "SessionType", "ActionParameters": map[string]any{"SessionType": "Port", "Properties": properties}}}})
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func portProtocol(t *testing.T, target config.ForwardTarget) *Protocol {
	t.Helper()
	p, err := newPortProtocol(ownedID, target)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func portReady(t *testing.T) *Protocol {
	t.Helper()
	target := config.ForwardTarget{LocalPort: 8080, RemotePort: 80}
	p := portProtocol(t, target)
	if _, err := p.Process(frame(t, outputStream, HandshakeRequest, 0, portRequest(t, target, "3.3.0.0")), time.Now()); err != nil {
		t.Fatal(err)
	}
	if _, err := p.Process(frame(t, outputStream, HandshakeComplete, 1, []byte(`{}`)), time.Now()); err != nil || !p.Ready() {
		t.Fatal("Port handshake did not establish readiness")
	}
	return p
}

func TestPortAgentCapability(t *testing.T) {
	for _, value := range []string{"3.1.1511.1", "3.1.1512.0", "3.2.0.0", "3.3.0.0", "4.0.0.0"} {
		if !portAgentSupported(value) {
			t.Fatal("compatible agent rejected")
		}
	}
	for _, value := range []string{"", "3.1.1511.0", "3.1.1510.99", "3.0.9999.0", "2.9.9999.0", "3.3.0", "3.3.0.0.1", "03.3.0.0", "3.3.0.-1", "3.3.0.+1", "3.3.0.0-dev", "3.3.0.4294967296", "3.3.0.0\n", "ssmh-dev"} {
		if portAgentSupported(value) {
			t.Fatal("unknown/old/malformed agent accepted")
		}
	}
}

func TestPortConstructorAndProperties(t *testing.T) {
	if _, err := NewProtocol(ownedID, "Port"); err == nil {
		t.Fatal("Port accepted without explicit destination")
	}
	for _, target := range []config.ForwardTarget{{LocalPort: 8080, RemotePort: 80}, {LocalPort: 15432, RemotePort: 5432, Host: "database.internal"}, {LocalPort: 1234, RemotePort: 4321, Host: "2001:db8::1"}} {
		p := portProtocol(t, target)
		original := target
		target.Host = "changed.internal"
		if *p.port != original || p.allowNoHandshake || p.Ready() {
			t.Fatal("forwarding expectation is mutable or readiness is premature")
		}
		event, err := p.Process(frame(t, outputStream, HandshakeRequest, 0, portRequest(t, original, "3.3.0.0")), time.Now())
		if err != nil || len(event.Outgoing) != 2 || event.Outgoing[1].PayloadType != HandshakeResponse || p.Ready() {
			t.Fatal("valid Port request rejected or prematurely ready")
		}
		var response struct {
			ClientVersion string
			Errors        []string
		}
		if json.Unmarshal(event.Outgoing[1].Payload, &response) != nil || response.ClientVersion != portClientVersion || len(response.Errors) != 0 {
			t.Fatal("incorrect Port capability response")
		}
		if _, err := p.Input(Output, []byte("binary"), time.Now()); err == nil {
			t.Fatal("data sent before Port completion")
		}
	}
	for _, target := range []config.ForwardTarget{{LocalPort: 0, RemotePort: 80}, {LocalPort: 8080, RemotePort: 65536}, {LocalPort: -1, RemotePort: 80}, {LocalPort: 8080, RemotePort: 80, Host: "bad host"}, {LocalPort: 8080, RemotePort: 80, Host: "[2001:db8::1]"}} {
		if _, err := newPortProtocol(ownedID, target); err == nil {
			t.Fatal("invalid direct target accepted")
		}
	}
}

func TestPortNegotiationFailClosed(t *testing.T) {
	target := config.ForwardTarget{LocalPort: 15432, RemotePort: 5432, Host: "database.internal"}
	good := string(portRequest(t, target, "3.3.0.0"))
	for _, payload := range []string{
		strings.Replace(good, `"database.internal"`, `"substituted.internal"`, 1),
		strings.Replace(good, `"5432"`, `"5433"`, 1),
		strings.Replace(good, `"15432"`, `"15433"`, 1),
		strings.Replace(good, `"5432"`, `"05432"`, 1),
		strings.Replace(good, `"5432"`, `5432`, 1),
		strings.Replace(good, `"localPortNumber":"15432",`, ``, 1),
		strings.Replace(good, `"database.internal"`, `null`, 1),
		strings.Replace(good, `"LocalPortForwarding"`, `"StandardStreamForwarding"`, 1),
		strings.Replace(good, `"type":`, `"localUnixSocket":"/tmp/secret-marker","type":`, 1),
		strings.Replace(good, `"type":`, `"localConnectionType":"unix","type":`, 1),
		strings.Replace(good, `"type":`, `"localConnectionType":null,"type":`, 1),
		strings.Replace(good, `"type":`, `"bindAddress":"0.0.0.0","type":`, 1),
		strings.Replace(good, `"host":`, `"Host":`, 1),
		strings.Replace(good, `"host":`, `"host":"secret-marker","host":`, 1),
		strings.Replace(good, `"3.3.0.0"`, `"3.1.1511.0"`, 1),
		strings.Replace(good, `"3.3.0.0"`, `null`, 1),
		strings.Replace(good, `"ActionType":"SessionType"`, `"ActionType":"KMSEncryption"`, 1),
		strings.Replace(good, `"RequestedClientActions":[`, `"RequestedClientActions":[{"ActionType":"KMSEncryption","ActionParameters":{"KMSKeyId":"secret-marker"}},`, 1),
		strings.Replace(good, `"Port"`, `"Standard_Stream"`, 1),
		`null`,
	} {
		p := portProtocol(t, target)
		event, err := p.Process(frame(t, outputStream, HandshakeRequest, 0, []byte(payload)), time.Now())
		if err == nil || p.Ready() || event.Ready || len(event.Output) != 0 || strings.Contains(err.Error(), "secret-marker") {
			t.Fatal("unsafe Port negotiation accepted or disclosed")
		}
		if _, err := p.Process(frame(t, outputStream, HandshakeRequest, 0, []byte(good)), time.Now()); err == nil {
			t.Fatal("Port protocol recovered after failed negotiation")
		}
	}
	// A valid optional TCP property is accepted; a host on instance-local mode
	// is not silently ignored, even if it names localhost.
	p := portProtocol(t, target)
	tcp := strings.Replace(good, `"type":`, `"localConnectionType":"tcp","localUnixSocket":"","type":`, 1)
	if _, err := p.Process(frame(t, outputStream, HandshakeRequest, 0, []byte(tcp)), time.Now()); err != nil {
		t.Fatal("explicit TCP properties rejected")
	}
	p = portProtocol(t, config.ForwardTarget{LocalPort: 8080, RemotePort: 80})
	local := string(portRequest(t, *p.port, "3.3.0.0"))
	local = strings.Replace(local, `"type":`, `"host":"localhost","type":`, 1)
	if _, err := p.Process(frame(t, outputStream, HandshakeRequest, 0, []byte(local)), time.Now()); err == nil {
		t.Fatal("instance-local destination substituted")
	}
}

func TestPortPayloadIsolation(t *testing.T) {
	p := portReady(t)
	binary := []byte{'\n', '\r', 0, 255}
	m, err := p.Input(Output, binary, time.Now())
	if err != nil || !bytes.Equal(m.Payload, binary) {
		t.Fatal("binary Port input changed")
	}
	for _, tc := range []struct {
		kind uint32
		data []byte
	}{
		{Size, []byte(`{"cols":80,"rows":24}`)}, {Flag, []byte{0, 0, 0, 1}},
		{Flag, []byte{0, 0, 0, 3}}, {Flag, []byte{0, 0, 0, 2, 0}}, {StdErr, binary},
	} {
		if _, err := p.Input(tc.kind, tc.data, time.Now()); err == nil {
			t.Fatal("terminal/invalid forwarding input accepted")
		}
	}
	if _, err := p.Input(Flag, []byte{0, 0, 0, 2}, time.Now()); err != nil {
		t.Fatal("valid terminate flag rejected")
	}
	for _, tc := range []struct {
		kind uint32
		data []byte
	}{
		{StdErr, binary}, {ExitCode, []byte("0")}, {Size, []byte(`{}`)},
		{Flag, []byte{0, 0, 0, 1}}, {Flag, []byte{0, 0, 0, 2}},
		{Flag, []byte{3, 0, 0, 0}}, {Flag, []byte{0, 0, 0, 3, 0}},
	} {
		p := portReady(t)
		if _, err := p.Process(frame(t, outputStream, tc.kind, 2, tc.data), time.Now()); err == nil || p.Ready() {
			t.Fatal("terminal/invalid forwarding output accepted")
		}
	}
	p = portReady(t)
	wire := frame(t, outputStream, Flag, 2, []byte{0, 0, 0, 3})
	event, err := p.Process(wire, time.Now())
	if err != nil || len(event.Output) != 1 || event.Output[0].PayloadType != Flag || !p.Ready() {
		t.Fatal("valid destination error not isolated as a control")
	}
	if event, err = p.Process(wire, time.Now()); err != nil || len(event.Output) != 0 {
		t.Fatal("retransmitted destination error redelivered")
	}
	p = portProtocol(t, config.ForwardTarget{LocalPort: 8080, RemotePort: 80})
	if _, err := p.Process(frame(t, outputStream, Output, 0, binary), time.Now()); err == nil {
		t.Fatal("Port downgraded to handshake-free stream")
	}
	p = portProtocol(t, config.ForwardTarget{LocalPort: 8080, RemotePort: 80})
	if _, err := p.Process(frame(t, outputStream, Flag, 0, []byte{0, 0, 0, 3}), time.Now()); err == nil {
		t.Fatal("Port accepted destination control before negotiation")
	}
	for _, kind := range []string{"Standard_Stream", "NonInteractiveCommands"} {
		p, err := NewProtocol(ownedID, kind)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := p.Process(frame(t, outputStream, Flag, 0, []byte{0, 0, 0, 3}), time.Now()); err == nil {
			t.Fatal("Port control accepted on a shell/command channel")
		}
	}
}

func TestConnectForwardValidationBeforeNetwork(t *testing.T) {
	session, err := ssm.Start(context.Background(), startAPI{}, &sdk.StartSessionInput{Target: aws.String("i-0123456789abcdef0")}, "ca-central-1")
	if err != nil {
		t.Fatal(err)
	}
	defer session.Terminate(context.Background())
	requests := 0
	client := &http.Client{Transport: portTestRoundTripper(func(*http.Request) (*http.Response, error) {
		requests++
		return nil, errors.New("secret-marker")
	})}
	cfg := aws.Config{Region: "ca-central-1", HTTPClient: client, Credentials: credentials.NewStaticCredentialsProvider("synthetic-key", "synthetic-secret", "synthetic-token")}
	valid := config.ForwardTarget{LocalPort: 8080, RemotePort: 80}
	for _, tc := range []struct {
		session *ssm.Session
		target  config.ForwardTarget
		timeout time.Duration
	}{
		{nil, valid, time.Second}, {session, valid, 0}, {session, valid, 11 * time.Minute},
		{session, config.ForwardTarget{LocalPort: 0, RemotePort: 80}, time.Second},
		{session, config.ForwardTarget{LocalPort: 8080, RemotePort: 80, Host: "secret-marker\n"}, time.Second},
	} {
		channel, err := ConnectForward(context.Background(), cfg, tc.session, tc.target, tc.timeout)
		if err == nil || channel != nil || requests != 0 || strings.Contains(err.Error(), "secret-marker") {
			t.Fatal("invalid forwarding setup reached network or disclosed input")
		}
	}
	// The unrestricted shell/command API cannot bypass explicit Port validation.
	if channel, err := Connect(context.Background(), cfg, session, "Port", time.Second); err == nil || channel != nil || requests != 0 {
		t.Fatal("ordinary Connect enabled Port without an expected destination")
	}
}

type portTestRoundTripper func(*http.Request) (*http.Response, error)

func (f portTestRoundTripper) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func portAgentHandshake(t *testing.T, conn net.Conn, payload []byte) error {
	t.Helper()
	if err := sendRemote(t, conn, outputStream, HandshakeRequest, 0, payload); err != nil {
		return err
	}
	m, err := clientMessage(conn)
	if err != nil || m.Type != acknowledge {
		return errors.New("Port request not acknowledged")
	}
	m, err = clientMessage(conn)
	var response struct {
		ClientVersion string
		Errors        []string
	}
	if err != nil || m.PayloadType != HandshakeResponse || json.Unmarshal(m.Payload, &response) != nil || response.ClientVersion != portClientVersion || len(response.Errors) != 0 {
		return errors.New("Port capability response invalid")
	}
	if err := acknowledgeInput(t, conn, m); err != nil {
		return err
	}
	if err := sendRemote(t, conn, outputStream, HandshakeComplete, 1, []byte(`{}`)); err != nil {
		return err
	}
	m, err = clientMessage(conn)
	if err != nil || m.Type != acknowledge {
		return errors.New("Port completion not acknowledged")
	}
	return nil
}

// Real TLS/HTTP, signing and token exchange, with synthetic AWS ownership and
// an in-memory listener. This is an authenticated channel, not a local tunnel.
func TestConnectForwardAuthenticatedBinaryChannel(t *testing.T) {
	for _, host := range []string{"", "database.internal"} {
		t.Run(host, func(t *testing.T) {
			target := config.ForwardTarget{LocalPort: 15432, RemotePort: 5432, Host: host}
			request := portRequest(t, target, "3.3.0.0")
			binary := []byte{'\n', '\r', 0, 255}
			agentDone := make(chan error, 1)
			server := newTLSServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				var result error
				defer func() { agentDone <- result }()
				if !strings.HasPrefix(r.Header.Get("Authorization"), "AWS4-HMAC-SHA256 ") || !strings.Contains(r.Header.Get("Authorization"), "/ssmmessages/") {
					result = errors.New("Port upgrade not authenticated")
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
				if _, err := fmt.Fprintf(buf, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: %s\r\n\r\n", base64.StdEncoding.EncodeToString(sum[:])); err != nil {
					result = err
					return
				}
				if err := buf.Flush(); err != nil {
					result = err
					return
				}
				op, data, err := readClientFrame(buf)
				var opened struct{ TokenValue, ClientVersion string }
				if err != nil || op != wsText || json.Unmarshal(data, &opened) != nil || opened.TokenValue != "synthetic-ssm-token" || opened.ClientVersion != portClientVersion {
					result = errors.New("Port token/version exchange invalid")
					return
				}
				if result = portAgentHandshake(t, conn, request); result != nil {
					return
				}
				m, err := clientMessage(conn)
				if err != nil || m.PayloadType != Output || !bytes.Equal(m.Payload, binary) {
					result = errors.New("binary Port input changed")
					return
				}
				if result = acknowledgeInput(t, conn, m); result != nil {
					return
				}
				for i, kind := range []uint32{Output, Flag} {
					payload := binary
					if kind == Flag {
						payload = []byte{0, 0, 0, 3}
					}
					if result = sendRemote(t, conn, outputStream, kind, int64(i+2), payload); result != nil {
						return
					}
					m, err = clientMessage(conn)
					if err != nil || m.Type != acknowledge {
						result = errors.New("Port output/control not acknowledged")
						return
					}
				}
				data, _ = json.Marshal(map[string]string{"SessionId": ownedID})
				result = sendRemote(t, conn, channelClosed, 0, 0, data)
				if result == nil {
					_, _ = conn.Read(make([]byte, 1)) // Allow controlled TLS shutdown.
				}
			}))
			defer server.Close()
			destination, _ := url.Parse(server.URL)
			client := server.Client()
			client.Transport = redirectTransport{client.Transport, destination}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			session, err := ssm.Start(ctx, startAPI{}, &sdk.StartSessionInput{Target: aws.String("i-0123456789abcdef0")}, "ca-central-1")
			if err != nil {
				t.Fatal(err)
			}
			cfg := aws.Config{Region: "ca-central-1", HTTPClient: client, Credentials: credentials.NewStaticCredentialsProvider("synthetic-key", "synthetic-secret", "synthetic-token")}
			channel, err := ConnectForward(ctx, cfg, session, target, time.Second)
			if err != nil {
				t.Fatal(err)
			}
			defer channel.Close()
			if err := channel.Send(ctx, Output, binary); err != nil {
				t.Fatal(err)
			}
			for _, kind := range []uint32{Output, Flag} {
				m, err := channel.Receive(ctx)
				want := binary
				if kind == Flag {
					want = []byte{0, 0, 0, 3}
				}
				if err != nil || m.PayloadType != kind || !bytes.Equal(m.Payload, want) {
					t.Fatal("Port binary/control delivery changed")
				}
			}
			if _, err := channel.Receive(ctx); err != io.EOF {
				t.Fatal("owned Port EOF missing")
			}
			if err := channel.Close(); err != nil {
				t.Fatal(err)
			}
			if err := <-agentDone; err != nil {
				t.Fatal(err)
			}
			if err := session.Terminate(ctx); err != nil {
				t.Fatal("caller-owned Port cleanup failed")
			}
			if channel, err := ConnectForward(ctx, cfg, session, target, time.Second); err == nil || channel != nil {
				t.Fatal("terminated session reused for forwarding")
			}
		})
	}
}

func FuzzPortNegotiation(f *testing.F) {
	f.Add([]byte(`{"AgentVersion":"3.3.0.0","RequestedClientActions":[{"ActionType":"SessionType","ActionParameters":{"SessionType":"Port","Properties":{"type":"LocalPortForwarding","localPortNumber":"8080","portNumber":"80"}}}]}`))
	f.Add([]byte(`null`))
	f.Fuzz(func(t *testing.T, payload []byte) {
		if len(payload) > 65536 {
			return
		}
		p := portProtocol(t, config.ForwardTarget{LocalPort: 8080, RemotePort: 80})
		_, err := p.Process(frame(t, outputStream, HandshakeRequest, 0, payload), time.Now())
		if err != nil && p.Ready() {
			t.Fatal("failed Port negotiation established readiness")
		}
	})
}
