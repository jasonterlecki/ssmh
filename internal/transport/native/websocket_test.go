package native

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha1"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	sdk "github.com/aws/aws-sdk-go-v2/service/ssm"
	"ssmh/internal/ssm"
)

// In-memory listener runs real TLS and HTTP without OS socket permissions.
type memoryListener struct {
	connections chan net.Conn
	done        chan struct{}
	once        sync.Once
}

func (l *memoryListener) Accept() (net.Conn, error) {
	select {
	case c := <-l.connections:
		return c, nil
	case <-l.done:
		return nil, net.ErrClosed
	}
}
func (l *memoryListener) Close() error   { l.once.Do(func() { close(l.done) }); return nil }
func (l *memoryListener) Addr() net.Addr { return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)} }

type memoryTLSServer struct {
	URL      string
	server   *http.Server
	listener *memoryListener
	client   *http.Client
	done     chan struct{}
}

func (s *memoryTLSServer) Client() *http.Client { return s.client }
func (s *memoryTLSServer) Close() {
	_ = s.server.Close()
	_ = s.listener.Close()
	s.client.CloseIdleConnections()
	<-s.done
}
func newTLSServer(t *testing.T, handler http.Handler) *memoryTLSServer {
	t.Helper()
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "synthetic test server"}, DNSNames: []string{"unit.test", "ssmmessages.ca-central-1.amazonaws.com"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, pub, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(cert)
	l := &memoryListener{connections: make(chan net.Conn), done: make(chan struct{})}
	transport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}, DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		a, b := net.Pipe()
		select {
		case l.connections <- b:
			return a, nil
		case <-ctx.Done():
			_ = a.Close()
			_ = b.Close()
			return nil, ctx.Err()
		case <-l.done:
			_ = a.Close()
			_ = b.Close()
			return nil, net.ErrClosed
		}
	}}
	s := &memoryTLSServer{URL: "https://unit.test", listener: l, client: &http.Client{Transport: transport}, done: make(chan struct{})}
	s.server = &http.Server{Handler: handler, TLSConfig: &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}, MinVersion: tls.VersionTLS12}, ErrorLog: log.New(io.Discard, "", 0)}
	go func() {
		defer close(s.done)
		err := s.server.ServeTLS(l, "", "")
		if err != nil && !errors.Is(err, http.ErrServerClosed) && !errors.Is(err, net.ErrClosed) {
			t.Error(err)
		}
	}()
	return s
}

type testStream struct {
	input  *bytes.Reader
	output bytes.Buffer
	closed bool
}

func (s *testStream) Read(b []byte) (int, error)  { return s.input.Read(b) }
func (s *testStream) Write(b []byte) (int, error) { return s.output.Write(b) }
func (s *testStream) Close() error                { s.closed = true; return nil }
func testSocket(b []byte) (*Socket, *testStream) {
	s := &testStream{input: bytes.NewReader(b)}
	return &Socket{stream: s}, s
}

func serverFrame(op byte, fin bool, data []byte) []byte {
	var header [10]byte
	header[0] = op
	if fin {
		header[0] |= 0x80
	}
	n := 2
	switch {
	case len(data) < 126:
		header[1] = byte(len(data))
	case len(data) <= 65535:
		header[1] = 126
		binary.BigEndian.PutUint16(header[2:4], uint16(len(data)))
		n = 4
	default:
		header[1] = 127
		binary.BigEndian.PutUint64(header[2:10], uint64(len(data)))
		n = 10
	}
	return append(bytes.Clone(header[:n]), data...)
}

// readClientFrame independently checks the RFC client masking requirement.
func readClientFrame(r io.Reader) (byte, []byte, error) {
	var h [2]byte
	if _, err := io.ReadFull(r, h[:]); err != nil {
		return 0, nil, err
	}
	if h[0]&0x80 == 0 || h[1]&0x80 == 0 {
		return 0, nil, errors.New("client frame not final and masked")
	}
	n := uint64(h[1] & 127)
	if n == 126 {
		var b [2]byte
		if _, err := io.ReadFull(r, b[:]); err != nil {
			return 0, nil, err
		}
		n = uint64(binary.BigEndian.Uint16(b[:]))
	}
	if n == 127 {
		var b [8]byte
		if _, err := io.ReadFull(r, b[:]); err != nil {
			return 0, nil, err
		}
		n = binary.BigEndian.Uint64(b[:])
	}
	if n > maxWebSocketMessage {
		return 0, nil, errors.New("client frame too large")
	}
	var mask [4]byte
	if _, err := io.ReadFull(r, mask[:]); err != nil {
		return 0, nil, err
	}
	b := make([]byte, int(n))
	if _, err := io.ReadFull(r, b); err != nil {
		return 0, nil, err
	}
	for i := range b {
		b[i] ^= mask[i%4]
	}
	return h[0] & 15, b, nil
}

func TestWebSocketFragmentationAndControl(t *testing.T) {
	wire := serverFrame(wsBinary, false, []byte("hel"))
	wire = append(wire, serverFrame(wsPing, true, []byte("ping"))...)
	wire = append(wire, serverFrame(0, true, []byte("lo"))...)
	s, stream := testSocket(wire)
	op, data, err := s.Read()
	if err != nil || op != wsBinary || string(data) != "hello" {
		t.Fatal("fragmented message not assembled")
	}
	op, data, err = readClientFrame(bytes.NewReader(stream.output.Bytes()))
	if err != nil || op != wsPong || string(data) != "ping" {
		t.Fatal("ping was not answered with a masked pong")
	}
	for _, n := range []int{0, 125, 126, 65535, 65536, maxWebSocketMessage} {
		s, stream = testSocket(nil)
		data = bytes.Repeat([]byte{0x80}, n)
		if err = s.Write(wsBinary, data); err != nil {
			t.Fatal(err)
		}
		op, decoded, e := readClientFrame(bytes.NewReader(stream.output.Bytes()))
		if e != nil || op != wsBinary || !bytes.Equal(data, decoded) {
			t.Fatalf("client masking/length at %d", n)
		}
	}
}

func TestWebSocketRejectsMalformedInput(t *testing.T) {
	for _, wire := range [][]byte{
		{}, {0x82}, {0xc2, 0}, {0x82, 0x80}, {0x83, 0}, {0x89, 126}, {0x09, 0},
		{0x82, 126, 0, 1}, {0x82, 127, 0, 0, 0, 0, 0, 0, 0, 126}, {0x82, 127, 0x80, 0, 0, 0, 0, 0, 0, 0},
		{0x82, 127, 0, 0, 0, 0, 0, 32, 0, 0}, {0x80, 0}, {0x81, 1, 0xff}, {0x88, 1, 0}, {0x88, 2, 3, 237},
		append(serverFrame(wsBinary, false, []byte("x")), serverFrame(wsText, true, []byte("bad"))...),
	} {
		s, stream := testSocket(wire)
		if _, _, err := s.Read(); err == nil || !stream.closed {
			t.Fatalf("malformed frame accepted: %x", wire)
		}
	}
	s, _ := testSocket(serverFrame(wsClose, true, append([]byte{3, 232}, []byte("synthetic-secret-close-reason")...)))
	if _, _, err := s.Read(); err == nil || strings.Contains(err.Error(), "synthetic-secret") {
		t.Fatal("close reason leaked or close treated as success")
	}
	wire := serverFrame(wsBinary, false, make([]byte, maxWebSocketMessage))
	wire = append(wire, serverFrame(0, true, []byte("x"))...)
	s, _ = testSocket(wire)
	if _, _, err := s.Read(); err == nil {
		t.Fatal("unbounded assembled message")
	}
}

func TestSocketCloseUnblocksIO(t *testing.T) {
	a, b := net.Pipe()
	defer b.Close()
	s := &Socket{stream: a}
	done := make(chan error, 1)
	go func() { _, _, err := s.Read(); done <- err }()
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("close not reported")
		}
	case <-time.After(time.Second):
		t.Fatal("reader leaked after Close")
	}
	if err := s.Close(); err != nil {
		t.Fatal("Close is not idempotent")
	}
}

func upgradeHandler(t *testing.T, mode string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if mode == "redirect" {
			http.Redirect(w, r, "https://attacker.invalid/synthetic-secret", http.StatusFound)
			return
		}
		key := r.Header.Get("Sec-WebSocket-Key")
		hash := sha1.Sum([]byte(key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))
		accept := base64.StdEncoding.EncodeToString(hash[:])
		extra := ""
		if mode == "bad accept" {
			accept = "bad"
		}
		if mode == "extension" {
			extra = "Sec-WebSocket-Extensions: permessage-deflate\r\n"
		}
		if mode == "protocol" {
			extra = "Sec-WebSocket-Protocol: unrequested\r\n"
		}
		conn, buf, err := w.(http.Hijacker).Hijack()
		if err != nil {
			t.Error(err)
			return
		}
		defer conn.Close()
		if _, err = fmt.Fprintf(buf, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: %s\r\n%s\r\n", accept, extra); err != nil {
			t.Error(err)
			return
		}
		if err = buf.Flush(); err != nil {
			t.Error(err)
			return
		}
		if mode == "valid" {
			_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
			op, data, e := readClientFrame(buf)
			if e != nil || op != wsBinary || string(data) != "hello" {
				t.Error("upgraded client data not received")
				return
			}
			_, _ = conn.Write(serverFrame(wsBinary, true, []byte("reply")))
		}
	}
}

func TestTLSUpgradeValidationAndCancellation(t *testing.T) {
	for _, mode := range []string{"valid", "bad accept", "extension", "protocol", "redirect"} {
		t.Run(mode, func(t *testing.T) {
			server := newTLSServer(t, upgradeHandler(t, mode))
			defer server.Close()
			req, _ := http.NewRequest("GET", server.URL, nil)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			s, err := upgrade(ctx, server.Client(), req, time.Second)
			if mode != "valid" {
				if err == nil {
					_ = s.Close()
					t.Fatal("invalid upgrade accepted")
				}
				if strings.Contains(err.Error(), "synthetic-secret") {
					t.Fatal("redirect leaked")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			if err = s.Write(wsBinary, []byte("hello")); err != nil {
				t.Fatal(err)
			}
			op, data, err := s.Read()
			if err != nil || op != wsBinary || string(data) != "reply" {
				t.Fatal("upgraded body not bidirectional")
			}
			cancel()
		})
	}
	server := newTLSServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { <-r.Context().Done() }))
	defer server.Close()
	req, _ := http.NewRequest("GET", server.URL, nil)
	if _, err := upgrade(context.Background(), server.Client(), req, 20*time.Millisecond); err == nil {
		t.Fatal("unbounded upgrade timeout")
	}
	// An untrusted certificate must fail; using the test server's trusted client
	// elsewhere adds its synthetic root without disabling certificate verification.
	server = newTLSServer(t, upgradeHandler(t, "bad accept"))
	defer server.Close()
	req, _ = http.NewRequest("GET", server.URL, nil)
	untrustedClient := *server.Client()
	untrustedTransport := server.Client().Transport.(*http.Transport).Clone()
	untrustedTransport.TLSClientConfig.RootCAs = x509.NewCertPool()
	untrustedClient.Transport = untrustedTransport
	if _, err := upgrade(context.Background(), &untrustedClient, req, time.Second); err == nil {
		t.Fatal("untrusted TLS accepted")
	}
}

type startAPI struct{}

func (startAPI) StartSession(context.Context, *sdk.StartSessionInput, ...func(*sdk.Options)) (*sdk.StartSessionOutput, error) {
	return &sdk.StartSessionOutput{SessionId: aws.String(ownedID), StreamUrl: aws.String("wss://ssmmessages.ca-central-1.amazonaws.com/v1/data-channel/" + ownedID + "?role=publish_subscribe"), TokenValue: aws.String("synthetic-ssm-token")}, nil
}
func (startAPI) TerminateSession(context.Context, *sdk.TerminateSessionInput, ...func(*sdk.Options)) (*sdk.TerminateSessionOutput, error) {
	return &sdk.TerminateSessionOutput{}, nil
}
func (startAPI) DescribeInstanceInformation(context.Context, *sdk.DescribeInstanceInformationInput, ...func(*sdk.Options)) (*sdk.DescribeInstanceInformationOutput, error) {
	return &sdk.DescribeInstanceInformationOutput{}, nil
}

type redirectTransport struct {
	base        http.RoundTripper
	destination *url.URL
}

func (r redirectTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	copyReq := req.Clone(req.Context())
	copyURL := *req.URL
	copyURL.Host = r.destination.Host
	copyReq.URL = &copyURL
	return r.base.RoundTrip(copyReq)
}

func TestAuthenticatedOpenSendsTokenAfterTLSUpgrade(t *testing.T) {
	var received atomic.Bool
	server := newTLSServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.Header.Get("Authorization"), "AWS4-HMAC-SHA256 ") || !strings.Contains(r.Header.Get("Authorization"), "/ssmmessages/") {
			t.Error("missing SigV4 data-channel authentication")
		}
		key := r.Header.Get("Sec-WebSocket-Key")
		sum := sha1.Sum([]byte(key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))
		conn, buf, e := w.(http.Hijacker).Hijack()
		if e != nil {
			t.Error(e)
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
		_, _ = fmt.Fprintf(buf, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: %s\r\n\r\n", base64.StdEncoding.EncodeToString(sum[:]))
		_ = buf.Flush()
		op, data, e := readClientFrame(buf)
		var opened struct{ MessageSchemaVersion, TokenValue, RequestId, ClientId, ClientVersion string }
		if e != nil || op != wsText || json.Unmarshal(data, &opened) != nil || opened.TokenValue != "synthetic-ssm-token" || opened.MessageSchemaVersion != "1.0" || opened.ClientVersion != "1.2.339.0" || len(opened.RequestId) != 36 || len(opened.ClientId) != 36 {
			t.Error("invalid OpenDataChannel token message")
			return
		}
		received.Store(true)
		_, _ = conn.Write(serverFrame(wsBinary, true, fixture()))
	}))
	defer server.Close()
	destination, _ := url.Parse(server.URL)
	client := server.Client()
	client.Transport = redirectTransport{client.Transport, destination}
	session, err := ssm.Start(context.Background(), startAPI{}, &sdk.StartSessionInput{Target: aws.String("i-0123456789abcdef0")}, "ca-central-1")
	if err != nil {
		t.Fatal(err)
	}
	cfg := aws.Config{Region: "ca-central-1", HTTPClient: client, Credentials: credentials.NewStaticCredentialsProvider("synthetic-key", "synthetic-secret", "")}
	socket, err := OpenSocket(context.Background(), cfg, session, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer socket.Close()
	_, _, err = socket.Read()
	if err != nil || !received.Load() {
		t.Fatal("token handshake not completed")
	}
}

func FuzzWebSocketRead(f *testing.F) {
	f.Add(serverFrame(wsBinary, true, fixture()))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, b []byte) {
		s, _ := testSocket(b)
		_, data, _ := s.Read()
		if len(data) > maxWebSocketMessage {
			t.Fatal("unbounded WebSocket message")
		}
	})
}
