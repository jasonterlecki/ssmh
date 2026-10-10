package native

import (
	"context"
	"crypto/rand"
	"crypto/sha1" // RFC 6455 handshake checksum; not an authentication primitive.
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"ssmh/internal/logging"
	"ssmh/internal/ssm"
)

const (
	wsText              byte = 1
	wsBinary            byte = 2
	wsClose             byte = 8
	wsPing              byte = 9
	wsPong              byte = 10
	maxWebSocketMessage      = MaxPayload + framePrefix
)

// Socket is a bounded RFC 6455 client. It negotiates no extensions or compression.
// One reader and concurrent writers/Close are supported. Network errors are
// replaced with static diagnostics so URLs, tokens, and close reasons never leak.
type Socket struct {
	stream    io.ReadWriteCloser
	writeMu   sync.Mutex
	closeOnce sync.Once
	closeErr  error
	cancel    context.CancelFunc
}

func (s *Socket) String() string   { return "SSM WebSocket [authentication and stream data redacted]" }
func (s *Socket) GoString() string { return s.String() }

// OpenSocket establishes the authenticated channel for an owned session and
// sends AWS's OpenDataChannel token message only after a validated TLS upgrade.
// ctx governs the socket lifetime; timeout bounds just connection establishment.
func OpenSocket(ctx context.Context, cfg aws.Config, session *ssm.Session, timeout time.Duration) (*Socket, error) {
	return openSocket(ctx, cfg, session, timeout, wireClientVersion)
}

func openSocket(ctx context.Context, cfg aws.Config, session *ssm.Session, timeout time.Duration, clientVersion string) (*Socket, error) {
	if session == nil || timeout <= 0 || timeout > 10*time.Minute {
		return nil, errors.New("invalid data-channel setup")
	}
	id, stream, token := session.TransportMaterial()
	if id == "" || stream == "" || token == "" {
		return nil, errors.New("owned session has no active transport material")
	}
	client, ok := cfg.HTTPClient.(*http.Client)
	if !ok {
		return nil, errors.New("native transport requires the configured AWS HTTP client")
	}
	req, err := http.NewRequestWithContext(ctx, "GET", "https:"+strings.TrimPrefix(stream, "wss:"), nil)
	if err != nil {
		return nil, errors.New("invalid data-channel URL")
	}
	q := req.URL.Query()
	if q.Get("X-Amz-Signature") == "" {
		for name := range q {
			if strings.HasPrefix(strings.ToLower(name), "x-amz-") {
				return nil, errors.New("incomplete data-channel presigned authentication")
			}
		}
		if cfg.Credentials == nil {
			return nil, errors.New("missing data-channel AWS credentials")
		}
		creds, e := cfg.Credentials.Retrieve(ctx)
		if e != nil {
			return nil, logging.Failure("authenticate data channel", e)
		}
		empty := sha256.Sum256(nil)
		if e = v4.NewSigner().SignHTTP(ctx, creds, req, hex.EncodeToString(empty[:]), "ssmmessages", cfg.Region, time.Now()); e != nil {
			return nil, logging.Failure("sign data channel", e)
		}
	}
	socket, err := upgrade(ctx, client, req, timeout)
	if err != nil {
		return nil, err
	}
	requestID, err := newUUID()
	if err != nil {
		closeErr := socket.Close()
		return nil, errors.Join(err, closeErr)
	}
	clientID, err := newUUID()
	if err != nil {
		closeErr := socket.Close()
		return nil, errors.Join(err, closeErr)
	}
	data, err := json.Marshal(struct{ MessageSchemaVersion, RequestId, TokenValue, ClientId, ClientVersion string }{"1.0", requestID.String(), token, clientID.String(), clientVersion})
	if err != nil {
		closeErr := socket.Close()
		return nil, errors.Join(errors.New("serialize data-channel authentication failed"), closeErr)
	}
	if err = socket.Write(wsText, data); err != nil {
		closeErr := socket.Close()
		return nil, errors.Join(err, closeErr)
	}
	return socket, nil
}

func upgrade(ctx context.Context, client *http.Client, request *http.Request, timeout time.Duration) (*Socket, error) {
	if request.URL.Scheme != "https" || request.URL.User != nil || request.URL.Fragment != "" {
		return nil, errors.New("data-channel connection requires HTTPS without userinfo or fragments")
	}
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, errors.New("generate WebSocket nonce failed")
	}
	key := base64.StdEncoding.EncodeToString(nonce[:])
	lifetime, cancel := context.WithCancel(ctx)
	request = request.Clone(lifetime)
	request.Header.Set("Connection", "Upgrade")
	request.Header.Set("Upgrade", "websocket")
	request.Header.Set("Sec-WebSocket-Key", key)
	request.Header.Set("Sec-WebSocket-Version", "13")
	// Preserve the configured TLS roots, proxy, endpoint guard, and connection
	// timeouts, while removing the API client's whole-response body timeout.
	copyClient := *client
	copyClient.Timeout = 0
	copyClient.CheckRedirect = func(*http.Request, []*http.Request) error { return errors.New("WebSocket redirects are refused") }
	timer := time.AfterFunc(timeout, cancel)
	response, err := copyClient.Do(request)
	if err != nil {
		timer.Stop()
		cancel()
		return nil, logging.Failure("establish Session Manager WebSocket", err)
	}
	if !timer.Stop() || lifetime.Err() != nil {
		cancel()
		return nil, errors.Join(errors.New("data-channel connection timed out"), closeResponse(response.Body))
	}
	expected := sha1.Sum([]byte(key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))
	valid := response.StatusCode == http.StatusSwitchingProtocols && strings.EqualFold(response.Header.Get("Upgrade"), "websocket") && headerToken(response.Header, "Connection", "upgrade") && len(response.Header.Values("Sec-WebSocket-Accept")) == 1 && response.Header.Get("Sec-WebSocket-Accept") == base64.StdEncoding.EncodeToString(expected[:]) && response.Header.Get("Sec-WebSocket-Extensions") == "" && response.Header.Get("Sec-WebSocket-Protocol") == ""
	if !valid {
		cancel()
		return nil, errors.Join(errors.New("SSM WebSocket upgrade was rejected or invalid; check permissions and network proxies"), closeResponse(response.Body))
	}
	stream, ok := response.Body.(io.ReadWriteCloser)
	if !ok {
		cancel()
		return nil, errors.Join(errors.New("SSM connection did not provide a bidirectional HTTP/1.1 upgrade"), closeResponse(response.Body))
	}
	s := &Socket{stream: stream, cancel: cancel}
	context.AfterFunc(lifetime, func() { _ = s.Close() })
	return s, nil
}

func closeResponse(body io.Closer) error {
	if err := body.Close(); err != nil {
		return errors.New("close failed data-channel response failed")
	}
	return nil
}

func headerToken(h http.Header, name, token string) bool {
	for _, v := range h.Values(name) {
		for _, part := range strings.Split(v, ",") {
			if strings.EqualFold(strings.TrimSpace(part), token) {
				return true
			}
		}
	}
	return false
}

// Close unblocks pending network I/O and releases the request lifetime.
func (s *Socket) Close() error {
	s.closeOnce.Do(func() {
		if s.cancel != nil {
			s.cancel()
		}
		if err := s.stream.Close(); err != nil {
			s.closeErr = errors.New("close Session Manager WebSocket failed")
		}
	})
	return s.closeErr
}

// Write sends a masked client message with bounded length and write timeout.
func (s *Socket) Write(opcode byte, data []byte) error {
	if (opcode != wsText && opcode != wsBinary && opcode != wsClose && opcode != wsPing && opcode != wsPong) || len(data) > maxWebSocketMessage || opcode >= 8 && len(data) > 125 || opcode == wsText && !utf8.Valid(data) {
		return errors.New("invalid outgoing WebSocket frame")
	}
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	var mask [4]byte
	if _, err := rand.Read(mask[:]); err != nil {
		return errors.New("generate WebSocket mask failed")
	}
	var header [14]byte
	header[0] = 0x80 | opcode
	n := 2
	switch {
	case len(data) < 126:
		header[1] = 0x80 | byte(len(data))
	case len(data) <= 65535:
		header[1] = 0x80 | 126
		binary.BigEndian.PutUint16(header[2:4], uint16(len(data)))
		n = 4
	default:
		header[1] = 0x80 | 127
		binary.BigEndian.PutUint64(header[2:10], uint64(len(data)))
		n = 10
	}
	copy(header[n:n+4], mask[:])
	n += 4
	masked := make([]byte, len(data))
	for i, b := range data {
		masked[i] = b ^ mask[i%4]
	}
	timer := time.AfterFunc(10*time.Second, func() { _ = s.Close() })
	defer timer.Stop()
	if err := writeAll(s.stream, header[:n]); err != nil {
		return errors.Join(errors.New("write Session Manager WebSocket failed"), s.Close())
	}
	if err := writeAll(s.stream, masked); err != nil {
		return errors.Join(errors.New("write Session Manager WebSocket failed"), s.Close())
	}
	return nil
}

func writeAll(w io.Writer, b []byte) error {
	for len(b) > 0 {
		n, err := w.Write(b)
		if err != nil {
			return err
		}
		if n <= 0 || n > len(b) {
			return io.ErrShortWrite
		}
		b = b[n:]
	}
	return nil
}

// Read assembles at most one bounded message, handles control frames interleaved
// with fragments, and rejects masked server frames or unnegotiated extensions.
func (s *Socket) Read() (opcode byte, data []byte, err error) {
	// The channel sends pings each minute. A peer that sends no frame (including
	// pong) for three minutes is disconnected; partial frames cannot wait forever.
	idle := time.AfterFunc(3*time.Minute, func() { _ = s.Close() })
	defer idle.Stop()
	defer func() {
		if err != nil {
			err = errors.Join(err, s.Close())
		}
	}()
	fragments := 0
	for {
		var h [2]byte
		if _, e := io.ReadFull(s.stream, h[:]); e != nil {
			return 0, nil, errors.New("Session Manager WebSocket disconnected")
		}
		fin := h[0]&0x80 != 0
		op := h[0] & 15
		length := uint64(h[1] & 127)
		if h[0]&0x70 != 0 || h[1]&0x80 != 0 {
			return 0, nil, errors.New("invalid WebSocket extension or server masking")
		}
		if op != 0 && op != wsText && op != wsBinary && op != wsClose && op != wsPing && op != wsPong {
			return 0, nil, errors.New("unsupported WebSocket opcode")
		}
		if op >= 8 && (!fin || length > 125) {
			return 0, nil, errors.New("invalid WebSocket control frame")
		}
		if length == 126 {
			var b [2]byte
			if _, e := io.ReadFull(s.stream, b[:]); e != nil {
				return 0, nil, errors.New("truncated WebSocket length")
			}
			length = uint64(binary.BigEndian.Uint16(b[:]))
			if length < 126 {
				return 0, nil, errors.New("noncanonical WebSocket length")
			}
		}
		if length == 127 {
			var b [8]byte
			if _, e := io.ReadFull(s.stream, b[:]); e != nil {
				return 0, nil, errors.New("truncated WebSocket length")
			}
			length = binary.BigEndian.Uint64(b[:])
			if length <= 65535 || length>>63 != 0 {
				return 0, nil, errors.New("noncanonical WebSocket length")
			}
		}
		if length > maxWebSocketMessage || op < 8 && uint64(len(data))+length > maxWebSocketMessage {
			return 0, nil, errors.New("WebSocket message size limit exceeded")
		}
		payload := make([]byte, int(length))
		if _, e := io.ReadFull(s.stream, payload); e != nil {
			return 0, nil, errors.New("truncated WebSocket payload")
		}
		idle.Reset(3 * time.Minute)
		switch op {
		case wsPing:
			if e := s.Write(wsPong, payload); e != nil {
				return 0, nil, e
			}
			continue
		case wsPong:
			continue
		case wsClose:
			if len(payload) == 1 || len(payload) > 2 && !utf8.Valid(payload[2:]) {
				return 0, nil, errors.New("invalid WebSocket close payload")
			}
			if len(payload) >= 2 {
				code := binary.BigEndian.Uint16(payload[:2])
				if !validCloseCode(code) {
					return 0, nil, errors.New("invalid WebSocket close status")
				}
			}
			// Closure is not proof that the SSM command/shell finished normally.
			return 0, nil, errors.New("Session Manager WebSocket closed before session completion")
		case 0:
			if opcode == 0 {
				return 0, nil, errors.New("unexpected WebSocket continuation")
			}
		default:
			if opcode != 0 {
				return 0, nil, errors.New("interleaved WebSocket data messages")
			}
			opcode = op
		}
		fragments++
		if fragments > 1024 {
			return 0, nil, errors.New("WebSocket fragmentation limit exceeded")
		}
		data = append(data, payload...)
		if fin {
			if opcode == wsText && !utf8.Valid(data) {
				return 0, nil, errors.New("invalid WebSocket text encoding")
			}
			return opcode, data, nil
		}
	}
}

func validCloseCode(code uint16) bool {
	switch code {
	case 1000, 1001, 1002, 1003, 1007, 1008, 1009, 1010, 1011, 1012, 1013, 1014:
		return true
	}
	return code >= 3000 && code <= 4999
}
