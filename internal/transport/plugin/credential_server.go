package plugin

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
)

const credentialPath = "/credentials"

// credentialServer is a private, authenticated loopback relay, not a plugin
// backend. The future launcher must isolate all alternate child credential
// sources and arrange its lifetime. Nothing starts this server from the CLI yet.
type credentialServer struct {
	mu       sync.Mutex
	stopping bool
	endpoint string
	token    string
	provider aws.CredentialsProvider
	lifetime context.Context
	active   sync.WaitGroup
	slots    chan struct{}
	cancel   context.CancelFunc
	done     chan struct{}
	serveErr error
}

func (s *credentialServer) String() string {
	return "plugin credential relay [endpoint and authentication material redacted]"
}

func (s *credentialServer) GoString() string { return s.String() }

func startCredentialServer(ctx context.Context, provider aws.CredentialsProvider) (*credentialServer, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if provider == nil {
		return nil, errors.New("selected plugin credential provider is unavailable")
	}
	var random [32]byte
	defer clear(random[:])
	if _, err := io.ReadFull(rand.Reader, random[:]); err != nil {
		return nil, errors.New("create plugin credential relay authorization failed")
	}
	var lc net.ListenConfig
	listener, err := lc.Listen(ctx, "tcp4", "127.0.0.1:0")
	if err != nil {
		return nil, errors.Join(ctx.Err(), errors.New("bind plugin credential relay failed"))
	}
	address, ok := listener.Addr().(*net.TCPAddr)
	if !ok || !address.IP.Equal(net.IPv4(127, 0, 0, 1)) || address.Port <= 0 || ctx.Err() != nil {
		closeErr := listener.Close()
		if closeErr != nil {
			closeErr = errors.New("close rejected plugin credential relay failed")
		}
		return nil, errors.Join(ctx.Err(), errors.New("plugin credential relay requires a live IPv4 loopback listener"), closeErr)
	}
	lifetime, cancel := context.WithCancel(ctx)
	s := &credentialServer{
		endpoint: "http://" + address.String() + credentialPath,
		token:    hex.EncodeToString(random[:]), provider: provider,
		slots: make(chan struct{}, 2), cancel: cancel, done: make(chan struct{}),
		lifetime: lifetime,
	}
	server := &http.Server{
		Handler: s, ReadHeaderTimeout: 2 * time.Second, ReadTimeout: 5 * time.Second,
		WriteTimeout: 6 * time.Second, IdleTimeout: 2 * time.Second, MaxHeaderBytes: 4096,
		ErrorLog:    log.New(io.Discard, "", 0),
		BaseContext: func(net.Listener) context.Context { return lifetime },
	}
	server.SetKeepAlivesEnabled(false)
	limited := &credentialListener{Listener: listener, slots: make(chan struct{}, 8), done: make(chan struct{})}
	var shutdownOnce sync.Once
	var shutdownErr error
	shutdown := func() error {
		shutdownOnce.Do(func() { shutdownErr = server.Close() })
		return shutdownErr
	}
	go func() {
		select {
		case <-lifetime.Done():
			_ = shutdown() // Serve owner records shutdown failures below.
		case <-s.done:
		}
	}()
	go func() {
		err := server.Serve(limited)
		s.mu.Lock()
		s.stopping = true // Serialize Wait with every handler admission.
		s.mu.Unlock()
		cancel()
		closeErr := shutdown()
		s.active.Wait() // Selected SDK providers must honor cancellation.
		s.mu.Lock()
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			s.serveErr = errors.New("serve plugin credential relay failed")
		}
		if closeErr != nil {
			s.serveErr = errors.Join(s.serveErr, errors.New("close plugin credential relay failed"))
		}
		if limited.closeFailed.Load() {
			s.serveErr = errors.Join(s.serveErr, errors.New("close plugin credential relay connection failed"))
		}
		s.provider, s.token, s.endpoint = nil, "", ""
		s.mu.Unlock()
		close(s.done)
	}()
	return s, nil
}

// environment returns only the two SDK endpoint settings. It is not a complete
// child environment and must not be appended to inherited AWS configuration.
func (s *credentialServer) environment() ([]string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.stopping || s.lifetime == nil || s.lifetime.Err() != nil || s.token == "" || s.endpoint == "" {
		return nil, errors.New("plugin credential relay is unavailable")
	}
	return []string{"AWS_CONTAINER_CREDENTIALS_FULL_URI=" + s.endpoint, "AWS_CONTAINER_AUTHORIZATION_TOKEN=" + s.token}, nil
}

// close cancels retrieval and closes sockets. A timeout reports incomplete
// shutdown; it does not pretend a context-ignoring provider has been joined.
func (s *credentialServer) close(ctx context.Context) error {
	s.mu.Lock()
	s.stopping = true
	s.mu.Unlock()
	s.cancel()
	result := func() error {
		s.mu.Lock()
		defer s.mu.Unlock()
		return s.serveErr
	}
	select {
	case <-s.done:
		return result()
	default:
	}
	select {
	case <-s.done:
		return result()
	case <-ctx.Done():
		return errors.Join(ctx.Err(), errors.New("plugin credential relay shutdown is incomplete"))
	}
}

func (s *credentialServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	fail := func(status int) {
		w.WriteHeader(status)
		_, _ = io.WriteString(w, `{"code":"CredentialRelayUnavailable","message":"Selected plugin credentials are unavailable"}`)
	}
	s.mu.Lock()
	if s.stopping {
		s.mu.Unlock()
		fail(http.StatusServiceUnavailable)
		return
	}
	s.active.Add(1)
	provider, token, endpoint := s.provider, s.token, s.endpoint
	s.mu.Unlock()
	defer s.active.Done()
	// Require the literal loopback authority as well as the exact origin-form
	// target, preventing browser DNS rebinding/alternate-host access. No body,
	// query, alternate path or duplicate Authorization is accepted.
	if r.Method != http.MethodGet || r.URL.IsAbs() || "http://"+r.Host+credentialPath != endpoint ||
		r.URL.Path != credentialPath || r.URL.RawPath != "" || r.URL.RawQuery != "" || r.URL.ForceQuery ||
		r.ContentLength != 0 || len(r.TransferEncoding) != 0 || len(r.Header.Values("Authorization")) != 1 ||
		token == "" || subtle.ConstantTimeCompare([]byte(r.Header.Get("Authorization")), []byte(token)) != 1 {
		fail(http.StatusBadRequest)
		return
	}
	select {
	case s.slots <- struct{}{}:
		defer func() { <-s.slots }()
	default:
		fail(http.StatusServiceUnavailable)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	response, err := credentialResponse(ctx, provider)
	if err != nil || ctx.Err() != nil {
		clear(response)
		fail(http.StatusServiceUnavailable)
		return
	}
	defer clear(response)    // Best effort for this buffer, not Go/HTTP copy erasure.
	_, _ = w.Write(response) // Never log payloads or raw write errors.
}

// Bound accepted connections, including idle/unauthenticated HTTP clients.
type credentialListener struct {
	net.Listener
	slots       chan struct{}
	done        chan struct{}
	once        sync.Once
	err         error
	closeFailed atomic.Bool
}

func (l *credentialListener) Accept() (net.Conn, error) {
	select {
	case l.slots <- struct{}{}:
	case <-l.done:
		return nil, net.ErrClosed
	}
	c, err := l.Listener.Accept()
	if err != nil {
		<-l.slots
		return nil, err
	}
	return &credentialConnection{Conn: c, release: func(err error) {
		if err != nil {
			l.closeFailed.Store(true)
		}
		<-l.slots
	}}, nil
}

func (l *credentialListener) Close() error {
	l.once.Do(func() { close(l.done); l.err = l.Listener.Close() })
	return l.err
}

type credentialConnection struct {
	net.Conn
	release func(error)
	once    sync.Once
	err     error
}

func (c *credentialConnection) Close() error {
	c.once.Do(func() { c.err = c.Conn.Close(); c.release(c.err) })
	return c.err
}
