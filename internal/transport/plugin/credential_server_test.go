package plugin

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials/endpointcreds"
)

func syntheticRelay(provider aws.CredentialsProvider) *credentialServer {
	return &credentialServer{provider: provider, token: "SYNTHETIC-LOCAL-AUTHORIZATION", endpoint: "http://127.0.0.1:12345/credentials", slots: make(chan struct{}, 2)}
}

func relayRequest(ctx context.Context, relay *credentialServer) *http.Request {
	r := httptest.NewRequest(http.MethodGet, relay.endpoint, nil).WithContext(ctx)
	r.URL.Scheme, r.URL.Host = "", "" // Actual origin-form HTTP request.
	r.Header.Set("Authorization", relay.token)
	return r
}

func TestCredentialRelayRejectsBeforeProvider(t *testing.T) {
	for _, test := range []struct {
		name   string
		change func(*http.Request, *credentialServer)
	}{
		{"missing-authorization", func(r *http.Request, _ *credentialServer) { r.Header.Del("Authorization") }},
		{"wrong-authorization", func(r *http.Request, _ *credentialServer) { r.Header.Set("Authorization", "SYNTHETIC-WRONG") }},
		{"duplicate-authorization", func(r *http.Request, _ *credentialServer) { r.Header.Add("Authorization", "SYNTHETIC-WRONG") }},
		{"method", func(r *http.Request, _ *credentialServer) { r.Method = http.MethodPost }},
		{"path", func(r *http.Request, _ *credentialServer) { r.URL.Path = "/credentials/" }},
		{"escaped-path", func(r *http.Request, _ *credentialServer) { r.URL.RawPath = "/%63redentials" }},
		{"query", func(r *http.Request, _ *credentialServer) { r.URL.RawQuery = "ignored=1" }},
		{"empty-query", func(r *http.Request, _ *credentialServer) { r.URL.ForceQuery = true }},
		{"absolute-target", func(r *http.Request, _ *credentialServer) { r.URL.Scheme, r.URL.Host = "http", r.Host }},
		{"alternate-host", func(r *http.Request, _ *credentialServer) { r.Host = "localhost:12345" }},
		{"body", func(r *http.Request, _ *credentialServer) { r.ContentLength = 1 }},
		{"chunked", func(r *http.Request, _ *credentialServer) { r.TransferEncoding = []string{"chunked"} }},
		{"stopping", func(_ *http.Request, s *credentialServer) { s.stopping = true }},
	} {
		t.Run(test.name, func(t *testing.T) {
			var calls atomic.Int32
			s := syntheticRelay(aws.CredentialsProviderFunc(func(context.Context) (aws.Credentials, error) {
				calls.Add(1)
				return syntheticCredentials(), nil
			}))
			r := relayRequest(context.Background(), s)
			test.change(r, s)
			w := httptest.NewRecorder()
			s.ServeHTTP(w, r)
			if w.Code == http.StatusOK || calls.Load() != 0 || strings.Contains(w.Body.String(), "SYNTHETIC") || w.Header().Get("Cache-Control") != "no-store" {
				t.Fatal("rejected request retrieved/exposed credentials or allowed caching")
			}
		})
	}
}

// Feed actual SDK HTTP requests through the real handler without OS sockets.
type relayHTTP struct{ server *credentialServer }

func (h relayHTTP) Do(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	if r.Method == "" {
		r.Method = http.MethodGet
	}
	r.Host = r.URL.Host
	r.URL.Scheme, r.URL.Host = "", ""
	w := httptest.NewRecorder()
	h.server.ServeHTTP(w, r)
	return w.Result(), nil
}

func TestCredentialRelaySDKRefreshAndRedaction(t *testing.T) {
	var calls atomic.Int32
	selected := aws.NewCredentialsCache(aws.CredentialsProviderFunc(func(context.Context) (aws.Credentials, error) {
		credentials := syntheticCredentials()
		if calls.Add(1) == 2 {
			credentials.SessionToken = "SYNTHETIC-REFRESHED"
		}
		return credentials, nil
	}))
	s := syntheticRelay(selected)
	decoder := endpointcreds.New(s.endpoint, func(o *endpointcreds.Options) {
		o.HTTPClient, o.AuthorizationToken, o.Retryer = relayHTTP{s}, s.token, aws.NopRetryer{}
	})
	first, err := decoder.Retrieve(context.Background())
	if err != nil || first.SessionToken != "SYNTHETIC-TOKEN" || !first.CanExpire {
		t.Fatal("SDK could not decode selected relay credentials")
	}
	selected.Invalidate()
	second, err := decoder.Retrieve(context.Background())
	if err != nil || second.SessionToken != "SYNTHETIC-REFRESHED" || calls.Load() != 2 {
		t.Fatal("relay did not retain the exact selected SDK cache/refresh path")
	}
	for _, format := range []string{"%v", "%+v", "%#v"} {
		if strings.Contains(fmt.Sprintf(format, s), "SYNTHETIC") || strings.Contains(fmt.Sprintf(format, s), "127.0.0.1") {
			t.Fatal("relay formatting exposed authentication material")
		}
	}
	s.provider = aws.CredentialsProviderFunc(func(context.Context) (aws.Credentials, error) {
		return syntheticCredentials(), errors.New("SYNTHETIC-SECRET raw cause")
	})
	failed, err := decoder.Retrieve(context.Background())
	if err == nil || failed.HasKeys() || strings.Contains(err.Error(), "SYNTHETIC") {
		t.Fatal("failed retrieval exposed raw cause/partial credentials")
	}
}

func TestCredentialRelayBoundedRetrievalAndCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	started := make(chan struct{}, 2)
	s := syntheticRelay(aws.CredentialsProviderFunc(func(ctx context.Context) (aws.Credentials, error) {
		started <- struct{}{}
		<-ctx.Done()
		return aws.Credentials{}, ctx.Err()
	}))
	finished := make(chan int, 2)
	for range 2 {
		go func() {
			w := httptest.NewRecorder()
			s.ServeHTTP(w, relayRequest(ctx, s))
			finished <- w.Code
		}()
	}
	for range 2 {
		select {
		case <-started:
		case <-time.After(time.Second):
			t.Fatal("credential retrieval did not start")
		}
	}
	w := httptest.NewRecorder()
	s.ServeHTTP(w, relayRequest(ctx, s))
	if w.Code != http.StatusServiceUnavailable || len(started) != 0 {
		t.Fatal("relay exceeded two concurrent provider retrievals")
	}
	cancel()
	for range 2 {
		select {
		case status := <-finished:
			if status != http.StatusServiceUnavailable {
				t.Fatal("canceled retrieval succeeded")
			}
		case <-time.After(time.Second):
			t.Fatal("canceled retrieval was not joined")
		}
	}
	s.active.Wait()
}

func TestCredentialRelayUnavailableBeforeBind(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if s, err := startCredentialServer(ctx, nil); s != nil || !errors.Is(err, context.Canceled) {
		t.Fatal("pre-canceled relay was accepted")
	}
	if s, err := startCredentialServer(context.Background(), nil); s != nil || err == nil {
		t.Fatal("missing selected provider was accepted")
	}
}

func TestCredentialRelayCacheCancellationDoesNotClaimRefreshJoin(t *testing.T) {
	started, release, refreshed := make(chan struct{}), make(chan struct{}), make(chan struct{})
	defer close(release)
	cache := aws.NewCredentialsCache(aws.CredentialsProviderFunc(func(context.Context) (aws.Credentials, error) {
		close(started)
		<-release // The SDK cache deliberately suppresses request cancellation.
		defer close(refreshed)
		return syntheticCredentials(), nil
	}))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s := syntheticRelay(cache)
	finished := make(chan struct{})
	go func() {
		defer close(finished)
		s.ServeHTTP(httptest.NewRecorder(), relayRequest(ctx, s))
	}()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("SDK cache refresh did not start")
	}
	cancel()
	select {
	case <-finished:
	case <-time.After(time.Second):
		t.Fatal("request cancellation did not release the relay handler")
	}
	select {
	case <-refreshed:
		t.Fatal("test unexpectedly completed the shared SDK refresh")
	default:
	}
	s.active.Wait() // Handlers joined; shared SDK refresh is still in flight.
	// The deferred release runs before test cleanup, which independently joins
	// the test-owned provider rather than assigning its ownership to the relay.
	t.Cleanup(func() {
		select {
		case <-refreshed:
		case <-time.After(time.Second):
			t.Error("test-owned SDK refresh did not finish")
		}
	})
}

type relayTestListener struct {
	queue chan net.Conn
	done  chan struct{}
	once  sync.Once
}

func (l *relayTestListener) Accept() (net.Conn, error) {
	select {
	case c := <-l.queue:
		return c, nil
	case <-l.done:
		return nil, net.ErrClosed
	}
}
func (l *relayTestListener) Close() error { l.once.Do(func() { close(l.done) }); return nil }
func (l *relayTestListener) Addr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 12345}
}

func TestCredentialListenerCapacityAndClose(t *testing.T) {
	base := &relayTestListener{queue: make(chan net.Conn, 9), done: make(chan struct{})}
	l := &credentialListener{Listener: base, slots: make(chan struct{}, 8), done: make(chan struct{})}
	defer l.Close()
	for range 9 {
		client, server := net.Pipe()
		defer client.Close()
		defer server.Close()
		base.queue <- server
	}
	var accepted []net.Conn
	defer func() {
		for _, c := range accepted {
			if err := c.Close(); err != nil {
				t.Error("test connection cleanup failed")
			}
		}
	}()
	for range 8 {
		c, err := l.Accept()
		if err != nil {
			t.Fatal("accept below capacity failed")
		}
		accepted = append(accepted, c)
	}
	type result struct {
		conn net.Conn
		err  error
	}
	next := make(chan result, 1)
	go func() { c, err := l.Accept(); next <- result{c, err} }()
	select {
	case r := <-next:
		if r.conn != nil {
			_ = r.conn.Close()
		}
		t.Fatal("accepted more than eight concurrent sockets")
	case <-time.After(20 * time.Millisecond):
	}
	if err := accepted[0].Close(); err != nil {
		t.Fatal("release connection capacity failed")
	}
	select {
	case r := <-next:
		if r.err != nil || r.conn == nil {
			t.Fatal("released slot was not reused")
		}
		accepted = append(accepted, r.conn)
	case <-time.After(time.Second):
		t.Fatal("accept remained blocked after connection closure")
	}
	go func() { c, err := l.Accept(); next <- result{c, err} }()
	if err := l.Close(); err != nil {
		t.Fatal("close listener failed")
	}
	select {
	case r := <-next:
		if r.conn != nil || !errors.Is(r.err, net.ErrClosed) {
			t.Fatal("shutdown did not unblock capacity-limited accept")
		}
	case <-time.After(time.Second):
		t.Fatal("accept remained blocked after listener shutdown")
	}
}

type relayCloseErrorConn struct {
	net.Conn
	calls atomic.Int32
}

func (c *relayCloseErrorConn) Close() error {
	c.calls.Add(1)
	_ = c.Conn.Close()
	return errors.New("SYNTHETIC-SECRET connection close failure")
}

func TestCredentialConnectionCloseErrorAndOnce(t *testing.T) {
	a, b := net.Pipe()
	defer b.Close()
	base := &relayCloseErrorConn{Conn: a}
	l := &credentialListener{slots: make(chan struct{}, 1)}
	l.slots <- struct{}{}
	c := &credentialConnection{Conn: base, release: func(err error) {
		l.closeFailed.Store(err != nil)
		<-l.slots
	}}
	for range 2 {
		if c.Close() == nil {
			t.Fatal("connection close failure was lost")
		}
	}
	if base.calls.Load() != 1 || len(l.slots) != 0 || !l.closeFailed.Load() {
		t.Fatal("connection was closed/released more than once or its error was lost")
	}
}

func TestCredentialRelayRealTCP(t *testing.T) {
	if os.Getenv("SSMH_TEST_TCP") != "1" {
		t.Skip("set SSMH_TEST_TCP=1 for synthetic credential relay over OS loopback")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	s, err := startCredentialServer(ctx, aws.CredentialsProviderFunc(func(context.Context) (aws.Credentials, error) {
		return syntheticCredentials(), nil
	}))
	if err != nil {
		t.Fatal("start synthetic loopback relay failed")
	}
	t.Cleanup(func() {
		cleanup, stop := context.WithTimeout(context.Background(), time.Second)
		defer stop()
		if err := s.close(cleanup); err != nil {
			t.Error("synthetic relay cleanup failed")
		}
	})
	entries, err := s.environment()
	if err != nil || len(entries) != 2 || len(s.token) != 64 || !strings.HasPrefix(s.endpoint, "http://127.0.0.1:") {
		t.Fatal("invalid relay environment/bind/authentication")
	}
	transport := &http.Transport{DisableKeepAlives: true}
	defer transport.CloseIdleConnections()
	decoder := endpointcreds.New(s.endpoint, func(o *endpointcreds.Options) {
		o.HTTPClient = &http.Client{Transport: transport, Timeout: time.Second}
		o.AuthorizationToken, o.Retryer = s.token, aws.NopRetryer{}
	})
	credentials, err := decoder.Retrieve(ctx)
	if err != nil || credentials.SessionToken != "SYNTHETIC-TOKEN" {
		t.Fatal("actual SDK request over loopback failed")
	}
	// An unauthenticated network request must never receive even partial secrets.
	r, _ := http.NewRequestWithContext(ctx, http.MethodGet, s.endpoint, nil)
	response, err := (&http.Client{Transport: transport, Timeout: time.Second}).Do(r)
	if err != nil {
		t.Fatal("unauthenticated loopback request failed")
	}
	body, readErr := io.ReadAll(io.LimitReader(response.Body, 1024))
	closeErr := response.Body.Close()
	if readErr != nil || closeErr != nil || response.StatusCode != http.StatusBadRequest || strings.Contains(string(body), "SYNTHETIC") {
		t.Fatal("unauthenticated network request exposed credentials")
	}
	address := strings.TrimSuffix(strings.TrimPrefix(s.endpoint, "http://"), credentialPath)
	if err := s.close(ctx); err != nil {
		t.Fatal("relay shutdown failed")
	}
	closedContext, closeCancel := context.WithCancel(context.Background())
	closeCancel()
	if err := s.close(closedContext); err != nil {
		t.Fatal("completed shutdown is not idempotent with an expired cleanup context")
	}
	if env, err := s.environment(); env != nil || err == nil {
		t.Fatal("closed relay exposed environment")
	}
	c, err := (&net.Dialer{Timeout: time.Second}).DialContext(ctx, "tcp4", address)
	if c != nil {
		_ = c.Close()
		t.Fatal("relay listener remained open")
	}
	if err == nil {
		t.Fatal("closed listener accepted a connection")
	}
}

func TestCredentialRelayParentCancellationRealTCP(t *testing.T) {
	if os.Getenv("SSMH_TEST_TCP") != "1" {
		t.Skip("set SSMH_TEST_TCP=1 for relay cancellation over OS loopback")
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	started, stopped := make(chan struct{}), make(chan struct{})
	s, err := startCredentialServer(ctx, aws.CredentialsProviderFunc(func(ctx context.Context) (aws.Credentials, error) {
		close(started)
		<-ctx.Done()
		close(stopped)
		return aws.Credentials{}, ctx.Err()
	}))
	if err != nil {
		t.Fatal("start synthetic relay failed")
	}
	t.Cleanup(func() {
		cleanup, stop := context.WithTimeout(context.Background(), time.Second)
		defer stop()
		if err := s.close(cleanup); err != nil {
			t.Error("relay cleanup failed")
		}
	})
	transport := &http.Transport{DisableKeepAlives: true}
	defer transport.CloseIdleConnections()
	r, _ := http.NewRequest(http.MethodGet, s.endpoint, nil)
	r.Header.Set("Authorization", s.token)
	finished := make(chan struct{})
	go func() {
		defer close(finished)
		response, _ := (&http.Client{Transport: transport, Timeout: 2 * time.Second}).Do(r)
		if response != nil {
			_ = response.Body.Close()
		}
	}()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("relay retrieval did not start")
	}
	cancel()
	if env, err := s.environment(); env != nil || err == nil {
		t.Fatal("canceled relay offered a child environment")
	}
	select {
	case <-s.done:
	case <-time.After(time.Second):
		t.Fatal("canceled relay did not finish shutdown")
	}
	select {
	case <-stopped:
	default:
		t.Fatal("relay reported shutdown before provider returned")
	}
	select {
	case <-finished:
	case <-time.After(time.Second):
		t.Fatal("canceled relay did not close active HTTP request")
	}
}

func TestCredentialRelayIncompleteShutdownRealTCP(t *testing.T) {
	if os.Getenv("SSMH_TEST_TCP") != "1" {
		t.Skip("set SSMH_TEST_TCP=1 for incomplete relay shutdown over OS loopback")
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	started, release := make(chan struct{}), make(chan struct{})
	var releaseOnce sync.Once
	unblock := func() { releaseOnce.Do(func() { close(release) }) }
	defer unblock()
	s, err := startCredentialServer(ctx, aws.CredentialsProviderFunc(func(context.Context) (aws.Credentials, error) {
		close(started)
		<-release // Simulate a trusted provider that does not honor context.
		return syntheticCredentials(), nil
	}))
	if err != nil {
		t.Fatal("start synthetic relay failed")
	}
	t.Cleanup(func() {
		unblock()
		cleanup, stop := context.WithTimeout(context.Background(), time.Second)
		defer stop()
		if err := s.close(cleanup); err != nil {
			t.Error("test-owned provider did not finish cleanup")
		}
	})
	transport := &http.Transport{DisableKeepAlives: true}
	defer transport.CloseIdleConnections()
	r, _ := http.NewRequest(http.MethodGet, s.endpoint, nil)
	r.Header.Set("Authorization", s.token)
	finished := make(chan struct{})
	go func() {
		defer close(finished)
		response, _ := (&http.Client{Transport: transport, Timeout: 2 * time.Second}).Do(r)
		if response != nil {
			_ = response.Body.Close()
		}
	}()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("relay retrieval did not start")
	}
	cleanup, stop := context.WithTimeout(context.Background(), 5*time.Millisecond)
	defer stop()
	err = s.close(cleanup)
	if !errors.Is(err, context.DeadlineExceeded) || !strings.Contains(err.Error(), "incomplete") {
		t.Fatal("relay claimed complete shutdown while provider remained active")
	}
	select {
	case <-s.done:
		t.Fatal("relay declared joined handlers while provider remained active")
	default:
	}
	unblock()
	select {
	case <-s.done:
	case <-time.After(time.Second):
		t.Fatal("unblocked provider was not joined")
	}
	select {
	case <-finished:
	case <-time.After(time.Second):
		t.Fatal("test HTTP request remained active after socket shutdown")
	}
}
