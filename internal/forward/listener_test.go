package forward

import (
	"context"
	"errors"
	"net"
	"os"
	"strings"
	"syscall"
	"testing"
	"time"

	"ssmh/internal/config"
)

type testListener struct {
	address  net.Addr
	closed   int
	closeErr error
}

func (l *testListener) Addr() net.Addr            { return l.address }
func (l *testListener) Accept() (net.Conn, error) { panic("listener setup must not accept") }
func (l *testListener) Close() error              { l.closed++; return l.closeErr }

func localListener() *testListener {
	return &testListener{address: &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 8080}}
}

func TestListenCreationAndOwnership(t *testing.T) {
	for _, host := range []string{"", "database.internal", "::1"} {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		l := localListener()
		target := config.ForwardTarget{LocalPort: 8080, RemotePort: 5432, Host: host}
		got, err := listen(ctx, target, func(received context.Context, network, address string) (net.Listener, error) {
			if received != ctx || network != "tcp4" || address != "127.0.0.1:8080" {
				t.Fatal("bind changed context, network or address")
			}
			return l, nil
		})
		cancel()
		if err != nil || got != l || l.closed != 0 {
			t.Fatal("successful listener not transferred to caller")
		}
		// Setup context cancellation must not close a transferred listener.
		if err := got.Close(); err != nil || l.closed != 1 {
			t.Fatal("caller cleanup failed")
		}
	}
}

func TestListenRejectsBeforeBind(t *testing.T) {
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	for _, tc := range []struct {
		ctx    context.Context
		target config.ForwardTarget
	}{
		{nil, config.ForwardTarget{LocalPort: 8080, RemotePort: 80}},
		{canceled, config.ForwardTarget{LocalPort: 8080, RemotePort: 80}},
		{context.Background(), config.ForwardTarget{LocalPort: 0, RemotePort: 80}},
		{context.Background(), config.ForwardTarget{LocalPort: 8080, RemotePort: 65536}},
		{context.Background(), config.ForwardTarget{LocalPort: 8080, RemotePort: 80, Host: "bad\nsecret"}},
	} {
		got, err := listen(tc.ctx, tc.target, func(context.Context, string, string) (net.Listener, error) {
			t.Fatal("invalid setup attempted bind")
			return nil, nil
		})
		if got != nil || err == nil || strings.Contains(err.Error(), "secret") {
			t.Fatal("invalid setup accepted or disclosed")
		}
		if tc.ctx == canceled && !errors.Is(err, context.Canceled) {
			t.Fatal("cancellation lost")
		}
	}
}

func TestListenBindErrors(t *testing.T) {
	for _, tc := range []struct {
		cause error
		label string
	}{
		{&net.OpError{Op: "listen", Err: errors.Join(errors.New("secret"), syscall.EADDRINUSE)}, "already in use"},
		{errors.Join(errors.New("secret"), syscall.EACCES), "permission denied"},
		{syscall.EPERM, "permission denied"},
		{errors.New("secret"), "bind forwarding"},
	} {
		for _, partial := range []bool{false, true} {
			l := localListener()
			l.closeErr = errors.New("secret-close")
			got, err := listen(context.Background(), config.ForwardTarget{LocalPort: 8080, RemotePort: 80}, func(context.Context, string, string) (net.Listener, error) {
				if partial {
					return l, tc.cause
				}
				return nil, tc.cause
			})
			if got != nil || err == nil || !strings.Contains(err.Error(), tc.label) || strings.Contains(err.Error(), "secret") {
				t.Fatal("unsafe or incorrect bind failure")
			}
			if partial && (l.closed != 1 || !strings.Contains(err.Error(), "close rejected")) {
				t.Fatal("partial listener cleanup lost")
			}
			if errors.Is(err, tc.cause) {
				t.Fatal("raw network cause retained")
			}
		}
	}
}

func TestListenRejectsUnexpectedBoundAddress(t *testing.T) {
	for _, addr := range []net.Addr{nil, (*net.TCPAddr)(nil), &net.UnixAddr{Name: "secret"},
		&net.TCPAddr{IP: net.IPv4zero, Port: 8080}, &net.TCPAddr{IP: net.IPv4(127, 0, 0, 2), Port: 8080},
		&net.TCPAddr{IP: net.IPv6loopback, Port: 8080}, &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 8081},
		&net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 8080, Zone: "secret"},
	} {
		l := &testListener{address: addr, closeErr: errors.New("secret")}
		got, err := listen(context.Background(), config.ForwardTarget{LocalPort: 8080, RemotePort: 80}, func(context.Context, string, string) (net.Listener, error) { return l, nil })
		if got != nil || err == nil || l.closed != 1 || !strings.Contains(err.Error(), "close rejected") || strings.Contains(err.Error(), "secret") {
			t.Fatal("unsafe address or cleanup")
		}
	}
}

func TestListenCancellationAfterBind(t *testing.T) {
	for _, failed := range []bool{false, true} {
		ctx, cancel := context.WithCancel(context.Background())
		l := localListener()
		l.closeErr = errors.New("secret")
		got, err := listen(ctx, config.ForwardTarget{LocalPort: 8080, RemotePort: 80}, func(context.Context, string, string) (net.Listener, error) {
			cancel()
			if failed {
				return l, errors.New("secret")
			}
			return l, nil
		})
		if got != nil || !errors.Is(err, context.Canceled) || l.closed != 1 || !strings.Contains(err.Error(), "close rejected") || strings.Contains(err.Error(), "secret") {
			t.Fatal("cancellation or cleanup failure lost")
		}
	}
	got, err := listen(context.Background(), config.ForwardTarget{LocalPort: 8080, RemotePort: 80}, func(context.Context, string, string) (net.Listener, error) { return nil, nil })
	if got != nil || err == nil {
		t.Fatal("nil successful listener accepted")
	}
}

// Real socket creation is explicitly opt-in; default tests are sandbox-safe.
func TestListenRealTCP(t *testing.T) {
	if os.Getenv("SSMH_TEST_TCP") != "1" {
		t.Skip("set SSMH_TEST_TCP=1 to test OS loopback binding")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var lc net.ListenConfig
	reservation, err := lc.Listen(ctx, "tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := reservation.Addr().(*net.TCPAddr).Port
	if err := reservation.Close(); err != nil {
		t.Fatal(err)
	}
	target := config.ForwardTarget{LocalPort: port, RemotePort: 80}
	l, err := Listen(ctx, target)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := l.Close(); err != nil {
			t.Error(err)
		}
	}()
	if l.Addr().String() != target.Address() {
		t.Fatal("non-loopback bind")
	}
	duplicate, err := Listen(ctx, target)
	if duplicate != nil {
		_ = duplicate.Close()
		t.Fatal("port conflict unexpectedly accepted")
	}
	if err == nil || !strings.Contains(err.Error(), "already in use") {
		t.Fatal("port conflict not reported")
	}
	accepted := make(chan error, 1)
	go func() {
		c, err := l.Accept()
		if c != nil {
			err = errors.Join(err, c.Close())
		}
		accepted <- err
	}()
	c, err := (&net.Dialer{}).DialContext(ctx, "tcp4", target.Address())
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-accepted:
		if err != nil {
			t.Fatal(err)
		}
	case <-ctx.Done():
		t.Fatal("loopback accept timed out")
	}
}
