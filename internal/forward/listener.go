// Package forward owns local resource boundaries for SSM TCP forwarding.
package forward

import (
	"context"
	"errors"
	"net"
	"syscall"

	"ssmh/internal/config"
)

// Listen binds only TCP4 127.0.0.1 at the validated requested local port. It
// never resolves the remote host, changes privileges or tries another port.
// ctx bounds creation, not listener lifetime: after success the caller owns
// Close, including on later setup failure, or transfers it to ServeForward.
// Loopback limits network exposure but does not authenticate local users.
func Listen(ctx context.Context, target config.ForwardTarget) (net.Listener, error) {
	var lc net.ListenConfig
	return listen(ctx, target, lc.Listen)
}

type listenFunc func(context.Context, string, string) (net.Listener, error)

func listen(ctx context.Context, target config.ForwardTarget, bind listenFunc) (net.Listener, error) {
	if ctx == nil || target.Validate() != nil {
		return nil, errors.New("invalid forwarding listener setup")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	listener, err := bind(ctx, "tcp4", target.Address())
	if err != nil {
		var failure error
		switch {
		case errors.Is(err, syscall.EADDRINUSE):
			failure = errors.New("forwarding local port is already in use")
		case errors.Is(err, syscall.EACCES), errors.Is(err, syscall.EPERM):
			failure = errors.New("permission denied binding forwarding local port; no privilege escalation attempted")
		default:
			failure = errors.New("bind forwarding loopback listener failed")
		}
		return nil, errors.Join(failure, ctx.Err(), closeRejected(listener))
	}
	if listener == nil {
		return nil, errors.New("bind forwarding loopback listener returned no listener")
	}
	if err := ctx.Err(); err != nil {
		return nil, errors.Join(err, closeRejected(listener))
	}
	address, ok := listener.Addr().(*net.TCPAddr)
	if !ok || address == nil || !address.IP.Equal(net.IPv4(127, 0, 0, 1)) || address.Zone != "" || address.Port != target.LocalPort {
		return nil, errors.Join(errors.New("bound forwarding listener does not match requested loopback port"), closeRejected(listener))
	}
	return listener, nil
}

func closeRejected(listener net.Listener) error {
	if listener != nil && listener.Close() != nil {
		return errors.New("close rejected forwarding listener failed")
	}
	return nil
}
