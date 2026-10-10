package cli

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

type compositionExecutable struct {
	path, roots string
	certificate tls.Certificate
}

// Exercise the real process signal boundary with a private PTY, never the user's
// terminal. The synthetic peer confirms resize delivery before SIGTERM; a raw
// ioctl observation alone would not prove channel establishment.
func compositionTTYSignal(t *testing.T, ctx context.Context, cmd *exec.Cmd, ready <-chan struct{}) error {
	t.Helper()
	master, err := unix.Open("/dev/ptmx", unix.O_RDWR|unix.O_NOCTTY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal("cannot open private compiled-client PTY")
	}
	defer unix.Close(master)
	if unix.IoctlSetPointerInt(master, unix.TIOCSPTLCK, 0) != nil {
		t.Fatal("cannot unlock private compiled-client PTY")
	}
	number, err := unix.IoctlGetInt(master, unix.TIOCGPTN)
	if err != nil {
		t.Fatal("cannot identify private compiled-client PTY")
	}
	slave, err := os.OpenFile("/dev/pts/"+strconv.Itoa(number), os.O_RDWR|unix.O_NOCTTY, 0)
	if err != nil {
		t.Fatal("cannot open compiled-client PTY slave")
	}
	defer slave.Close()
	fd := int(slave.Fd()) // This owned descriptor is not used by Go's poller.
	before, err := unix.IoctlGetTermios(fd, unix.TCGETS)
	if err != nil || unix.IoctlSetWinsize(fd, unix.TIOCSWINSZ, &unix.Winsize{Col: 80, Row: 24}) != nil {
		t.Fatal("cannot prepare compiled-client PTY state")
	}
	cmd.Stdin = slave
	if cmd.Start() != nil {
		t.Fatal("cannot start compiled TTY client")
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	joined := false
	defer func() {
		if !joined {
			_ = cmd.Process.Kill()
			<-done
		}
	}()
	select {
	case <-ready:
	case <-done:
		joined = true
		t.Fatal("compiled TTY client exited before dimension delivery")
	case <-ctx.Done():
		t.Fatal("compiled TTY establishment exceeded its budget")
	}
	raw, err := unix.IoctlGetTermios(fd, unix.TCGETS)
	if err != nil || raw.Lflag&(unix.ECHO|unix.ICANON|unix.ISIG) != 0 {
		t.Fatal("compiled TTY client did not enter raw mode")
	}
	if cmd.Process.Signal(unix.SIGTERM) != nil {
		t.Fatal("cannot signal compiled TTY client")
	}
	select {
	case err = <-done:
		joined = true
	case <-ctx.Done():
		t.Fatal("compiled TTY shutdown exceeded its budget")
	}
	after, restoreErr := unix.IoctlGetTermios(fd, unix.TCGETS)
	if restoreErr != nil || *after != *before {
		t.Fatal("compiled TTY client did not restore full terminal state")
	}
	return err
}

// All child configuration is explicit and synthetic. The production executable
// uses its ordinary SDK and proxy/CA support, without injected dependencies,
// service overrides, disabled verification, live AWS or inherited credentials.
func TestNativeExecutableTLSComposition(t *testing.T) {
	if testing.Short() || os.Getenv("SSMH_TEST_TCP") != "1" {
		t.Skip("set SSMH_TEST_TCP=1 for compiled client TLS composition")
	}
	dir := t.TempDir()
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal("cannot resolve build root")
	}
	executable := &compositionExecutable{path: filepath.Join(dir, "ssmh"), roots: filepath.Join(dir, "synthetic-public-ca.pem")}
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	build := exec.CommandContext(ctx, filepath.Join(runtime.GOROOT(), "bin", "go"), "build", "-trimpath", "-buildvcs=false", "-o", executable.path, "./cmd/ssmh")
	build.Dir = root
	// Build does not execute app/tests; preserve tooling/cache settings, never
	// expose build output (which may include paths/environment) in diagnostics.
	build.Env = compositionBuildEnvironment(os.Environ())
	if build.Run() != nil {
		t.Fatal("cannot build offline compiled client; ensure dependencies are cached")
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal("cannot generate synthetic TLS key")
	}
	now := time.Now()
	cert := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "synthetic CLI test CA"}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1)}}
	for _, service := range []string{"ec2", "ssm", "ssmmessages", "kms"} {
		cert.DNSNames = append(cert.DNSNames, service+".ca-central-1.amazonaws.com")
	}
	der, err := x509.CreateCertificate(rand.Reader, cert, cert, &key.PublicKey, key)
	if err != nil {
		t.Fatal("cannot create synthetic certificate")
	}
	executable.certificate = tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
	// Only the PUBLIC root is written. Private key and fake AWS credentials are
	// never stored; this trust file exists solely in the owned temporary test dir.
	if os.WriteFile(executable.roots, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0600) != nil {
		t.Fatal("cannot prepare public test trust bundle")
	}
	t.Run("command", func(t *testing.T) { testNativeTLSComposition(t, false, executable) })
	t.Run("shell", func(t *testing.T) { testNativeTLSComposition(t, true, executable) })
}

func (e *compositionExecutable) environment(proxy string) []string {
	return []string{"LANG=C", "LC_ALL=C", "AWS_ACCESS_KEY_ID=synthetic-key", "AWS_SECRET_ACCESS_KEY=synthetic-secret", "AWS_CONFIG_FILE=/dev/null", "AWS_SHARED_CREDENTIALS_FILE=/dev/null", "AWS_EC2_METADATA_DISABLED=true", "HTTPS_PROXY=" + proxy, "HTTP_PROXY=" + proxy, "NO_PROXY="}
}

func compositionBuildEnvironment(inherited []string) []string {
	var env []string
	for _, entry := range inherited {
		key, _, _ := strings.Cut(entry, "=")
		switch key {
		case "PATH", "HOME", "TMPDIR", "GOCACHE", "GOMODCACHE", "GOPATH":
			env = append(env, entry)
		}
	}
	return append(env, "CGO_ENABLED=0", "GOENV=off", "GOTOOLCHAIN=local", "GOWORK=off", "GOPROXY=off", "GOFLAGS=-mod=readonly")
}

func compositionSignedRequest(r *http.Request) bool {
	service := strings.TrimSuffix(r.Host, ".ca-central-1.amazonaws.com")
	if r.Host != service+".ca-central-1.amazonaws.com" {
		return false
	}
	switch service {
	case "ec2", "ssm", "ssmmessages", "kms":
	default:
		return false
	}
	return strings.Contains(r.Header.Get("Authorization"), "/ca-central-1/"+service+"/aws4_request") && strings.Contains(r.Header.Get("Authorization"), "Credential=synthetic-key/")
}

// CONNECT forwards encrypted bytes only to the explicit local fixture. It is
// not a general proxy, decryptor, TLS bypass, production helper or public bind.
func compositionProxy(t *testing.T, destination string) *httptest.Server {
	t.Helper()
	var workers sync.WaitGroup
	var admission sync.Mutex
	closing := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		admission.Lock()
		if closing {
			admission.Unlock()
			w.WriteHeader(503)
			return
		}
		workers.Add(1)
		admission.Unlock()
		defer workers.Done()
		host, port, err := net.SplitHostPort(r.Host)
		service := strings.TrimSuffix(host, ".ca-central-1.amazonaws.com")
		allowed := false
		switch service {
		case "ec2", "ssm", "ssmmessages", "kms":
			allowed = true
		}
		if err != nil || r.Method != "CONNECT" || port != "443" || !allowed || host != service+".ca-central-1.amazonaws.com" {
			w.WriteHeader(403)
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
		defer cancel()
		upstream, err := (&net.Dialer{}).DialContext(ctx, "tcp", destination)
		if err != nil {
			w.WriteHeader(502)
			return
		}
		defer upstream.Close()
		client, buffer, err := w.(http.Hijacker).Hijack()
		if err != nil {
			return
		}
		defer client.Close()
		_ = client.SetDeadline(time.Now().Add(12 * time.Second))
		_ = upstream.SetDeadline(time.Now().Add(12 * time.Second))
		if _, err = buffer.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
			return
		}
		if buffer.Flush() != nil {
			return
		}
		joined := make(chan struct{})
		go func() {
			defer close(joined)
			_, _ = io.Copy(upstream, buffer)
			_ = upstream.Close()
			_ = client.Close()
		}()
		_, _ = io.Copy(client, upstream)
		_ = upstream.Close()
		_ = client.Close()
		<-joined
	}))
	t.Cleanup(func() { admission.Lock(); closing = true; admission.Unlock(); server.Close(); workers.Wait() })
	return server
}

func TestCompositionExecutableIsolation(t *testing.T) {
	build := compositionBuildEnvironment([]string{"PATH=/trusted/bin", "GOCACHE=/tmp/synthetic-build", "AWS_ACCESS_KEY_ID=host-secret", "AWS_PROFILE=host-profile", "HTTPS_PROXY=http://host-proxy", "LD_PRELOAD=/host/loader", "GOFLAGS=-overlay=host"})
	joined := strings.Join(build, "\n")
	if strings.Contains(joined, "host-") || strings.Contains(joined, "LD_PRELOAD") || strings.Contains(joined, "overlay") || !strings.Contains(joined, "GOPROXY=off") || !strings.Contains(joined, "GOFLAGS=-mod=readonly") {
		t.Fatal("compiled build inherited sensitive/uncontrolled settings")
	}
	env := (&compositionExecutable{roots: "/synthetic/public-ca.pem"}).environment("http://127.0.0.1:12345")
	values := map[string]string{}
	for _, entry := range env {
		key, value, ok := strings.Cut(entry, "=")
		_, duplicate := values[key]
		if !ok || duplicate {
			t.Fatal("invalid duplicate child configuration")
		}
		values[key] = value
	}
	if values["AWS_ACCESS_KEY_ID"] != "synthetic-key" || values["AWS_SECRET_ACCESS_KEY"] != "synthetic-secret" || values["AWS_CONFIG_FILE"] != "/dev/null" || values["AWS_SHARED_CREDENTIALS_FILE"] != "/dev/null" || values["AWS_EC2_METADATA_DISABLED"] != "true" || values["AWS_PROFILE"] != "" || values["AWS_ENDPOINT_URL"] != "" {
		t.Fatal("compiled child identity/config isolation changed")
	}
	for _, host := range []string{"ec2", "ec2:443", "ec2.ca-central-1.amazonaws.com.evil", "kms.us-east-1.amazonaws.com", "ssm.ca-central-1.amazonaws.com:443"} {
		r := &http.Request{Host: host, Header: make(http.Header)}
		r.Header.Set("Authorization", "AWS4-HMAC-SHA256 Credential=synthetic-key/unit/ca-central-1/ec2/aws4_request")
		if compositionSignedRequest(r) {
			t.Fatal("test service allowlist accepted an unrelated host")
		}
	}
	r := &http.Request{Host: "ec2.ca-central-1.amazonaws.com", Header: make(http.Header)}
	r.Header.Set("Authorization", "AWS4-HMAC-SHA256 Credential=synthetic-key/unit/ca-central-1/ec2/aws4_request")
	if !compositionSignedRequest(r) {
		t.Fatal("selected signed test host rejected")
	}
}
