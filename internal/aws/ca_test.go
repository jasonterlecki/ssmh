package aws

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"ssmh/internal/config"
)

func syntheticCA(t *testing.T, serial int64) ([]byte, *x509.Certificate, tls.Certificate) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: "Synthetic test CA"}, DNSNames: []string{"ssm.ca-central-1.amazonaws.com"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), cert, tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

func caOptions(t *testing.T) config.Options {
	t.Helper()
	isolate(t)
	t.Setenv("AWS_CA_BUNDLE", "")
	t.Setenv("AWS_ACCESS_KEY_ID", "synthetic-key")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "synthetic-secret")
	t.Setenv("AWS_REGION", "ca-central-1")
	return config.Options{Instance: "web", Backend: "auto", Timeout: time.Second}
}

func TestCustomCASelectionAndPrecedence(t *testing.T) {
	o := caOptions(t)
	firstPEM, first, _ := syntheticCA(t, 1)
	secondPEM, second, _ := syntheticCA(t, 2)
	firstPath := filepath.Join(t.TempDir(), "first-ca.pem")
	secondPath := filepath.Join(t.TempDir(), "second-ca.pem")
	if os.WriteFile(firstPath, firstPEM, 0600) != nil || os.WriteFile(secondPath, secondPEM, 0600) != nil {
		t.Fatal("write public CA fixtures")
	}
	for _, tc := range []struct {
		env, profile, cli  string
		selected, rejected *x509.Certificate
	}{
		{firstPath, "", "", first, second}, {"", secondPath, "", second, first},
		{firstPath, secondPath, "", first, second}, {firstPath, "/missing-profile-ca", "", first, second},
		{firstPath, firstPath, secondPath, second, first},
		{"/missing-environment-ca", "/missing-profile-ca", secondPath, second, first},
	} {
		o.CACert = tc.cli
		t.Setenv("AWS_CA_BUNDLE", tc.env)
		content := "[default]\nregion = ca-central-1\n"
		if tc.profile != "" {
			content += "ca_bundle = " + tc.profile + "\n"
		}
		if os.WriteFile(os.Getenv("AWS_CONFIG_FILE"), []byte(content), 0600) != nil {
			t.Fatal("write synthetic profile")
		}
		cfg, err := Load(context.Background(), o, nil)
		if err != nil {
			t.Fatal(err)
		}
		client := cfg.HTTPClient.(*http.Client)
		tr := client.Transport.(signedTransport).base
		if tr.TLSClientConfig == nil || tr.TLSClientConfig.InsecureSkipVerify || tr.TLSClientConfig.RootCAs == nil || tr.TLSClientConfig.MinVersion < tls.VersionTLS12 || tr.DisableKeepAlives {
			t.Fatal("CA roots or owned-client security settings lost")
		}
		if _, err := tc.selected.Verify(x509.VerifyOptions{Roots: tr.TLSClientConfig.RootCAs, DNSName: "ssm.ca-central-1.amazonaws.com"}); err != nil {
			t.Fatal("selected CA missing")
		}
		if _, err := tc.rejected.Verify(x509.VerifyOptions{Roots: tr.TLSClientConfig.RootCAs}); err == nil {
			t.Fatal("lower-precedence CA unexpectedly trusted")
		}
		if err := client.CheckRedirect(&http.Request{}, nil); err == nil {
			t.Fatal("primary client allowed redirect")
		}
		unsafe, _ := http.NewRequest("GET", "https://attacker.invalid/", nil)
		unsafe.Header.Set("Authorization", "AWS4-HMAC-SHA256 synthetic")
		if _, err := tr.Proxy(unsafe); err == nil {
			t.Fatal("SDK CA resolver discarded captured transport guard")
		}
		Close(cfg)
	}
}

func TestCustomCAFailureIsClosedAndRedacted(t *testing.T) {
	o := caOptions(t)
	validPEM, _, _ := syntheticCA(t, 5)
	valid := filepath.Join(t.TempDir(), "valid-ca.pem")
	if os.WriteFile(valid, validPEM, 0600) != nil {
		t.Fatal("write public CA fixture")
	}
	invalid := filepath.Join(t.TempDir(), "synthetic-secret-invalid.pem")
	if os.WriteFile(invalid, []byte("synthetic-secret-content"), 0600) != nil {
		t.Fatal("write invalid public fixture")
	}
	for _, path := range []string{invalid, filepath.Join(t.TempDir(), "synthetic-secret-missing.pem")} {
		for _, selection := range []string{"profile", "environment", "cli"} {
			o.CACert = ""
			t.Setenv("AWS_CA_BUNDLE", "")
			profile := "[default]\n"
			if selection == "environment" {
				t.Setenv("AWS_CA_BUNDLE", path)
				profile += "ca_bundle = " + valid + "\n" // No fallback after explicit CA failure.
			} else if selection == "cli" {
				o.CACert = path
				t.Setenv("AWS_CA_BUNDLE", valid)
				profile += "ca_bundle = " + valid + "\n"
			} else {
				profile += "ca_bundle = " + path + "\n"
			}
			if os.WriteFile(os.Getenv("AWS_CONFIG_FILE"), []byte(profile), 0600) != nil {
				t.Fatal("write synthetic profile")
			}
			cfg, err := Load(context.Background(), o, nil)
			if err == nil || cfg.Credentials != nil || cfg.HTTPClient != nil || strings.Contains(err.Error(), "synthetic-secret") {
				t.Fatal("invalid CA silently ignored, leaked or returned usable credentials")
			}
		}
	}
}

func TestExplicitCAFileBoundsAndType(t *testing.T) {
	o := caOptions(t)
	large := filepath.Join(t.TempDir(), "synthetic-secret-large.pem")
	fifo := filepath.Join(t.TempDir(), "synthetic-secret-fifo.pem")
	if syscall.Mkfifo(fifo, 0600) != nil {
		t.Fatal("cannot prepare FIFO fixture")
	}
	if os.WriteFile(large, make([]byte, (4<<20)+1), 0600) != nil {
		t.Fatal("cannot prepare oversized fixture")
	}
	for _, path := range []string{large, fifo, t.TempDir(), "/dev/null"} {
		o.CACert = path
		cfg, err := Load(context.Background(), o, nil)
		if err == nil || cfg.Credentials != nil || strings.Contains(err.Error(), "synthetic-secret") {
			t.Fatal("unsafe CA file accepted or leaked")
		}
	}
}

func TestSDKBuilderCopiesRetainEndpointAndRedirectGuards(t *testing.T) {
	for _, endpoint := range []string{"http://sts.us-east-1.amazonaws.com/", "https://attacker.invalid/", "https://sts.us-east-1.amazonaws.com:444/"} {
		var dials atomic.Int32
		builder := guardedBuilder().WithTransportOptions(func(tr *http.Transport) {
			tr.DialContext = func(context.Context, string, string) (net.Conn, error) {
				dials.Add(1)
				return nil, errors.New("unexpected dial")
			}
		})
		request, _ := http.NewRequest("POST", endpoint, nil)
		request.Header.Set("Authorization", "AWS4-HMAC-SHA256 synthetic")
		if _, err := builder.Do(request); err == nil || dials.Load() != 0 {
			t.Fatal("builder copy transmitted signed request before guard")
		}
		tr := builder.GetTransport()
		if !tr.DisableKeepAlives || tr.ResponseHeaderTimeout != 15*time.Second || tr.Protocols.HTTP2() || !tr.Protocols.HTTP1() {
			t.Fatal("SDK-captured client resource bounds lost")
		}
	}
	proxyURL, _ := url.Parse("http://reviewed-proxy.invalid:8080")
	called := 0
	proxy := guardedProxy(func(*http.Request) (*url.URL, error) { called++; return proxyURL, nil })
	request, _ := http.NewRequest("GET", "https://sts.us-east-1.amazonaws.com/", nil)
	request.Header.Set("Authorization", "AWS4-HMAC-SHA256 synthetic")
	if got, err := proxy(request); err != nil || got != proxyURL || called != 1 {
		t.Fatal("guard bypassed configured proxy")
	}
	request.Response = &http.Response{StatusCode: 307}
	if _, err := proxy(request); err == nil || called != 1 {
		t.Fatal("redirect reached proxy selection")
	}
}

func TestSDKBuilderDoesNotFollowAnyRedirect(t *testing.T) {
	for _, status := range []int{301, 302, 303, 307, 308} {
		var dials atomic.Int32
		serverDone := make(chan struct{})
		builder := guardedBuilder().WithTransportOptions(func(tr *http.Transport) {
			tr.Proxy = guardedProxy(nil)
			tr.DialContext = func(context.Context, string, string) (net.Conn, error) {
				dials.Add(1)
				client, server := net.Pipe()
				go func() {
					defer close(serverDone)
					defer server.Close()
					_ = server.SetDeadline(time.Now().Add(time.Second))
					request, err := http.ReadRequest(bufio.NewReader(server))
					if err != nil {
						return
					}
					_ = request.Body.Close()
					_, _ = fmt.Fprintf(server, "HTTP/1.1 %d Redirect\r\nLocation: http://same-host.invalid/redirected\r\nConnection: close\r\nContent-Length: 0\r\n\r\n", status)
				}()
				return client, nil
			}
		})
		// Unsigned synthetic credential-provider HTTP traffic is SDK-managed.
		// This fixture carries no real authorization or secret material.
		request, _ := http.NewRequest("GET", "http://same-host.invalid/original", nil)
		response, err := builder.Do(request)
		if response != nil {
			_ = response.Body.Close()
		}
		if dials.Load() != 1 || (status == 307 || status == 308) && err == nil {
			t.Fatal("builder followed redirect")
		}
		select {
		case <-serverDone:
		case <-time.After(2 * time.Second):
			t.Fatal("synthetic HTTP server leaked")
		}
	}
}

func TestCustomCARealTLSVerification(t *testing.T) {
	o := caOptions(t)
	caPEM, _, cert := syntheticCA(t, 3)
	path := filepath.Join(t.TempDir(), "ca.pem")
	if os.WriteFile(path, caPEM, 0600) != nil {
		t.Fatal("write public CA")
	}
	t.Setenv("AWS_CA_BUNDLE", path)
	_, _, untrusted := syntheticCA(t, 4)
	for _, tc := range []struct {
		endpoint string
		cert     tls.Certificate
		success  bool
	}{
		{"https://ssm.ca-central-1.amazonaws.com/", cert, true},
		{"https://ssm.us-east-1.amazonaws.com/", cert, false},
		{"https://ssm.ca-central-1.amazonaws.com/", untrusted, false},
	} {
		cfg, err := Load(context.Background(), o, nil)
		if err != nil {
			t.Fatal(err)
		}
		tr := cfg.HTTPClient.(*http.Client).Transport.(signedTransport).base
		tr.Proxy = guardedProxy(nil)
		serverDone := make(chan struct{})
		var transmitted atomic.Bool
		tr.DialContext = func(context.Context, string, string) (net.Conn, error) {
			client, server := net.Pipe()
			go func() {
				defer close(serverDone)
				defer server.Close()
				_ = server.SetDeadline(time.Now().Add(time.Second))
				tlsServer := tls.Server(server, &tls.Config{Certificates: []tls.Certificate{tc.cert}, MinVersion: tls.VersionTLS12})
				if err := tlsServer.Handshake(); err != nil {
					return
				}
				buffer := make([]byte, 8192)
				if _, err := tlsServer.Read(buffer); err == nil {
					transmitted.Store(true)
					_, _ = fmt.Fprint(tlsServer, "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: 0\r\n\r\n")
				}
			}()
			return client, nil
		}
		request, _ := http.NewRequest("GET", tc.endpoint, nil)
		request.Header.Set("Authorization", "AWS4-HMAC-SHA256 synthetic")
		response, err := cfg.HTTPClient.Do(request)
		if (err == nil) != tc.success {
			t.Fatal("TLS verification accepted wrong host/root or rejected selected root")
		}
		if response != nil {
			if err := response.Body.Close(); err != nil {
				t.Fatal(err)
			}
		}
		select {
		case <-serverDone:
		case <-time.After(2 * time.Second):
			t.Fatal("synthetic TLS server leaked")
		}
		Close(cfg)
		if transmitted.Load() != tc.success {
			t.Fatal("HTTP authentication sent before certificate/hostname verification")
		}
	}
}
