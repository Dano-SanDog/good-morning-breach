package alerting

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

type fakeSMTP struct {
	port     int
	roots    *x509.CertPool
	mu       sync.Mutex
	data     string
	sessions int
	authSeen string
}

func (f *fakeSMTP) received() (string, string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.data, f.authSeen
}

// startFakeSMTP runs a loopback-only SMTP server with a self-signed certificate.
func startFakeSMTP(t *testing.T, implicit bool, password string) *fakeSMTP {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "127.0.0.1"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
	leaf, _ := x509.ParseCertificate(der)
	pool := x509.NewCertPool()
	pool.AddCert(leaf)
	tlsConfig := &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })
	f := &fakeSMTP{port: listener.Addr().(*net.TCPAddr).Port, roots: pool}
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go f.serve(conn, tlsConfig, implicit, password)
		}
	}()
	return f
}

func (f *fakeSMTP) serve(conn net.Conn, tlsConfig *tls.Config, implicit bool, password string) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	secure := implicit
	if implicit {
		conn = tls.Server(conn, tlsConfig)
	}
	f.mu.Lock()
	f.sessions++
	f.mu.Unlock()
	reader := bufio.NewReader(conn)
	reply := func(s string) { conn.Write([]byte(s + "\r\n")) }
	reply("220 fake ESMTP")
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return
		}
		line = strings.TrimRight(line, "\r\n")
		upper := strings.ToUpper(line)
		switch {
		case strings.HasPrefix(upper, "EHLO"):
			if secure {
				conn.Write([]byte("250-fake\r\n250 AUTH PLAIN\r\n"))
			} else {
				conn.Write([]byte("250-fake\r\n250 STARTTLS\r\n"))
			}
		case upper == "STARTTLS":
			reply("220 go ahead")
			conn = tls.Server(conn, tlsConfig)
			reader = bufio.NewReader(conn)
			secure = true
		case strings.HasPrefix(upper, "AUTH PLAIN"):
			raw, _ := base64.StdEncoding.DecodeString(strings.TrimSpace(line[len("AUTH PLAIN"):]))
			f.mu.Lock()
			f.authSeen = string(raw)
			f.mu.Unlock()
			if strings.Split(string(raw), "\x00")[2] == password {
				reply("235 ok")
			} else {
				reply("535 bad credentials")
			}
		case strings.HasPrefix(upper, "MAIL"), strings.HasPrefix(upper, "RCPT"):
			reply("250 ok")
		case upper == "DATA":
			reply("354 go")
			var body strings.Builder
			for {
				l, err := reader.ReadString('\n')
				if err != nil || l == ".\r\n" {
					break
				}
				body.WriteString(l)
			}
			f.mu.Lock()
			f.data = body.String()
			f.mu.Unlock()
			reply("250 queued")
		case upper == "QUIT":
			reply("221 bye")
			return
		default:
			reply("250 ok")
		}
	}
}

func newTestSender(t *testing.T, f *fakeSMTP, mode, password string) *SMTPSender {
	t.Helper()
	sender, err := NewSMTPSender(SMTPConfig{Host: "127.0.0.1", Port: f.port, TLSMode: mode, Username: "user", Password: password, From: "from@example.org"})
	if err != nil {
		t.Fatal(err)
	}
	sender.roots = f.roots
	return sender
}

func TestSMTPSendOverSTARTTLSAndImplicitTLS(t *testing.T) {
	for _, tc := range []struct {
		mode     string
		implicit bool
	}{{TLSModeSTARTTLS, false}, {TLSModeImplicit, true}} {
		f := startFakeSMTP(t, tc.implicit, "s3cret-pass")
		sender := newTestSender(t, f, tc.mode, "s3cret-pass")
		if err := sender.SendText(context.Background(), "to@example.org", "Subject", "hello body"); err != nil {
			t.Fatalf("%s: %v", tc.mode, err)
		}
		data, _ := f.received()
		if !strings.Contains(data, "To: <to@example.org>") || !strings.Contains(data, "hello body") {
			t.Fatalf("%s: message not delivered: %q", tc.mode, data)
		}
	}
}

func TestSMTPVerifyDoesNotSend(t *testing.T) {
	f := startFakeSMTP(t, false, "s3cret-pass")
	if err := newTestSender(t, f, TLSModeSTARTTLS, "s3cret-pass").Verify(context.Background()); err != nil {
		t.Fatal(err)
	}
	if data, auth := f.received(); data != "" || auth == "" {
		t.Fatalf("data %q auth %q", data, auth)
	}
}

func TestSMTPBadPasswordDoesNotLeak(t *testing.T) {
	f := startFakeSMTP(t, false, "right-password")
	err := newTestSender(t, f, TLSModeSTARTTLS, "wrong-password").Verify(context.Background())
	if err == nil || !strings.Contains(err.Error(), "authenticate") {
		t.Fatalf("err = %v", err)
	}
	if strings.Contains(err.Error(), "wrong-password") {
		t.Fatal("password present in error")
	}
}

func TestSMTPUntrustedCertificateRefused(t *testing.T) {
	f := startFakeSMTP(t, false, "p")
	sender := newTestSender(t, f, TLSModeSTARTTLS, "p")
	sender.roots = nil
	if err := sender.Verify(context.Background()); err == nil {
		t.Fatal("self-signed certificate accepted")
	}
}

func TestSMTPWrongModeHint(t *testing.T) {
	f := startFakeSMTP(t, false, "p")
	sender := newTestSender(t, f, TLSModeImplicit, "p")
	err := sender.Verify(context.Background())
	if err == nil || !strings.Contains(err.Error(), "GB_SMTP_TLS=starttls") {
		t.Fatalf("err = %v", err)
	}
}

func writeSecret(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "smtp-password")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoadSMTPConfig(t *testing.T) {
	secret := writeSecret(t, "pw\n")
	base := map[string]string{"GB_SMTP_HOST": "smtp.example.org", "GB_SMTP_USERNAME": "me@example.org", "GB_SMTP_PASSWORD_FILE": secret}
	cases := []struct {
		name    string
		env     map[string]string
		wantErr string
		check   func(SMTPConfig) bool
	}{
		{"defaults", nil, "", func(c SMTPConfig) bool {
			return c.Port == 587 && c.TLSMode == TLSModeSTARTTLS && c.From == "me@example.org" && c.Password == "pw"
		}},
		{"465 implies implicit", map[string]string{"GB_SMTP_PORT": "465"}, "", func(c SMTPConfig) bool { return c.TLSMode == TLSModeImplicit }},
		{"explicit mode", map[string]string{"GB_SMTP_PORT": "2525", "GB_SMTP_TLS": "IMPLICIT"}, "", func(c SMTPConfig) bool { return c.TLSMode == TLSModeImplicit }},
		{"bad mode", map[string]string{"GB_SMTP_TLS": "none"}, "GB_SMTP_TLS", nil},
		{"host with port", map[string]string{"GB_SMTP_HOST": "smtp.example.org:587"}, "GB_SMTP_HOST", nil},
		{"host with scheme", map[string]string{"GB_SMTP_HOST": "https://smtp.example.org"}, "GB_SMTP_HOST", nil},
		{"bad port", map[string]string{"GB_SMTP_PORT": "99999"}, "GB_SMTP_PORT", nil},
		{"bad from", map[string]string{"GB_SMTP_USERNAME": "plainuser", "GB_SMTP_FROM": ""}, "GB_SMTP_FROM", nil},
		{"empty password file", map[string]string{"GB_SMTP_PASSWORD_FILE": writeSecret(t, "\n")}, "empty", nil},
		{"username without password", map[string]string{"GB_SMTP_PASSWORD_FILE": ""}, "GB_SMTP_PASSWORD_FILE", nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			for _, k := range []string{"GB_SMTP_HOST", "GB_SMTP_PORT", "GB_SMTP_TLS", "GB_SMTP_USERNAME", "GB_SMTP_FROM", "GB_SMTP_PASSWORD_FILE"} {
				t.Setenv(k, "")
			}
			for k, v := range base {
				t.Setenv(k, v)
			}
			for k, v := range tc.env {
				t.Setenv(k, v)
			}
			config, ok, err := LoadSMTPConfig()
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("err = %v", err)
				}
				if strings.Contains(err.Error(), "pw") && tc.name != "empty password file" {
					t.Fatalf("error mentions secret: %v", err)
				}
				return
			}
			if err != nil || !ok || !tc.check(config) {
				t.Fatalf("config %v ok %v err %v", config, ok, err)
			}
		})
	}
}

func TestLoadSMTPConfigRejectsLoosePasswordFile(t *testing.T) {
	path := writeSecret(t, "pw")
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GB_SMTP_HOST", "smtp.example.org")
	t.Setenv("GB_SMTP_PASSWORD_FILE", path)
	t.Setenv("GB_SMTP_FROM", "me@example.org")
	if _, _, err := LoadSMTPConfig(); err == nil {
		t.Fatal("0644 password file accepted")
	}
}

func TestSMTPConfigRedactsPassword(t *testing.T) {
	config := SMTPConfig{Host: "h", Port: 587, Username: "u", Password: "hunter2-secret"}
	for _, out := range []string{config.String(), config.GoString(), config.LogValue().String()} {
		if strings.Contains(out, "hunter2-secret") {
			t.Fatalf("password in %q", out)
		}
	}
}
