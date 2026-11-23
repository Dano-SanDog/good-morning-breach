package alerting

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"html"
	"log/slog"
	"mime"
	"mime/multipart"
	"mime/quotedprintable"
	"net"
	"net/mail"
	"net/smtp"
	"net/textproto"
	"os"
	"strconv"
	"strings"
	"time"
)

type SMTPConfig struct {
	Host     string
	Port     int
	Username string
	Password string
	From     string
	// TLSMode is "starttls" or "implicit". Empty means implicit on port 465, otherwise starttls.
	TLSMode string
}

const (
	TLSModeSTARTTLS = "starttls"
	TLSModeImplicit = "implicit"
)

func (c SMTPConfig) implicitTLS() bool {
	switch c.TLSMode {
	case TLSModeImplicit:
		return true
	case TLSModeSTARTTLS:
		return false
	}
	return c.Port == 465
}

// LogValue keeps the password and username out of logs (SC-080).
func (c SMTPConfig) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("host", c.Host),
		slog.Int("port", c.Port),
		slog.Bool("implicit_tls", c.implicitTLS()),
		slog.String("password", "[redacted]"),
	)
}

func (c SMTPConfig) String() string {
	return fmt.Sprintf("SMTP %s:%d (implicit TLS: %t)", c.Host, c.Port, c.implicitTLS())
}

// GoString prevents %#v from printing the password.
func (c SMTPConfig) GoString() string { return c.String() }

// LoadSMTPConfig reads GB_SMTP_HOST, GB_SMTP_PORT (default 587), GB_SMTP_TLS
// (starttls or implicit; default implicit on 465, otherwise starttls), GB_SMTP_USERNAME,
// GB_SMTP_FROM, and GB_SMTP_PASSWORD_FILE (a 0600 file, per SC-071). It returns
// false when GB_SMTP_HOST is unset.
func LoadSMTPConfig() (SMTPConfig, bool, error) {
	host := os.Getenv("GB_SMTP_HOST")
	if host == "" {
		return SMTPConfig{}, false, nil
	}
	config := SMTPConfig{
		Host:     host,
		Port:     587,
		Username: os.Getenv("GB_SMTP_USERNAME"),
		From:     os.Getenv("GB_SMTP_FROM"),
	}
	if raw := os.Getenv("GB_SMTP_PORT"); raw != "" {
		port, err := strconv.Atoi(raw)
		if err != nil || port < 1 || port > 65535 {
			return SMTPConfig{}, false, errors.New("GB_SMTP_PORT is invalid")
		}
		config.Port = port
	}
	switch mode := strings.ToLower(os.Getenv("GB_SMTP_TLS")); mode {
	case "":
		config.TLSMode = TLSModeSTARTTLS
		if config.Port == 465 {
			config.TLSMode = TLSModeImplicit
		}
	case TLSModeSTARTTLS, TLSModeImplicit:
		config.TLSMode = mode
	default:
		return SMTPConfig{}, false, errors.New("GB_SMTP_TLS must be starttls or implicit")
	}
	if config.From == "" {
		config.From = config.Username
	}
	if path := os.Getenv("GB_SMTP_PASSWORD_FILE"); path != "" {
		info, err := os.Lstat(path)
		if err != nil {
			return SMTPConfig{}, false, fmt.Errorf("inspect SMTP password file: %w", err)
		}
		if !info.Mode().IsRegular() || info.Mode().Perm() != 0600 {
			return SMTPConfig{}, false, errors.New("SMTP password file must be a regular 0600 file")
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return SMTPConfig{}, false, fmt.Errorf("read SMTP password file: %w", err)
		}
		config.Password = strings.TrimRight(string(data), "\r\n")
		if config.Password == "" {
			return SMTPConfig{}, false, errors.New("SMTP password file is empty")
		}
	}
	if err := config.validate(); err != nil {
		return SMTPConfig{}, false, err
	}
	return config, true, nil
}

func (c SMTPConfig) validate() error {
	if c.Host == "" || strings.ContainsAny(c.Host, "\r\n \t:/@") {
		return errors.New("GB_SMTP_HOST must be a bare host name (no scheme, port, or path)")
	}
	if c.Port < 1 || c.Port > 65535 {
		return errors.New("GB_SMTP_PORT is invalid")
	}
	if c.TLSMode != "" && c.TLSMode != TLSModeSTARTTLS && c.TLSMode != TLSModeImplicit {
		return errors.New("GB_SMTP_TLS must be starttls or implicit")
	}
	if _, err := parseAddress(c.From); err != nil {
		return errors.New("GB_SMTP_FROM must be a valid email address (required when GB_SMTP_USERNAME is not an email address)")
	}
	if c.Username != "" && c.Password == "" {
		return errors.New("GB_SMTP_PASSWORD_FILE is required with GB_SMTP_USERNAME")
	}
	if strings.ContainsAny(c.Username, "\r\n\x00") || strings.ContainsAny(c.Password, "\r\n\x00") {
		return errors.New("SMTP credentials contain invalid characters")
	}
	return nil
}

// SMTPSender sends over implicit TLS (port 465) or mandatory STARTTLS, never plaintext (SC-033).
type SMTPSender struct {
	config SMTPConfig
	roots  *x509.CertPool // nil uses the system roots; set only by tests
}

func NewSMTPSender(config SMTPConfig) (*SMTPSender, error) {
	if err := config.validate(); err != nil {
		return nil, err
	}
	return &SMTPSender{config: config}, nil
}

// SendText sends a plain message with an escaped HTML copy (password reset).
func (s *SMTPSender) SendText(ctx context.Context, to, subject, text string) error {
	escaped := strings.ReplaceAll(html.EscapeString(text), "\n", "<br>\n")
	return s.Send(ctx, to, Message{Subject: subject, Text: text, HTML: "<p>" + escaped + "</p>"})
}

func parseAddress(value string) (string, error) {
	if value == "" || strings.ContainsAny(value, "\r\n") {
		return "", errors.New("invalid address")
	}
	address, err := mail.ParseAddress(value)
	if err != nil {
		return "", err
	}
	return address.Address, nil
}

// connect opens a TLS-protected, authenticated SMTP session. It never sends mail.
func (s *SMTPSender) connect(ctx context.Context) (*smtp.Client, error) {
	address := net.JoinHostPort(s.config.Host, strconv.Itoa(s.config.Port))
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12, ServerName: s.config.Host, RootCAs: s.roots}
	dialer := &net.Dialer{Timeout: 15 * time.Second}
	implicit := s.config.implicitTLS()
	var conn net.Conn
	var err error
	if implicit {
		conn, err = (&tls.Dialer{NetDialer: dialer, Config: tlsConfig}).DialContext(ctx, "tcp", address)
	} else {
		conn, err = dialer.DialContext(ctx, "tcp", address)
	}
	if err != nil {
		hint := ""
		if implicit {
			hint = " (implicit TLS is selected; if this port expects STARTTLS, set GB_SMTP_TLS=starttls)"
		}
		return nil, fmt.Errorf("connect to SMTP server: %w%s", err, hint)
	}
	deadline := time.Now().Add(60 * time.Second)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	_ = conn.SetDeadline(deadline)
	client, err := smtp.NewClient(conn, s.config.Host)
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("start SMTP session (if this port uses STARTTLS, set GB_SMTP_TLS=starttls): %w", err)
	}
	if !implicit {
		if ok, _ := client.Extension("STARTTLS"); !ok {
			_ = client.Close()
			return nil, errors.New("SMTP server does not offer STARTTLS")
		}
		if err := client.StartTLS(tlsConfig); err != nil {
			_ = client.Close()
			return nil, fmt.Errorf("start SMTP TLS: %w", err)
		}
	}
	if s.config.Username != "" {
		auth := smtp.PlainAuth("", s.config.Username, s.config.Password, s.config.Host)
		if err := client.Auth(auth); err != nil {
			_ = client.Close()
			return nil, fmt.Errorf("authenticate to SMTP server: %w", err)
		}
	}
	return client, nil
}

// Verify connects, negotiates TLS, and authenticates, then quits without sending mail.
func (s *SMTPSender) Verify(ctx context.Context) error {
	client, err := s.connect(ctx)
	if err != nil {
		return err
	}
	defer client.Close()
	return client.Quit()
}

func (s *SMTPSender) Send(ctx context.Context, to string, message Message) error {
	from, err := parseAddress(s.config.From)
	if err != nil {
		return errors.New("invalid sender address")
	}
	recipient, err := parseAddress(to)
	if err != nil {
		return errors.New("invalid recipient address")
	}
	if strings.ContainsAny(message.Subject, "\r\n") {
		return errors.New("invalid subject")
	}
	body, err := buildMessage(from, recipient, message, time.Now())
	if err != nil {
		return err
	}

	client, err := s.connect(ctx)
	if err != nil {
		return err
	}
	defer client.Close()
	if err := client.Mail(from); err != nil {
		return fmt.Errorf("SMTP sender rejected: %w", err)
	}
	if err := client.Rcpt(recipient); err != nil {
		return fmt.Errorf("SMTP recipient rejected: %w", err)
	}
	writer, err := client.Data()
	if err != nil {
		return fmt.Errorf("start SMTP data: %w", err)
	}
	if _, err := writer.Write(body); err != nil {
		_ = writer.Close()
		return fmt.Errorf("write SMTP data: %w", err)
	}
	if err := writer.Close(); err != nil {
		return fmt.Errorf("finish SMTP data: %w", err)
	}
	return client.Quit()
}

func buildMessage(from, to string, message Message, now time.Time) ([]byte, error) {
	random := make([]byte, 12)
	if _, err := rand.Read(random); err != nil {
		return nil, errors.New("generate message ID")
	}
	domain := "localhost"
	if at := strings.LastIndex(from, "@"); at >= 0 {
		domain = from[at+1:]
	}
	var buffer bytes.Buffer
	writer := multipart.NewWriter(&buffer)
	headers := []string{
		"From: " + (&mail.Address{Address: from}).String(),
		"To: " + (&mail.Address{Address: to}).String(),
		"Subject: " + mime.QEncoding.Encode("utf-8", message.Subject),
		"Date: " + now.Format(time.RFC1123Z),
		"Message-ID: <" + hex.EncodeToString(random) + "@" + domain + ">",
		"MIME-Version: 1.0",
		"Content-Type: multipart/alternative; boundary=" + writer.Boundary(),
	}
	for _, header := range headers {
		if strings.ContainsAny(header, "\r\n") {
			return nil, errors.New("invalid message header")
		}
	}
	var out bytes.Buffer
	out.WriteString(strings.Join(headers, "\r\n") + "\r\n\r\n")
	if err := writeQuotedPart(writer, "text/plain; charset=utf-8", message.Text); err != nil {
		return nil, err
	}
	if len(message.LogoPNG) == 0 {
		if err := writeQuotedPart(writer, "text/html; charset=utf-8", message.HTML); err != nil {
			return nil, err
		}
	} else if err := writeRelatedHTML(writer, message); err != nil {
		return nil, err
	}
	if err := writer.Close(); err != nil {
		return nil, err
	}
	out.Write(buffer.Bytes())
	return out.Bytes(), nil
}

func writeQuotedPart(writer *multipart.Writer, contentType, content string) error {
	partWriter, err := writer.CreatePart(textproto.MIMEHeader{
		"Content-Type":              {contentType},
		"Content-Transfer-Encoding": {"quoted-printable"},
	})
	if err != nil {
		return err
	}
	encoder := quotedprintable.NewWriter(partWriter)
	if _, err := encoder.Write([]byte(content)); err != nil {
		return err
	}
	return encoder.Close()
}

// writeRelatedHTML writes the HTML part together with its inline logo as
// multipart/related, referenced from the HTML by cid.
func writeRelatedHTML(outer *multipart.Writer, message Message) error {
	var inner bytes.Buffer
	related := multipart.NewWriter(&inner)
	if err := writeQuotedPart(related, "text/html; charset=utf-8", message.HTML); err != nil {
		return err
	}
	imagePart, err := related.CreatePart(textproto.MIMEHeader{
		"Content-Type":              {"image/png; name=\"logo.png\""},
		"Content-Transfer-Encoding": {"base64"},
		"Content-ID":                {"<" + logoCID + ">"},
		"Content-Disposition":       {"inline; filename=\"logo.png\""},
	})
	if err != nil {
		return err
	}
	encoded := base64.StdEncoding.EncodeToString(message.LogoPNG)
	for len(encoded) > 76 {
		if _, err := imagePart.Write([]byte(encoded[:76] + "\r\n")); err != nil {
			return err
		}
		encoded = encoded[76:]
	}
	if _, err := imagePart.Write([]byte(encoded + "\r\n")); err != nil {
		return err
	}
	if err := related.Close(); err != nil {
		return err
	}
	part, err := outer.CreatePart(textproto.MIMEHeader{
		"Content-Type": {"multipart/related; type=\"text/html\"; boundary=" + related.Boundary()},
	})
	if err != nil {
		return err
	}
	_, err = part.Write(inner.Bytes())
	return err
}
