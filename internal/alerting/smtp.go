package alerting

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
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
}

// LoadSMTPConfig reads GB_SMTP_HOST, GB_SMTP_PORT (default 587), GB_SMTP_USERNAME,
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
	}
	if err := config.validate(); err != nil {
		return SMTPConfig{}, false, err
	}
	return config, true, nil
}

func (c SMTPConfig) validate() error {
	if c.Host == "" || strings.ContainsAny(c.Host, "\r\n ") {
		return errors.New("SMTP host is invalid")
	}
	if _, err := parseAddress(c.From); err != nil {
		return errors.New("GB_SMTP_FROM must be a valid email address")
	}
	if c.Username != "" && c.Password == "" {
		return errors.New("GB_SMTP_PASSWORD_FILE is required with GB_SMTP_USERNAME")
	}
	if strings.ContainsAny(c.Username, "\r\n") {
		return errors.New("SMTP username is invalid")
	}
	return nil
}

// SMTPSender sends over implicit TLS (port 465) or mandatory STARTTLS, never plaintext (SC-033).
type SMTPSender struct {
	config SMTPConfig
}

func NewSMTPSender(config SMTPConfig) (*SMTPSender, error) {
	if err := config.validate(); err != nil {
		return nil, err
	}
	return &SMTPSender{config: config}, nil
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

	address := net.JoinHostPort(s.config.Host, strconv.Itoa(s.config.Port))
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12, ServerName: s.config.Host}
	dialer := &net.Dialer{Timeout: 15 * time.Second}
	var conn net.Conn
	if s.config.Port == 465 {
		conn, err = (&tls.Dialer{NetDialer: dialer, Config: tlsConfig}).DialContext(ctx, "tcp", address)
	} else {
		conn, err = dialer.DialContext(ctx, "tcp", address)
	}
	if err != nil {
		return fmt.Errorf("connect to SMTP server: %w", err)
	}
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}
	client, err := smtp.NewClient(conn, s.config.Host)
	if err != nil {
		_ = conn.Close()
		return fmt.Errorf("start SMTP session: %w", err)
	}
	defer client.Close()

	if s.config.Port != 465 {
		if ok, _ := client.Extension("STARTTLS"); !ok {
			return errors.New("SMTP server does not offer STARTTLS")
		}
		if err := client.StartTLS(tlsConfig); err != nil {
			return fmt.Errorf("start SMTP TLS: %w", err)
		}
	}
	if s.config.Username != "" {
		auth := smtp.PlainAuth("", s.config.Username, s.config.Password, s.config.Host)
		if err := client.Auth(auth); err != nil {
			return fmt.Errorf("authenticate to SMTP server: %w", err)
		}
	}
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
	for _, part := range []struct{ contentType, content string }{
		{"text/plain; charset=utf-8", message.Text},
		{"text/html; charset=utf-8", message.HTML},
	} {
		partWriter, err := writer.CreatePart(textproto.MIMEHeader{
			"Content-Type":              {part.contentType},
			"Content-Transfer-Encoding": {"quoted-printable"},
		})
		if err != nil {
			return nil, err
		}
		encoder := quotedprintable.NewWriter(partWriter)
		if _, err := encoder.Write([]byte(part.content)); err != nil {
			return nil, err
		}
		if err := encoder.Close(); err != nil {
			return nil, err
		}
	}
	if err := writer.Close(); err != nil {
		return nil, err
	}
	out.Write(buffer.Bytes())
	return out.Bytes(), nil
}
