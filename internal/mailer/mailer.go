// Package mailer sends the login's own email (codes, password reset): over
// SMTP in production, or as files in a directory in development ("log"
// mailer), where tests and people read the codes.
package mailer

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"mime"
	"mime/quotedprintable"
	"net"
	"net/mail"
	"net/smtp"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
)

// Message is one email.
type Message struct {
	From    string // "Name <addr>"
	To      string
	Subject string
	Text    string
	HTML    string
	Kind    string // code, reset... (used in log file names)
}

// Mailer sends messages.
type Mailer interface {
	Send(ctx context.Context, m Message) error
}

// Build renders a multipart/alternative MIME message.
func Build(m Message, now time.Time) ([]byte, error) {
	from, err := mail.ParseAddress(m.From)
	if err != nil {
		return nil, fmt.Errorf("mailer: from: %w", err)
	}
	to, err := mail.ParseAddress(m.To)
	if err != nil {
		return nil, fmt.Errorf("mailer: to: %w", err)
	}
	var id [12]byte
	_, _ = rand.Read(id[:])
	boundary := "b-" + hex.EncodeToString(id[:])
	domain := from.Address[strings.LastIndex(from.Address, "@")+1:]
	var b bytes.Buffer
	h := func(k, v string) { fmt.Fprintf(&b, "%s: %s\r\n", k, v) }
	h("From", from.String())
	h("To", to.String())
	h("Subject", mime.QEncoding.Encode("utf-8", m.Subject))
	h("Date", now.UTC().Format(time.RFC1123Z))
	h("Message-ID", "<"+hex.EncodeToString(id[:])+"@"+domain+">")
	h("MIME-Version", "1.0")
	h("Auto-Submitted", "auto-generated")
	h("Content-Type", `multipart/alternative; boundary="`+boundary+`"`)
	b.WriteString("\r\n")
	part := func(ctype, body string) {
		fmt.Fprintf(&b, "--%s\r\nContent-Type: %s; charset=utf-8\r\nContent-Transfer-Encoding: quoted-printable\r\n\r\n", boundary, ctype)
		w := quotedprintable.NewWriter(&b)
		_, _ = w.Write([]byte(strings.ReplaceAll(body, "\n", "\r\n")))
		_ = w.Close()
		b.WriteString("\r\n")
	}
	part("text/plain", m.Text)
	if m.HTML != "" {
		part("text/html", m.HTML)
	}
	fmt.Fprintf(&b, "--%s--\r\n", boundary)
	return b.Bytes(), nil
}

// Log writes each message to Dir as <time>-<kind>-<to>.eml plus a .txt with
// the headers and plain-text body, for development and tests.
type Log struct {
	Dir string
	mu  sync.Mutex
}

var unsafeChars = regexp.MustCompile(`[^A-Za-z0-9@._+-]`)

// Send implements Mailer.
func (l *Log) Send(_ context.Context, m Message) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if err := os.MkdirAll(l.Dir, 0o700); err != nil {
		return err
	}
	now := time.Now()
	raw, err := Build(m, now)
	if err != nil {
		return err
	}
	base := filepath.Join(l.Dir, fmt.Sprintf("%s-%s-%s",
		now.UTC().Format("20060102T150405.000000000Z"), unsafeChars.ReplaceAllString(m.Kind, "_"),
		unsafeChars.ReplaceAllString(strings.ToLower(m.To), "_")))
	txt := fmt.Sprintf("From: %s\nTo: %s\nSubject: %s\n\n%s\n", m.From, m.To, m.Subject, m.Text)
	if err := os.WriteFile(base+".eml", raw, 0o600); err != nil {
		return err
	}
	return os.WriteFile(base+".txt", []byte(txt), 0o600)
}

// SMTP sends through an SMTP server.
type SMTP struct {
	Host     string
	Port     string
	User     string
	Password string
	// TLS is "starttls" (default, required), "tls" (implicit, port 465) or
	// "none" (only for a local relay).
	TLS string
}

// Send implements Mailer.
func (s *SMTP) Send(ctx context.Context, m Message) error {
	raw, err := Build(m, time.Now())
	if err != nil {
		return err
	}
	from, _ := mail.ParseAddress(m.From)
	to, _ := mail.ParseAddress(m.To)
	addr := net.JoinHostPort(s.Host, s.Port)
	d := net.Dialer{Timeout: 15 * time.Second}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	var conn net.Conn
	tlsConfig := &tls.Config{ServerName: s.Host, MinVersion: tls.VersionTLS12}
	if s.TLS == "tls" {
		conn, err = (&tls.Dialer{NetDialer: &d, Config: tlsConfig}).DialContext(ctx, "tcp", addr)
	} else {
		conn, err = d.DialContext(ctx, "tcp", addr)
	}
	if err != nil {
		return err
	}
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}
	c, err := smtp.NewClient(conn, s.Host)
	if err != nil {
		conn.Close()
		return err
	}
	defer c.Close()
	if s.TLS == "" || s.TLS == "starttls" {
		if ok, _ := c.Extension("STARTTLS"); !ok {
			return errors.New("mailer: server does not offer STARTTLS")
		}
		if err := c.StartTLS(tlsConfig); err != nil {
			return err
		}
	}
	if s.User != "" {
		if err := c.Auth(smtp.PlainAuth("", s.User, s.Password, s.Host)); err != nil {
			return err
		}
	}
	if err := c.Mail(from.Address); err != nil {
		return err
	}
	if err := c.Rcpt(to.Address); err != nil {
		return err
	}
	w, err := c.Data()
	if err != nil {
		return err
	}
	if _, err := w.Write(raw); err != nil {
		return err
	}
	if err := w.Close(); err != nil {
		return err
	}
	return c.Quit()
}
