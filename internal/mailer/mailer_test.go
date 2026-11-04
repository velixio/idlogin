package mailer

import (
	"bytes"
	"context"
	"encoding/base64"
	"io"
	"mime"
	"mime/multipart"
	"net/mail"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestLogMailer(t *testing.T) {
	dir := t.TempDir()
	l := &Log{Dir: dir}
	err := l.Send(context.Background(), Message{From: "Example <no-reply@example.com>", To: "A@B.test",
		Subject: "Your Example sign-in code", Text: "Your code is 123456.", HTML: "<p>Your code is <b>123456</b>.</p>", Kind: "code"})
	if err != nil {
		t.Fatal(err)
	}
	txt, _ := filepath.Glob(filepath.Join(dir, "*-code-a@b.test.txt"))
	eml, _ := filepath.Glob(filepath.Join(dir, "*-code-a@b.test.eml"))
	if len(txt) != 1 || len(eml) != 1 {
		t.Fatalf("files: %v %v", txt, eml)
	}
	b, _ := os.ReadFile(txt[0])
	if !strings.Contains(string(b), "123456") {
		t.Fatal("code missing from .txt")
	}
	raw, _ := os.ReadFile(eml[0])
	for _, want := range []string{"multipart/alternative", "Subject: Your Example sign-in code", "text/html"} {
		if !strings.Contains(string(raw), want) {
			t.Errorf("eml lacks %q", want)
		}
	}
}

func TestBuildRejectsBadAddress(t *testing.T) {
	if _, err := Build(Message{From: "x", To: "y@z"}, testNow); err == nil {
		t.Fatal("bad from accepted")
	}
}

var testNow = time.Unix(1_700_000_000, 0)

func TestBuildCarriesInlineImagesInsideRelated(t *testing.T) {
	raw, err := Build(Message{From: "Example <no-reply@example.com>", To: "a@b.test", Subject: "Code", Text: "text", HTML: `<img src="cid:logo@x">`,
		Inline: []Inline{{ContentID: "logo@x", ContentType: "image/png", Data: []byte("png-bytes")}}}, time.Unix(0, 0))
	if err != nil {
		t.Fatal(err)
	}
	msg, err := mail.ReadMessage(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	mediaType, params, err := mime.ParseMediaType(msg.Header.Get("Content-Type"))
	if err != nil || mediaType != "multipart/related" {
		t.Fatalf("content type %q, %v", mediaType, err)
	}
	reader := multipart.NewReader(msg.Body, params["boundary"])
	first, err := reader.NextPart()
	if err != nil || !strings.HasPrefix(first.Header.Get("Content-Type"), "multipart/alternative") {
		t.Fatalf("first part %v, %v", first, err)
	}
	second, err := reader.NextRawPart()
	if err != nil || second.Header.Get("Content-ID") != "<logo@x>" || second.Header.Get("Content-Type") != "image/png" {
		t.Fatalf("second part %v, %v", second, err)
	}
	body, _ := io.ReadAll(base64.NewDecoder(base64.StdEncoding, second))
	if string(body) != "png-bytes" {
		t.Fatalf("image = %q", body)
	}
	if _, err := reader.NextRawPart(); err != io.EOF {
		t.Fatalf("after the image: %v", err)
	}
}
