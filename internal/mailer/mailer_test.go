package mailer

import (
	"context"
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
