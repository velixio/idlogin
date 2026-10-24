package web

import (
	"bytes"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"testing"
)

var logoHref = regexp.MustCompile(`<img src="(/login/brand/logo\?v=[0-9a-f]{12})"`)

func fetch(t *testing.T, e *env, path string) (*http.Response, []byte) {
	t.Helper()
	resp, err := http.Get(e.srv.URL + path)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return resp, body
}

func TestDefaultLogo(t *testing.T) {
	e := newEnv(t, brandCfg{Registration: true})
	p := e.browser().start(e.z.newAuthRequest("web", nil, nil, ""))
	m := logoHref.FindStringSubmatch(p.body)
	if m == nil {
		t.Fatalf("no logo in page: %.400s", p.body)
	}
	mustContain(t, p, "Example tagline.", "· Example</title>")
	resp, body := fetch(t, e, m[1])
	if resp.StatusCode != 200 || resp.Header.Get("Content-Type") != "image/svg+xml" || !bytes.Equal(body, defaultLogo) {
		t.Fatalf("default logo: %d %s", resp.StatusCode, resp.Header.Get("Content-Type"))
	}
	if resp.Header.Get("Cache-Control") == "no-store" {
		t.Fatal("logo not cacheable")
	}
}

func TestLogoFile(t *testing.T) {
	png := []byte("\x89PNG\r\n\x1a\nfake")
	e := newEnv(t, brandCfg{Registration: true, Extra: map[string]any{"logo_file": "mark.png"}, Files: map[string][]byte{"mark.png": png}})
	p := e.browser().start(e.z.newAuthRequest("web", nil, nil, ""))
	m := logoHref.FindStringSubmatch(p.body)
	if m == nil || m[1] == "/login/brand/logo?v="+defaultLogoVersion {
		t.Fatalf("logo URL: %v", m)
	}
	resp, body := fetch(t, e, m[1])
	if resp.StatusCode != 200 || resp.Header.Get("Content-Type") != "image/png" || !bytes.Equal(body, png) {
		t.Fatalf("logo: %d %s %q", resp.StatusCode, resp.Header.Get("Content-Type"), body)
	}
}

func TestMailSubjects(t *testing.T) {
	e := newEnv(t, brandCfg{Registration: true, Extra: map[string]any{
		"mail_subjects": map[string]string{"signup": "Welcome to {name}: your code"}}})
	b := e.browser()
	p := b.start(e.z.newAuthRequest("web", nil, nil, ""))
	b.post(p, "/login/email", url.Values{"email": {"new@example.com"}})
	e.mail.mu.Lock()
	defer e.mail.mu.Unlock()
	if len(e.mail.msgs) != 1 || e.mail.msgs[0].Subject != "Welcome to Example: your code" || e.mail.msgs[0].From != "Example <no-reply@example.test>" {
		t.Fatalf("mail: %+v", e.mail.msgs)
	}
}
