package web

import (
	"bytes"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"github.com/velixio/idlogin/internal/config"
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

func TestCodeEmailCarriesTheBrandsLook(t *testing.T) {
	cfg := &config.Brand{Name: "Example", MailFrom: "Example <no-reply@example.com>", MailAccent: "#F47FA3", MailLogo: []byte("png"), MailLogoType: "image/png",
		MailFooter: "Example Ltd, 1 Road <Town>", MailLinks: []config.MailLink{{Label: "Privacy", URL: "https://example.com/privacy"}}}
	m := codeMessage(cfg, kindSignin, "a@example.com", "123456")
	for _, want := range []string{`cid:logo@idlogin`, "#F47FA3", "123456", `name="viewport"`, "Example Ltd, 1 Road &lt;Town&gt;", `href="https://example.com/privacy"`} {
		if !strings.Contains(m.HTML, want) {
			t.Fatalf("HTML lacks %q:\n%s", want, m.HTML)
		}
	}
	if strings.Contains(m.HTML, "ZgotmplZ") {
		t.Fatalf("a value was rejected by the template:\n%s", m.HTML)
	}
	if len(m.Inline) != 1 || m.Inline[0].ContentID != "logo@idlogin" || !strings.Contains(m.Text, "Example Ltd") {
		t.Fatalf("inline %+v, text %q", m.Inline, m.Text)
	}
	// With no email look configured it still works, and names no logo.
	plain := codeMessage(&config.Brand{Name: "Example", MailFrom: "Example <no-reply@example.com>"}, kindSignin, "a@example.com", "123456")
	if strings.Contains(plain.HTML, "cid:") || len(plain.Inline) != 0 || !strings.Contains(plain.HTML, "#ffffff") {
		t.Fatalf("plain brand: %d inline\n%s", len(plain.Inline), plain.HTML)
	}
}

func TestMailLogoFileReachesTheEmail(t *testing.T) {
	png := []byte("\x89PNG\r\n\x1a\nfake")
	e := newEnv(t, brandCfg{Registration: true, Extra: map[string]any{"mail_logo_file": "mail.png", "mail_accent": "#F47FA3"}, Files: map[string][]byte{"mail.png": png}})
	b := e.browser()
	p := b.start(e.z.newAuthRequest("web", nil, nil, ""))
	b.post(p, "/login/email", url.Values{"email": {"new@example.com"}})
	e.mail.mu.Lock()
	defer e.mail.mu.Unlock()
	if len(e.mail.msgs) != 1 || len(e.mail.msgs[0].Inline) != 1 || !bytes.Equal(e.mail.msgs[0].Inline[0].Data, png) || !strings.Contains(e.mail.msgs[0].HTML, "#F47FA3") {
		t.Fatalf("mail: %+v", e.mail.msgs)
	}
}
