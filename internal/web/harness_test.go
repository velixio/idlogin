package web

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/velixio/idlogin/internal/config"
	"github.com/velixio/idlogin/internal/mailer"
	"github.com/velixio/idlogin/internal/store"
)

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *clock) add(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

type recMailer struct {
	mu   sync.Mutex
	msgs []mailer.Message
}

func (m *recMailer) Send(_ context.Context, msg mailer.Message) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.msgs = append(m.msgs, msg)
	return nil
}

func (m *recMailer) count() int { m.mu.Lock(); defer m.mu.Unlock(); return len(m.msgs) }

var sixDigits = regexp.MustCompile(`\b(\d{6})\b`)

func (m *recMailer) lastCode(t *testing.T, to string) string {
	t.Helper()
	m.mu.Lock()
	defer m.mu.Unlock()
	for i := len(m.msgs) - 1; i >= 0; i-- {
		if strings.EqualFold(m.msgs[i].To, to) {
			if c := sixDigits.FindString(m.msgs[i].Text); c != "" {
				return c
			}
		}
	}
	t.Fatalf("no code mailed to %s", to)
	return ""
}

type env struct {
	t     *testing.T
	srv   *httptest.Server
	z     *fakeZitadel
	mail  *recMailer
	clock *clock
	key   *rsa.PrivateKey
	web   *Server
	cfg   *brandCfg
}

type brandCfg struct {
	Registration bool
	IDPs         []config.IDP
	Extra        map[string]any    // more brand fields
	Files        map[string][]byte // files next to the brands file
}

var testKey *rsa.PrivateKey

func init() {
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	testKey = k
}

func newEnv(t *testing.T, bc brandCfg) *env {
	t.Helper()
	c := &clock{t: time.Date(2026, 10, 24, 12, 0, 0, 0, time.UTC)}
	e := &env{t: t, z: newFake(c.now, testKey), mail: &recMailer{}, clock: c, key: testKey, cfg: &bc}
	e.srv = httptest.NewUnstartedServer(nil)
	origin := "http://" + e.srv.Listener.Addr().String()
	dir := t.TempDir()
	_ = os.WriteFile(filepath.Join(dir, "pat"), []byte("login-token"), 0o600)
	doc := map[string]any{"brands": []any{map[string]any{
		"id": "example", "name": "Example", "hosts": []string{e.srv.Listener.Addr().String()},
		"public_origin": origin, "zitadel_host": "zitadel.test", "mail_from": "Example <no-reply@example.test>",
		"login_client_pat_file": "pat", "return_urls": []string{"https://app.example.test/"},
		"registration_enabled": bc.Registration, "idps": bc.IDPs, "tagline": "Example tagline.",
	}}}
	for k, v := range bc.Extra {
		doc["brands"].([]any)[0].(map[string]any)[k] = v
	}
	for name, data := range bc.Files {
		_ = os.WriteFile(filepath.Join(dir, name), data, 0o600)
	}
	raw, _ := json.Marshal(doc)
	_ = os.WriteFile(filepath.Join(dir, "brands.json"), raw, 0o600)
	brands, err := config.LoadBrands(filepath.Join(dir, "brands.json"))
	if err != nil {
		t.Fatal(err)
	}
	s, err := New(Options{
		Brands: func() *config.Brands { return brands }, API: e.z, Store: store.NewMem(c.now), Mailer: e.mail,
		CookieKey: make([]byte, 32), Logger: slog.New(slog.NewTextHandler(io.Discard, nil)), Now: c.now,
	})
	if err != nil {
		t.Fatal(err)
	}
	e.web = s
	e.srv.Config.Handler = s
	e.srv.Start()
	t.Cleanup(e.srv.Close)
	return e
}

// browser is a cookie-keeping client that does not follow redirects by itself.
type browser struct {
	e      *env
	c      *http.Client
	origin string
}

func (e *env) browser() *browser {
	jar, _ := cookiejar.New(nil)
	return &browser{e: e, origin: e.srv.URL, c: &http.Client{Jar: jar,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}
}

type page struct {
	status   int
	location string
	body     string
}

func (b *browser) do(req *http.Request) page {
	b.e.t.Helper()
	resp, err := b.c.Do(req)
	if err != nil {
		b.e.t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return page{status: resp.StatusCode, location: resp.Header.Get("Location"), body: string(body)}
}

func (b *browser) get(path string) page {
	req, _ := http.NewRequest(http.MethodGet, b.abs(path), nil)
	return b.follow(b.do(req))
}

func (b *browser) abs(p string) string {
	if strings.HasPrefix(p, "http") {
		return p
	}
	return b.origin + p
}

// follow follows redirects within the login service; external redirects
// (the RP callback, the IdP) are returned as they are.
func (b *browser) follow(p page) page {
	for i := 0; i < 10 && p.status >= 300 && p.status < 400; i++ {
		u, err := url.Parse(b.abs(p.location))
		if err != nil || "http://"+u.Host != b.origin {
			return p
		}
		req, _ := http.NewRequest(http.MethodGet, u.String(), nil)
		p = b.do(req)
	}
	return p
}

var csrfRe = regexp.MustCompile(`name="csrf" value="([^"]+)"`)
var arRe = regexp.MustCompile(`name="authRequest" value="([^"]+)"`)

// post submits a form on the current page, filling csrf/authRequest from it.
func (b *browser) post(from page, path string, form url.Values) page {
	b.e.t.Helper()
	if form == nil {
		form = url.Values{}
	}
	if m := csrfRe.FindStringSubmatch(from.body); m != nil && !form.Has("csrf") {
		form.Set("csrf", m[1])
	}
	if m := arRe.FindStringSubmatch(from.body); m != nil && !form.Has("authRequest") {
		form.Set("authRequest", m[1])
	}
	req, _ := http.NewRequest(http.MethodPost, b.abs(path), strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", b.origin)
	return b.follow(b.do(req))
}

func (b *browser) start(ar string) page { return b.get("/login?authRequest=" + url.QueryEscape(ar)) }

func mustContain(t *testing.T, p page, want ...string) {
	t.Helper()
	for _, w := range want {
		if !strings.Contains(p.body, w) {
			t.Fatalf("page (status %d, location %q) lacks %q:\n%s", p.status, p.location, w, p.body)
		}
	}
}

func mustCallback(t *testing.T, p page, ar string) *url.URL {
	t.Helper()
	if p.status != http.StatusSeeOther || !strings.HasPrefix(p.location, "https://rp.test/cb?code=c-"+ar) {
		t.Fatalf("want callback for %s, got %d %q\n%s", ar, p.status, p.location, p.body)
	}
	u, _ := url.Parse(p.location)
	return u
}

// signLogoutToken makes a token like Zitadel's logout_token.
func (e *env) signLogoutToken(claims map[string]any) string {
	h, _ := json.Marshal(map[string]string{"alg": "RS256", "kid": "k1"})
	c, _ := json.Marshal(claims)
	in := base64.RawURLEncoding.EncodeToString(h) + "." + base64.RawURLEncoding.EncodeToString(c)
	d := sha256.Sum256([]byte(in))
	sig, err := rsa.SignPKCS1v15(rand.Reader, e.key, crypto.SHA256, d[:])
	if err != nil {
		panic(err)
	}
	return in + "." + base64.RawURLEncoding.EncodeToString(sig)
}

func signInWithPassword(t *testing.T, e *env, b *browser, email, password string, remember bool) *url.URL {
	t.Helper()
	ar := e.z.newAuthRequest("web", nil, nil, "")
	p := b.start(ar)
	form := url.Values{"email": {email}}
	if remember {
		form.Set("remember", "on")
	}
	p = b.post(p, "/login/email", form)
	mustContain(t, p, "Enter your password")
	p = b.post(p, "/login/password", url.Values{"password": {password}, "action": {"password"}})
	return mustCallback(t, p, ar)
}

var _ = fmt.Sprintf

func (s *Server) browserSessionsForTest(t *testing.T, b *browser) []browserSession {
	t.Helper()
	u, _ := url.Parse(b.origin)
	for _, c := range b.c.Jar.Cookies(u) {
		if c.Name == sessionsCookie {
			var list []browserSession
			if err := s.sealer.Open(c.Name, c.Value, &list); err != nil {
				t.Fatal(err)
			}
			return list
		}
	}
	return nil
}
