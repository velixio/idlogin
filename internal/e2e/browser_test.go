package e2e

import (
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"
)

// browser drives pages like a user agent: cookie jar, redirects followed by
// hand (so the test can see every hop), Origin on POSTs.
type browser struct {
	t     *testing.T
	c     *http.Client
	chain []string // URLs visited by the last navigation
	// stop, when it returns true for a redirect target, ends the navigation
	// there without fetching it (e.g. a native app's callback).
	stop func(*url.URL) bool
}

type page struct {
	url    *url.URL
	status int
	body   string
	loc    string // Location of a stopped redirect
}

func newBrowser(t *testing.T) *browser {
	jar, _ := cookiejar.New(nil)
	return &browser{t: t, c: &http.Client{Jar: jar, Timeout: 30 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}
}

func (b *browser) nav(req *http.Request) page {
	b.t.Helper()
	b.chain = nil
	for hop := 0; hop < 25; hop++ {
		req.Header.Set("Accept", "text/html,application/xhtml+xml")
		b.chain = append(b.chain, req.Method+" "+req.URL.String())
		resp, err := b.c.Do(req)
		if err != nil {
			b.t.Fatalf("%s %s: %v", req.Method, req.URL, err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		p := page{url: req.URL, status: resp.StatusCode, body: string(body)}
		if resp.StatusCode < 300 || resp.StatusCode >= 400 || resp.Header.Get("Location") == "" {
			return p
		}
		next, err := req.URL.Parse(resp.Header.Get("Location"))
		if err != nil {
			b.t.Fatalf("bad location %q", resp.Header.Get("Location"))
		}
		if b.stop != nil && b.stop(next) {
			p.loc = next.String()
			b.chain = append(b.chain, "STOP "+next.String())
			return p
		}
		req, _ = http.NewRequest(http.MethodGet, next.String(), nil)
	}
	b.t.Fatalf("redirect loop: %v", b.chain)
	return page{}
}

func (b *browser) get(raw string) page {
	req, err := http.NewRequest(http.MethodGet, raw, nil)
	if err != nil {
		b.t.Fatal(err)
	}
	return b.nav(req)
}

var (
	csrfRe = regexp.MustCompile(`name="csrf" value="([^"]+)"`)
	arRe   = regexp.MustCompile(`name="authRequest" value="([^"]+)"`)
)

// submit posts a form of the current page (csrf/authRequest taken from it).
func (b *browser) submit(from page, path string, form url.Values) page {
	b.t.Helper()
	if form == nil {
		form = url.Values{}
	}
	if m := csrfRe.FindStringSubmatch(from.body); m != nil && !form.Has("csrf") {
		form.Set("csrf", m[1])
	}
	if m := arRe.FindStringSubmatch(from.body); m != nil && !form.Has("authRequest") {
		form.Set("authRequest", m[1])
	}
	target, _ := from.url.Parse(path)
	req, _ := http.NewRequest(http.MethodPost, target.String(), strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", target.Scheme+"://"+target.Host)
	return b.nav(req)
}

func (b *browser) postTo(raw, origin string, form url.Values) page {
	req, _ := http.NewRequest(http.MethodPost, raw, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", origin)
	return b.nav(req)
}

// visited reports whether any hop of the last navigation matched.
func (b *browser) visited(substr string) bool {
	for _, c := range b.chain {
		if strings.Contains(c, substr) {
			return true
		}
	}
	return false
}

func (b *browser) dropCookie(rawURL, name string) {
	u, _ := url.Parse(rawURL)
	b.c.Jar.SetCookies(u, []*http.Cookie{{Name: name, Value: "", Path: "/", MaxAge: -1}})
}

func must(t *testing.T, p page, want ...string) {
	t.Helper()
	for _, w := range want {
		if !strings.Contains(p.body, w) {
			t.Fatalf("%s (%d) lacks %q:\n%.3000s", p.url, p.status, w, p.body)
		}
	}
}
