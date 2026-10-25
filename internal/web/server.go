// Package web serves the customer-facing sign-in pages and drives Zitadel's
// v2 API: email-first sign-in, password, email code, TOTP, password reset,
// Google/GitHub through IdP intents, SSO reuse and logout. See docs/idlogin.md.
package web

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"embed"
	"encoding/hex"
	"errors"
	"html/template"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/velixio/idlogin/internal/config"
	"github.com/velixio/idlogin/internal/mailer"
	"github.com/velixio/idlogin/internal/seal"
	"github.com/velixio/idlogin/internal/store"
	"github.com/velixio/idlogin/internal/zitadel"
)

//go:embed templates/*.html
var templateFS embed.FS

//go:embed static
var staticFS embed.FS

// Code and rate-limit policy (docs/idlogin.md).
const (
	CodeDigits      = 6
	CodeTTL         = 10 * time.Minute
	CodeMaxAttempts = 5

	SessionLifetime         = 7 * 24 * time.Hour
	SessionLifetimeRemember = 30 * 24 * time.Hour
	// NativeApprovalWindow is how recent a browser sign-in must be for a
	// native app to take it over with one approval click instead of a fresh
	// sign-in.
	NativeApprovalWindow = 24 * time.Hour

	flowTTL        = 30 * time.Minute
	maxSessions    = 5
	sessionsMaxAge = 31 * 24 * time.Hour
)

// Limits are the rate-limit windows. Exported so tests can shrink them.
type Limits struct {
	SendsPerAddress    store.Limit // codes sent to one address
	SendsPerIP         store.Limit // codes requested from one IP
	PasswordPerAccount store.Limit
	PasswordPerIP      store.Limit
	LookupsPerIP       store.Limit // email-first submissions
	CodeChecksPerIP    store.Limit
	TOTPPerAccount     store.Limit
}

// DefaultLimits are the production limits.
var DefaultLimits = Limits{
	SendsPerAddress:    store.Limit{Max: 5, Window: time.Hour},
	SendsPerIP:         store.Limit{Max: 30, Window: time.Hour},
	PasswordPerAccount: store.Limit{Max: 10, Window: 15 * time.Minute},
	PasswordPerIP:      store.Limit{Max: 50, Window: 15 * time.Minute},
	LookupsPerIP:       store.Limit{Max: 60, Window: 15 * time.Minute},
	CodeChecksPerIP:    store.Limit{Max: 60, Window: 15 * time.Minute},
	TOTPPerAccount:     store.Limit{Max: 10, Window: 15 * time.Minute},
}

// Options configure a Server.
type Options struct {
	Brands     func() *config.Brands // called per request (supports reload)
	API        zitadel.API
	Store      store.Store
	Mailer     mailer.Mailer
	CookieKey  []byte // 32 bytes
	TrustProxy bool
	Logger     *slog.Logger
	Now        func() time.Time
	Limits     *Limits
}

// Server is the HTTP handler.
type Server struct {
	brands     func() *config.Brands
	api        zitadel.API
	store      store.Store
	mail       mailer.Mailer
	sealer     *seal.Sealer
	codeKey    []byte
	trustProxy bool
	log        *slog.Logger
	now        func() time.Time
	limits     Limits
	pages      map[string]*template.Template
	mux        *http.ServeMux

	jwksMu sync.Mutex
	jwks   map[string]jwksEntry
}

// New builds the server.
func New(o Options) (*Server, error) {
	if len(o.CookieKey) != 32 {
		return nil, errors.New("web: cookie key must be 32 bytes")
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.Logger == nil {
		o.Logger = slog.Default()
	}
	sealer, err := seal.New(seal.DeriveKey(o.CookieKey, "cookies"), o.Now)
	if err != nil {
		return nil, err
	}
	s := &Server{
		brands: o.Brands, api: o.API, store: o.Store, mail: o.Mailer, sealer: sealer,
		codeKey: seal.DeriveKey(o.CookieKey, "codes"), trustProxy: o.TrustProxy,
		log: o.Logger, now: o.Now, limits: DefaultLimits, jwks: map[string]jwksEntry{},
	}
	if o.Limits != nil {
		s.limits = *o.Limits
	}
	if s.pages, err = parseTemplates(); err != nil {
		return nil, err
	}
	s.routes()
	return s, nil
}

func (s *Server) routes() {
	m := http.NewServeMux()
	static, _ := fs.Sub(staticFS, "static")
	files := http.StripPrefix("/login/static/", http.FileServerFS(static))
	m.Handle("GET /login/static/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/") {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Cache-Control", "public, max-age=86400")
		files.ServeHTTP(w, r)
	}))
	m.HandleFunc("GET /login/brand/logo", s.handleLogo)
	m.HandleFunc("GET /login/healthz", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("ok\n")) })

	m.HandleFunc("GET /login", s.handleLogin)
	m.HandleFunc("GET /login/email", s.handleEmailPage)
	m.HandleFunc("POST /login/email", s.handleEmail)
	m.HandleFunc("GET /login/password", s.handlePasswordPage)
	m.HandleFunc("POST /login/password", s.handlePassword)
	m.HandleFunc("GET /login/code", s.handleCodePage)
	m.HandleFunc("POST /login/code", s.handleCode)
	m.HandleFunc("GET /login/totp", s.handleTOTPPage)
	m.HandleFunc("POST /login/totp", s.handleTOTP)
	m.HandleFunc("POST /login/restart", s.handleRestart)
	m.HandleFunc("GET /login/approve", s.handleApprovePage)
	m.HandleFunc("POST /login/approve", s.handleApprove)
	m.HandleFunc("POST /login/idp", s.handleIDPStart)
	m.HandleFunc("GET /login/idp/callback", s.handleIDPCallback)
	m.HandleFunc("GET /login/idp/failure", s.handleIDPFailure)

	m.HandleFunc("GET /reset", s.handleResetPage)
	m.HandleFunc("POST /reset", s.handleReset)
	m.HandleFunc("GET /reset/code", s.handleResetCodePage)
	m.HandleFunc("POST /reset/code", s.handleResetCode)

	m.HandleFunc("GET /logout", s.handleLogout)
	m.HandleFunc("POST /logout", s.handleLogoutConfirm)
	m.HandleFunc("GET /logout/done", s.handleLogoutDone)
	s.mux = m
}

type ctxKey int

const brandKey ctxKey = 1

// defaultLogo is the neutral built-in mark used when a brand has no logo_file.
var defaultLogo = func() []byte {
	b, err := staticFS.ReadFile("static/logo.svg")
	if err != nil {
		panic(err)
	}
	return b
}()

var defaultLogoVersion = func() string {
	sum := sha256.Sum256(defaultLogo)
	return hex.EncodeToString(sum[:6])
}()

// logoURL is the brand's logo URL, versioned by content so it can be cached.
func logoURL(b *config.Brand) string {
	v := b.LogoVersion
	if b.Logo == nil {
		v = defaultLogoVersion
	}
	return "/login/brand/logo?v=" + v
}

// handleLogo serves the logo of the request's brand (read from its
// logo_file when the brands file was loaded), or the built-in mark.
func (s *Server) handleLogo(w http.ResponseWriter, r *http.Request) {
	b := brandOf(r)
	data, typ := b.Logo, b.LogoType
	if data == nil {
		data, typ = defaultLogo, "image/svg+xml"
	}
	h := w.Header()
	h.Set("Content-Type", typ)
	h.Set("Cache-Control", "public, max-age=86400")
	// An SVG opened directly runs nothing and loads nothing.
	h.Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; sandbox")
	_, _ = w.Write(data)
}

func brandOf(r *http.Request) *config.Brand { return r.Context().Value(brandKey).(*config.Brand) }

// ServeHTTP applies the security headers, resolves the brand from the Host
// header, rejects cross-origin POSTs, and dispatches.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h := w.Header()
	h.Set("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; font-src 'self'; "+
		"connect-src 'none'; base-uri 'none'; object-src 'none'; frame-ancestors 'none'")
	h.Set("X-Frame-Options", "DENY")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Referrer-Policy", "same-origin")
	h.Set("Cross-Origin-Opener-Policy", "same-origin")
	h.Set("Cross-Origin-Resource-Policy", "same-origin")
	h.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=()")
	if !strings.HasPrefix(r.URL.Path, "/login/static/") && r.URL.Path != "/login/brand/logo" {
		h.Set("Cache-Control", "no-store")
	}
	b := s.brands().ByHost[strings.ToLower(r.Host)]
	if b == nil {
		http.Error(w, "unknown host", http.StatusMisdirectedRequest)
		return
	}
	if b.Secure {
		h.Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
	}
	if r.Method == http.MethodPost {
		if !sameOrigin(r, b.PublicOrigin) {
			http.Error(w, "cross-origin request refused", http.StatusForbidden)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
	}
	defer func() {
		if p := recover(); p != nil {
			if p == http.ErrAbortHandler {
				panic(p)
			}
			s.log.Error("panic", "path", r.URL.Path, "panic", p)
			http.Error(w, "internal error", http.StatusInternalServerError)
		}
	}()
	s.mux.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), brandKey, b)))
}

// sameOrigin requires the Origin header (or, when a browser omits it, the
// Referer) to be our public origin.
func sameOrigin(r *http.Request, origin string) bool {
	if r.Header.Get("Sec-Fetch-Site") == "cross-site" {
		return false
	}
	if o := r.Header.Get("Origin"); o != "" {
		return o == origin
	}
	ref := r.Header.Get("Referer")
	return ref != "" && strings.HasPrefix(ref, origin+"/")
}

func (s *Server) clientIP(r *http.Request) string {
	if s.trustProxy {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			parts := strings.Split(xff, ",")
			if ip := net.ParseIP(strings.TrimSpace(parts[len(parts)-1])); ip != nil {
				return ip.String()
			}
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func instance(b *config.Brand) zitadel.Instance {
	return zitadel.Instance{Host: b.ZitadelHost, Token: b.Token}
}

var authRequestRe = regexp.MustCompile(`^[A-Za-z0-9_-]{1,128}$`)

func validAuthRequest(ar string) bool { return authRequestRe.MatchString(ar) }

func query(ar string) string {
	if ar == "" {
		return ""
	}
	return "?authRequest=" + url.QueryEscape(ar)
}

func ctEqual(a, b string) bool {
	return a != "" && len(a) == len(b) && subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

func (s *Server) hashCode(id, code string) []byte {
	m := hmac.New(sha256.New, s.codeKey)
	m.Write([]byte(id + ":" + code))
	return m.Sum(nil)
}

// safeCallback accepts the URLs Zitadel hands us to continue to: absolute
// URLs, never script-capable schemes. (Native apps may use custom schemes.)
func safeCallback(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" {
		return false
	}
	switch strings.ToLower(u.Scheme) {
	case "javascript", "data", "vbscript", "file", "blob":
		return false
	case "http", "https":
		return u.Host != ""
	}
	return true
}
