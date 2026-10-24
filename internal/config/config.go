// Package config loads the login service configuration: process settings
// from LOGIN_* environment variables and the brands from a JSON file.
package config

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
)

// Config is the process configuration.
type Config struct {
	Addr             string // LOGIN_ADDR, public listener (default 127.0.0.1:8091)
	ActionsKeyFile   string // LOGIN_ACTIONS_SIGNING_KEY_FILE
	ZitadelURL       string // LOGIN_ZITADEL_URL (API base, default http://127.0.0.1:8090)
	DatabaseURL      string // LOGIN_DATABASE_URL
	DatabasePassword string // LOGIN_DATABASE_PASSWORD (optional, overrides the URL's)
	CookieKey        []byte // LOGIN_COOKIE_KEY, base64 32 bytes
	BrandsFile       string // LOGIN_BRANDS_FILE
	Mailer           string // LOGIN_MAILER: log | smtp
	MailDir          string // LOGIN_MAIL_DIR (log mailer)
	SMTPHost         string // LOGIN_SMTP_HOST
	SMTPPort         string // LOGIN_SMTP_PORT (default 587)
	SMTPUser         string // LOGIN_SMTP_USER
	SMTPPassword     string // LOGIN_SMTP_PASSWORD
	SMTPTLS          string // LOGIN_SMTP_TLS: starttls (default) | tls | none
	TrustProxy       bool   // LOGIN_TRUST_PROXY: take the client IP from X-Forwarded-For
	LogLevel         string // LOGIN_LOG_LEVEL: debug | info (default)
}

// FromEnv reads the process configuration.
func FromEnv(getenv func(string) string) (*Config, error) {
	get := func(k, def string) string {
		if v := strings.TrimSpace(getenv(k)); v != "" {
			return v
		}
		return def
	}
	c := &Config{
		Addr:             get("LOGIN_ADDR", "127.0.0.1:8091"),
		ActionsKeyFile:   get("LOGIN_ACTIONS_SIGNING_KEY_FILE", ""),
		ZitadelURL:       strings.TrimRight(get("LOGIN_ZITADEL_URL", "http://127.0.0.1:8090"), "/"),
		DatabaseURL:      get("LOGIN_DATABASE_URL", ""),
		DatabasePassword: getenv("LOGIN_DATABASE_PASSWORD"),
		BrandsFile:       get("LOGIN_BRANDS_FILE", ""),
		Mailer:           get("LOGIN_MAILER", "log"),
		MailDir:          get("LOGIN_MAIL_DIR", ""),
		SMTPHost:         get("LOGIN_SMTP_HOST", ""),
		SMTPPort:         get("LOGIN_SMTP_PORT", "587"),
		SMTPUser:         get("LOGIN_SMTP_USER", ""),
		SMTPPassword:     getenv("LOGIN_SMTP_PASSWORD"),
		SMTPTLS:          get("LOGIN_SMTP_TLS", "starttls"),
		TrustProxy:       get("LOGIN_TRUST_PROXY", "false") == "true",
		LogLevel:         get("LOGIN_LOG_LEVEL", "info"),
	}
	var errs []error
	key, err := base64.StdEncoding.DecodeString(get("LOGIN_COOKIE_KEY", ""))
	if err != nil || len(key) != 32 {
		errs = append(errs, errors.New("LOGIN_COOKIE_KEY must be 32 bytes, base64 (openssl rand -base64 32)"))
	}
	c.CookieKey = key
	if c.DatabaseURL == "" {
		errs = append(errs, errors.New("LOGIN_DATABASE_URL is required"))
	}
	if c.BrandsFile == "" {
		errs = append(errs, errors.New("LOGIN_BRANDS_FILE is required"))
	}
	switch c.Mailer {
	case "log":
		if c.MailDir == "" {
			errs = append(errs, errors.New("LOGIN_MAIL_DIR is required for LOGIN_MAILER=log"))
		}
	case "smtp":
		if c.SMTPHost == "" {
			errs = append(errs, errors.New("LOGIN_SMTP_HOST is required for LOGIN_MAILER=smtp"))
		}
		if c.SMTPTLS != "starttls" && c.SMTPTLS != "tls" && c.SMTPTLS != "none" {
			errs = append(errs, errors.New("LOGIN_SMTP_TLS must be starttls, tls or none"))
		}
	default:
		errs = append(errs, errors.New("LOGIN_MAILER must be log or smtp"))
	}
	if get("LOGIN_ACTIONS_ADDR", "") != "" {
		errs = append(errs, errors.New("LOGIN_ACTIONS_ADDR is no longer used: the action target is served on LOGIN_ADDR at /login/zitadel/preaccesstoken; set LOGIN_ACTIONS_SIGNING_KEY_FILE to enable it"))
	}
	return c, errors.Join(errs...)
}

// IDP is a social login button backed by a Zitadel IdP.
type IDP struct {
	Key   string `json:"key"`   // google, github, or any other short name
	ID    string `json:"id"`    // Zitadel IdP ID; empty disables the button
	Label string `json:"label"` // defaults to Google / GitHub / key
}

// Brand is one customer-facing sign-in site (one Zitadel instance).
type Brand struct {
	ID                  string            `json:"id"`
	Hosts               []string          `json:"hosts"`         // Host header values served, e.g. id.example.com
	PublicOrigin        string            `json:"public_origin"` // e.g. https://id.example.com
	ZitadelHost         string            `json:"zitadel_host"`  // instance host sent to Zitadel, e.g. id.example.com
	Name                string            `json:"name"`          // shown in page titles, headings and emails
	LogoFile            string            `json:"logo_file"`     // SVG/PNG/WebP/ICO, read at load; relative to the brands file; empty = built-in mark
	Tagline             string            `json:"tagline"`       // optional small line under the card
	MailFrom            string            `json:"mail_from"`     // From header of code emails, e.g. Example <no-reply@example.com>
	MailSubjects        map[string]string `json:"mail_subjects"` // optional subject per email kind (signin, signup, reset, verify); {name} = Name
	PATFile             string            `json:"login_client_pat_file"`
	ReturnURLs          []string          `json:"return_urls"` // allowlisted return URL prefixes (standalone reset, logout)
	RegistrationEnabled bool              `json:"registration_enabled"`
	OrgID               string            `json:"org_id"` // org for new users; empty = the login client's org
	IDPs                []IDP             `json:"idps"`

	Token       string    `json:"-"` // read from PATFile
	Secure      bool      `json:"-"` // PublicOrigin is https
	Logo        []byte    `json:"-"` // contents of LogoFile (nil = built-in mark)
	LogoType    string    `json:"-"` // media type of Logo
	LogoVersion string    `json:"-"` // short content hash, for cache busting
	allow       []url.URL `json:"-"`
}

// MaxLogoBytes bounds a brand logo file.
const MaxLogoBytes = 256 << 10

// MailKinds are the email kinds a brand may give its own subject.
var MailKinds = []string{"signin", "signup", "reset", "verify"}

var logoTypes = map[string]string{
	".svg": "image/svg+xml", ".png": "image/png", ".webp": "image/webp", ".ico": "image/x-icon",
}

// Brands maps request hosts to brands.
type Brands struct {
	ByHost map[string]*Brand
	All    []*Brand
}

// LoadBrands reads the brands file. ${VAR} references in it are expanded
// from the environment; relative PAT and logo paths are relative to the file.
func LoadBrands(path string) (*Brands, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var doc struct {
		Brands []*Brand `json:"brands"`
	}
	dec := json.NewDecoder(strings.NewReader(os.ExpandEnv(string(raw))))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&doc); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if len(doc.Brands) == 0 {
		return nil, fmt.Errorf("%s: no brands", path)
	}
	out := &Brands{ByHost: map[string]*Brand{}}
	for i, b := range doc.Brands {
		if err := b.prepare(filepath.Dir(path)); err != nil {
			return nil, fmt.Errorf("%s: brand %d (%s): %w", path, i, b.ID, err)
		}
		for _, h := range b.Hosts {
			h = strings.ToLower(h)
			if _, dup := out.ByHost[h]; dup {
				return nil, fmt.Errorf("%s: host %s listed twice", path, h)
			}
			out.ByHost[h] = b
		}
		out.All = append(out.All, b)
	}
	return out, nil
}

func (b *Brand) prepare(dir string) error {
	if b.ID == "" || b.Name == "" || len(b.Hosts) == 0 || b.ZitadelHost == "" || b.PATFile == "" || b.MailFrom == "" {
		return errors.New("id, name, hosts, zitadel_host, login_client_pat_file and mail_from are required")
	}
	o, err := url.Parse(b.PublicOrigin)
	if err != nil || (o.Scheme != "https" && o.Scheme != "http") || o.Host == "" || (o.Path != "" && o.Path != "/") {
		return fmt.Errorf("public_origin %q must be scheme://host[:port]", b.PublicOrigin)
	}
	b.PublicOrigin = o.Scheme + "://" + o.Host
	b.Secure = o.Scheme == "https"
	if err := b.loadLogo(dir); err != nil {
		return err
	}
	for k, v := range b.MailSubjects {
		if !slices.Contains(MailKinds, k) {
			return fmt.Errorf("mail_subjects: unknown kind %q (want one of %s)", k, strings.Join(MailKinds, ", "))
		}
		if strings.TrimSpace(v) == "" || strings.ContainsAny(v, "\r\n") {
			return fmt.Errorf("mail_subjects.%s must be one non-empty line", k)
		}
	}
	pat := b.PATFile
	if !filepath.IsAbs(pat) {
		pat = filepath.Join(dir, pat)
	}
	tok, err := os.ReadFile(pat)
	if err != nil {
		return fmt.Errorf("login client token: %w", err)
	}
	if b.Token = strings.TrimSpace(string(tok)); b.Token == "" {
		return fmt.Errorf("login client token file %s is empty", pat)
	}
	for _, r := range b.ReturnURLs {
		u, err := url.Parse(r)
		if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
			return fmt.Errorf("return_urls: %q must be an absolute http(s) URL without query", r)
		}
		if u.Path == "" {
			u.Path = "/"
		}
		b.allow = append(b.allow, *u)
	}
	for i := range b.IDPs {
		p := &b.IDPs[i]
		if p.Label == "" {
			switch p.Key {
			case "google":
				p.Label = "Google"
			case "github":
				p.Label = "GitHub"
			default:
				p.Label = p.Key
			}
		}
	}
	return nil
}

func (b *Brand) loadLogo(dir string) error {
	if b.LogoFile == "" {
		return nil
	}
	p := b.LogoFile
	if !filepath.IsAbs(p) {
		p = filepath.Join(dir, p)
	}
	typ, ok := logoTypes[strings.ToLower(filepath.Ext(p))]
	if !ok {
		return fmt.Errorf("logo_file %s: must be .svg, .png, .webp or .ico", p)
	}
	data, err := os.ReadFile(p)
	if err != nil {
		return fmt.Errorf("logo_file: %w", err)
	}
	if len(data) == 0 || len(data) > MaxLogoBytes {
		return fmt.Errorf("logo_file %s: must be 1 byte to %d KiB", p, MaxLogoBytes>>10)
	}
	sum := sha256.Sum256(data)
	b.Logo, b.LogoType, b.LogoVersion = data, typ, hex.EncodeToString(sum[:6])
	return nil
}

// MailSubject is the brand's subject for an email kind, or def. In both,
// {name} is replaced by the brand name.
func (b *Brand) MailSubject(kind, def string) string {
	s := def
	if v, ok := b.MailSubjects[kind]; ok {
		s = v
	}
	return strings.ReplaceAll(s, "{name}", b.Name)
}

// IDP returns the configured, enabled IdP for a key.
func (b *Brand) IDP(key string) (IDP, bool) {
	for _, p := range b.IDPs {
		if p.Key == key && p.ID != "" {
			return p, true
		}
	}
	return IDP{}, false
}

// EnabledIDPs lists the IdPs with an ID.
func (b *Brand) EnabledIDPs() []IDP {
	var out []IDP
	for _, p := range b.IDPs {
		if p.ID != "" {
			out = append(out, p)
		}
	}
	return out
}

// AllowedReturn reports whether raw is an absolute URL under one of the
// allowlisted return URLs: same scheme, host and port, and a path at or below
// the allowlisted path (segment-wise). Anything else, including userinfo,
// backslashes and non-http schemes, is rejected.
func (b *Brand) AllowedReturn(raw string) bool {
	if raw == "" || len(raw) > 2048 || strings.ContainsAny(raw, "\\\r\n\t ") {
		return false
	}
	u, err := url.Parse(raw)
	if err != nil || u.User != nil || u.Opaque != "" || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
		return false
	}
	p := u.EscapedPath()
	if p == "" {
		p = "/"
	}
	if strings.Contains(p, "/../") || strings.HasSuffix(p, "/..") || strings.Contains(strings.ToLower(p), "%2e%2e") {
		return false
	}
	for _, a := range b.allow {
		if !strings.EqualFold(a.Scheme, u.Scheme) || !strings.EqualFold(a.Host, u.Host) {
			continue
		}
		ap := a.EscapedPath()
		if p == ap || strings.HasPrefix(p, strings.TrimSuffix(ap, "/")+"/") {
			return true
		}
	}
	return false
}
