package web

import (
	"bytes"
	"html/template"
	"io/fs"
	"net/http"
	"path"
	"strings"

	"github.com/velixio/idlogin/internal/config"
)

// view is the data every page template gets.
type view struct {
	Brand        *config.Brand
	LogoURL      string
	Title        string
	Description  string
	Error        string
	Info         string
	CSRF         string
	AuthRequest  string
	Query        string
	Email        string
	Remember     bool
	Signup       bool
	IDPs         []config.IDP
	CodeKind     string
	CodeMinutes  int
	ResetOK      bool
	PasswordHint string
	Standalone   bool
	Link         string
	LinkLabel    string
}

const (
	iconGoogle = `<svg class="social-icon" viewBox="0 0 24 24" aria-hidden="true"><path fill="#4285F4" d="M23.5 12.27c0-.85-.08-1.67-.22-2.45H12v4.63h6.45a5.5 5.5 0 0 1-2.39 3.62v3h3.87c2.27-2.09 3.57-5.17 3.57-8.8Z"/><path fill="#34A853" d="M12 24c3.24 0 5.96-1.07 7.94-2.91l-3.87-3c-1.07.72-2.45 1.15-4.07 1.15-3.13 0-5.78-2.11-6.73-4.96H1.27v3.1A12 12 0 0 0 12 24Z"/><path fill="#FBBC05" d="M5.27 14.28a7.2 7.2 0 0 1 0-4.56v-3.1H1.27a12 12 0 0 0 0 10.76l4-3.1Z"/><path fill="#EA4335" d="M12 4.75c1.76 0 3.34.61 4.59 1.8l3.44-3.44C17.96 1.19 15.24 0 12 0A12 12 0 0 0 1.27 6.62l4 3.1C6.22 6.86 8.87 4.75 12 4.75Z"/></svg>`
	iconGitHub = `<svg class="social-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M15 22v-4a4.8 4.8 0 0 0-1-3.5c3 0 6-2 6-5.5.08-1.25-.27-2.48-1-3.5.28-1.15.28-2.35 0-3.5 0 0-1 0-3 1.5-2.64-.5-5.36-.5-8 0C6 2 5 2 5 2c-.3 1.15-.3 2.35 0 3.5A5.403 5.403 0 0 0 4 9c0 3.5 3 5.5 6 5.5-.39.49-.68 1.05-.85 1.65-.17.6-.22 1.23-.15 1.85v4"/><path d="M9 18c-4.51 2-5-2-7-2"/></svg>`
	iconMail   = `<svg class="social-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><rect width="20" height="16" x="2" y="4" rx="2"/><path d="m22 7-8.97 5.7a1.94 1.94 0 0 1-2.06 0L2 7"/></svg>`
)

var funcs = template.FuncMap{
	"icon": func(key string) template.HTML {
		switch key {
		case "google":
			return template.HTML(iconGoogle)
		case "github":
			return template.HTML(iconGitHub)
		case "mail":
			return template.HTML(iconMail)
		}
		return ""
	},
}

func parseTemplates() (map[string]*template.Template, error) {
	layout, err := template.New("layout.html").Funcs(funcs).ParseFS(templateFS, "templates/layout.html")
	if err != nil {
		return nil, err
	}
	names, err := fs.Glob(templateFS, "templates/*.html")
	if err != nil {
		return nil, err
	}
	pages := map[string]*template.Template{}
	for _, n := range names {
		base := strings.TrimSuffix(path.Base(n), ".html")
		if base == "layout" {
			continue
		}
		t, err := template.Must(layout.Clone()).ParseFS(templateFS, n)
		if err != nil {
			return nil, err
		}
		pages[base] = t
	}
	return pages, nil
}

func (s *Server) render(w http.ResponseWriter, r *http.Request, status int, page string, v view) {
	v.Brand = brandOf(r)
	v.LogoURL = logoURL(v.Brand)
	if v.Query == "" {
		v.Query = query(v.AuthRequest)
	}
	var buf bytes.Buffer
	if err := s.pages[page].ExecuteTemplate(&buf, "layout", v); err != nil {
		s.log.Error("render", "page", page, "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	_, _ = w.Write(buf.Bytes())
}

func (s *Server) message(w http.ResponseWriter, r *http.Request, status int, title, text, link, linkLabel string) {
	s.render(w, r, status, "message", view{Title: title, Description: text, Link: link, LinkLabel: linkLabel})
}

// expired is shown when the flow cookie or the auth request is gone.
func (s *Server) expired(w http.ResponseWriter, r *http.Request, authRequest string) {
	s.message(w, r, http.StatusBadRequest, "This sign-in has expired",
		"Go back to the app you were signing in to and start again.", "", "")
}

func (s *Server) failure(w http.ResponseWriter, r *http.Request, err error, what string) {
	s.log.Error(what, "error", err)
	s.message(w, r, http.StatusBadGateway, "We couldn't continue",
		"Something went wrong on our side. Try again in a moment.", "", "")
}

// unavailable is the one neutral answer for "unknown address with
// registration closed" and "disabled or locked account". It must not differ
// between those cases.
func (s *Server) unavailable(w http.ResponseWriter, r *http.Request, f *flow) {
	s.render(w, r, http.StatusOK, "unavailable", view{
		Title: "We couldn't continue", Description: "This address can't be used to sign in.",
		CSRF: f.CSRF, AuthRequest: f.AuthRequest,
	})
}

func (s *Server) emailView(f *flow, b *config.Brand) view {
	v := view{
		Title:       "Sign in or create your account",
		Description: "Enter your email. We will ask for your password if you have set one, or email you a code.",
		CSRF:        f.CSRF, AuthRequest: f.AuthRequest, Email: f.Email, Remember: f.Remember, Signup: f.Signup,
		IDPs: b.EnabledIDPs(),
	}
	if !b.RegistrationEnabled {
		v.Title = "Sign in to " + b.Name
		v.Description = "Enter your email. We will ask for your password if you have set one, or email you a code."
	}
	if f.Signup {
		v.Title = "Create your " + b.Name + " account"
		v.Description = "Enter your email and we'll send you a code. Entering it creates your account."
	}
	return v
}
