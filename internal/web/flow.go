package web

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"net/http"
	"slices"
	"time"

	"github.com/velixio/idlogin/internal/config"
)

// Steps of a flow.
const (
	stepEmail     = "email"
	stepPassword  = "password"
	stepCode      = "code"
	stepTOTP      = "totp"
	stepReset     = "reset"
	stepResetCode = "reset_code"
	stepApprove   = "approve" // native app: one click on a recent browser session
)

// Code purposes.
const (
	kindSignin = "signin"
	kindSignup = "signup"
	kindReset  = "reset"
	kindVerify = "verify"
)

// flow is the sealed per-auth-request state. It never holds anything that
// must not be replayed: codes and attempt counters live in the store.
type flow struct {
	Key         string `json:"k"`
	AuthRequest string `json:"ar,omitempty"`
	Return      string `json:"ret,omitempty"` // standalone reset: allowlisted return URL
	CSRF        string `json:"csrf"`
	Step        string `json:"st"`
	Signup      bool   `json:"su,omitempty"` // prompt=create
	Native      bool   `json:"na,omitempty"` // native app: fresh session unless it approves a recent browser session
	Remember    bool   `json:"rm,omitempty"`
	Email       string `json:"em,omitempty"`
	UserID      string `json:"uid,omitempty"`
	CodeID      string `json:"cid,omitempty"`
	CodeKind    string `json:"ck,omitempty"`
	EmailProven bool   `json:"ep,omitempty"` // this flow proved ownership of Email
	ResetOK     bool   `json:"ro,omitempty"` // reset code verified; only the new password is missing
	// TOTPFor records the user and Zitadel session a TOTP check (or the
	// finding that none is needed) was made for, as totpKey(user, session).
	// A bare flag would let a TOTP passed for one account count for another
	// account reached later in the same flow, e.g. through a password reset.
	TOTPFor    string `json:"tf,omitempty"`
	SessionID  string `json:"sid,omitempty"` // first factor done, waiting for TOTP / email verification
	SessionTok string `json:"stk,omitempty"`
	IDPState   string `json:"is,omitempty"`
	IDPKey     string `json:"ik,omitempty"`
}

func randomToken(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

// flowKey names the cookie of a flow: one per auth request, so parallel tabs
// and nested flows (an IdP that is itself this Zitadel) do not clash.
func flowKey(authRequest string) string {
	if authRequest == "" {
		return "r"
	}
	h := sha256.Sum256([]byte(authRequest))
	return "a" + hex.EncodeToString(h[:8])
}

func newFlow(authRequest string) *flow {
	return &flow{Key: flowKey(authRequest), AuthRequest: authRequest, CSRF: randomToken(32), Step: stepEmail}
}

func cookieName(b *config.Brand, name string) string {
	if b.Secure {
		return "__Host-" + name
	}
	return name
}

func (s *Server) setCookie(w http.ResponseWriter, b *config.Brand, name string, v any, ttl time.Duration) {
	full := cookieName(b, name)
	val, err := s.sealer.Seal(full, v, ttl)
	if err != nil {
		panic(err)
	}
	http.SetCookie(w, &http.Cookie{Name: full, Value: val, Path: "/", MaxAge: int(ttl / time.Second),
		HttpOnly: true, Secure: b.Secure, SameSite: http.SameSiteLaxMode})
}

func (s *Server) clearCookie(w http.ResponseWriter, b *config.Brand, name string) {
	http.SetCookie(w, &http.Cookie{Name: cookieName(b, name), Value: "", Path: "/", MaxAge: -1,
		HttpOnly: true, Secure: b.Secure, SameSite: http.SameSiteLaxMode})
}

func (s *Server) readCookie(r *http.Request, b *config.Brand, name string, v any) bool {
	full := cookieName(b, name)
	c, err := r.Cookie(full)
	if err != nil {
		return false
	}
	return s.sealer.Open(full, c.Value, v) == nil
}

func (s *Server) loadFlow(r *http.Request, b *config.Brand, authRequest string) *flow {
	var f flow
	if !s.readCookie(r, b, "idl-f-"+flowKey(authRequest), &f) || f.AuthRequest != authRequest {
		return nil
	}
	return &f
}

func (s *Server) saveFlow(w http.ResponseWriter, b *config.Brand, f *flow) {
	s.setCookie(w, b, "idl-f-"+f.Key, f, flowTTL)
}

func (s *Server) dropFlow(w http.ResponseWriter, b *config.Brand, f *flow) {
	s.clearCookie(w, b, "idl-f-"+f.Key)
}

// formFlow loads the flow a POST belongs to and checks its CSRF token. It
// writes the error response itself and returns nil when the check fails.
func (s *Server) formFlow(w http.ResponseWriter, r *http.Request) (*flow, bool) {
	b := brandOf(r)
	ar := r.PostFormValue("authRequest")
	if ar != "" && !validAuthRequest(ar) {
		http.Error(w, "bad request", http.StatusBadRequest)
		return nil, false
	}
	f := s.loadFlow(r, b, ar)
	if f == nil {
		s.expired(w, r, ar)
		return nil, false
	}
	if !ctEqual(r.PostFormValue("csrf"), f.CSRF) {
		http.Error(w, "invalid form token; reload the page and try again", http.StatusForbidden)
		return nil, false
	}
	return f, true
}

// pageFlow loads the flow for a GET step page, or redirects to where the
// flow actually is.
func (s *Server) pageFlow(w http.ResponseWriter, r *http.Request, steps ...string) (*flow, bool) {
	b := brandOf(r)
	ar := r.URL.Query().Get("authRequest")
	if ar != "" && !validAuthRequest(ar) {
		http.Error(w, "bad request", http.StatusBadRequest)
		return nil, false
	}
	f := s.loadFlow(r, b, ar)
	if f == nil {
		s.expired(w, r, ar)
		return nil, false
	}
	if !slices.Contains(steps, f.Step) {
		s.toStep(w, r, f)
		return nil, false
	}
	return f, true
}

func stepPath(step string) string {
	switch step {
	case stepPassword:
		return "/login/password"
	case stepCode:
		return "/login/code"
	case stepTOTP:
		return "/login/totp"
	case stepReset:
		return "/reset"
	case stepResetCode:
		return "/reset/code"
	case stepApprove:
		return "/login/approve"
	}
	return "/login/email"
}

// toStep saves nothing; it redirects (303) to the page of the flow's step.
func (s *Server) toStep(w http.ResponseWriter, r *http.Request, f *flow) {
	http.Redirect(w, r, stepPath(f.Step)+query(f.AuthRequest), http.StatusSeeOther)
}

// browserSession is one Zitadel session this browser holds.
type browserSession struct {
	ID       string `json:"id"`
	Token    string `json:"t"`
	UserID   string `json:"u"`
	Remember bool   `json:"rm,omitempty"`
	At       int64  `json:"at"`
}

const sessionsCookie = "idl-sessions"

func (s *Server) browserSessions(r *http.Request, b *config.Brand) []browserSession {
	var list []browserSession
	s.readCookie(r, b, sessionsCookie, &list)
	return list
}

func (s *Server) saveBrowserSessions(w http.ResponseWriter, b *config.Brand, list []browserSession) {
	if len(list) == 0 {
		s.clearCookie(w, b, sessionsCookie)
		return
	}
	s.setCookie(w, b, sessionsCookie, list, sessionsMaxAge)
}

// rememberSession puts a session first in the browser's list (max 5).
func (s *Server) rememberSession(w http.ResponseWriter, r *http.Request, b *config.Brand, e browserSession) {
	e.At = s.now().Unix()
	list := []browserSession{e}
	for _, o := range s.browserSessions(r, b) {
		if o.ID != e.ID && len(list) < maxSessions {
			list = append(list, o)
		}
	}
	s.saveBrowserSessions(w, b, list)
}

// totpKey binds a TOTP result to one user and one Zitadel session.
func totpKey(userID, sessionID string) string {
	if userID == "" || sessionID == "" {
		return ""
	}
	return userID + "|" + sessionID
}

// totpDone reports whether the TOTP step was settled for the flow's current
// user and session.
func (f *flow) totpDone() bool {
	key := totpKey(f.UserID, f.SessionID)
	return key != "" && f.TOTPFor == key
}
