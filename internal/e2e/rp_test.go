package e2e

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"html/template"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
)

// rpSessionCookie is the relying party's own session cookie.
const rpSessionCookie = "rp_session"

const backchannelLogoutEvent = "http://schemas.openid.net/event/backchannel-logout"

var rpPage = template.Must(template.New("rp").Parse(`<!doctype html>
<title>e2e relying party</title>
<p>Signed in as {{.Name}} &lt;{{.Email}}&gt; (subject {{.Subject}})</p>
<form method="post" action="/auth/logout"><button>Sign out</button></form>`))

type rpSession struct {
	Subject, SID, Name, Email, IDToken string
}

type rpPending struct {
	verifier, nonce string
}

// relyingParty is a minimal confidential OIDC web client on :8095 (code flow
// with PKCE, RP-initiated logout with id_token_hint, back-channel logout),
// registered in Zitadel as the fixture project's "e2e-rp" app. It stands in
// for a product so the e2e test needs nothing outside this module.
type relyingParty struct {
	clientID, secret string
	provider         *oidc.Provider
	idTokens         *oidc.IDTokenVerifier
	logoutTokens     *oidc.IDTokenVerifier
	endSession       string

	mu       sync.Mutex
	pending  map[string]rpPending // by state
	sessions map[string]rpSession // by cookie value
}

func randomHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// startRP starts the relying party on :8095 for the duration of the test.
func (s *stack) startRP() {
	t := s.t
	ctx := context.Background()
	provider, err := oidc.NewProvider(ctx, zitadelURL)
	if err != nil {
		t.Fatalf("relying party discovery: %v", err)
	}
	var meta struct {
		EndSession string `json:"end_session_endpoint"`
	}
	_ = provider.Claims(&meta)
	clientID := s.rp.ClientID
	rp := &relyingParty{
		clientID: clientID, secret: s.rp.ClientSecret, provider: provider,
		idTokens: provider.Verifier(&oidc.Config{ClientID: clientID}),
		// Logout tokens carry no nonce and may carry no exp; their events
		// claim is checked by hand.
		logoutTokens: provider.Verifier(&oidc.Config{ClientID: clientID, SkipExpiryCheck: true}),
		endSession:   meta.EndSession,
		pending:      map[string]rpPending{}, sessions: map[string]rpSession{},
	}
	ln, err := net.Listen("tcp", "127.0.0.1:8095")
	if err != nil {
		t.Fatalf("relying party listen: %v", err)
	}
	srv := &http.Server{Handler: rp.routes(), ReadHeaderTimeout: 10 * time.Second}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
}

func (rp *relyingParty) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", rp.home)
	mux.HandleFunc("GET /auth/login", rp.login)
	mux.HandleFunc("GET /auth/callback", rp.callback)
	mux.HandleFunc("POST /auth/logout", rp.logout)
	mux.HandleFunc("POST /auth/backchannel-logout", rp.backchannelLogout)
	return mux
}

func (rp *relyingParty) session(r *http.Request) (string, rpSession, bool) {
	c, err := r.Cookie(rpSessionCookie)
	if err != nil {
		return "", rpSession{}, false
	}
	rp.mu.Lock()
	defer rp.mu.Unlock()
	sess, ok := rp.sessions[c.Value]
	return c.Value, sess, ok
}

func (rp *relyingParty) home(w http.ResponseWriter, r *http.Request) {
	_, sess, ok := rp.session(r)
	if !ok {
		http.Redirect(w, r, "/auth/login", http.StatusSeeOther)
		return
	}
	_ = rpPage.Execute(w, sess)
}

func (rp *relyingParty) login(w http.ResponseWriter, r *http.Request) {
	verifier, challenge := pkce()
	state, nonce := randomHex(16), randomHex(16)
	rp.mu.Lock()
	rp.pending[state] = rpPending{verifier: verifier, nonce: nonce}
	rp.mu.Unlock()
	q := url.Values{"client_id": {rp.clientID}, "response_type": {"code"}, "scope": {"openid profile email"},
		"redirect_uri": {rpURL + "/auth/callback"}, "state": {state}, "nonce": {nonce},
		"code_challenge": {challenge}, "code_challenge_method": {"S256"}}
	http.Redirect(w, r, rp.provider.Endpoint().AuthURL+"?"+q.Encode(), http.StatusSeeOther)
}

func (rp *relyingParty) callback(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	rp.mu.Lock()
	pend, ok := rp.pending[q.Get("state")]
	delete(rp.pending, q.Get("state"))
	rp.mu.Unlock()
	if !ok || q.Get("code") == "" {
		http.Error(w, "invalid callback: "+q.Get("error"), http.StatusBadRequest)
		return
	}
	tok, status := tokenRequest(url.Values{"grant_type": {"authorization_code"}, "code": {q.Get("code")},
		"redirect_uri": {rpURL + "/auth/callback"}, "code_verifier": {pend.verifier}}, rp.clientID, rp.secret)
	if status != http.StatusOK {
		http.Error(w, "token exchange: "+tok.Error, http.StatusBadGateway)
		return
	}
	idt, err := rp.idTokens.Verify(r.Context(), tok.IDToken)
	if err == nil && idt.Nonce != pend.nonce {
		err = errors.New("nonce mismatch")
	}
	var claims struct {
		SID   string `json:"sid"`
		Name  string `json:"name"`
		Email string `json:"email"`
	}
	if err == nil {
		err = idt.Claims(&claims)
	}
	if err != nil {
		http.Error(w, "id token: "+err.Error(), http.StatusBadGateway)
		return
	}
	id := randomHex(32)
	rp.mu.Lock()
	rp.sessions[id] = rpSession{Subject: idt.Subject, SID: claims.SID, Name: claims.Name, Email: claims.Email, IDToken: tok.IDToken}
	rp.mu.Unlock()
	http.SetCookie(w, &http.Cookie{Name: rpSessionCookie, Value: id, Path: "/", HttpOnly: true, SameSite: http.SameSiteLaxMode})
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (rp *relyingParty) logout(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Origin") != rpURL {
		http.Error(w, "cross-origin", http.StatusForbidden)
		return
	}
	target := rpURL + "/"
	if id, sess, ok := rp.session(r); ok {
		rp.mu.Lock()
		delete(rp.sessions, id)
		rp.mu.Unlock()
		if rp.endSession != "" {
			target = rp.endSession + "?" + url.Values{"id_token_hint": {sess.IDToken},
				"post_logout_redirect_uri": {rpURL + "/"}, "client_id": {rp.clientID}}.Encode()
		}
	}
	http.SetCookie(w, &http.Cookie{Name: rpSessionCookie, Value: "", Path: "/", MaxAge: -1})
	http.Redirect(w, r, target, http.StatusSeeOther)
}

func (rp *relyingParty) backchannelLogout(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	lt, err := rp.logoutTokens.Verify(r.Context(), strings.TrimSpace(r.PostForm.Get("logout_token")))
	var claims struct {
		SID    string         `json:"sid"`
		Events map[string]any `json:"events"`
		Nonce  *string        `json:"nonce"`
	}
	if err == nil {
		err = lt.Claims(&claims)
	}
	if err == nil && (claims.Events[backchannelLogoutEvent] == nil || claims.Nonce != nil) {
		err = errors.New("not a logout token")
	}
	if err != nil {
		http.Error(w, "invalid logout token: "+err.Error(), http.StatusBadRequest)
		return
	}
	rp.mu.Lock()
	for id, sess := range rp.sessions {
		if sess.Subject == lt.Subject && (claims.SID == "" || sess.SID == claims.SID) {
			delete(rp.sessions, id)
		}
	}
	rp.mu.Unlock()
	w.WriteHeader(http.StatusOK)
}
