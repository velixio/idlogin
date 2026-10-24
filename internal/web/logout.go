package web

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"net/http"
	"strings"
	"time"

	"github.com/velixio/idlogin/internal/config"
)

// logoutState is the sealed state of the logout confirmation page.
type logoutState struct {
	CSRF   string `json:"csrf"`
	Target string `json:"t,omitempty"`
}

const logoutCookie = "idl-logout"

// handleLogout is Zitadel's end-session landing page:
// /logout?post_logout_redirect=...&logout_token=<JWT>. A valid logout token
// (signed by the instance) proves Zitadel sent the browser here as part of an
// RP-initiated logout, so this browser's sessions end right away and the
// browser continues to the (Zitadel-validated) redirect. Without it, the
// page asks for confirmation and only redirects to allowlisted URLs.
func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	b := brandOf(r)
	q := r.URL.Query()
	redirect := q.Get("post_logout_redirect")
	target := ""
	trusted := false
	if tok := q.Get("logout_token"); tok != "" {
		if claims, err := s.verifyLogoutToken(r.Context(), b, tok); err == nil {
			trusted = true
			if claims.PostLogoutRedirectURI != "" && claims.PostLogoutRedirectURI == redirect {
				target = redirect
			}
		} else {
			s.log.Info("logout token rejected", "error", err)
		}
	}
	if target == "" && b.AllowedReturn(redirect) {
		target = redirect
	}
	if target == "/logout/done" {
		target = ""
	}
	if trusted {
		s.endBrowserSessions(w, r, b)
		s.afterLogout(w, r, target)
		return
	}
	st := logoutState{CSRF: randomToken(32), Target: target}
	s.setCookie(w, b, logoutCookie, st, 15*time.Minute)
	s.render(w, r, http.StatusOK, "logout", view{Title: "Sign out", Description: "Sign out of " + b.Name + " on this device?", CSRF: st.CSRF})
}

func (s *Server) handleLogoutConfirm(w http.ResponseWriter, r *http.Request) {
	b := brandOf(r)
	var st logoutState
	if !s.readCookie(r, b, logoutCookie, &st) || !ctEqual(r.PostFormValue("csrf"), st.CSRF) {
		http.Error(w, "invalid form token; reload the page and try again", http.StatusForbidden)
		return
	}
	s.clearCookie(w, b, logoutCookie)
	s.endBrowserSessions(w, r, b)
	s.afterLogout(w, r, st.Target)
}

func (s *Server) afterLogout(w http.ResponseWriter, r *http.Request, target string) {
	if target != "" && safeCallback(target) {
		http.Redirect(w, r, target, http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, "/logout/done", http.StatusSeeOther)
}

func (s *Server) handleLogoutDone(w http.ResponseWriter, r *http.Request) {
	s.message(w, r, http.StatusOK, "You're signed out", "You have been signed out on this device. You can close this page.", "", "")
}

// endBrowserSessions terminates every Zitadel session this browser holds
// (Zitadel then sends back-channel logouts to the apps) and clears the list.
func (s *Server) endBrowserSessions(w http.ResponseWriter, r *http.Request, b *config.Brand) {
	for _, e := range s.browserSessions(r, b) {
		if err := s.api.DeleteSession(r.Context(), instance(b), e.ID, e.Token); err != nil {
			s.log.Warn("terminate session", "session", e.ID, "error", err)
		}
	}
	s.saveBrowserSessions(w, b, nil)
}

type logoutClaims struct {
	PostLogoutRedirectURI string `json:"post_logout_redirect_uri"`
	LogoutHint            string `json:"logout_hint"`
}

type jwksEntry struct {
	keys    map[string]crypto.PublicKey
	fetched time.Time
}

func (s *Server) keys(ctx context.Context, b *config.Brand, refresh bool) (map[string]crypto.PublicKey, error) {
	s.jwksMu.Lock()
	e, ok := s.jwks[b.ID]
	s.jwksMu.Unlock()
	if ok && !refresh && s.now().Sub(e.fetched) < 10*time.Minute {
		return e.keys, nil
	}
	if ok && refresh && s.now().Sub(e.fetched) < 10*time.Second {
		return e.keys, nil
	}
	raw, err := s.api.SigningKeys(ctx, instance(b))
	if err != nil {
		return nil, err
	}
	keys, err := parseJWKS(raw)
	if err != nil {
		return nil, err
	}
	s.jwksMu.Lock()
	s.jwks[b.ID] = jwksEntry{keys: keys, fetched: s.now()}
	s.jwksMu.Unlock()
	return keys, nil
}

func parseJWKS(raw []byte) (map[string]crypto.PublicKey, error) {
	var set struct {
		Keys []struct {
			Kty, Kid, Use, Alg, N, E, Crv, X, Y string
		} `json:"keys"`
	}
	if err := json.Unmarshal(raw, &set); err != nil {
		return nil, err
	}
	out := map[string]crypto.PublicKey{}
	dec := base64.RawURLEncoding.DecodeString
	for _, k := range set.Keys {
		switch k.Kty {
		case "RSA":
			n, err1 := dec(k.N)
			e, err2 := dec(k.E)
			if err1 != nil || err2 != nil || len(e) > 4 {
				continue
			}
			out[k.Kid] = &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: int(new(big.Int).SetBytes(e).Int64())}
		case "EC":
			if k.Crv != "P-256" {
				continue
			}
			x, err1 := dec(k.X)
			y, err2 := dec(k.Y)
			if err1 != nil || err2 != nil {
				continue
			}
			out[k.Kid] = &ecdsa.PublicKey{Curve: elliptic.P256(), X: new(big.Int).SetBytes(x), Y: new(big.Int).SetBytes(y)}
		}
	}
	return out, nil
}

// verifyLogoutToken checks the JWS Zitadel puts on the logout redirect
// (RS256 or ES256, instance signing keys).
func (s *Server) verifyLogoutToken(ctx context.Context, b *config.Brand, tok string) (*logoutClaims, error) {
	parts := strings.Split(tok, ".")
	if len(parts) != 3 || len(tok) > 8192 {
		return nil, errors.New("malformed token")
	}
	hb, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, err
	}
	var hdr struct{ Alg, Kid string }
	if err := json.Unmarshal(hb, &hdr); err != nil {
		return nil, err
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, err
	}
	keys, err := s.keys(ctx, b, false)
	if err != nil {
		return nil, err
	}
	key, ok := keys[hdr.Kid]
	if !ok {
		if keys, err = s.keys(ctx, b, true); err != nil {
			return nil, err
		}
		if key, ok = keys[hdr.Kid]; !ok {
			return nil, errors.New("unknown key")
		}
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	switch k := key.(type) {
	case *rsa.PublicKey:
		if hdr.Alg != "RS256" || rsa.VerifyPKCS1v15(k, crypto.SHA256, digest[:], sig) != nil {
			return nil, errors.New("bad signature")
		}
	case *ecdsa.PublicKey:
		if hdr.Alg != "ES256" || len(sig) != 64 ||
			!ecdsa.Verify(k, digest[:], new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])) {
			return nil, errors.New("bad signature")
		}
	default:
		return nil, errors.New("unsupported key")
	}
	pb, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, err
	}
	var c logoutClaims
	if err := json.Unmarshal(pb, &c); err != nil {
		return nil, err
	}
	return &c, nil
}
