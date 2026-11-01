package web

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/velixio/idlogin/internal/zitadel"
)

func (s *Server) consentView(f *flow, req *zitadel.AuthRequest) view {
	v := view{Title: "Allow " + f.AppName + " to sign in?", Description: fmt.Sprintf("%s wants to use your account as %s.", f.AppName, f.Email), CSRF: f.CSRF, AuthRequest: f.AuthRequest, Email: f.Email}
	labels := map[string]string{"openid": "Sign you in to this app", "profile": "Read your name and profile", "email": "Read your email address", "offline_access": "Keep you signed in"}
	for _, scope := range req.Scope {
		if label, ok := labels[scope]; ok {
			v.Permissions = append(v.Permissions, label)
		} else {
			v.Permissions = append(v.Permissions, "Requested permission: "+scope)
		}
	}
	return v
}

func (s *Server) handleConsentPage(w http.ResponseWriter, r *http.Request) {
	f, ok := s.pageFlow(w, r, stepConsent)
	if !ok {
		return
	}
	req, err := s.api.GetAuthRequest(r.Context(), instance(brandOf(r)), f.AuthRequest)
	if err != nil || req.ClientID != f.ClientID || !req.HasPrompt(zitadel.PromptConsent) || strings.TrimSpace(f.AppName) == "" {
		s.dropFlow(w, brandOf(r), f)
		s.expired(w, r, f.AuthRequest)
		return
	}
	s.render(w, r, http.StatusOK, "consent", s.consentView(f, req))
}

// Consent is per authorization request, never inferred from an earlier app grant.
func (s *Server) handleConsent(w http.ResponseWriter, r *http.Request) {
	f, ok := s.formFlow(w, r)
	if !ok {
		return
	}
	b := brandOf(r)
	if f.Step != stepConsent {
		s.toStep(w, r, f)
		return
	}
	action := r.PostFormValue("action")
	if action != "allow" && action != "deny" {
		http.Error(w, "Choose Allow or Deny.", http.StatusBadRequest)
		return
	}
	req, err := s.api.GetAuthRequest(r.Context(), instance(b), f.AuthRequest)
	if err != nil || req.ClientID != f.ClientID || !req.HasPrompt(zitadel.PromptConsent) {
		s.dropFlow(w, b, f)
		s.expired(w, r, f.AuthRequest)
		return
	}
	if action == "deny" {
		cb, err := s.api.FailAuthRequest(r.Context(), instance(b), f.AuthRequest, zitadel.ErrorAccessDenied, "user declined app sign-in")
		if err != nil || !safeCallback(cb) {
			s.failure(w, r, err, "deny auth request")
			return
		}
		s.dropFlow(w, b, f)
		http.Redirect(w, r, cb, http.StatusSeeOther)
		return
	}
	sess, err := s.api.GetSession(r.Context(), instance(b), f.SessionID)
	if err != nil || sess.Expired(s.now()) || sess.FirstFactorAt().IsZero() || sess.UserID() != f.UserID || !s.sessionFits(r.Context(), b, sess, req, s.now()) {
		s.dropFlow(w, b, f)
		http.Redirect(w, r, "/login"+query(f.AuthRequest), http.StatusSeeOther)
		return
	}
	s.finishAuthRequest(w, r, f)
}
