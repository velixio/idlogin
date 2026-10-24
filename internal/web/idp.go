package web

import (
	"net/http"
	"net/url"
	"strings"

	"github.com/velixio/idlogin/internal/zitadel"
)

// handleIDPStart starts a Zitadel IdP intent (Google, GitHub, ...). The
// success URL carries a random state bound to the flow cookie, so a callback
// can only finish the flow that started it.
func (s *Server) handleIDPStart(w http.ResponseWriter, r *http.Request) {
	f, ok := s.formFlow(w, r)
	if !ok {
		return
	}
	b := brandOf(r)
	idp, ok := b.IDP(r.PostFormValue("provider"))
	if !ok || f.Step != stepEmail {
		s.toStep(w, r, f)
		return
	}
	f.IDPState, f.IDPKey = randomToken(18), idp.Key
	f.Remember = r.PostFormValue("remember") == "on" || f.Remember
	q := url.Values{"state": {f.IDPState}}
	if f.AuthRequest != "" {
		q.Set("authRequest", f.AuthRequest)
	}
	success := b.PublicOrigin + "/login/idp/callback?" + q.Encode()
	failure := b.PublicOrigin + "/login/idp/failure?" + q.Encode()
	authURL, err := s.api.StartIDPIntent(r.Context(), instance(b), idp.ID, success, failure)
	if err != nil {
		s.failure(w, r, err, "start idp intent")
		return
	}
	u, err := url.Parse(authURL)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
		s.failure(w, r, err, "idp auth url")
		return
	}
	s.saveFlow(w, b, f)
	http.Redirect(w, r, authURL, http.StatusSeeOther)
}

func (s *Server) idpFlow(w http.ResponseWriter, r *http.Request) (*flow, bool) {
	b := brandOf(r)
	q := r.URL.Query()
	ar := q.Get("authRequest")
	if ar != "" && !validAuthRequest(ar) {
		http.Error(w, "bad request", http.StatusBadRequest)
		return nil, false
	}
	f := s.loadFlow(r, b, ar)
	if f == nil {
		s.expired(w, r, ar)
		return nil, false
	}
	if f.IDPState == "" || !ctEqual(q.Get("state"), f.IDPState) {
		http.Error(w, "this sign-in response does not belong to this browser", http.StatusForbidden)
		return nil, false
	}
	return f, true
}

func (s *Server) handleIDPFailure(w http.ResponseWriter, r *http.Request) {
	f, ok := s.idpFlow(w, r)
	if !ok {
		return
	}
	b := brandOf(r)
	label := f.IDPKey
	if p, ok := b.IDP(f.IDPKey); ok {
		label = p.Label
	}
	s.log.Info("idp failure", "idp", f.IDPKey, "error", r.URL.Query().Get("error"))
	f.IDPState, f.IDPKey, f.Step = "", "", stepEmail
	s.saveFlow(w, b, f)
	v := s.emailView(f, b)
	v.Error = "Signing in with " + label + " did not work. Try again or use your email."
	s.render(w, r, http.StatusOK, "email", v)
}

// handleIDPCallback finishes an intent: an already linked user signs in; a
// provider-verified email links to the existing user with that email;
// otherwise a new user is created when registration is open.
func (s *Server) handleIDPCallback(w http.ResponseWriter, r *http.Request) {
	f, ok := s.idpFlow(w, r)
	if !ok {
		return
	}
	b := brandOf(r)
	ctx := r.Context()
	in := instance(b)
	q := r.URL.Query()
	id, token := q.Get("id"), q.Get("token")
	f.IDPState = ""
	idp, _ := b.IDP(f.IDPKey)
	it, err := s.api.RetrieveIDPIntent(ctx, in, id, token)
	if err != nil {
		s.saveFlow(w, b, f)
		if zitadel.IsRejected(err) {
			v := s.emailView(f, b)
			v.Error = "Signing in with " + idp.Label + " did not work. Try again or use your email."
			s.render(w, r, http.StatusOK, "email", v)
			return
		}
		s.failure(w, r, err, "retrieve intent")
		return
	}
	if idp.ID != "" && it.IDPID != "" && it.IDPID != idp.ID {
		http.Error(w, "unexpected identity provider", http.StatusForbidden)
		return
	}
	email := strings.ToLower(strings.TrimSpace(it.Email))
	uid := it.UserID
	link := zitadel.IDPLink{IDPID: it.IDPID, UserID: it.ExtID, UserName: it.ExtName}
	if uid == "" {
		var users []zitadel.User
		if email != "" {
			if users, err = s.api.FindUsers(ctx, in, email); err != nil {
				s.failure(w, r, err, "find users")
				return
			}
		}
		switch {
		case len(users) == 1 && it.Verified:
			if !users[0].Usable() {
				s.unavailable(w, r, f)
				return
			}
			uid = users[0].UserID
			if err := s.api.AddIDPLink(ctx, in, uid, link); err != nil {
				s.failure(w, r, err, "link idp")
				return
			}
		// A new account needs a provider-verified email, like linking does.
		// Otherwise anyone could create an account under someone else's
		// address with their own provider login attached; the owner would
		// later prove the email by code and inherit the attacker's link.
		case len(users) == 0 && b.RegistrationEnabled && email != "" && it.Verified:
			if _, valid := normalizeEmail(email); !valid {
				s.unavailable(w, r, f)
				return
			}
			local := email[:strings.LastIndex(email, "@")]
			given, family, display := firstNonEmpty(it.Given, local), firstNonEmpty(it.Family, local), firstNonEmpty(it.Display, it.Given, local)
			uid, err = s.api.CreateHuman(ctx, in, zitadel.NewHuman{
				OrgID: b.OrgID, Username: email, GivenName: given, FamilyName: family, DisplayName: display,
				Email: email, EmailVerified: true, IDPLinks: []zitadel.IDPLink{link},
			})
			if err != nil {
				if zitadel.IsAlreadyExists(err) {
					s.unavailable(w, r, f)
					return
				}
				s.failure(w, r, err, "create user from idp")
				return
			}
			s.log.Info("account created", "brand", b.ID, "user", uid, "idp", f.IDPKey)
		default:
			// Unverified email (for linking or sign-up), no email, or registration closed.
			s.unavailable(w, r, f)
			return
		}
	} else if u, err := s.api.GetUser(ctx, in, uid); err != nil || !u.Usable() {
		if err != nil && !zitadel.IsRejected(err) {
			s.failure(w, r, err, "get user")
			return
		}
		s.unavailable(w, r, f)
		return
	}
	res, err := s.api.CreateSession(ctx, in, zitadel.Checks{UserID: uid, IntentID: id, IntentToken: token}, s.lifetime(f))
	if err != nil {
		if zitadel.IsRejected(err) {
			s.unavailable(w, r, f)
			return
		}
		s.failure(w, r, err, "idp session")
		return
	}
	f.UserID = uid
	if u, err := s.api.GetUser(ctx, in, uid); err == nil {
		f.Email = strings.ToLower(u.Email())
		f.EmailProven = it.Verified && email != "" && email == f.Email
	}
	s.complete(w, r, f, res)
}

func firstNonEmpty(v ...string) string {
	for _, s := range v {
		if s = strings.TrimSpace(s); s != "" {
			return s
		}
	}
	return ""
}
