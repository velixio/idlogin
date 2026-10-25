package web

import (
	"context"
	"crypto/rand"
	"fmt"
	"math/big"
	"net/http"
	"net/mail"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/velixio/idlogin/internal/config"
	"github.com/velixio/idlogin/internal/store"
	"github.com/velixio/idlogin/internal/zitadel"
)

// handleLogin is where Zitadel sends the browser: /login?authRequest=V2_...
// It applies prompt / max_age, reuses a valid browser session when allowed,
// and otherwise shows the email-first page.
func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	b := brandOf(r)
	ctx := r.Context()
	ar := r.URL.Query().Get("authRequest")
	if !validAuthRequest(ar) {
		s.message(w, r, http.StatusBadRequest, "Nothing to sign in to",
			"Open the app you want to use and sign in from there.", "", "")
		return
	}
	if f := s.loadFlow(r, b, ar); f != nil {
		s.toStep(w, r, f) // reload or back button: resume
		return
	}
	req, err := s.api.GetAuthRequest(ctx, instance(b), ar)
	if err != nil {
		if zitadel.IsRejected(err) {
			s.expired(w, r, ar)
		} else {
			s.failure(w, r, err, "get auth request")
		}
		return
	}
	f := newFlow(ar)
	if f.Native, err = s.api.AppIsNative(ctx, instance(b), req.ClientID); err != nil {
		// Fail towards a fresh session: never hand the browser's SSO session
		// to an app we could not classify.
		s.log.Warn("app type lookup failed; treating as native", "client", req.ClientID, "error", err)
		f.Native = true
	}
	f.Signup = req.HasPrompt(zitadel.PromptCreate)
	if hint := strings.TrimSpace(req.LoginHint); strings.Contains(hint, "@") {
		f.Email = strings.ToLower(hint)
	}

	interactive := !req.HasPrompt(zitadel.PromptLogin) && !req.HasPrompt(zitadel.PromptSelectAccount) && !f.Signup
	if interactive && f.Native && !req.HasPrompt(zitadel.PromptNone) {
		// A native app never takes the browser's session silently: its
		// redirect can be claimed by any program on the device. A sign-in
		// within NativeApprovalWindow can be handed over with one click.
		if e, ok := s.findSession(w, r, b, req); ok {
			if email, ok := s.approvable(ctx, b, e); ok {
				f.Step, f.SessionID, f.SessionTok, f.UserID, f.Email, f.Remember = stepApprove, e.ID, e.Token, e.UserID, email, e.Remember
				s.saveFlow(w, b, f)
				s.toStep(w, r, f)
				return
			}
		}
	}
	if req.HasPrompt(zitadel.PromptNone) || (interactive && !f.Native) {
		if !f.Native {
			if e, ok := s.findSession(w, r, b, req); ok {
				if cb, err := s.api.FinalizeAuthRequest(ctx, instance(b), ar, e.ID, e.Token); err == nil && safeCallback(cb) {
					if e.Remember {
						cb = withRememberMe(cb)
					}
					http.Redirect(w, r, cb, http.StatusSeeOther)
					return
				} else if err != nil {
					s.log.Info("session reuse failed", "error", err)
				}
			}
		}
		if req.HasPrompt(zitadel.PromptNone) {
			cb, err := s.api.FailAuthRequest(ctx, instance(b), ar, zitadel.ErrorLoginRequired, "no active session")
			if err != nil || !safeCallback(cb) {
				s.failure(w, r, err, "fail auth request")
				return
			}
			http.Redirect(w, r, cb, http.StatusSeeOther)
			return
		}
	}
	if f.Signup && !b.RegistrationEnabled {
		f.Signup = false
		s.saveFlow(w, b, f)
		s.render(w, r, http.StatusOK, "message", view{
			Title:       "Sign in to " + b.Name,
			Description: "New accounts can't be created here right now. If you already have an account, sign in with your email.",
			Link:        "/login/email" + query(ar), LinkLabel: "Continue to sign in",
		})
		return
	}
	s.saveFlow(w, b, f)
	s.render(w, r, http.StatusOK, "email", s.emailView(f, b))
}

func withRememberMe(cb string) string {
	u, err := url.Parse(cb)
	if err != nil || u.Query().Has("error") {
		return cb
	}
	q := u.Query()
	q.Set("remember_me", "1")
	u.RawQuery = q.Encode()
	return u.String()
}

// findSession returns the newest browser session that may answer req: not
// expired, really authenticated (a first factor, not just a user check),
// TOTP done if the user has TOTP, email verified, within max_age, and
// matching login_hint / hint_user_id. Dead sessions are dropped from the
// browser's list.
func (s *Server) findSession(w http.ResponseWriter, r *http.Request, b *config.Brand, req *zitadel.AuthRequest) (browserSession, bool) {
	ctx := r.Context()
	list := s.browserSessions(r, b)
	var keep []browserSession
	var found *browserSession
	for i := range list {
		e := list[i]
		sess, err := s.api.GetSession(ctx, instance(b), e.ID)
		if err != nil {
			if !zitadel.IsNotFound(err) {
				keep = append(keep, e) // outage: keep it, just don't use it now
			}
			continue
		}
		now := s.now()
		if sess.Expired(now) || sess.FirstFactorAt().IsZero() || sess.UserID() == "" {
			continue
		}
		keep = append(keep, e)
		if found != nil || !s.sessionFits(ctx, b, sess, req, now) {
			continue
		}
		found = &list[i]
	}
	if len(keep) != len(list) {
		s.saveBrowserSessions(w, b, keep)
	}
	if found == nil {
		return browserSession{}, false
	}
	return *found, true
}

func (s *Server) sessionFits(ctx context.Context, b *config.Brand, sess *zitadel.Session, req *zitadel.AuthRequest, now time.Time) bool {
	uid := sess.UserID()
	if req.HintUserID != "" && req.HintUserID != uid {
		return false
	}
	if req.MaxAge != nil && now.Sub(sess.AuthTime()) > req.MaxAge.Duration {
		return false
	}
	user, err := s.api.GetUser(ctx, instance(b), uid)
	if err != nil || !user.Usable() || !user.Human.Email.IsVerified {
		return false
	}
	if hint := strings.TrimSpace(req.LoginHint); hint != "" && !strings.EqualFold(hint, user.Email()) &&
		!slices.ContainsFunc(user.LoginNames, func(n string) bool { return strings.EqualFold(n, hint) }) {
		return false
	}
	if !sess.TOTPVerified() {
		methods, err := s.api.AuthMethods(ctx, instance(b), uid)
		if err != nil || slices.Contains(methods, zitadel.MethodTOTP) {
			return false
		}
	}
	return true
}

func (s *Server) handleEmailPage(w http.ResponseWriter, r *http.Request) {
	f, ok := s.pageFlow(w, r, stepEmail)
	if !ok {
		return
	}
	s.render(w, r, http.StatusOK, "email", s.emailView(f, brandOf(r)))
}

func normalizeEmail(raw string) (string, bool) {
	e := strings.ToLower(strings.TrimSpace(raw))
	if len(e) > 254 || strings.ContainsAny(e, " <>\"(),;:\\[]") {
		return "", false
	}
	a, err := mail.ParseAddress(e)
	if err != nil || a.Address != e || !strings.Contains(e[strings.LastIndex(e, "@")+1:], ".") && !strings.HasSuffix(e, "@localhost") {
		return "", false
	}
	return e, true
}

func (s *Server) handleEmail(w http.ResponseWriter, r *http.Request) {
	f, ok := s.formFlow(w, r)
	if !ok {
		return
	}
	b := brandOf(r)
	ctx := r.Context()
	if f.Step != stepEmail {
		s.toStep(w, r, f)
		return
	}
	f.Remember = r.PostFormValue("remember") == "on"
	email, valid := normalizeEmail(r.PostFormValue("email"))
	f.Email = strings.TrimSpace(r.PostFormValue("email"))
	if !valid {
		v := s.emailView(f, b)
		v.Error = "Enter a valid email address."
		s.render(w, r, http.StatusOK, "email", v)
		return
	}
	f.Email = email
	if ok, err := s.store.Allow(ctx, s.limit(s.limits.LookupsPerIP, "lookup:ip:"+s.clientIP(r))); err != nil || !ok {
		v := s.emailView(f, b)
		v.Error = "Too many attempts. Try again in a few minutes."
		s.render(w, r, http.StatusTooManyRequests, "email", v)
		return
	}
	users, err := s.api.FindUsers(ctx, instance(b), email)
	if err != nil {
		s.failure(w, r, err, "find users")
		return
	}
	switch len(users) {
	case 0:
		if !b.RegistrationEnabled {
			s.unavailable(w, r, f)
			return
		}
		s.startCode(w, r, f, kindSignup, "", "email")
	case 1:
		u := users[0]
		if !u.Usable() {
			s.unavailable(w, r, f)
			return
		}
		f.UserID = u.UserID
		methods, err := s.api.AuthMethods(ctx, instance(b), u.UserID)
		if err != nil {
			s.failure(w, r, err, "auth methods")
			return
		}
		if slices.Contains(methods, zitadel.MethodPassword) {
			f.Step = stepPassword
			s.saveFlow(w, b, f)
			s.toStep(w, r, f)
			return
		}
		s.startCode(w, r, f, kindSignin, u.UserID, "email")
	default:
		// The same address on several accounts: we cannot tell which one.
		s.unavailable(w, r, f)
	}
}

func (s *Server) limit(l store.Limit, key string) store.Limit { l.Key = key; return l }

// errTooManyCodes / errSendFailed are user-facing send problems.
type sendProblem string

func (p sendProblem) Error() string { return string(p) }

const (
	errTooManyCodes = sendProblem("Too many codes were sent to this address in the last hour. Try again later.")
	errSendFailed   = sendProblem("We could not send the email. Try again in a moment.")
)

func newCode() string {
	n, err := rand.Int(rand.Reader, big.NewInt(1_000_000))
	if err != nil {
		panic(err)
	}
	return fmt.Sprintf("%06d", n.Int64())
}

// sendCode issues a new code for f.Email (retiring older ones), counts it
// against the per-address and per-IP send limits, and emails it. With
// deliver=false the code is stored but never sent (reset for an unknown
// address), so the pages behave the same either way.
func (s *Server) sendCode(r *http.Request, f *flow, kind, userID string, deliver bool) error {
	b := brandOf(r)
	ctx := r.Context()
	ok, err := s.store.Allow(ctx,
		s.limit(s.limits.SendsPerAddress, "send:addr:"+b.ID+":"+f.Email),
		s.limit(s.limits.SendsPerIP, "send:ip:"+s.clientIP(r)))
	if err != nil {
		return err
	}
	if !ok {
		return errTooManyCodes
	}
	code := newCode()
	id := randomToken(18)
	if !deliver {
		code = randomToken(24) // unguessable, never sent
	}
	if err := s.store.PutCode(ctx, store.Code{
		ID: id, Brand: b.ID, Purpose: kind, Email: f.Email, UserID: userID,
		Hash: s.hashCode(id, code), ExpiresAt: s.now().Add(CodeTTL),
	}); err != nil {
		return err
	}
	f.CodeID, f.CodeKind = id, kind
	if !deliver {
		return nil
	}
	if err := s.mail.Send(ctx, codeMessage(b, kind, f.Email, code)); err != nil {
		s.log.Error("send code", "error", err)
		return errSendFailed
	}
	return nil
}

// startCode sends a code and moves to the code page; on a send problem it
// re-renders the page the user came from.
func (s *Server) startCode(w http.ResponseWriter, r *http.Request, f *flow, kind, userID, from string) {
	b := brandOf(r)
	if err := s.sendCode(r, f, kind, userID, true); err != nil {
		s.sendError(w, r, f, err, from)
		return
	}
	f.Step = stepCode
	s.saveFlow(w, b, f)
	s.toStep(w, r, f)
}

func (s *Server) sendError(w http.ResponseWriter, r *http.Request, f *flow, err error, page string) {
	msg, ok := err.(sendProblem)
	if !ok {
		s.failure(w, r, err, "send code")
		return
	}
	status := http.StatusOK
	if msg == errTooManyCodes {
		status = http.StatusTooManyRequests
	}
	b := brandOf(r)
	var v view
	switch page {
	case "email":
		v = s.emailView(f, b)
	case "password":
		v = s.passwordView(f)
	case "code":
		v = s.codeView(f)
	case "reset":
		v = s.resetView(f)
	case "reset_code":
		v = s.resetCodeView(r, f)
	}
	v.Error = string(msg)
	s.saveFlow(w, b, f)
	s.render(w, r, status, page, v)
}

func (s *Server) passwordView(f *flow) view {
	return view{Title: "Enter your password", Description: "Sign in with your password, or get a code by email.",
		CSRF: f.CSRF, AuthRequest: f.AuthRequest, Email: f.Email}
}

func (s *Server) handlePasswordPage(w http.ResponseWriter, r *http.Request) {
	f, ok := s.pageFlow(w, r, stepPassword)
	if !ok {
		return
	}
	v := s.passwordView(f)
	v.Description = "Sign in with your " + brandOf(r).Name + " password."
	s.render(w, r, http.StatusOK, "password", v)
}

func (s *Server) handlePassword(w http.ResponseWriter, r *http.Request) {
	f, ok := s.formFlow(w, r)
	if !ok {
		return
	}
	b := brandOf(r)
	ctx := r.Context()
	if f.Step != stepPassword {
		s.toStep(w, r, f)
		return
	}
	if r.PostFormValue("action") == "code" {
		s.startCode(w, r, f, kindSignin, f.UserID, "password")
		return
	}
	password := r.PostFormValue("password")
	render := func(status int, msg string) {
		v := s.passwordView(f)
		v.Error = msg
		s.render(w, r, status, "password", v)
	}
	if password == "" || len(password) > 512 {
		render(http.StatusOK, "Enter your password.")
		return
	}
	if ok, err := s.store.Allow(ctx,
		s.limit(s.limits.PasswordPerAccount, "pw:user:"+b.ID+":"+f.UserID),
		s.limit(s.limits.PasswordPerIP, "pw:ip:"+s.clientIP(r))); err != nil || !ok {
		render(http.StatusTooManyRequests, "Too many attempts. Try again in a few minutes, or get a code by email.")
		return
	}
	res, err := s.api.CreateSession(ctx, instance(b), zitadel.Checks{UserID: f.UserID, Password: password}, s.lifetime(f))
	if err != nil {
		if zitadel.IsRejected(err) {
			render(http.StatusOK, "That password is not right.")
			return
		}
		s.failure(w, r, err, "password check")
		return
	}
	s.complete(w, r, f, res)
}

func (s *Server) lifetime(f *flow) time.Duration {
	if f.Remember {
		return SessionLifetimeRemember
	}
	return SessionLifetime
}

func (s *Server) codeView(f *flow) view {
	v := view{Title: "Check your email", CSRF: f.CSRF, AuthRequest: f.AuthRequest, Email: f.Email,
		CodeKind: f.CodeKind, CodeMinutes: int(CodeTTL / time.Minute)}
	v.Description = fmt.Sprintf("We sent a 6-digit code to %s. It works once and expires in %d minutes.", f.Email, v.CodeMinutes)
	switch f.CodeKind {
	case kindSignup:
		v.Description += " Entering it creates your account."
	case kindVerify:
		v.Title = "Verify your email"
		v.Description = fmt.Sprintf("Confirm your email address to continue. We sent a 6-digit code to %s. It expires in %d minutes.", f.Email, v.CodeMinutes)
	}
	return v
}

func (s *Server) handleCodePage(w http.ResponseWriter, r *http.Request) {
	f, ok := s.pageFlow(w, r, stepCode)
	if !ok {
		return
	}
	s.render(w, r, http.StatusOK, "code", s.codeView(f))
}

func validCodeFormat(c string) bool {
	if len(c) != CodeDigits {
		return false
	}
	for _, ch := range c {
		if ch < '0' || ch > '9' {
			return false
		}
	}
	return true
}

// checkCode spends one attempt on the flow's code. It returns the message to
// show, or "" when the code was right.
func (s *Server) checkCode(r *http.Request, f *flow, code string) (string, *store.Code, error) {
	b := brandOf(r)
	ctx := r.Context()
	code = strings.ReplaceAll(strings.TrimSpace(code), " ", "")
	if !validCodeFormat(code) {
		return "Enter the 6-digit code from the email.", nil, nil
	}
	if ok, err := s.store.Allow(ctx, s.limit(s.limits.CodeChecksPerIP, "code:ip:"+s.clientIP(r))); err != nil || !ok {
		return "Too many attempts. Try again in a few minutes.", nil, err
	}
	want := s.hashCode(f.CodeID, code)
	res, c, err := s.store.CheckCode(ctx, f.CodeID, func(stored []byte) bool { return ctEqual(string(stored), string(want)) }, CodeMaxAttempts)
	if err != nil {
		return "", nil, err
	}
	switch res {
	case store.CodeOK:
		if c.Brand != b.ID || c.Purpose != f.CodeKind || c.Email != f.Email {
			return "That code is not right. Check the latest email and try again.", nil, nil
		}
		return "", c, nil
	case store.CodeWrong:
		return "That code is not right. Check the latest email and try again.", nil, nil
	case store.CodeLocked:
		return "Too many wrong attempts for this code. Send a new code.", nil, nil
	case store.CodeExpired:
		return "That code has expired. Send a new code.", nil, nil
	}
	return "That code is no longer valid. Send a new code.", nil, nil
}

func (s *Server) handleCode(w http.ResponseWriter, r *http.Request) {
	f, ok := s.formFlow(w, r)
	if !ok {
		return
	}
	b := brandOf(r)
	ctx := r.Context()
	if f.Step != stepCode {
		s.toStep(w, r, f)
		return
	}
	if r.PostFormValue("action") == "resend" {
		if err := s.sendCode(r, f, f.CodeKind, f.UserID, true); err != nil {
			s.sendError(w, r, f, err, "code")
			return
		}
		s.saveFlow(w, b, f)
		v := s.codeView(f)
		v.Info = "A new code is on its way."
		s.render(w, r, http.StatusOK, "code", v)
		return
	}
	msg, _, err := s.checkCode(r, f, r.PostFormValue("code"))
	if err != nil {
		s.failure(w, r, err, "check code")
		return
	}
	if msg != "" {
		v := s.codeView(f)
		v.Error = msg
		s.render(w, r, http.StatusOK, "code", v)
		return
	}
	f.EmailProven = true
	f.CodeID = ""
	switch f.CodeKind {
	case kindVerify:
		// First factor (and TOTP) already done; the session is in the flow.
		s.complete(w, r, f, &zitadel.SessionResult{SessionID: f.SessionID, SessionToken: f.SessionTok})
		return
	case kindSignup:
		uid, done := s.signupUser(w, r, f)
		if !done {
			return
		}
		f.UserID = uid
	}
	res, err := s.codeSession(ctx, b, f.UserID, s.lifetime(f))
	if err != nil {
		if zitadel.IsRejected(err) {
			s.unavailable(w, r, f)
			return
		}
		s.failure(w, r, err, "code session")
		return
	}
	s.complete(w, r, f, res)
}

// codeSession creates a Zitadel session for a user who has just proven
// their email with our code. Zitadel needs a verified factor for that: the
// user gets the email-code factor, and the session's OTP-email challenge is
// requested with returnCode and answered right away (nothing is mailed by
// Zitadel; our own code was the real check).
func (s *Server) codeSession(ctx context.Context, b *config.Brand, userID string, lifetime time.Duration) (*zitadel.SessionResult, error) {
	in := instance(b)
	if err := s.api.AddOTPEmail(ctx, in, userID); err != nil {
		return nil, err
	}
	res, err := s.api.CreateSession(ctx, in, zitadel.Checks{UserID: userID, OTPEmailCode: true}, lifetime)
	if err != nil {
		return nil, err
	}
	if res.OTPEmailCode == "" {
		return nil, fmt.Errorf("zitadel returned no email OTP challenge")
	}
	return s.api.SetSession(ctx, in, res.SessionID, res.SessionToken, zitadel.Checks{OTPEmail: res.OTPEmailCode})
}

// signupUser creates the account after the sign-up code succeeded: email
// verified, no password. If the address got an account in the meantime, that
// account is used (the code proved ownership of the address).
func (s *Server) signupUser(w http.ResponseWriter, r *http.Request, f *flow) (string, bool) {
	b := brandOf(r)
	ctx := r.Context()
	users, err := s.api.FindUsers(ctx, instance(b), f.Email)
	if err != nil {
		s.failure(w, r, err, "find users")
		return "", false
	}
	if len(users) == 1 {
		if !users[0].Usable() {
			s.unavailable(w, r, f)
			return "", false
		}
		return users[0].UserID, true
	}
	if len(users) > 1 || !b.RegistrationEnabled {
		s.unavailable(w, r, f)
		return "", false
	}
	local := f.Email[:strings.LastIndex(f.Email, "@")]
	if len(local) > 200 {
		local = local[:200]
	}
	uid, err := s.api.CreateHuman(ctx, instance(b), zitadel.NewHuman{
		OrgID: b.OrgID, Username: f.Email, GivenName: local, FamilyName: local, DisplayName: local,
		Email: f.Email, EmailVerified: true,
	})
	if zitadel.IsAlreadyExists(err) {
		if users, err2 := s.api.FindUsers(ctx, instance(b), f.Email); err2 == nil && len(users) == 1 && users[0].Usable() {
			return users[0].UserID, true
		}
	}
	if err != nil {
		s.failure(w, r, err, "create user")
		return "", false
	}
	s.log.Info("account created", "brand", b.ID, "user", uid)
	return uid, true
}

func (s *Server) handleTOTPPage(w http.ResponseWriter, r *http.Request) {
	f, ok := s.pageFlow(w, r, stepTOTP)
	if !ok {
		return
	}
	s.render(w, r, http.StatusOK, "totp", s.totpView(f))
}

func (s *Server) totpView(f *flow) view {
	return view{Title: "Two-step verification", Description: "Enter the current code from your authenticator app.",
		CSRF: f.CSRF, AuthRequest: f.AuthRequest}
}

func (s *Server) handleTOTP(w http.ResponseWriter, r *http.Request) {
	f, ok := s.formFlow(w, r)
	if !ok {
		return
	}
	b := brandOf(r)
	ctx := r.Context()
	if f.Step != stepTOTP {
		s.toStep(w, r, f)
		return
	}
	render := func(status int, msg string) {
		v := s.totpView(f)
		v.Error = msg
		s.render(w, r, status, "totp", v)
	}
	code := strings.ReplaceAll(strings.TrimSpace(r.PostFormValue("otp")), " ", "")
	if !validCodeFormat(code) {
		render(http.StatusOK, "Enter the 6-digit code from your authenticator app.")
		return
	}
	if ok, err := s.store.Allow(ctx, s.limit(s.limits.TOTPPerAccount, "totp:user:"+b.ID+":"+f.UserID)); err != nil || !ok {
		render(http.StatusTooManyRequests, "Too many attempts. Try again in a few minutes.")
		return
	}
	res, err := s.api.SetSession(ctx, instance(b), f.SessionID, f.SessionTok, zitadel.Checks{TOTP: code})
	if err != nil {
		if zitadel.IsRejected(err) {
			render(http.StatusOK, "That code is not right. Try the current code.")
			return
		}
		s.failure(w, r, err, "totp check")
		return
	}
	f.TOTPFor = totpKey(f.UserID, f.SessionID)
	s.complete(w, r, f, res)
}

// handleRestart is "Use a different email": back to the first step of the
// flow, keeping the auth request.
func (s *Server) handleRestart(w http.ResponseWriter, r *http.Request) {
	f, ok := s.formFlow(w, r)
	if !ok {
		return
	}
	n := newFlow(f.AuthRequest)
	n.CSRF, n.Remember, n.Native, n.Return = f.CSRF, f.Remember, f.Native, f.Return
	if r.PostFormValue("to") == stepReset || f.AuthRequest == "" {
		n.Step = stepReset
	}
	s.saveFlow(w, brandOf(r), n)
	s.toStep(w, r, n)
}

// complete runs after a first factor succeeded: TOTP if the user has it,
// email verification if the address is unverified, then finalises the auth
// request (or, for a standalone reset, returns to the product).
func (s *Server) complete(w http.ResponseWriter, r *http.Request, f *flow, res *zitadel.SessionResult) {
	b := brandOf(r)
	ctx := r.Context()
	in := instance(b)
	f.SessionID, f.SessionTok = res.SessionID, res.SessionToken
	if !f.totpDone() {
		methods, err := s.api.AuthMethods(ctx, in, f.UserID)
		if err != nil {
			s.failure(w, r, err, "auth methods")
			return
		}
		if slices.Contains(methods, zitadel.MethodTOTP) {
			f.Step = stepTOTP
			s.saveFlow(w, b, f)
			s.toStep(w, r, f)
			return
		}
		f.TOTPFor = totpKey(f.UserID, f.SessionID)
	}
	user, err := s.api.GetUser(ctx, in, f.UserID)
	if err != nil {
		s.failure(w, r, err, "get user")
		return
	}
	if !user.Usable() {
		s.unavailable(w, r, f)
		return
	}
	if !user.Human.Email.IsVerified {
		email := strings.ToLower(user.Email())
		if f.EmailProven && email == f.Email {
			if err := s.api.MarkEmailVerified(ctx, in, f.UserID, user.Email()); err != nil {
				s.failure(w, r, err, "verify email")
				return
			}
		} else {
			f.Email = email
			f.EmailProven = false
			if err := s.sendCode(r, f, kindVerify, f.UserID, true); err != nil {
				s.sendError(w, r, f, err, "email")
				return
			}
			f.Step = stepCode
			s.saveFlow(w, b, f)
			s.toStep(w, r, f)
			return
		}
	}
	entry := browserSession{ID: f.SessionID, Token: f.SessionTok, UserID: f.UserID, Remember: f.Remember}
	if f.AuthRequest == "" {
		// Standalone password reset: the browser is now signed in.
		s.rememberSession(w, r, b, entry)
		s.dropFlow(w, b, f)
		if f.Return != "" && b.AllowedReturn(f.Return) {
			http.Redirect(w, r, f.Return, http.StatusSeeOther)
			return
		}
		s.message(w, r, http.StatusOK, "Password changed", "Your new password is set. You can close this page.", "", "")
		return
	}
	cb, err := s.api.FinalizeAuthRequest(ctx, in, f.AuthRequest, f.SessionID, f.SessionTok)
	if err != nil || !safeCallback(cb) {
		if err != nil && zitadel.IsRejected(err) {
			s.dropFlow(w, b, f)
			s.expired(w, r, f.AuthRequest)
			return
		}
		s.failure(w, r, err, "finalize auth request")
		return
	}
	if !f.Native {
		s.rememberSession(w, r, b, entry)
	}
	if f.Remember {
		cb = withRememberMe(cb)
	}
	s.dropFlow(w, b, f)
	http.Redirect(w, r, cb, http.StatusSeeOther)
}
