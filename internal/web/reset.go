package web

import (
	"net/http"
	"strings"

	"github.com/velixio/idlogin/internal/zitadel"
)

// handleResetPage starts a password reset: inside an auth request
// (/reset?authRequest=...), or standalone (/reset?return=<allowlisted URL>)
// for "change password" links from products.
func (s *Server) handleResetPage(w http.ResponseWriter, r *http.Request) {
	b := brandOf(r)
	q := r.URL.Query()
	ar := q.Get("authRequest")
	if ar != "" {
		if !validAuthRequest(ar) {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		f := s.loadFlow(r, b, ar)
		if f == nil {
			s.expired(w, r, ar)
			return
		}
		switch f.Step {
		case stepEmail, stepPassword, stepCode, stepReset:
		default:
			s.toStep(w, r, f)
			return
		}
		if f.Step != stepReset {
			f.Step = stepReset
			// Nothing proven for an earlier account carries over into a reset.
			f.CodeID, f.CodeKind, f.EmailProven, f.ResetOK = "", "", false, false
			f.UserID, f.SessionID, f.SessionTok, f.TOTPFor = "", "", "", ""
			s.saveFlow(w, b, f)
		}
		s.render(w, r, http.StatusOK, "reset", s.resetView(f))
		return
	}
	ret := q.Get("return")
	if ret != "" && !b.AllowedReturn(ret) {
		s.message(w, r, http.StatusBadRequest, "This link is not valid",
			"Open the password page from the app you use and try again.", "", "")
		return
	}
	f := s.loadFlow(r, b, "")
	if f == nil || q.Has("return") || f.Step != stepReset && f.Step != stepResetCode {
		f = newFlow("")
		f.Step = stepReset
		f.Return = ret
		s.saveFlow(w, b, f)
	} else if f.Step == stepResetCode {
		s.toStep(w, r, f)
		return
	}
	s.render(w, r, http.StatusOK, "reset", s.resetView(f))
}

func (s *Server) resetView(f *flow) view {
	return view{Title: "Reset your password", Description: "Enter your email and we'll send you a code to choose a new password.",
		CSRF: f.CSRF, AuthRequest: f.AuthRequest, Email: f.Email, Standalone: f.AuthRequest == "", Link: f.Return}
}

func (s *Server) handleReset(w http.ResponseWriter, r *http.Request) {
	f, ok := s.formFlow(w, r)
	if !ok {
		return
	}
	b := brandOf(r)
	ctx := r.Context()
	if f.Step != stepReset {
		s.toStep(w, r, f)
		return
	}
	email, valid := normalizeEmail(r.PostFormValue("email"))
	if !valid {
		v := s.resetView(f)
		v.Email = strings.TrimSpace(r.PostFormValue("email"))
		v.Error = "Enter a valid email address."
		s.render(w, r, http.StatusOK, "reset", v)
		return
	}
	f.Email = email
	if ok, err := s.store.Allow(ctx, s.limit(s.limits.LookupsPerIP, "lookup:ip:"+s.clientIP(r))); err != nil || !ok {
		v := s.resetView(f)
		v.Error = "Too many attempts. Try again in a few minutes."
		s.render(w, r, http.StatusTooManyRequests, "reset", v)
		return
	}
	if err := s.sendResetCode(r, f); err != nil {
		s.sendError(w, r, f, err, "reset")
		return
	}
	f.Step = stepResetCode
	f.ResetOK = false
	s.saveFlow(w, b, f)
	s.toStep(w, r, f)
}

// sendResetCode mails a reset code when the address belongs to exactly one
// usable account. Otherwise it stores a code that is never sent, so the
// following pages look the same and nobody learns which addresses exist.
func (s *Server) sendResetCode(r *http.Request, f *flow) error {
	b := brandOf(r)
	users, err := s.api.FindUsers(r.Context(), instance(b), f.Email)
	if err != nil {
		return err
	}
	if len(users) == 1 && users[0].Usable() {
		f.UserID = users[0].UserID
		return s.sendCode(r, f, kindReset, f.UserID, true)
	}
	f.UserID = ""
	return s.sendCode(r, f, kindReset, "", false)
}

func (s *Server) resetCodeView(r *http.Request, f *flow) view {
	v := view{Title: "Choose a new password", CSRF: f.CSRF, AuthRequest: f.AuthRequest, Email: f.Email,
		ResetOK: f.ResetOK, CodeMinutes: int(CodeTTL.Minutes())}
	if f.ResetOK {
		v.Description = "Your code is confirmed. Choose your new password."
	} else {
		v.Description = "If " + f.Email + " belongs to an account, we sent it a 6-digit code. Enter it with your new password."
	}
	if pc, err := s.api.PasswordComplexity(r.Context(), instance(brandOf(r))); err == nil {
		v.PasswordHint = pc.Describe()
	}
	return v
}

func (s *Server) handleResetCodePage(w http.ResponseWriter, r *http.Request) {
	f, ok := s.pageFlow(w, r, stepResetCode)
	if !ok {
		return
	}
	s.render(w, r, http.StatusOK, "reset_code", s.resetCodeView(r, f))
}

func (s *Server) handleResetCode(w http.ResponseWriter, r *http.Request) {
	f, ok := s.formFlow(w, r)
	if !ok {
		return
	}
	b := brandOf(r)
	ctx := r.Context()
	in := instance(b)
	if f.Step != stepResetCode {
		s.toStep(w, r, f)
		return
	}
	render := func(status int, msg, info string) {
		v := s.resetCodeView(r, f)
		v.Error, v.Info = msg, info
		s.saveFlow(w, b, f)
		s.render(w, r, status, "reset_code", v)
	}
	if r.PostFormValue("action") == "resend" {
		if f.ResetOK {
			render(http.StatusOK, "", "")
			return
		}
		if err := s.sendResetCode(r, f); err != nil {
			s.sendError(w, r, f, err, "reset_code")
			return
		}
		render(http.StatusOK, "", "A new code is on its way.")
		return
	}
	password, confirm := r.PostFormValue("password"), r.PostFormValue("password_confirm")
	if password == "" || len(password) > 512 {
		render(http.StatusOK, "Enter a new password.", "")
		return
	}
	if password != confirm {
		render(http.StatusOK, "The passwords do not match.", "")
		return
	}
	pc, err := s.api.PasswordComplexity(ctx, in)
	if err == nil {
		if problem := pc.Check(password); problem != "" {
			render(http.StatusOK, problem, "")
			return
		}
	}
	if !f.ResetOK {
		msg, c, err := s.checkCode(r, f, r.PostFormValue("code"))
		if err != nil {
			s.failure(w, r, err, "check code")
			return
		}
		if msg != "" {
			render(http.StatusOK, msg, "")
			return
		}
		if c.UserID == "" || c.UserID != f.UserID {
			render(http.StatusOK, "That code is not right. Check the latest email and try again.", "")
			return
		}
		f.ResetOK, f.EmailProven, f.CodeID = true, true, ""
	}
	zcode, err := s.api.PasswordResetCode(ctx, in, f.UserID)
	if err == nil {
		err = s.api.SetPassword(ctx, in, f.UserID, zcode, password)
	}
	if err != nil {
		if zitadel.IsRejected(err) {
			render(http.StatusOK, "That password can't be used. "+pc.Describe(), "")
			return
		}
		s.failure(w, r, err, "set password")
		return
	}
	res, err := s.api.CreateSession(ctx, in, zitadel.Checks{UserID: f.UserID, Password: password}, s.lifetime(f))
	if err != nil {
		if zitadel.IsRejected(err) {
			s.unavailable(w, r, f)
			return
		}
		s.failure(w, r, err, "session after reset")
		return
	}
	s.log.Info("password reset", "brand", b.ID, "user", f.UserID)
	s.complete(w, r, f, res)
}
