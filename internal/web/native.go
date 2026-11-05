package web

import (
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"strings"

	"github.com/velixio/idlogin/internal/config"
	"github.com/velixio/idlogin/internal/zitadel"
)

// The JSON sign-in API lets an allowlisted first-party native app show its own
// email and code screens. The app starts a normal OIDC request with PKCE and
// reads the auth request ID from the redirect; the response here carries the
// callback URL the browser would have been sent to, and the app redeems it
// with its PKCE verifier. Everyone gets an email code, even with a password:
// these apps never ask for one. TOTP is still enforced. It uses the same code
// store, attempt counters and rate limits as the pages, and no cookies.
const nativePrefix = "/login/native/"

// Error codes of the API. Apps translate them; the server sends no display text.
const (
	nativeInvalidEmail     = "invalid_email"
	nativeRateLimited      = "rate_limited"
	nativeWrongCode        = "wrong_code"
	nativeCodeLocked       = "code_locked"
	nativeCodeExpired      = "code_expired"
	nativeUnavailable      = "unavailable"
	nativeExpired          = "expired"
	nativeClientNotAllowed = "client_not_allowed"
	nativeSendFailed       = "send_failed"
	nativeTemporary        = "temporary"
)

// nativeRetryAfter is what a rate-limited app is told, in seconds.
const nativeRetryAfter = "300"

// nativeRequest refuses anything a browser would send, so a web page cannot
// drive this cookie-free API with a visitor's IP or address.
func nativeRequest(r *http.Request) bool {
	if r.Header.Get("Origin") != "" || r.Header.Get("Referer") != "" || r.Header.Get("Sec-Fetch-Site") != "" {
		return false
	}
	return strings.HasPrefix(strings.ToLower(r.Header.Get("Content-Type")), "application/json")
}

type nativeResponse struct {
	Step     string `json:"step,omitempty"`
	Flow     string `json:"flow,omitempty"`
	Callback string `json:"callback,omitempty"`
	Error    string `json:"error,omitempty"`
}

// nativeJSON writes one API response with the given status.
func nativeJSON(w http.ResponseWriter, status int, v nativeResponse) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// nativeFail writes an API error code with its matching status.
func nativeFail(w http.ResponseWriter, code string) {
	status := http.StatusUnprocessableEntity
	switch code {
	case nativeRateLimited:
		status = http.StatusTooManyRequests
		w.Header().Set("Retry-After", nativeRetryAfter)
	case nativeExpired:
		status = http.StatusGone
	case nativeClientNotAllowed, nativeUnavailable:
		status = http.StatusForbidden
	case nativeTemporary:
		status = http.StatusServiceUnavailable
	}
	nativeJSON(w, status, nativeResponse{Error: code})
}

// nativeFlowPurpose scopes sealed API flows to the brand, apart from browser cookies.
func nativeFlowPurpose(b *config.Brand) string { return "idl-native-flow:" + b.ID }

// nativeStep answers with the next step and the flow that continues it. The
// flow is sealed under its own purpose, so it cannot stand in for a cookie.
func (s *Server) nativeStep(w http.ResponseWriter, r *http.Request, f *flow, step string) {
	b := brandOf(r)
	f.Step = step
	sealed, err := s.sealer.Seal(nativeFlowPurpose(b), f, flowTTL)
	if err != nil {
		s.log.Error("seal native flow", "error", err)
		nativeFail(w, nativeTemporary)
		return
	}
	nativeJSON(w, http.StatusOK, nativeResponse{Step: step, Flow: sealed})
}

// nativeBody decodes the JSON request body, answering the request itself when it can't.
func nativeBody(w http.ResponseWriter, r *http.Request, v any) bool {
	if err := json.NewDecoder(r.Body).Decode(v); err != nil {
		nativeJSON(w, http.StatusBadRequest, nativeResponse{Error: nativeExpired})
		return false
	}
	return true
}

// nativeFlow opens the flow a request continues and checks its step and client.
func (s *Server) nativeFlow(w http.ResponseWriter, r *http.Request, sealed, step string) (*flow, bool) {
	b := brandOf(r)
	var f flow
	if s.sealer.Open(nativeFlowPurpose(b), sealed, &f) != nil || f.Step != step || !f.Native {
		nativeFail(w, nativeExpired)
		return nil, false
	}
	if !slices.Contains(b.NativeAPIClients, f.ClientID) {
		nativeFail(w, nativeClientNotAllowed)
		return nil, false
	}
	return &f, true
}

// nativeSendFailure maps a failure to send a code to its API error.
func (s *Server) nativeSendFailure(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, errTooManyCodes):
		nativeFail(w, nativeRateLimited)
	case errors.Is(err, errSendFailed):
		nativeFail(w, nativeSendFailed)
	default:
		s.log.Error("native send code", "error", err)
		nativeFail(w, nativeTemporary)
	}
}

// sendNativeCode mails a code, except to a configured review login, whose fixed
// code goes through the same store, attempt counter and limits unsent. Only this
// API reads review logins: the pages always mail a random code.
func (s *Server) sendNativeCode(r *http.Request, f *flow, kind string) error {
	if code, ok := brandOf(r).ReviewLogins[f.Email]; ok {
		return s.issueCode(r, f, kind, f.UserID, code, false)
	}
	return s.sendCode(r, f, kind, f.UserID, true)
}

// handleNativeStart begins sign-in for an email and sends its first code.
func (s *Server) handleNativeStart(w http.ResponseWriter, r *http.Request) {
	var in struct {
		AuthRequest string `json:"auth_request"`
		Email       string `json:"email"`
	}
	if !nativeBody(w, r, &in) {
		return
	}
	b := brandOf(r)
	ctx := r.Context()
	if !validAuthRequest(in.AuthRequest) {
		nativeFail(w, nativeExpired)
		return
	}
	req, err := s.api.GetAuthRequest(ctx, instance(b), in.AuthRequest)
	if err != nil {
		if zitadel.IsRejected(err) {
			nativeFail(w, nativeExpired)
		} else {
			s.log.Error("native get auth request", "error", err)
			nativeFail(w, nativeTemporary)
		}
		return
	}
	if !slices.Contains(b.NativeAPIClients, req.ClientID) {
		nativeFail(w, nativeClientNotAllowed)
		return
	}
	app, err := s.api.GetApplication(ctx, instance(b), req.ClientID)
	if err != nil {
		s.log.Error("native get application", "error", err)
		nativeFail(w, nativeTemporary)
		return
	}
	if !app.Native {
		nativeFail(w, nativeClientNotAllowed)
		return
	}
	email, valid := normalizeEmail(in.Email)
	if !valid {
		nativeFail(w, nativeInvalidEmail)
		return
	}
	if ok, err := s.store.Allow(ctx, s.limit(s.limits.LookupsPerIP, "lookup:ip:"+s.clientIP(r))); err != nil || !ok {
		nativeFail(w, nativeRateLimited)
		return
	}
	users, err := s.api.FindUsers(ctx, instance(b), email)
	if err != nil {
		s.log.Error("native find users", "error", err)
		nativeFail(w, nativeTemporary)
		return
	}
	f := newFlow(in.AuthRequest)
	f.Native, f.ClientID, f.AppName, f.Email = true, req.ClientID, app.Name, email
	kind := kindSignup
	switch {
	case len(users) == 0 && b.RegistrationEnabled:
	case len(users) == 1 && users[0].Usable():
		kind, f.UserID = kindSignin, users[0].UserID
	default:
		// Same answer for a closed registration, a disabled account and an
		// address shared by several accounts.
		nativeFail(w, nativeUnavailable)
		return
	}
	if err := s.sendNativeCode(r, f, kind); err != nil {
		s.nativeSendFailure(w, err)
		return
	}
	s.nativeStep(w, r, f, stepCode)
}

// handleNativeResend sends a new code for a flow waiting on one.
func (s *Server) handleNativeResend(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Flow string `json:"flow"`
	}
	if !nativeBody(w, r, &in) {
		return
	}
	f, ok := s.nativeFlow(w, r, in.Flow, stepCode)
	if !ok {
		return
	}
	if err := s.sendNativeCode(r, f, f.CodeKind); err != nil {
		s.nativeSendFailure(w, err)
		return
	}
	s.nativeStep(w, r, f, stepCode)
}

// handleNativeCode checks an emailed code and moves the flow to its next step.
func (s *Server) handleNativeCode(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Flow string `json:"flow"`
		Code string `json:"code"`
	}
	if !nativeBody(w, r, &in) {
		return
	}
	f, ok := s.nativeFlow(w, r, in.Flow, stepCode)
	if !ok {
		return
	}
	msg, _, err := s.checkCode(r, f, in.Code)
	if err != nil {
		s.log.Error("native check code", "error", err)
		nativeFail(w, nativeTemporary)
		return
	}
	switch msg {
	case "":
	case msgTooManyAttempts:
		nativeFail(w, nativeRateLimited)
		return
	case msgCodeLocked:
		nativeFail(w, nativeCodeLocked)
		return
	case msgCodeExpired:
		nativeFail(w, nativeCodeExpired)
		return
	case msgCodeGone:
		// Used or replaced: start again rather than asking for another code,
		// since a used code usually means the auth request is finished too.
		nativeFail(w, nativeExpired)
		return
	default:
		nativeFail(w, nativeWrongCode)
		return
	}
	b := brandOf(r)
	f.EmailProven = true
	f.CodeID = ""
	res := &zitadel.SessionResult{SessionID: f.SessionID, SessionToken: f.SessionTok}
	if f.CodeKind != kindVerify {
		if f.CodeKind == kindSignup {
			if f.UserID, err = s.ensureSignupUser(r.Context(), b, f); err != nil {
				s.nativeFailure(w, err)
				return
			}
		}
		if res, err = s.codeSession(r.Context(), b, f.UserID, s.lifetime(f)); err != nil {
			if zitadel.IsRejected(err) {
				nativeFail(w, nativeUnavailable)
			} else {
				s.nativeFailure(w, err)
			}
			return
		}
	}
	s.nativeComplete(w, r, f, res)
}

// handleNativeTOTP checks an authenticator code and finishes the flow.
func (s *Server) handleNativeTOTP(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Flow string `json:"flow"`
		Code string `json:"code"`
	}
	if !nativeBody(w, r, &in) {
		return
	}
	f, ok := s.nativeFlow(w, r, in.Flow, stepTOTP)
	if !ok {
		return
	}
	b := brandOf(r)
	ctx := r.Context()
	code := strings.ReplaceAll(strings.TrimSpace(in.Code), " ", "")
	if !validCodeFormat(code) {
		nativeFail(w, nativeWrongCode)
		return
	}
	if ok, err := s.store.Allow(ctx, s.limit(s.limits.TOTPPerAccount, "totp:user:"+b.ID+":"+f.UserID)); err != nil || !ok {
		nativeFail(w, nativeRateLimited)
		return
	}
	res, err := s.api.SetSession(ctx, instance(b), f.SessionID, f.SessionTok, zitadel.Checks{TOTP: code})
	if err != nil {
		if zitadel.IsRejected(err) {
			nativeFail(w, nativeWrongCode)
		} else {
			s.nativeFailure(w, err)
		}
		return
	}
	f.TOTPFor = totpKey(f.UserID, f.SessionID)
	s.nativeComplete(w, r, f, res)
}

// nativeFailure maps a sign-in step failure to its API error, logging unexpected ones.
func (s *Server) nativeFailure(w http.ResponseWriter, err error) {
	if errors.Is(err, errUnavailable) {
		nativeFail(w, nativeUnavailable)
		return
	}
	s.log.Error("native sign-in step", "error", err)
	nativeFail(w, nativeTemporary)
}

// nativeComplete is complete for the API. An allowlisted first-party client
// shows its own agreement, so a consent prompt adds no step. No browser session
// is remembered.
func (s *Server) nativeComplete(w http.ResponseWriter, r *http.Request, f *flow, res *zitadel.SessionResult) {
	b := brandOf(r)
	next, err := s.secondFactors(r, f, res)
	if err != nil {
		if _, sending := err.(sendProblem); sending {
			s.nativeSendFailure(w, err)
		} else {
			s.nativeFailure(w, err)
		}
		return
	}
	if next != "" {
		s.nativeStep(w, r, f, next)
		return
	}
	cb, err := s.api.FinalizeAuthRequest(r.Context(), instance(b), f.AuthRequest, f.SessionID, f.SessionTok)
	if err != nil {
		if zitadel.IsRejected(err) {
			nativeFail(w, nativeExpired)
		} else {
			s.log.Error("native finalize auth request", "error", err)
			nativeFail(w, nativeTemporary)
		}
		return
	}
	if !safeCallback(cb) {
		s.log.Error("native finalize auth request", "error", "unsafe callback")
		nativeFail(w, nativeTemporary)
		return
	}
	nativeJSON(w, http.StatusOK, nativeResponse{Step: "done", Callback: cb})
}
