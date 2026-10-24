// Package zitadel is a small JSON client for the Zitadel v2 API calls the
// login service makes (Sessions, Users, OIDC auth requests, IdP intents,
// settings). Every call carries the instance host in the same headers the
// official Login UI sends (x-zitadel-instance-host, x-zitadel-public-host), so
// one Zitadel deployment can answer for several brands.
package zitadel

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// API is what the web handlers need from Zitadel. *Client implements it;
// tests use a fake.
type API interface {
	GetAuthRequest(ctx context.Context, in Instance, id string) (*AuthRequest, error)
	FinalizeAuthRequest(ctx context.Context, in Instance, id, sessionID, sessionToken string) (string, error)
	FailAuthRequest(ctx context.Context, in Instance, id, reason, description string) (string, error)
	AppIsNative(ctx context.Context, in Instance, clientID string) (bool, error)

	FindUsers(ctx context.Context, in Instance, email string) ([]User, error)
	GetUser(ctx context.Context, in Instance, userID string) (*User, error)
	AuthMethods(ctx context.Context, in Instance, userID string) ([]string, error)
	CreateHuman(ctx context.Context, in Instance, h NewHuman) (string, error)
	MarkEmailVerified(ctx context.Context, in Instance, userID, email string) error
	AddOTPEmail(ctx context.Context, in Instance, userID string) error
	PasswordResetCode(ctx context.Context, in Instance, userID string) (string, error)
	SetPassword(ctx context.Context, in Instance, userID, code, password string) error
	PasswordComplexity(ctx context.Context, in Instance) (PasswordComplexity, error)
	AddIDPLink(ctx context.Context, in Instance, userID string, link IDPLink) error

	CreateSession(ctx context.Context, in Instance, c Checks, lifetime time.Duration) (*SessionResult, error)
	SetSession(ctx context.Context, in Instance, sessionID, token string, c Checks) (*SessionResult, error)
	GetSession(ctx context.Context, in Instance, sessionID string) (*Session, error)
	DeleteSession(ctx context.Context, in Instance, sessionID, token string) error

	StartIDPIntent(ctx context.Context, in Instance, idpID, successURL, failureURL string) (string, error)
	RetrieveIDPIntent(ctx context.Context, in Instance, id, token string) (*Intent, error)

	SigningKeys(ctx context.Context, in Instance) ([]byte, error)
}

// Error is a non-2xx answer from Zitadel.
type Error struct {
	Status  int    // HTTP status
	Code    int    `json:"code"` // gRPC code
	Message string `json:"message"`
}

func (e *Error) Error() string { return fmt.Sprintf("zitadel %d/%d: %s", e.Status, e.Code, e.Message) }

// gRPC codes used by the login.
const (
	codeInvalidArgument    = 3
	codeNotFound           = 5
	codeAlreadyExists      = 6
	codeFailedPrecondition = 9
)

func hasCode(err error, codes ...int) bool {
	var e *Error
	if !errors.As(err, &e) {
		return false
	}
	for _, c := range codes {
		if e.Code == c {
			return true
		}
	}
	return false
}

// IsNotFound reports a missing resource.
func IsNotFound(err error) bool { return hasCode(err, codeNotFound) }

// IsAlreadyExists reports a conflict.
func IsAlreadyExists(err error) bool { return hasCode(err, codeAlreadyExists) }

// IsRejected reports a check or argument Zitadel refused (wrong password or
// code, user not active, weak password): the user's fault, not an outage.
func IsRejected(err error) bool {
	return hasCode(err, codeInvalidArgument, codeFailedPrecondition, codeNotFound)
}

// Client talks to one Zitadel deployment.
type Client struct {
	BaseURL string // e.g. http://127.0.0.1:8090
	HTTP    *http.Client
}

// New returns a client with sane timeouts.
func New(baseURL string) *Client {
	return &Client{BaseURL: strings.TrimRight(baseURL, "/"), HTTP: &http.Client{
		Timeout: 15 * time.Second,
		// Zitadel never redirects API calls; never follow anything.
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}}
}

func (c *Client) do(ctx context.Context, in Instance, method, path string, body, out any) error {
	var raw []byte
	if body != nil {
		var err error
		if raw, err = json.Marshal(body); err != nil {
			return err
		}
	}
	// Right after Zitadel starts its REST gateway answers 503 for a moment.
	for attempt := 0; ; attempt++ {
		req, err := http.NewRequestWithContext(ctx, method, c.BaseURL+path, bytes.NewReader(raw))
		if err != nil {
			return err
		}
		req.Header.Set("Accept", "application/json")
		if body != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		if in.Token != "" {
			req.Header.Set("Authorization", "Bearer "+in.Token)
		}
		if in.Host != "" {
			req.Header.Set("x-zitadel-instance-host", in.Host)
			req.Header.Set("x-zitadel-public-host", in.Host)
		}
		resp, err := c.HTTP.Do(req)
		if err != nil {
			return err
		}
		data, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
		resp.Body.Close()
		if err != nil {
			return err
		}
		if resp.StatusCode == http.StatusServiceUnavailable && attempt < 5 {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(400 * time.Millisecond):
			}
			continue
		}
		if resp.StatusCode/100 != 2 {
			e := &Error{Status: resp.StatusCode}
			_ = json.Unmarshal(data, e)
			if e.Message == "" {
				e.Message = strings.TrimSpace(string(data))
			}
			return e
		}
		if out == nil || len(data) == 0 {
			return nil
		}
		return json.Unmarshal(data, out)
	}
}

func esc(s string) string { return url.PathEscape(s) }

func seconds(d time.Duration) string { return fmt.Sprintf("%ds", int64(d/time.Second)) }

// GetAuthRequest loads an OIDC auth request (id with the V2_ prefix).
func (c *Client) GetAuthRequest(ctx context.Context, in Instance, id string) (*AuthRequest, error) {
	var out struct {
		AuthRequest AuthRequest `json:"authRequest"`
	}
	if err := c.do(ctx, in, http.MethodGet, "/v2/oidc/auth_requests/"+esc(id), nil, &out); err != nil {
		return nil, err
	}
	return &out.AuthRequest, nil
}

// FinalizeAuthRequest links a session to the auth request and returns the
// client's callback URL.
func (c *Client) FinalizeAuthRequest(ctx context.Context, in Instance, id, sessionID, sessionToken string) (string, error) {
	var out struct {
		CallbackURL string `json:"callbackUrl"`
	}
	err := c.do(ctx, in, http.MethodPost, "/v2/oidc/auth_requests/"+esc(id), map[string]any{
		"session": map[string]string{"sessionId": sessionID, "sessionToken": sessionToken},
	}, &out)
	return out.CallbackURL, err
}

// FailAuthRequest ends the auth request with an OIDC error and returns the
// client's callback URL carrying it.
func (c *Client) FailAuthRequest(ctx context.Context, in Instance, id, reason, description string) (string, error) {
	var out struct {
		CallbackURL string `json:"callbackUrl"`
	}
	err := c.do(ctx, in, http.MethodPost, "/v2/oidc/auth_requests/"+esc(id), map[string]any{
		"error": map[string]string{"error": reason, "errorDescription": description},
	}, &out)
	return out.CallbackURL, err
}

// AppIsNative reports whether the OIDC app with this client ID is a native
// (desktop/mobile) app. Uses the connect endpoint of the v2 application
// service, which has no REST mapping in v4.19.5.
func (c *Client) AppIsNative(ctx context.Context, in Instance, clientID string) (bool, error) {
	var out struct {
		Applications []struct {
			OIDC *struct {
				ApplicationType string `json:"applicationType"`
				ClientID        string `json:"clientId"`
			} `json:"oidcConfiguration"`
		} `json:"applications"`
	}
	err := c.do(ctx, in, http.MethodPost, "/zitadel.application.v2.ApplicationService/ListApplications", map[string]any{
		"filters": []any{map[string]any{"clientIdFilter": map[string]string{"clientId": clientID}}},
	}, &out)
	if err != nil {
		return false, err
	}
	for _, a := range out.Applications {
		if a.OIDC != nil && a.OIDC.ClientID == clientID {
			return a.OIDC.ApplicationType == "OIDC_APP_TYPE_NATIVE", nil
		}
	}
	return false, nil
}

// FindUsers returns the human users whose current email equals the given
// address, ignoring case. It deliberately does not match login names: after
// an email change the login name can still be the old address, and every
// caller then sends a code to the address that was typed, so matching it
// would hand the account to whoever controls the old inbox. The result is
// re-checked here so a looser server-side match can never widen it.
func (c *Client) FindUsers(ctx context.Context, in Instance, email string) ([]User, error) {
	var out struct {
		Result []User `json:"result"`
	}
	err := c.do(ctx, in, http.MethodPost, "/v2/users", map[string]any{
		"queries": []any{
			map[string]any{"emailQuery": map[string]string{"emailAddress": email, "method": "TEXT_QUERY_METHOD_EQUALS_IGNORE_CASE"}},
		},
	}, &out)
	if err != nil {
		return nil, err
	}
	var humans []User
	for _, u := range out.Result {
		if u.Human != nil && strings.EqualFold(strings.TrimSpace(u.Email()), strings.TrimSpace(email)) {
			humans = append(humans, u)
		}
	}
	return humans, nil
}

// GetUser loads one user.
func (c *Client) GetUser(ctx context.Context, in Instance, userID string) (*User, error) {
	var out struct {
		User User `json:"user"`
	}
	if err := c.do(ctx, in, http.MethodGet, "/v2/users/"+esc(userID), nil, &out); err != nil {
		return nil, err
	}
	return &out.User, nil
}

// AuthMethods lists the user's authentication method types.
func (c *Client) AuthMethods(ctx context.Context, in Instance, userID string) ([]string, error) {
	var out struct {
		Types []string `json:"authMethodTypes"`
	}
	err := c.do(ctx, in, http.MethodGet, "/v2/users/"+esc(userID)+"/authentication_methods", nil, &out)
	return out.Types, err
}

// CreateHuman creates a human user without a password.
func (c *Client) CreateHuman(ctx context.Context, in Instance, h NewHuman) (string, error) {
	body := map[string]any{
		"username": h.Username,
		"profile":  map[string]string{"givenName": h.GivenName, "familyName": h.FamilyName, "displayName": h.DisplayName},
		"email":    map[string]any{"email": h.Email, "isVerified": h.EmailVerified},
	}
	if h.OrgID != "" {
		body["organization"] = map[string]string{"orgId": h.OrgID}
	}
	if len(h.IDPLinks) > 0 {
		body["idpLinks"] = h.IDPLinks
	}
	var out struct {
		UserID string `json:"userId"`
	}
	err := c.do(ctx, in, http.MethodPost, "/v2/users/human", body, &out)
	return out.UserID, err
}

// MarkEmailVerified marks the user's current email verified (the login has
// just proven ownership with an emailed code). Setting the same address with
// isVerified is refused by Zitadel ("Email not changed"), so this asks for a
// verification code without sending it and redeems it right away.
func (c *Client) MarkEmailVerified(ctx context.Context, in Instance, userID, email string) error {
	var out struct {
		Code string `json:"verificationCode"`
	}
	if err := c.do(ctx, in, http.MethodPost, "/v2/users/"+esc(userID)+"/email/send",
		map[string]any{"returnCode": map[string]any{}}, &out); err != nil {
		return err
	}
	return c.do(ctx, in, http.MethodPost, "/v2/users/"+esc(userID)+"/email/verify",
		map[string]string{"verificationCode": out.Code}, nil)
}

// AddOTPEmail registers the email-code factor; an existing one is fine.
func (c *Client) AddOTPEmail(ctx context.Context, in Instance, userID string) error {
	err := c.do(ctx, in, http.MethodPost, "/v2/users/"+esc(userID)+"/otp_email", map[string]any{}, nil)
	if IsAlreadyExists(err) {
		return nil
	}
	return err
}

// PasswordResetCode asks Zitadel for a reset code without sending anything.
func (c *Client) PasswordResetCode(ctx context.Context, in Instance, userID string) (string, error) {
	var out struct {
		Code string `json:"verificationCode"`
	}
	err := c.do(ctx, in, http.MethodPost, "/v2/users/"+esc(userID)+"/password_reset",
		map[string]any{"returnCode": map[string]any{}}, &out)
	return out.Code, err
}

// SetPassword sets a new password using a reset code.
func (c *Client) SetPassword(ctx context.Context, in Instance, userID, code, password string) error {
	return c.do(ctx, in, http.MethodPost, "/v2/users/"+esc(userID)+"/password", map[string]any{
		"newPassword":      map[string]any{"password": password, "changeRequired": false},
		"verificationCode": code,
	}, nil)
}

// PasswordComplexity returns the instance password policy.
func (c *Client) PasswordComplexity(ctx context.Context, in Instance) (PasswordComplexity, error) {
	var out struct {
		Settings PasswordComplexity `json:"settings"`
	}
	err := c.do(ctx, in, http.MethodGet, "/v2/settings/password/complexity", nil, &out)
	return out.Settings, err
}

// AddIDPLink links an external identity to a user.
func (c *Client) AddIDPLink(ctx context.Context, in Instance, userID string, link IDPLink) error {
	err := c.do(ctx, in, http.MethodPost, "/v2/users/"+esc(userID)+"/links", map[string]any{"idpLink": link}, nil)
	if IsAlreadyExists(err) {
		return nil
	}
	return err
}

func checksBody(c Checks) (map[string]any, map[string]any) {
	checks := map[string]any{}
	switch {
	case c.UserID != "":
		checks["user"] = map[string]string{"userId": c.UserID}
	case c.LoginName != "":
		checks["user"] = map[string]string{"loginName": c.LoginName}
	}
	if c.Password != "" {
		checks["password"] = map[string]string{"password": c.Password}
	}
	if c.TOTP != "" {
		checks["totp"] = map[string]string{"code": c.TOTP}
	}
	if c.OTPEmail != "" {
		checks["otpEmail"] = map[string]string{"code": c.OTPEmail}
	}
	if c.IntentID != "" {
		checks["idpIntent"] = map[string]string{"idpIntentId": c.IntentID, "idpIntentToken": c.IntentToken}
	}
	var challenges map[string]any
	if c.OTPEmailCode {
		challenges = map[string]any{"otpEmail": map[string]any{"returnCode": map[string]any{}}}
	}
	return checks, challenges
}

type sessionOut struct {
	SessionID    string `json:"sessionId"`
	SessionToken string `json:"sessionToken"`
	Challenges   struct {
		OTPEmail string `json:"otpEmail"`
	} `json:"challenges"`
}

// CreateSession creates a session with the given checks and lifetime.
func (c *Client) CreateSession(ctx context.Context, in Instance, ch Checks, lifetime time.Duration) (*SessionResult, error) {
	checks, challenges := checksBody(ch)
	body := map[string]any{"checks": checks}
	if challenges != nil {
		body["challenges"] = challenges
	}
	if lifetime > 0 {
		body["lifetime"] = seconds(lifetime)
	}
	var out sessionOut
	if err := c.do(ctx, in, http.MethodPost, "/v2/sessions", body, &out); err != nil {
		return nil, err
	}
	return &SessionResult{SessionID: out.SessionID, SessionToken: out.SessionToken, OTPEmailCode: out.Challenges.OTPEmail}, nil
}

// SetSession adds checks to a session; it returns the new session token.
func (c *Client) SetSession(ctx context.Context, in Instance, sessionID, token string, ch Checks) (*SessionResult, error) {
	checks, challenges := checksBody(ch)
	delete(checks, "user")
	body := map[string]any{"sessionToken": token, "checks": checks}
	if challenges != nil {
		body["challenges"] = challenges
	}
	var out sessionOut
	if err := c.do(ctx, in, http.MethodPatch, "/v2/sessions/"+esc(sessionID), body, &out); err != nil {
		return nil, err
	}
	return &SessionResult{SessionID: sessionID, SessionToken: out.SessionToken, OTPEmailCode: out.Challenges.OTPEmail}, nil
}

// GetSession loads a session.
func (c *Client) GetSession(ctx context.Context, in Instance, sessionID string) (*Session, error) {
	var out struct {
		Session Session `json:"session"`
	}
	if err := c.do(ctx, in, http.MethodGet, "/v2/sessions/"+esc(sessionID), nil, &out); err != nil {
		return nil, err
	}
	return &out.Session, nil
}

// DeleteSession terminates a session. A session that is already gone is fine.
func (c *Client) DeleteSession(ctx context.Context, in Instance, sessionID, token string) error {
	body := map[string]any{}
	if token != "" {
		body["sessionToken"] = token
	}
	err := c.do(ctx, in, http.MethodDelete, "/v2/sessions/"+esc(sessionID), body, nil)
	if IsNotFound(err) {
		return nil
	}
	return err
}

// StartIDPIntent starts an IdP intent and returns the provider URL to send
// the browser to.
func (c *Client) StartIDPIntent(ctx context.Context, in Instance, idpID, successURL, failureURL string) (string, error) {
	var out struct {
		AuthURL string `json:"authUrl"`
	}
	err := c.do(ctx, in, http.MethodPost, "/v2/idp_intents", map[string]any{
		"idpId": idpID,
		"urls":  map[string]string{"successUrl": successURL, "failureUrl": failureURL},
	}, &out)
	if err == nil && out.AuthURL == "" {
		err = errors.New("zitadel: intent has no auth URL (only redirect-based providers are supported)")
	}
	return out.AuthURL, err
}

// RetrieveIDPIntent reads a successful intent.
func (c *Client) RetrieveIDPIntent(ctx context.Context, in Instance, id, token string) (*Intent, error) {
	var out struct {
		IDPInformation struct {
			IDPID    string `json:"idpId"`
			UserID   string `json:"userId"`
			UserName string `json:"userName"`
		} `json:"idpInformation"`
		UserID       string `json:"userId"`
		AddHumanUser *struct {
			Username string `json:"username"`
			Profile  struct {
				GivenName   string `json:"givenName"`
				FamilyName  string `json:"familyName"`
				DisplayName string `json:"displayName"`
			} `json:"profile"`
			Email struct {
				Email      string `json:"email"`
				IsVerified bool   `json:"isVerified"`
			} `json:"email"`
		} `json:"addHumanUser"`
	}
	if err := c.do(ctx, in, http.MethodPost, "/v2/idp_intents/"+esc(id), map[string]string{"idpIntentToken": token}, &out); err != nil {
		return nil, err
	}
	it := &Intent{UserID: out.UserID, IDPID: out.IDPInformation.IDPID, ExtID: out.IDPInformation.UserID, ExtName: out.IDPInformation.UserName}
	if h := out.AddHumanUser; h != nil {
		it.Email, it.Verified = h.Email.Email, h.Email.IsVerified
		it.Given, it.Family, it.Display, it.Username = h.Profile.GivenName, h.Profile.FamilyName, h.Profile.DisplayName, h.Username
	}
	return it, nil
}

// SigningKeys returns the instance's JWKS (used to verify logout tokens).
func (c *Client) SigningKeys(ctx context.Context, in Instance) ([]byte, error) {
	var raw json.RawMessage
	err := c.do(ctx, Instance{Host: in.Host}, http.MethodGet, "/oauth/v2/keys", nil, &raw)
	return raw, err
}

// Call makes an arbitrary JSON API call (used by the setup commands).
func (c *Client) Call(ctx context.Context, in Instance, method, path string, body, out any) error {
	return c.do(ctx, in, method, path, body, out)
}
