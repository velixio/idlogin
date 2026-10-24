package zitadel

import (
	"strings"
	"time"
)

// Instance identifies the Zitadel instance a call is made for: the host that
// Zitadel matches instances on (sent as x-zitadel-instance-host and
// x-zitadel-public-host, like the official login does) and the login-client
// token of that instance.
type Instance struct {
	Host  string
	Token string
}

// Prompt values as the v2 API returns them.
const (
	PromptNone          = "PROMPT_NONE"
	PromptLogin         = "PROMPT_LOGIN"
	PromptConsent       = "PROMPT_CONSENT"
	PromptSelectAccount = "PROMPT_SELECT_ACCOUNT"
	PromptCreate        = "PROMPT_CREATE"
)

// AuthRequest is an OIDC authorization request waiting for the login UI.
type AuthRequest struct {
	ID          string    `json:"id"`
	CreatedAt   time.Time `json:"creationDate"`
	ClientID    string    `json:"clientId"`
	Scope       []string  `json:"scope"`
	RedirectURI string    `json:"redirectUri"`
	Prompt      []string  `json:"prompt"`
	UILocales   []string  `json:"uiLocales"`
	LoginHint   string    `json:"loginHint"`
	MaxAge      *Duration `json:"maxAge"`
	HintUserID  string    `json:"hintUserId"`
}

// HasPrompt reports whether the request carries the given prompt value.
func (a *AuthRequest) HasPrompt(p string) bool {
	for _, v := range a.Prompt {
		if v == p {
			return true
		}
	}
	return false
}

// OIDC error reasons for FailAuthRequest.
const (
	ErrorLoginRequired       = "ERROR_REASON_LOGIN_REQUIRED"
	ErrorInteractionRequired = "ERROR_REASON_INTERACTION_REQUIRED"
	ErrorAccessDenied        = "ERROR_REASON_ACCESS_DENIED"
)

// User states.
const (
	UserStateActive   = "USER_STATE_ACTIVE"
	UserStateInactive = "USER_STATE_INACTIVE"
	UserStateLocked   = "USER_STATE_LOCKED"
	UserStateInitial  = "USER_STATE_INITIAL"
)

// Authentication method types.
const (
	MethodPassword = "AUTHENTICATION_METHOD_TYPE_PASSWORD"
	MethodPasskey  = "AUTHENTICATION_METHOD_TYPE_PASSKEY"
	MethodIDP      = "AUTHENTICATION_METHOD_TYPE_IDP"
	MethodTOTP     = "AUTHENTICATION_METHOD_TYPE_TOTP"
	MethodU2F      = "AUTHENTICATION_METHOD_TYPE_U2F"
	MethodOTPSMS   = "AUTHENTICATION_METHOD_TYPE_OTP_SMS"
	MethodOTPEmail = "AUTHENTICATION_METHOD_TYPE_OTP_EMAIL"
)

// User is the subset of a v2 user the login needs.
type User struct {
	UserID             string   `json:"userId"`
	State              string   `json:"state"`
	Username           string   `json:"username"`
	LoginNames         []string `json:"loginNames"`
	PreferredLoginName string   `json:"preferredLoginName"`
	Details            struct {
		ResourceOwner string `json:"resourceOwner"`
	} `json:"details"`
	Human *struct {
		Profile struct {
			GivenName   string `json:"givenName"`
			FamilyName  string `json:"familyName"`
			DisplayName string `json:"displayName"`
		} `json:"profile"`
		Email struct {
			Email      string `json:"email"`
			IsVerified bool   `json:"isVerified"`
		} `json:"email"`
	} `json:"human"`
}

// Email returns the user's email address, or "" for machine users.
func (u *User) Email() string {
	if u.Human == nil {
		return ""
	}
	return u.Human.Email.Email
}

// Usable reports whether the user may sign in at all. INITIAL users (created
// by an admin without a password) can still sign in by email code.
func (u *User) Usable() bool {
	return u.Human != nil && (u.State == UserStateActive || u.State == UserStateInitial)
}

// NewHuman describes a user the login creates.
type NewHuman struct {
	OrgID         string
	Username      string
	GivenName     string
	FamilyName    string
	DisplayName   string
	Email         string
	EmailVerified bool
	IDPLinks      []IDPLink
}

// IDPLink links a Zitadel user to an external identity.
type IDPLink struct {
	IDPID    string `json:"idpId"`
	UserID   string `json:"userId"`
	UserName string `json:"userName"`
}

// Checks are the session checks the login uses.
type Checks struct {
	UserID       string
	LoginName    string
	Password     string
	TOTP         string
	OTPEmail     string
	IntentID     string
	IntentToken  string
	OTPEmailCode bool // request an OTP email challenge with returnCode
}

// SessionResult is what create/set session return.
type SessionResult struct {
	SessionID    string
	SessionToken string
	OTPEmailCode string // only when Checks.OTPEmailCode was set
}

// Session is a v2 session.
type Session struct {
	ID             string     `json:"id"`
	CreationDate   time.Time  `json:"creationDate"`
	ChangeDate     time.Time  `json:"changeDate"`
	ExpirationDate *time.Time `json:"expirationDate"`
	Factors        struct {
		User *struct {
			VerifiedAt     time.Time `json:"verifiedAt"`
			ID             string    `json:"id"`
			LoginName      string    `json:"loginName"`
			DisplayName    string    `json:"displayName"`
			OrganizationID string    `json:"organizationId"`
		} `json:"user"`
		Password *Factor `json:"password"`
		WebAuthN *Factor `json:"webAuthN"`
		Intent   *Factor `json:"intent"`
		TOTP     *Factor `json:"totp"`
		OTPSMS   *Factor `json:"otpSms"`
		OTPEmail *Factor `json:"otpEmail"`
	} `json:"factors"`
}

// Factor is a verified session factor.
type Factor struct {
	VerifiedAt time.Time `json:"verifiedAt"`
}

func (f *Factor) at() time.Time {
	if f == nil {
		return time.Time{}
	}
	return f.VerifiedAt
}

// UserID returns the session's user, or "".
func (s *Session) UserID() string {
	if s.Factors.User == nil {
		return ""
	}
	return s.Factors.User.ID
}

// FirstFactorAt is the latest time a first factor (password, passkey, IdP,
// email code) was verified. Zero if none was: such a session has not
// authenticated anybody, even though Zitadel would accept it for an auth
// request.
func (s *Session) FirstFactorAt() time.Time {
	var t time.Time
	for _, f := range []*Factor{s.Factors.Password, s.Factors.WebAuthN, s.Factors.Intent, s.Factors.OTPEmail} {
		if f.at().After(t) {
			t = f.at()
		}
	}
	return t
}

// AuthTime is the latest verification of any authentication factor.
func (s *Session) AuthTime() time.Time {
	t := s.FirstFactorAt()
	for _, f := range []*Factor{s.Factors.TOTP, s.Factors.OTPSMS} {
		if f.at().After(t) {
			t = f.at()
		}
	}
	return t
}

// TOTPVerified reports whether the session has a TOTP check.
func (s *Session) TOTPVerified() bool { return !s.Factors.TOTP.at().IsZero() }

// Expired reports whether the session is past its expiration date.
func (s *Session) Expired(now time.Time) bool {
	return s.ExpirationDate != nil && !s.ExpirationDate.After(now)
}

// Intent is the result of a finished IdP intent.
type Intent struct {
	UserID   string // Zitadel user already linked to the external identity
	IDPID    string
	ExtID    string // user id at the provider
	ExtName  string // user name at the provider
	Email    string
	Verified bool
	Given    string
	Family   string
	Display  string
	Username string
}

// PasswordComplexity is the instance's password policy.
type PasswordComplexity struct {
	MinLength int  `json:"minLength,string"`
	Upper     bool `json:"requiresUppercase"`
	Lower     bool `json:"requiresLowercase"`
	Number    bool `json:"requiresNumber"`
	Symbol    bool `json:"requiresSymbol"`
}

// Check returns a human-readable problem with password, or "".
func (p PasswordComplexity) Check(password string) string {
	var upper, lower, number, symbol bool
	for _, r := range password {
		switch {
		case r >= 'A' && r <= 'Z':
			upper = true
		case r >= 'a' && r <= 'z':
			lower = true
		case r >= '0' && r <= '9':
			number = true
		default:
			symbol = true
		}
	}
	var missing []string
	if p.Upper && !upper {
		missing = append(missing, "an uppercase letter")
	}
	if p.Lower && !lower {
		missing = append(missing, "a lowercase letter")
	}
	if p.Number && !number {
		missing = append(missing, "a number")
	}
	if p.Symbol && !symbol {
		missing = append(missing, "a symbol")
	}
	if len([]rune(password)) < p.MinLength || len(missing) > 0 {
		return p.Describe()
	}
	return ""
}

// Describe states the policy in one sentence.
func (p PasswordComplexity) Describe() string {
	var parts []string
	if p.Upper {
		parts = append(parts, "an uppercase letter")
	}
	if p.Lower {
		parts = append(parts, "a lowercase letter")
	}
	if p.Number {
		parts = append(parts, "a number")
	}
	if p.Symbol {
		parts = append(parts, "a symbol")
	}
	s := "Use at least " + itoa(max(p.MinLength, 1)) + " characters"
	if len(parts) > 0 {
		s += ", including " + joinAnd(parts)
	}
	return s + "."
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}

func joinAnd(parts []string) string {
	switch len(parts) {
	case 0:
		return ""
	case 1:
		return parts[0]
	}
	return strings.Join(parts[:len(parts)-1], ", ") + " and " + parts[len(parts)-1]
}

// Duration is a protobuf JSON duration ("3600s", "0.5s").
type Duration struct{ time.Duration }

// UnmarshalJSON parses "<seconds>s".
func (d *Duration) UnmarshalJSON(b []byte) error {
	s := strings.Trim(string(b), `"`)
	if s == "" || s == "null" {
		return nil
	}
	v, err := time.ParseDuration(s)
	if err != nil {
		return err
	}
	d.Duration = v
	return nil
}
