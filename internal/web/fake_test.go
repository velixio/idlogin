package web

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/velixio/idlogin/internal/zitadel"
)

// fakeZitadel is an in-memory stand-in for the parts of the v2 API the login
// uses, strict enough to catch misuse (wrong tokens, unknown users, reused
// auth requests, sessions without a factor are accepted like the real one).
type fakeZitadel struct {
	mu    sync.Mutex
	now   func() time.Time
	seq   int
	users map[string]*fakeUser
	sess  map[string]*fakeSession
	ars   map[string]*zitadel.AuthRequest
	done  map[string]string // auth request -> session id or "error:<reason>"
	// native client IDs
	native map[string]bool
	// IdP intents: id -> intent
	intents map[string]*fakeIntent
	links   map[string]string // idp|extID -> user id
	key     *rsa.PrivateKey
	calls   []string
}

type fakeUser struct {
	zitadel.User
	password string
	totp     string
	otpEmail bool
}

type fakeSession struct {
	s       zitadel.Session
	token   string
	otpCode string
}

type fakeIntent struct {
	token string
	zitadel.Intent
}

func newFake(now func() time.Time, key *rsa.PrivateKey) *fakeZitadel {
	return &fakeZitadel{now: now, users: map[string]*fakeUser{}, sess: map[string]*fakeSession{},
		ars: map[string]*zitadel.AuthRequest{}, done: map[string]string{}, native: map[string]bool{},
		intents: map[string]*fakeIntent{}, links: map[string]string{}, key: key}
}

func errCode(code int, msg string) error {
	return &zitadel.Error{Status: 400, Code: code, Message: msg}
}

func (f *fakeZitadel) id() string { f.seq++; return fmt.Sprintf("%d", 1000+f.seq) }

func (f *fakeZitadel) addUser(email, password string, verified bool) *fakeUser {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.addUserLocked(email, password, verified)
}

func (f *fakeZitadel) addUserLocked(email, password string, verified bool) *fakeUser {
	u := &fakeUser{password: password}
	u.UserID = f.id()
	u.State = zitadel.UserStateActive
	u.Username = email
	u.LoginNames = []string{email}
	u.Human = &struct {
		Profile struct {
			GivenName   string `json:"givenName"`
			FamilyName  string `json:"familyName"`
			DisplayName string `json:"displayName"`
		} `json:"profile"`
		Email struct {
			Email      string `json:"email"`
			IsVerified bool   `json:"isVerified"`
		} `json:"email"`
	}{}
	u.Human.Email.Email = email
	u.Human.Email.IsVerified = verified
	f.users[u.UserID] = u
	return u
}

func (f *fakeZitadel) newAuthRequest(clientID string, prompts []string, maxAge *time.Duration, hint string) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	id := "V2_" + f.id()
	ar := &zitadel.AuthRequest{ID: id, ClientID: clientID, Prompt: prompts, LoginHint: hint, RedirectURI: "https://rp.test/cb"}
	if maxAge != nil {
		ar.MaxAge = &zitadel.Duration{Duration: *maxAge}
	}
	f.ars[id] = ar
	return id
}

func (f *fakeZitadel) user(email string) *fakeUser {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, u := range f.users {
		if strings.EqualFold(u.Email(), email) {
			return u
		}
	}
	return nil
}

func (f *fakeZitadel) userCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.users)
}

func (f *fakeZitadel) GetAuthRequest(_ context.Context, _ zitadel.Instance, id string) (*zitadel.AuthRequest, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	ar, ok := f.ars[id]
	if !ok || f.done[id] != "" {
		return nil, errCode(5, "Auth Request does not exist")
	}
	cp := *ar
	return &cp, nil
}

func (f *fakeZitadel) FinalizeAuthRequest(_ context.Context, _ zitadel.Instance, id, sid, tok string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, ok := f.ars[id]; !ok {
		return "", errCode(5, "no auth request")
	}
	if f.done[id] != "" {
		return "", errCode(9, "Errors.AuthRequest.AlreadyHandled")
	}
	s, ok := f.sess[sid]
	if !ok || s.token != tok {
		return "", errCode(9, "session invalid")
	}
	f.done[id] = sid
	return "https://rp.test/cb?code=c-" + id + "&state=s", nil
}

func (f *fakeZitadel) FailAuthRequest(_ context.Context, _ zitadel.Instance, id, reason, _ string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.done[id] != "" {
		return "", errCode(9, "Errors.AuthRequest.AlreadyHandled")
	}
	f.done[id] = "error:" + reason
	e := strings.ToLower(strings.TrimPrefix(reason, "ERROR_REASON_"))
	return "https://rp.test/cb?error=" + e + "&state=s", nil
}

func (f *fakeZitadel) AppIsNative(_ context.Context, _ zitadel.Instance, clientID string) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.native[clientID], nil
}

func (f *fakeZitadel) FindUsers(_ context.Context, _ zitadel.Instance, email string) ([]zitadel.User, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []zitadel.User
	for _, u := range f.users {
		if strings.EqualFold(u.Email(), email) {
			out = append(out, u.User)
		}
	}
	return out, nil
}

func (f *fakeZitadel) GetUser(_ context.Context, _ zitadel.Instance, id string) (*zitadel.User, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	u, ok := f.users[id]
	if !ok {
		return nil, errCode(5, "user not found")
	}
	cp := u.User
	h := *u.Human
	cp.Human = &h
	return &cp, nil
}

func (f *fakeZitadel) AuthMethods(_ context.Context, _ zitadel.Instance, id string) ([]string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	u, ok := f.users[id]
	if !ok {
		return nil, errCode(5, "user not found")
	}
	var m []string
	if u.password != "" {
		m = append(m, zitadel.MethodPassword)
	}
	if u.totp != "" {
		m = append(m, zitadel.MethodTOTP)
	}
	if u.otpEmail {
		m = append(m, zitadel.MethodOTPEmail)
	}
	return m, nil
}

func (f *fakeZitadel) CreateHuman(_ context.Context, _ zitadel.Instance, h zitadel.NewHuman) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if h.GivenName == "" || h.FamilyName == "" || h.Username == "" {
		return "", errCode(3, "profile incomplete")
	}
	for _, u := range f.users {
		if u.Username == h.Username {
			return "", errCode(6, "User already exists")
		}
	}
	u := f.addUserLocked(h.Email, "", h.EmailVerified)
	u.Human.Profile.GivenName, u.Human.Profile.FamilyName, u.Human.Profile.DisplayName = h.GivenName, h.FamilyName, h.DisplayName
	for _, l := range h.IDPLinks {
		f.links[l.IDPID+"|"+l.UserID] = u.UserID
	}
	f.calls = append(f.calls, "create:"+h.Email)
	return u.UserID, nil
}

func (f *fakeZitadel) MarkEmailVerified(_ context.Context, _ zitadel.Instance, id, email string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	u, ok := f.users[id]
	if !ok {
		return errCode(5, "nope")
	}
	u.Human.Email.Email, u.Human.Email.IsVerified = email, true
	return nil
}

func (f *fakeZitadel) AddOTPEmail(_ context.Context, _ zitadel.Instance, id string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	u, ok := f.users[id]
	if !ok {
		return errCode(5, "nope")
	}
	u.otpEmail = true
	return nil
}

func (f *fakeZitadel) PasswordResetCode(_ context.Context, _ zitadel.Instance, id string) (string, error) {
	return "ZRESET-" + id, nil
}

func (f *fakeZitadel) SetPassword(_ context.Context, _ zitadel.Instance, id, code, pw string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	u, ok := f.users[id]
	if !ok || code != "ZRESET-"+id {
		return errCode(3, "bad code")
	}
	u.password = pw
	return nil
}

func (f *fakeZitadel) PasswordComplexity(context.Context, zitadel.Instance) (zitadel.PasswordComplexity, error) {
	return zitadel.PasswordComplexity{MinLength: 8, Upper: true, Lower: true, Number: true}, nil
}

func (f *fakeZitadel) AddIDPLink(_ context.Context, _ zitadel.Instance, uid string, l zitadel.IDPLink) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.links[l.IDPID+"|"+l.UserID] = uid
	return nil
}

func (f *fakeZitadel) newToken() string { return "tok-" + f.id() }

func (f *fakeZitadel) CreateSession(_ context.Context, _ zitadel.Instance, c zitadel.Checks, lifetime time.Duration) (*zitadel.SessionResult, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	u, ok := f.users[c.UserID]
	if !ok {
		return nil, errCode(5, "user not found")
	}
	if u.State != zitadel.UserStateActive {
		return nil, errCode(9, "Errors.User.NotActive")
	}
	now := f.now()
	s := &fakeSession{token: f.newToken()}
	s.s.ID = f.id()
	s.s.CreationDate, s.s.ChangeDate = now, now
	exp := now.Add(lifetime)
	s.s.ExpirationDate = &exp
	s.s.Factors.User = &struct {
		VerifiedAt     time.Time `json:"verifiedAt"`
		ID             string    `json:"id"`
		LoginName      string    `json:"loginName"`
		DisplayName    string    `json:"displayName"`
		OrganizationID string    `json:"organizationId"`
	}{VerifiedAt: now, ID: u.UserID, LoginName: u.Username}
	if c.Password != "" {
		if u.password == "" || c.Password != u.password {
			return nil, errCode(3, "Password is invalid")
		}
		s.s.Factors.Password = &zitadel.Factor{VerifiedAt: now}
	}
	if c.IntentID != "" {
		it, ok := f.intents[c.IntentID]
		if !ok || it.token != c.IntentToken {
			return nil, errCode(9, "intent invalid")
		}
		if f.links[it.IDPID+"|"+it.ExtID] != u.UserID {
			return nil, errCode(9, "Errors.Intent.OtherUser")
		}
		s.s.Factors.Intent = &zitadel.Factor{VerifiedAt: now}
	}
	res := &zitadel.SessionResult{SessionID: s.s.ID, SessionToken: s.token}
	if c.OTPEmailCode {
		if !u.otpEmail {
			return nil, errCode(9, "otp email not set up")
		}
		s.otpCode = "87654321"
		res.OTPEmailCode = s.otpCode
	}
	f.sess[s.s.ID] = s
	return res, nil
}

func (f *fakeZitadel) SetSession(_ context.Context, _ zitadel.Instance, id, tok string, c zitadel.Checks) (*zitadel.SessionResult, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	s, ok := f.sess[id]
	if !ok || s.token != tok {
		return nil, errCode(9, "session token invalid")
	}
	now := f.now()
	u := f.users[s.s.UserID()]
	if c.OTPEmail != "" {
		if s.otpCode == "" || c.OTPEmail != s.otpCode {
			return nil, errCode(3, "code invalid")
		}
		s.otpCode = ""
		s.s.Factors.OTPEmail = &zitadel.Factor{VerifiedAt: now}
	}
	if c.TOTP != "" {
		if u.totp == "" || c.TOTP != u.totp {
			return nil, errCode(3, "totp invalid")
		}
		s.s.Factors.TOTP = &zitadel.Factor{VerifiedAt: now}
	}
	s.token = f.newToken()
	s.s.ChangeDate = now
	return &zitadel.SessionResult{SessionID: id, SessionToken: s.token}, nil
}

func (f *fakeZitadel) GetSession(_ context.Context, _ zitadel.Instance, id string) (*zitadel.Session, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	s, ok := f.sess[id]
	if !ok {
		return nil, errCode(5, "Session does not exist")
	}
	cp := s.s
	return &cp, nil
}

func (f *fakeZitadel) DeleteSession(_ context.Context, _ zitadel.Instance, id, _ string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.sess, id)
	f.calls = append(f.calls, "delete-session:"+id)
	return nil
}

func (f *fakeZitadel) sessionCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.sess)
}

func (f *fakeZitadel) StartIDPIntent(_ context.Context, _ zitadel.Instance, idpID, success, failure string) (string, error) {
	return "https://idp.test/authorize?idp=" + url.QueryEscape(idpID) + "&success=" + url.QueryEscape(success) + "&failure=" + url.QueryEscape(failure), nil
}

// finishIntent simulates the provider + Zitadel callback: it registers an
// intent and returns its id and token.
func (f *fakeZitadel) finishIntent(it zitadel.Intent) (string, string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	id, tok := "intent-"+f.id(), "itok-"+f.id()
	if uid, ok := f.links[it.IDPID+"|"+it.ExtID]; ok {
		it.UserID = uid
	}
	f.intents[id] = &fakeIntent{token: tok, Intent: it}
	return id, tok
}

func (f *fakeZitadel) RetrieveIDPIntent(_ context.Context, _ zitadel.Instance, id, tok string) (*zitadel.Intent, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	it, ok := f.intents[id]
	if !ok || it.token != tok {
		return nil, errCode(9, "intent invalid")
	}
	cp := it.Intent
	return &cp, nil
}

func (f *fakeZitadel) SigningKeys(context.Context, zitadel.Instance) ([]byte, error) {
	pub := f.key.PublicKey
	return json.Marshal(map[string]any{"keys": []any{map[string]string{
		"kty": "RSA", "kid": "k1", "alg": "RS256", "use": "sig",
		"n": base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
		"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
	}}})
}
