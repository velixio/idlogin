package web

import (
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/velixio/idlogin/internal/config"
	"github.com/velixio/idlogin/internal/zitadel"
)

func TestSignupByCode(t *testing.T) {
	e := newEnv(t, brandCfg{Registration: true})
	b := e.browser()
	ar := e.z.newAuthRequest("web", nil, nil, "")
	p := b.start(ar)
	mustContain(t, p, "Sign in or create your account", "Keep me signed in for 30 days")
	p = b.post(p, "/login/email", url.Values{"email": {"New.Person@Example.com"}})
	mustContain(t, p, "Check your email", "new.person@example.com", "creates your account")
	if e.z.userCount() != 0 {
		t.Fatal("user created before the code was entered")
	}
	code := e.mail.lastCode(t, "new.person@example.com")
	p = b.post(p, "/login/code", url.Values{"code": {code}, "action": {"verify"}})
	cb := mustCallback(t, p, ar)
	if cb.Query().Has("remember_me") {
		t.Fatal("remember_me without the box ticked")
	}
	u := e.z.user("new.person@example.com")
	if u == nil || !u.Human.Email.IsVerified || u.password != "" || !u.otpEmail || u.Human.Profile.GivenName != "new.person" {
		t.Fatalf("user: %+v", u)
	}
}

func TestPasswordUser(t *testing.T) {
	e := newEnv(t, brandCfg{Registration: true})
	e.z.addUser("pw@example.com", "Secret-123", true)
	b := e.browser()
	ar := e.z.newAuthRequest("web", nil, nil, "")
	p := b.start(ar)
	p = b.post(p, "/login/email", url.Values{"email": {"pw@example.com"}, "remember": {"on"}})
	mustContain(t, p, "Enter your password", "Forgot password?", "Email me a code instead")
	p = b.post(p, "/login/password", url.Values{"password": {"wrong"}, "action": {"password"}})
	mustContain(t, p, "That password is not right.")
	p = b.post(p, "/login/password", url.Values{"password": {"Secret-123"}, "action": {"password"}})
	cb := mustCallback(t, p, ar)
	if cb.Query().Get("remember_me") != "1" {
		t.Fatalf("remember_me missing: %s", cb)
	}
	if e.mail.count() != 0 {
		t.Fatal("mail sent in a password sign-in")
	}
}

func TestPasswordlessUserGetsCodeImmediately(t *testing.T) {
	e := newEnv(t, brandCfg{Registration: false})
	e.z.addUser("code@example.com", "", true)
	b := e.browser()
	ar := e.z.newAuthRequest("web", nil, nil, "")
	p := b.post(b.start(ar), "/login/email", url.Values{"email": {"code@example.com"}})
	mustContain(t, p, "Check your email")
	if strings.Contains(p.body, "creates your account") {
		t.Fatal("existing user told a code creates an account")
	}
	p = b.post(p, "/login/code", url.Values{"code": {e.mail.lastCode(t, "code@example.com")}})
	mustCallback(t, p, ar)
}

func TestPasswordToCodeSwitch(t *testing.T) {
	e := newEnv(t, brandCfg{})
	e.z.addUser("pw@example.com", "Secret-123", true)
	b := e.browser()
	ar := e.z.newAuthRequest("web", nil, nil, "")
	p := b.post(b.start(ar), "/login/email", url.Values{"email": {"pw@example.com"}})
	p = b.post(p, "/login/password", url.Values{"action": {"code"}})
	mustContain(t, p, "Check your email")
	p = b.post(p, "/login/code", url.Values{"code": {e.mail.lastCode(t, "pw@example.com")}})
	mustCallback(t, p, ar)
}

func TestWrongCodeFiveTimesKillsCode(t *testing.T) {
	e := newEnv(t, brandCfg{})
	e.z.addUser("code@example.com", "", true)
	b := e.browser()
	ar := e.z.newAuthRequest("web", nil, nil, "")
	p := b.post(b.start(ar), "/login/email", url.Values{"email": {"code@example.com"}})
	good := e.mail.lastCode(t, "code@example.com")
	bad := "000000"
	if good == bad {
		bad = "111111"
	}
	for i := 1; i <= 5; i++ {
		p = b.post(p, "/login/code", url.Values{"code": {bad}})
		if i < 5 {
			mustContain(t, p, "That code is not right.")
		} else {
			mustContain(t, p, "Too many wrong attempts for this code. Send a new code.")
		}
	}
	p = b.post(p, "/login/code", url.Values{"code": {good}})
	mustContain(t, p, "Too many wrong attempts")
	// A new code works.
	p = b.post(p, "/login/code", url.Values{"action": {"resend"}})
	mustContain(t, p, "A new code is on its way.")
	p = b.post(p, "/login/code", url.Values{"code": {e.mail.lastCode(t, "code@example.com")}})
	mustCallback(t, p, ar)
}

func TestCodeExpires(t *testing.T) {
	e := newEnv(t, brandCfg{})
	e.z.addUser("code@example.com", "", true)
	b := e.browser()
	ar := e.z.newAuthRequest("web", nil, nil, "")
	p := b.post(b.start(ar), "/login/email", url.Values{"email": {"code@example.com"}})
	code := e.mail.lastCode(t, "code@example.com")
	e.clock.add(CodeTTL + time.Second)
	p = b.post(p, "/login/code", url.Values{"code": {code}})
	mustContain(t, p, "That code has expired.")
}

func TestSixthSendInAnHourRefused(t *testing.T) {
	e := newEnv(t, brandCfg{})
	e.z.addUser("code@example.com", "", true)
	b := e.browser()
	ar := e.z.newAuthRequest("web", nil, nil, "")
	p := b.post(b.start(ar), "/login/email", url.Values{"email": {"code@example.com"}})
	for i := 2; i <= 5; i++ {
		p = b.post(p, "/login/code", url.Values{"action": {"resend"}})
		mustContain(t, p, "A new code is on its way.")
	}
	if e.mail.count() != 5 {
		t.Fatalf("sent %d", e.mail.count())
	}
	p = b.post(p, "/login/code", url.Values{"action": {"resend"}})
	mustContain(t, p, "Too many codes were sent to this address in the last hour.")
	if p.status != http.StatusTooManyRequests || e.mail.count() != 5 {
		t.Fatalf("6th send: status %d, sent %d", p.status, e.mail.count())
	}
	// A different browser cannot bypass the per-address limit.
	b2 := e.browser()
	ar2 := e.z.newAuthRequest("web", nil, nil, "")
	p = b2.post(b2.start(ar2), "/login/email", url.Values{"email": {"code@example.com"}})
	mustContain(t, p, "Too many codes")
	// After an hour it works again.
	e.clock.add(time.Hour + time.Minute)
	b3 := e.browser()
	ar3 := e.z.newAuthRequest("web", nil, nil, "")
	p = b3.post(b3.start(ar3), "/login/email", url.Values{"email": {"code@example.com"}})
	mustContain(t, p, "Check your email")
}

func TestNeutralErrorRegistrationClosedAndDisabledUser(t *testing.T) {
	e := newEnv(t, brandCfg{Registration: false})
	locked := e.z.addUser("locked@example.com", "Secret-123", true)
	locked.State = zitadel.UserStateLocked
	before := e.z.userCount()

	strip := regexp.MustCompile(`value="[^"]*"`)
	body := func(email string) string {
		b := e.browser()
		ar := e.z.newAuthRequest("web", nil, nil, "")
		p := b.post(b.start(ar), "/login/email", url.Values{"email": {email}})
		mustContain(t, p, "This address can&#39;t be used to sign in.")
		return strip.ReplaceAllString(p.body, "")
	}
	unknown, disabled := body("nobody@example.com"), body("locked@example.com")
	if unknown != disabled {
		t.Fatalf("neutral pages differ:\n%s\n----\n%s", unknown, disabled)
	}
	if e.mail.count() != 0 || e.z.userCount() != before {
		t.Fatalf("mail %d, users %d->%d", e.mail.count(), before, e.z.userCount())
	}
}

func TestCSRFAndOrigin(t *testing.T) {
	e := newEnv(t, brandCfg{Registration: true})
	b := e.browser()
	ar := e.z.newAuthRequest("web", nil, nil, "")
	p := b.start(ar)
	post := func(form url.Values, origin, referer string) int {
		req, _ := http.NewRequest(http.MethodPost, b.abs("/login/email"), strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		if origin != "" {
			req.Header.Set("Origin", origin)
		}
		if referer != "" {
			req.Header.Set("Referer", referer)
		}
		return b.do(req).status
	}
	csrf := csrfRe.FindStringSubmatch(p.body)[1]
	ok := url.Values{"csrf": {csrf}, "authRequest": {ar}, "email": {"x@example.com"}}
	noToken := url.Values{"authRequest": {ar}, "email": {"x@example.com"}}
	badToken := url.Values{"csrf": {csrf + "x"}, "authRequest": {ar}, "email": {"x@example.com"}}
	if s := post(noToken, b.origin, ""); s != http.StatusForbidden {
		t.Errorf("missing token: %d", s)
	}
	if s := post(badToken, b.origin, ""); s != http.StatusForbidden {
		t.Errorf("wrong token: %d", s)
	}
	if s := post(ok, "https://evil.test", ""); s != http.StatusForbidden {
		t.Errorf("cross origin: %d", s)
	}
	if s := post(ok, "", ""); s != http.StatusForbidden {
		t.Errorf("no origin/referer: %d", s)
	}
	if s := post(ok, "", "https://evil.test/login"); s != http.StatusForbidden {
		t.Errorf("evil referer: %d", s)
	}
	// Another browser's token does not work with this browser's cookie.
	b2 := e.browser()
	p2 := b2.start(ar)
	other := csrfRe.FindStringSubmatch(p2.body)[1]
	if s := post(url.Values{"csrf": {other}, "authRequest": {ar}, "email": {"x@example.com"}}, b.origin, ""); s != http.StatusForbidden {
		t.Errorf("foreign token: %d", s)
	}
	if s := post(ok, "", b.origin+"/login?authRequest="+ar); s != http.StatusSeeOther {
		t.Errorf("same-origin referer: %d", s)
	}
}

func TestSecurityHeadersAndCookies(t *testing.T) {
	e := newEnv(t, brandCfg{Registration: true})
	b := e.browser()
	ar := e.z.newAuthRequest("web", nil, nil, "")
	resp, err := b.c.Get(b.abs("/login?authRequest=" + ar))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	csp := resp.Header.Get("Content-Security-Policy")
	for _, want := range []string{"default-src 'none'", "script-src 'self'", "frame-ancestors 'none'"} {
		if !strings.Contains(csp, want) {
			t.Errorf("CSP %q lacks %q", csp, want)
		}
	}
	if strings.Contains(csp, "unsafe-inline") {
		t.Error("CSP allows inline")
	}
	for _, c := range resp.Cookies() {
		if !c.HttpOnly || c.SameSite != http.SameSiteLaxMode {
			t.Errorf("cookie %s: httponly %v samesite %v", c.Name, c.HttpOnly, c.SameSite)
		}
	}
	// Unknown host.
	req, _ := http.NewRequest(http.MethodGet, b.abs("/login"), nil)
	req.Host = "evil.test"
	if p := b.do(req); p.status != http.StatusMisdirectedRequest {
		t.Errorf("unknown host: %d", p.status)
	}
	// Static assets.
	if p := b.get("/login/static/app.css"); p.status != 200 || !strings.Contains(p.body, "--paper") {
		t.Errorf("css: %d", p.status)
	}
}

func TestPromptHandling(t *testing.T) {
	e := newEnv(t, brandCfg{Registration: true})
	e.z.addUser("pw@example.com", "Secret-123", true)
	b := e.browser()

	// prompt=none without a session: login_required at the RP, no page.
	ar := e.z.newAuthRequest("web", []string{zitadel.PromptNone}, nil, "")
	p := b.start(ar)
	if p.status != http.StatusSeeOther || p.location != "https://rp.test/cb?error=login_required&state=s" {
		t.Fatalf("prompt=none: %d %q", p.status, p.location)
	}

	signInWithPassword(t, e, b, "pw@example.com", "Secret-123", true)

	// SSO reuse without prompt (remember_me carried over).
	ar = e.z.newAuthRequest("web", nil, nil, "")
	cb := mustCallback(t, b.start(ar), ar)
	if cb.Query().Get("remember_me") != "1" {
		t.Error("remember_me lost on reuse")
	}
	// prompt=none with a session: straight back.
	ar = e.z.newAuthRequest("web", []string{zitadel.PromptNone}, nil, "")
	mustCallback(t, b.start(ar), ar)
	// prompt=login: asks again.
	ar = e.z.newAuthRequest("web", []string{zitadel.PromptLogin}, nil, "")
	mustContain(t, b.start(ar), `action="/login/email"`)
	// login_hint for another account: asks.
	ar = e.z.newAuthRequest("web", nil, nil, "other@example.com")
	mustContain(t, b.start(ar), `value="other@example.com"`)
	// max_age exceeded: asks.
	e.clock.add(10 * time.Minute)
	ma := 5 * time.Minute
	ar = e.z.newAuthRequest("web", nil, &ma, "")
	mustContain(t, b.start(ar), `action="/login/email"`)
	ma = time.Hour
	ar = e.z.newAuthRequest("web", nil, &ma, "")
	mustCallback(t, b.start(ar), ar)
	// prompt=create: sign-up page.
	ar = e.z.newAuthRequest("web", []string{zitadel.PromptCreate}, nil, "")
	mustContain(t, b.start(ar), "Create your Example account")
	// Unknown auth request.
	mustContain(t, b.start("V2_999999"), "This sign-in has expired")
}

func TestPromptCreateRegistrationClosed(t *testing.T) {
	e := newEnv(t, brandCfg{Registration: false})
	b := e.browser()
	ar := e.z.newAuthRequest("web", []string{zitadel.PromptCreate}, nil, "")
	p := b.start(ar)
	mustContain(t, p, "New accounts can&#39;t be created here", "Continue to sign in")
	p = b.get("/login/email?authRequest=" + ar)
	mustContain(t, p, "Sign in to Example")
}

func TestTerminatedSessionNotReused(t *testing.T) {
	e := newEnv(t, brandCfg{Registration: true})
	e.z.addUser("pw@example.com", "Secret-123", true)
	b := e.browser()
	signInWithPassword(t, e, b, "pw@example.com", "Secret-123", false)
	for id := range e.z.sess {
		_ = e.z.DeleteSession(t.Context(), zitadel.Instance{}, id, "")
	}
	ar := e.z.newAuthRequest("web", nil, nil, "")
	mustContain(t, b.start(ar), `action="/login/email"`)
}

func TestTOTPRequired(t *testing.T) {
	e := newEnv(t, brandCfg{})
	u := e.z.addUser("op@example.com", "Secret-123", true)
	u.totp = "424242"
	b := e.browser()
	ar := e.z.newAuthRequest("web", nil, nil, "")
	p := b.post(b.start(ar), "/login/email", url.Values{"email": {"op@example.com"}})
	p = b.post(p, "/login/password", url.Values{"password": {"Secret-123"}, "action": {"password"}})
	mustContain(t, p, "Two-step verification")
	p = b.post(p, "/login/totp", url.Values{"otp": {"111111"}})
	mustContain(t, p, "That code is not right.")
	p = b.post(p, "/login/totp", url.Values{"otp": {"424242"}})
	mustCallback(t, p, ar)

	// A session reused later must have TOTP: it does, so SSO works.
	ar = e.z.newAuthRequest("web", nil, nil, "")
	mustCallback(t, b.start(ar), ar)

	// Email code as first factor also leads to TOTP.
	b2 := e.browser()
	ar = e.z.newAuthRequest("web", nil, nil, "")
	p = b2.post(b2.start(ar), "/login/email", url.Values{"email": {"op@example.com"}})
	p = b2.post(p, "/login/password", url.Values{"action": {"code"}})
	p = b2.post(p, "/login/code", url.Values{"code": {e.mail.lastCode(t, "op@example.com")}})
	mustContain(t, p, "Two-step verification")
}

func TestUnverifiedEmailRequiresCode(t *testing.T) {
	e := newEnv(t, brandCfg{})
	e.z.addUser("changed@example.com", "Secret-123", false)
	b := e.browser()
	ar := e.z.newAuthRequest("web", nil, nil, "")
	p := b.post(b.start(ar), "/login/email", url.Values{"email": {"changed@example.com"}})
	p = b.post(p, "/login/password", url.Values{"password": {"Secret-123"}, "action": {"password"}})
	mustContain(t, p, "Verify your email")
	if e.z.user("changed@example.com").Human.Email.IsVerified {
		t.Fatal("verified too early")
	}
	p = b.post(p, "/login/code", url.Values{"code": {e.mail.lastCode(t, "changed@example.com")}})
	mustCallback(t, p, ar)
	if !e.z.user("changed@example.com").Human.Email.IsVerified {
		t.Fatal("email not marked verified")
	}

	// Signing in by email code verifies the address on the way.
	e.z.addUser("unverified2@example.com", "", false)
	b2 := e.browser()
	ar = e.z.newAuthRequest("web", nil, nil, "")
	p = b2.post(b2.start(ar), "/login/email", url.Values{"email": {"unverified2@example.com"}})
	p = b2.post(p, "/login/code", url.Values{"code": {e.mail.lastCode(t, "unverified2@example.com")}})
	mustCallback(t, p, ar)
	if !e.z.user("unverified2@example.com").Human.Email.IsVerified {
		t.Fatal("code sign-in did not verify the email")
	}
}

func TestNativeAppGetsFreshSession(t *testing.T) {
	e := newEnv(t, brandCfg{})
	e.z.addUser("pw@example.com", "Secret-123", true)
	e.z.native["desktop"] = true
	b := e.browser()
	signInWithPassword(t, e, b, "pw@example.com", "Secret-123", false)
	webSessions := len(e.web.browserSessionsForTest(t, b))

	// The desktop app does not reuse the browser session...
	ar := e.z.newAuthRequest("desktop", nil, nil, "")
	p := b.start(ar)
	mustContain(t, p, `action="/login/email"`)
	p = b.post(p, "/login/email", url.Values{"email": {"pw@example.com"}})
	p = b.post(p, "/login/password", url.Values{"password": {"Secret-123"}, "action": {"password"}})
	mustCallback(t, p, ar)
	// ...and its new session is not added to the browser's list (logout
	// there must not end it).
	if n := len(e.web.browserSessionsForTest(t, b)); n != webSessions {
		t.Fatalf("browser sessions %d -> %d", webSessions, n)
	}
	// prompt=none from a native app: never the browser session.
	ar = e.z.newAuthRequest("desktop", []string{zitadel.PromptNone}, nil, "")
	if p := b.start(ar); !strings.Contains(p.location, "error=login_required") {
		t.Fatalf("native prompt=none: %q", p.location)
	}
}

func TestResetPasswordInAuthRequest(t *testing.T) {
	e := newEnv(t, brandCfg{})
	e.z.addUser("pw@example.com", "Old-Pass-1", true)
	b := e.browser()
	ar := e.z.newAuthRequest("web", nil, nil, "")
	p := b.post(b.start(ar), "/login/email", url.Values{"email": {"pw@example.com"}})
	p = b.get("/reset?authRequest=" + ar)
	mustContain(t, p, "Reset your password")
	p = b.post(p, "/reset", url.Values{"email": {"pw@example.com"}})
	mustContain(t, p, "Choose a new password")
	code := e.mail.lastCode(t, "pw@example.com")
	p = b.post(p, "/reset/code", url.Values{"code": {code}, "password": {"New-Pass-1"}, "password_confirm": {"New-Pass-2"}})
	mustContain(t, p, "The passwords do not match.")
	p = b.post(p, "/reset/code", url.Values{"code": {code}, "password": {"weak"}, "password_confirm": {"weak"}})
	mustContain(t, p, "Use at least 8 characters")
	p = b.post(p, "/reset/code", url.Values{"code": {code}, "password": {"New-Pass-1"}, "password_confirm": {"New-Pass-1"}})
	mustCallback(t, p, ar)
	if e.z.user("pw@example.com").password != "New-Pass-1" {
		t.Fatal("password not changed")
	}
}

func TestResetStandaloneReturnAllowlist(t *testing.T) {
	e := newEnv(t, brandCfg{})
	e.z.addUser("pw@example.com", "Old-Pass-1", true)
	b := e.browser()
	if p := b.get("/reset?return=" + url.QueryEscape("https://evil.test/")); p.status != http.StatusBadRequest {
		t.Fatalf("evil return accepted: %d", p.status)
	}
	p := b.get("/reset?return=" + url.QueryEscape("https://app.example.test/settings"))
	mustContain(t, p, "Reset your password")
	p = b.post(p, "/reset", url.Values{"email": {"pw@example.com"}})
	p = b.post(p, "/reset/code", url.Values{"code": {e.mail.lastCode(t, "pw@example.com")}, "password": {"New-Pass-1"}, "password_confirm": {"New-Pass-1"}})
	if p.status != http.StatusSeeOther || p.location != "https://app.example.test/settings" {
		t.Fatalf("after reset: %d %q", p.status, p.location)
	}
}

func TestResetUnknownAddressLooksTheSame(t *testing.T) {
	e := newEnv(t, brandCfg{})
	b := e.browser()
	p := b.get("/reset")
	p = b.post(p, "/reset", url.Values{"email": {"ghost@example.com"}})
	mustContain(t, p, "Choose a new password", "If ghost@example.com belongs to an account")
	if e.mail.count() != 0 {
		t.Fatal("mail sent for unknown address")
	}
	for i := 0; i < 5; i++ {
		p = b.post(p, "/reset/code", url.Values{"code": {"123456"}, "password": {"New-Pass-1"}, "password_confirm": {"New-Pass-1"}})
	}
	mustContain(t, p, "Too many wrong attempts")
}

func TestLogout(t *testing.T) {
	e := newEnv(t, brandCfg{})
	e.z.addUser("pw@example.com", "Secret-123", true)
	b := e.browser()
	signInWithPassword(t, e, b, "pw@example.com", "Secret-123", false)
	if e.z.sessionCount() != 1 {
		t.Fatal("no session")
	}

	// Without a valid logout token: confirmation, and no redirect to an
	// unlisted URL.
	p := b.get("/logout?post_logout_redirect=" + url.QueryEscape("https://evil.test/"))
	mustContain(t, p, "Sign out of Example on this device?")
	if e.z.sessionCount() != 1 {
		t.Fatal("GET without token ended the session")
	}
	forged := e.signLogoutToken(map[string]any{"post_logout_redirect_uri": "https://evil.test/"})
	forged = forged[:len(forged)-4] + "AAAA"
	p = b.get("/logout?post_logout_redirect=" + url.QueryEscape("https://evil.test/") + "&logout_token=" + forged)
	mustContain(t, p, "Sign out of Example on this device?")
	p = b.post(p, "/logout", nil)
	mustContain(t, p, "You&#39;re signed out")
	if e.z.sessionCount() != 0 {
		t.Fatal("session not terminated")
	}

	// With Zitadel's signed logout token: immediate, to the RP's URL.
	signInWithPassword(t, e, b, "pw@example.com", "Secret-123", false)
	target := "https://rp.test/after-logout"
	tok := e.signLogoutToken(map[string]any{"post_logout_redirect_uri": target})
	p = b.get("/logout?post_logout_redirect=" + url.QueryEscape(target) + "&logout_token=" + tok)
	if p.status != http.StatusSeeOther || p.location != target {
		t.Fatalf("logout: %d %q", p.status, p.location)
	}
	if e.z.sessionCount() != 0 {
		t.Fatal("session not terminated")
	}
	// A signed token for another URL does not redirect there.
	tok = e.signLogoutToken(map[string]any{"post_logout_redirect_uri": target})
	p = b.get("/logout?post_logout_redirect=" + url.QueryEscape("https://evil.test/") + "&logout_token=" + tok)
	mustContain(t, p, "You&#39;re signed out")
	// SSO no longer applies.
	ar := e.z.newAuthRequest("web", nil, nil, "")
	mustContain(t, b.start(ar), `action="/login/email"`)
}

func TestIDP(t *testing.T) {
	idps := []config.IDP{{Key: "google", ID: "idp-google"}, {Key: "github", ID: ""}}
	start := func(t *testing.T, e *env, b *browser) (string, string) {
		ar := e.z.newAuthRequest("web", nil, nil, "")
		p := b.start(ar)
		mustContain(t, p, "Or continue with", "Google")
		if strings.Contains(p.body, "GitHub") {
			t.Fatal("unconfigured provider shown")
		}
		p = b.post(p, "/login/idp", url.Values{"provider": {"google"}})
		if p.status != http.StatusSeeOther || !strings.HasPrefix(p.location, "https://idp.test/authorize") {
			t.Fatalf("idp start: %d %q", p.status, p.location)
		}
		u, _ := url.Parse(p.location)
		return ar, u.Query().Get("success")
	}
	back := func(b *browser, success, id, tok string) page {
		return b.get(success + "&id=" + url.QueryEscape(id) + "&token=" + url.QueryEscape(tok))
	}

	t.Run("verified email links existing user", func(t *testing.T) {
		e := newEnv(t, brandCfg{Registration: false, IDPs: idps})
		u := e.z.addUser("g@example.com", "Secret-123", true)
		b := e.browser()
		ar, success := start(t, e, b)
		id, tok := e.z.finishIntent(zitadel.Intent{IDPID: "idp-google", ExtID: "g-1", ExtName: "g", Email: "G@example.com", Verified: true})
		mustCallback(t, back(b, success, id, tok), ar)
		if e.z.links["idp-google|g-1"] != u.UserID {
			t.Fatal("not linked")
		}
	})
	t.Run("unverified email does not link", func(t *testing.T) {
		e := newEnv(t, brandCfg{Registration: true, IDPs: idps})
		e.z.addUser("g@example.com", "Secret-123", true)
		b := e.browser()
		_, success := start(t, e, b)
		id, tok := e.z.finishIntent(zitadel.Intent{IDPID: "idp-google", ExtID: "g-2", Email: "g@example.com", Verified: false})
		mustContain(t, back(b, success, id, tok), "This address can&#39;t be used to sign in.")
		if len(e.z.links) != 0 {
			t.Fatal("linked on unverified email")
		}
	})
	t.Run("unverified email does not create a user", func(t *testing.T) {
		e := newEnv(t, brandCfg{Registration: true, IDPs: idps})
		b := e.browser()
		_, success := start(t, e, b)
		id, tok := e.z.finishIntent(zitadel.Intent{IDPID: "idp-google", ExtID: "g-6", Email: "victim@example.com", Verified: false})
		mustContain(t, back(b, success, id, tok), "This address can&#39;t be used to sign in.")
		if e.z.userCount() != 0 || len(e.z.links) != 0 {
			t.Fatal("account created from an unverified provider email")
		}
	})
	t.Run("new user when registration open", func(t *testing.T) {
		e := newEnv(t, brandCfg{Registration: true, IDPs: idps})
		b := e.browser()
		ar, success := start(t, e, b)
		id, tok := e.z.finishIntent(zitadel.Intent{IDPID: "idp-google", ExtID: "g-3", Email: "fresh@example.com", Verified: true, Given: "Fresh", Family: "Person"})
		mustCallback(t, back(b, success, id, tok), ar)
		u := e.z.user("fresh@example.com")
		if u == nil || u.Human.Profile.GivenName != "Fresh" || !u.Human.Email.IsVerified {
			t.Fatalf("user %+v", u)
		}
	})
	t.Run("new user refused when registration closed", func(t *testing.T) {
		e := newEnv(t, brandCfg{Registration: false, IDPs: idps})
		b := e.browser()
		_, success := start(t, e, b)
		id, tok := e.z.finishIntent(zitadel.Intent{IDPID: "idp-google", ExtID: "g-4", Email: "fresh@example.com", Verified: true})
		mustContain(t, back(b, success, id, tok), "This address can&#39;t be used to sign in.")
		if e.z.userCount() != 0 {
			t.Fatal("user created")
		}
	})
	t.Run("callback state must match the browser", func(t *testing.T) {
		e := newEnv(t, brandCfg{Registration: true, IDPs: idps})
		b := e.browser()
		_, success := start(t, e, b)
		id, tok := e.z.finishIntent(zitadel.Intent{IDPID: "idp-google", ExtID: "g-5", Email: "fresh@example.com", Verified: true})
		evil := strings.Replace(success, "state=", "state=x", 1)
		if p := back(b, evil, id, tok); p.status != http.StatusForbidden {
			t.Fatalf("wrong state: %d", p.status)
		}
		// Another browser cannot complete this browser's flow.
		b2 := e.browser()
		if p := back(b2, success, id, tok); p.status == http.StatusSeeOther {
			t.Fatalf("other browser completed the flow: %q", p.location)
		}
	})
}

func TestPasswordAttemptsRateLimited(t *testing.T) {
	e := newEnv(t, brandCfg{})
	e.z.addUser("pw@example.com", "Secret-123", true)
	b := e.browser()
	ar := e.z.newAuthRequest("web", nil, nil, "")
	p := b.post(b.start(ar), "/login/email", url.Values{"email": {"pw@example.com"}})
	for i := 0; i < DefaultLimits.PasswordPerAccount.Max; i++ {
		p = b.post(p, "/login/password", url.Values{"password": {"wrong"}, "action": {"password"}})
		mustContain(t, p, "That password is not right.")
	}
	// Even the right password is refused while the window is full.
	p = b.post(p, "/login/password", url.Values{"password": {"Secret-123"}, "action": {"password"}})
	mustContain(t, p, "Too many attempts.")
	if p.status != http.StatusTooManyRequests {
		t.Fatalf("status %d", p.status)
	}
	e.clock.add(DefaultLimits.PasswordPerAccount.Window + time.Second)
	p = b.post(p, "/login/password", url.Values{"password": {"Secret-123"}, "action": {"password"}})
	mustCallback(t, p, ar)
}

func TestWithRememberMe(t *testing.T) {
	if got := withRememberMe("https://rp.test/cb?code=x&state=s"); !strings.Contains(got, "remember_me=1") {
		t.Fatal(got)
	}
	if got := withRememberMe("https://rp.test/cb?error=login_required&state=s"); strings.Contains(got, "remember_me") {
		t.Fatal(got)
	}
}

// After an email change the Zitadel login name can still be the old address.
// Typing that old address must never reach the account: no sign-in code, no
// password step and no reset code may go to it, because whoever controls the
// old inbox would then take the account over.
func TestOldAddressAfterEmailChangeDoesNotReachTheAccount(t *testing.T) {
	e := newEnv(t, brandCfg{Registration: false})
	u := e.z.addUser("new@example.com", "Secret-123", true)
	u.Username = "old@example.com"
	u.LoginNames = []string{"old@example.com"}

	b := e.browser()
	ar := e.z.newAuthRequest("web", nil, nil, "")
	p := b.post(b.start(ar), "/login/email", url.Values{"email": {"old@example.com"}})
	mustContain(t, p, "This address can&#39;t be used to sign in.")

	r := e.browser()
	p = r.get("/reset")
	p = r.post(p, "/reset", url.Values{"email": {"old@example.com"}})
	mustContain(t, p, "Choose a new password")
	if e.mail.count() != 0 {
		t.Fatalf("mail sent for the old address: %d", e.mail.count())
	}

	// The current address still works.
	c := e.browser()
	ar = e.z.newAuthRequest("web", nil, nil, "")
	p = c.post(c.start(ar), "/login/email", url.Values{"email": {"new@example.com"}})
	mustContain(t, p, "password")
}

// A TOTP passed for one account must not count for another account reached
// later in the same flow. Here an attacker passes TOTP on their own account
// (whose unverified email keeps the flow open), then switches the flow to a
// password reset for a victim whose inbox they control: the victim's TOTP is
// still required.
func TestTOTPDoesNotCarryOverToAnotherAccount(t *testing.T) {
	e := newEnv(t, brandCfg{})
	attacker := e.z.addUser("attacker@example.com", "Secret-123", false)
	attacker.totp = "111222"
	victim := e.z.addUser("victim@example.com", "Victim-Pass-1", true)
	victim.totp = "424242"

	b := e.browser()
	ar := e.z.newAuthRequest("web", nil, nil, "")
	p := b.post(b.start(ar), "/login/email", url.Values{"email": {"attacker@example.com"}})
	p = b.post(p, "/login/password", url.Values{"password": {"Secret-123"}, "action": {"password"}})
	mustContain(t, p, "Two-step verification")
	p = b.post(p, "/login/totp", url.Values{"otp": {"111222"}})
	if p.status == http.StatusSeeOther && strings.Contains(p.location, "code=") {
		t.Fatal("attacker flow finished; the test needs it to stay open")
	}

	p = b.get("/reset?authRequest=" + ar)
	p = b.post(p, "/reset", url.Values{"email": {"victim@example.com"}})
	code := e.mail.lastCode(t, "victim@example.com")
	p = b.post(p, "/reset/code", url.Values{"code": {code}, "password": {"New-Pass-1"}, "password_confirm": {"New-Pass-1"}})
	mustContain(t, p, "Two-step verification")
	p = b.post(p, "/login/totp", url.Values{"otp": {"111222"}})
	mustContain(t, p, "That code is not right.")
}
