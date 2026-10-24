package e2e

import (
	"net/url"
	"os"
	"slices"
	"strings"
	"testing"
	"time"
)

const fixturePassword = "E2e-Passw0rd!"

func signedIn(t *testing.T, p page, email string) {
	t.Helper()
	if p.url.Host != "localhost:8095" || !strings.Contains(p.body, "Signed in as") || !strings.Contains(p.body, email) {
		t.Fatalf("not signed in at the RP as %s: %s (%d)\n%.2000s", email, p.url, p.status, p.body)
	}
}

// rpLogin opens the relying party, which sends the browser through Zitadel to
// idlogin.
func rpLogin(b *browser) page { return b.get(rpURL + "/") }

func emailPage(t *testing.T, p page) {
	t.Helper()
	if p.url.Host != "localhost:8091" && p.url.Host != "127.0.0.1:8091" || !strings.Contains(p.body, `action="/login/email"`) {
		t.Fatalf("expected the email page, got %s (%d)\n%.2000s", p.url, p.status, p.body)
	}
}

func passwordSignIn(t *testing.T, b *browser, email string, remember bool) page {
	t.Helper()
	p := rpLogin(b)
	emailPage(t, p)
	form := url.Values{"email": {email}}
	if remember {
		form.Set("remember", "on")
	}
	p = b.submit(p, "/login/email", form)
	must(t, p, "Enter your password")
	return b.submit(p, "/login/password", url.Values{"password": {fixturePassword}, "action": {"password"}})
}

func TestE2E(t *testing.T) {
	if os.Getenv("LOGIN_E2E") != "1" {
		t.Skip("set LOGIN_E2E=1 to run against the local stack (scripts/dev-up.sh)")
	}
	s := newStack(t)
	t.Cleanup(s.cleanup)
	s.resetIPLimits()
	s.startRP()
	s.idpID = s.ensureLoopbackIdP()
	s.overrideBrands(s.idpID)

	t.Run("signup by code", func(t *testing.T) {
		b := newBrowser(t)
		email := s.email("new")
		p := rpLogin(b)
		emailPage(t, p)
		must(t, p, "Sign in or create your account", "Keep me signed in for 30 days")
		p = b.submit(p, "/login/email", url.Values{"email": {email}})
		must(t, p, "Check your email", "creates your account")
		if s.findUser(email) != nil {
			t.Fatal("user exists before the code was entered")
		}
		p = b.submit(p, "/login/code", url.Values{"code": {s.code(email)}, "action": {"verify"}})
		signedIn(t, p, email)
		if b.visited("remember_me=1") {
			t.Error("remember_me without the box ticked")
		}
		u := s.findUser(email)
		if u == nil || !u.Human.Email.IsVerified {
			t.Fatalf("user %+v", u)
		}
		if m := s.authMethods(u.UserID); slices.Contains(m, "AUTHENTICATION_METHOD_TYPE_PASSWORD") || !slices.Contains(m, "AUTHENTICATION_METHOD_TYPE_OTP_EMAIL") {
			t.Fatalf("auth methods %v", m)
		}
	})

	pwUser := s.email("pw")
	pwUserID := s.fixtureUser(pwUser, fixturePassword, true)

	t.Run("password user with remember me", func(t *testing.T) {
		b := newBrowser(t)
		p := passwordSignIn(t, b, pwUser, true)
		signedIn(t, p, pwUser)
		if !b.visited("remember_me=1") {
			t.Errorf("remember_me=1 not on the callback: %v", b.chain)
		}
	})

	t.Run("wrong password", func(t *testing.T) {
		b := newBrowser(t)
		p := rpLogin(b)
		p = b.submit(p, "/login/email", url.Values{"email": {pwUser}})
		p = b.submit(p, "/login/password", url.Values{"password": {"nope"}, "action": {"password"}})
		must(t, p, "That password is not right.")
	})

	t.Run("passwordless user gets a code", func(t *testing.T) {
		b := newBrowser(t)
		email := s.email("nopw")
		s.fixtureUser(email, "", true)
		p := rpLogin(b)
		p = b.submit(p, "/login/email", url.Values{"email": {email}})
		must(t, p, "Check your email")
		if strings.Contains(p.body, "creates your account") {
			t.Fatal("existing user told the code creates an account")
		}
		signedIn(t, b.submit(p, "/login/code", url.Values{"code": {s.code(email)}}), email)
	})

	t.Run("password to code switch", func(t *testing.T) {
		b := newBrowser(t)
		p := rpLogin(b)
		p = b.submit(p, "/login/email", url.Values{"email": {pwUser}})
		p = b.submit(p, "/login/password", url.Values{"action": {"code"}})
		must(t, p, "Check your email")
		signedIn(t, b.submit(p, "/login/code", url.Values{"code": {s.code(pwUser)}}), pwUser)
	})

	t.Run("five wrong codes kill the code", func(t *testing.T) {
		b := newBrowser(t)
		email := s.email("wrong")
		s.fixtureUser(email, "", true)
		p := b.submit(rpLogin(b), "/login/email", url.Values{"email": {email}})
		good := s.code(email)
		bad := "000000"
		if good == bad {
			bad = "111111"
		}
		for i := 1; i <= 5; i++ {
			p = b.submit(p, "/login/code", url.Values{"code": {bad}})
		}
		must(t, p, "Too many wrong attempts for this code")
		p = b.submit(p, "/login/code", url.Values{"code": {good}})
		must(t, p, "Too many wrong attempts for this code")
		if p.url.Host != "localhost:8091" {
			t.Fatal("dead code signed in")
		}
	})

	t.Run("sixth send in an hour refused", func(t *testing.T) {
		b := newBrowser(t)
		email := s.email("sends")
		s.fixtureUser(email, "", true)
		p := b.submit(rpLogin(b), "/login/email", url.Values{"email": {email}})
		for i := 2; i <= 5; i++ {
			p = b.submit(p, "/login/code", url.Values{"action": {"resend"}})
			must(t, p, "A new code is on its way.")
		}
		p = b.submit(p, "/login/code", url.Values{"action": {"resend"}})
		must(t, p, "Too many codes were sent to this address in the last hour.")
		if p.status != 429 || len(s.mailFiles(email)) != 5 {
			t.Fatalf("status %d, mails %d", p.status, len(s.mailFiles(email)))
		}
	})

	t.Run("registration closed: neutral error, no user", func(t *testing.T) {
		b := newBrowser(t)
		b.stop = func(u *url.URL) bool { return u.Host == "localhost:8091" }
		p := rpLogin(b)
		if p.loc == "" {
			t.Fatalf("no redirect to the login: %v", b.chain)
		}
		// Same auth request, served by the registration-closed brand.
		closed := strings.Replace(p.loc, loginURL, closedURL, 1)
		b.stop = nil
		p = b.get(closed)
		emailPage(t, p)
		email := s.email("closed")
		p = b.submit(p, "/login/email", url.Values{"email": {email}})
		must(t, p, "This address can&#39;t be used to sign in.")
		if s.findUser(email) != nil || len(s.mailFiles(email)) != 0 {
			t.Fatal("user created or mail sent")
		}
		// A locked account gets exactly the same answer.
		locked := s.email("locked")
		uid := s.fixtureUser(locked, fixturePassword, true)
		if err := s.api("POST", "/v2/users/"+uid+"/lock", map[string]any{}, nil); err != nil {
			t.Fatal(err)
		}
		p2 := b.submit(b.submit(p, "/login/restart", nil), "/login/email", url.Values{"email": {locked}})
		must(t, p2, "This address can&#39;t be used to sign in.")
	})

	t.Run("reset password", func(t *testing.T) {
		b := newBrowser(t)
		email := s.email("reset")
		s.fixtureUser(email, fixturePassword, true)
		p := b.submit(rpLogin(b), "/login/email", url.Values{"email": {email}})
		must(t, p, "Forgot password?")
		ar := arRe.FindStringSubmatch(p.body)[1]
		p = b.get(loginURL + "/reset?authRequest=" + url.QueryEscape(ar))
		must(t, p, "Reset your password")
		p = b.submit(p, "/reset", url.Values{"email": {email}})
		must(t, p, "Choose a new password")
		newPW := "N3w-Passw0rd!"
		p = b.submit(p, "/reset/code", url.Values{"code": {s.code(email)}, "password": {newPW}, "password_confirm": {newPW}, "action": {"update"}})
		signedIn(t, p, email)
		// The new password works.
		b2 := newBrowser(t)
		p = b2.submit(rpLogin(b2), "/login/email", url.Values{"email": {email}})
		signedIn(t, b2.submit(p, "/login/password", url.Values{"password": {newPW}, "action": {"password"}}), email)
	})

	t.Run("standalone reset rejects unlisted return URL", func(t *testing.T) {
		b := newBrowser(t)
		p := b.get(loginURL + "/reset?return=" + url.QueryEscape("https://evil.example/"))
		if p.status != 400 {
			t.Fatalf("status %d", p.status)
		}
		p = b.get(loginURL + "/reset?return=" + url.QueryEscape(rpURL+"/"))
		must(t, p, "Reset your password")
	})

	t.Run("unverified email needs a code", func(t *testing.T) {
		b := newBrowser(t)
		email := s.email("unverified")
		s.fixtureUser(email, fixturePassword, false)
		p := rpLogin(b)
		p = b.submit(p, "/login/email", url.Values{"email": {email}})
		p = b.submit(p, "/login/password", url.Values{"password": {fixturePassword}, "action": {"password"}})
		must(t, p, "Verify your email")
		signedIn(t, b.submit(p, "/login/code", url.Values{"code": {s.code(email)}}), email)
		if u := s.findUser(email); u == nil || !u.Human.Email.IsVerified {
			t.Fatal("email not verified")
		}
	})

	// One browser for SSO, prompt and logout.
	sso := newBrowser(t)
	t.Run("SSO reuse on a second auth request", func(t *testing.T) {
		signedIn(t, passwordSignIn(t, sso, pwUser, false), pwUser)
		sso.dropCookie(rpURL, rpSessionCookie)
		p := rpLogin(sso)
		signedIn(t, p, pwUser)
		if !sso.visited(loginURL+"/login?authRequest=") || sso.visited("/login/email") {
			t.Fatalf("expected a silent pass through the login: %v", sso.chain)
		}
	})

	t.Run("prompt=login forces re-authentication", func(t *testing.T) {
		_, ch := pkce()
		sso.stop = func(u *url.URL) bool { return u.Host == "localhost:8095" }
		defer func() { sso.stop = nil }()
		p := sso.get(authorizeURL(s.rp.ClientID, rpURL+"/auth/callback", "openid email", ch, map[string]string{"prompt": "login"}))
		emailPage(t, p)
		p = sso.submit(p, "/login/email", url.Values{"email": {pwUser}})
		p = sso.submit(p, "/login/password", url.Values{"password": {fixturePassword}, "action": {"password"}})
		if !strings.HasPrefix(p.loc, rpURL+"/auth/callback?code=") {
			t.Fatalf("no code after re-auth: %q %v", p.loc, sso.chain)
		}
	})

	t.Run("prompt=none without session gives login_required", func(t *testing.T) {
		b := newBrowser(t)
		b.stop = func(u *url.URL) bool { return u.Host == "localhost:8095" }
		_, ch := pkce()
		p := b.get(authorizeURL(s.rp.ClientID, rpURL+"/auth/callback", "openid email", ch, map[string]string{"prompt": "none"}))
		if !strings.HasPrefix(p.loc, rpURL+"/auth/callback?") || !strings.Contains(p.loc, "error=login_required") {
			t.Fatalf("got %q (%v)", p.loc, b.chain)
		}
		// With a session, prompt=none succeeds silently.
		sso.stop = b.stop
		defer func() { sso.stop = nil }()
		p = sso.get(authorizeURL(s.rp.ClientID, rpURL+"/auth/callback", "openid email", ch, map[string]string{"prompt": "none"}))
		if !strings.Contains(p.loc, "code=") {
			t.Fatalf("prompt=none with session: %q", p.loc)
		}
	})

	t.Run("native app gets its own session, JWT access token carries email", func(t *testing.T) {
		native := s.ensureApp("idlogin-e2e", "e2e-native", map[string]any{
			"redirectUris": []string{nativeCB}, "responseTypes": []string{"OIDC_RESPONSE_TYPE_CODE"},
			"grantTypes": []string{"OIDC_GRANT_TYPE_AUTHORIZATION_CODE", "OIDC_GRANT_TYPE_REFRESH_TOKEN"},
			"appType":    "OIDC_APP_TYPE_NATIVE", "authMethodType": "OIDC_AUTH_METHOD_TYPE_NONE",
			"accessTokenType": "OIDC_TOKEN_TYPE_JWT", "devMode": true,
		})
		s.native = native.ClientID
		sso.stop = func(u *url.URL) bool { return strings.HasPrefix(u.String(), nativeCB) }
		defer func() { sso.stop = nil }()
		ver, ch := pkce()
		p := sso.get(authorizeURL(native.ClientID, nativeCB, "openid email offline_access", ch, nil))
		emailPage(t, p) // no SSO for native apps, although the browser has a session
		p = sso.submit(p, "/login/email", url.Values{"email": {pwUser}})
		p = sso.submit(p, "/login/password", url.Values{"password": {fixturePassword}, "action": {"password"}})
		cb, err := url.Parse(p.loc)
		if err != nil || cb.Query().Get("code") == "" {
			t.Fatalf("native callback %q", p.loc)
		}
		tok, status := tokenRequest(url.Values{"grant_type": {"authorization_code"}, "code": {cb.Query().Get("code")},
			"redirect_uri": {nativeCB}, "code_verifier": {ver}}, native.ClientID, "")
		if status != 200 {
			t.Fatalf("token: %d %s", status, tok.Error)
		}
		claims := jwtClaims(t, tok.AccessToken)
		if claims["email"] != pwUser || claims["email_verified"] != true {
			t.Fatalf("access token claims lack email: %v", claims)
		}
		nativeRefresh = tok.RefreshToken
	})

	t.Run("logout via end_session ends the browser sessions, RP gets back-channel logout", func(t *testing.T) {
		// RP session is live.
		signedIn(t, rpLogin(sso), pwUser)
		// RP-initiated logout without id_token_hint lands on idlogin's /logout.
		p := sso.get(zitadelURL + "/oidc/v1/end_session?" + url.Values{
			"client_id": {s.rp.ClientID}, "post_logout_redirect_uri": {rpURL + "/"}}.Encode())
		if !sso.visited(loginURL + "/logout?") {
			t.Fatalf("did not pass idlogin /logout: %v", sso.chain)
		}
		// The RP's own session is ended by the back-channel logout (async).
		deadline := time.Now().Add(15 * time.Second)
		for !sso.visited("/auth/login") {
			if time.Now().After(deadline) {
				t.Fatalf("RP still signed in after logout: %v\n%.500s", sso.chain, p.body)
			}
			time.Sleep(500 * time.Millisecond)
			sso.stop = func(u *url.URL) bool { return u.Host != "localhost:8095" }
			p = sso.get(rpURL + "/")
			sso.stop = nil
		}
		// No SSO any more.
		emailPage(t, rpLogin(sso))
		// The native app's tokens survive the web logout.
		if nativeRefresh == "" {
			t.Skip("no native refresh token")
		}
		tok, status := tokenRequest(url.Values{"grant_type": {"refresh_token"}, "refresh_token": {nativeRefresh}}, s.native, "")
		if status != 200 {
			t.Fatalf("native refresh after web logout: %d %s", status, tok.Error)
		}
	})

	t.Run("RP logout with id_token_hint ends SSO", func(t *testing.T) {
		b := newBrowser(t)
		signedIn(t, passwordSignIn(t, b, pwUser, false), pwUser)
		b.postTo(rpURL+"/auth/logout", rpURL, nil)
		b.dropCookie(rpURL, rpSessionCookie)
		emailPage(t, rpLogin(b))
	})

	t.Run("console sign-in for the admin", func(t *testing.T) {
		var env struct {
			ClientID string `json:"clientid"`
		}
		resp, err := httpGetJSON(zitadelURL+"/ui/console/assets/environment.json", &env)
		if err != nil || env.ClientID == "" {
			t.Fatalf("console env: %v %v", err, resp)
		}
		b := newBrowser(t)
		redirect := zitadelURL + "/ui/console/auth/callback"
		b.stop = func(u *url.URL) bool { return strings.HasPrefix(u.String(), redirect) }
		ver, ch := pkce()
		p := b.get(authorizeURL(env.ClientID, redirect, "openid profile email offline_access urn:zitadel:iam:org:project:id:zitadel:aud", ch, nil))
		emailPage(t, p)
		p = b.submit(p, "/login/email", url.Values{"email": {"admin@id.localhost"}})
		must(t, p, "Enter your password")
		p = b.submit(p, "/login/password", url.Values{"password": {s.env["ZITADEL_FIRSTINSTANCE_ORG_HUMAN_PASSWORD"]}, "action": {"password"}})
		cb, _ := url.Parse(p.loc)
		if cb == nil || cb.Query().Get("code") == "" {
			t.Fatalf("console callback %q\n%.1000s", p.loc, p.body)
		}
		tok, status := tokenRequest(url.Values{"grant_type": {"authorization_code"}, "code": {cb.Query().Get("code")},
			"redirect_uri": {redirect}, "code_verifier": {ver}}, env.ClientID, "")
		if status != 200 {
			t.Fatalf("console token: %d %s", status, tok.Error)
		}
		var me struct {
			User struct {
				UserName string `json:"userName"`
			} `json:"user"`
		}
		if err := call(tok.AccessToken, "GET", "/auth/v1/users/me", nil, &me); err != nil || me.User.UserName == "" {
			t.Fatalf("console API as admin: %v %+v", err, me)
		}
	})

	t.Run("generic OIDC IdP (loopback) links the verified email", func(t *testing.T) {
		b := newBrowser(t)
		email := s.email("idp")
		uid := s.fixtureUser(email, fixturePassword, true)
		p := rpLogin(b)
		must(t, p, "Loopback IdP")
		// Out to the "provider" (this Zitadel), which sends the browser to
		// idlogin again for its own auth request.
		p = b.submit(p, "/login/idp", url.Values{"provider": {"e2e"}})
		emailPage(t, p)
		p = b.submit(p, "/login/email", url.Values{"email": {email}})
		p = b.submit(p, "/login/password", url.Values{"password": {fixturePassword}, "action": {"password"}})
		// Back through /idps/callback and /login/idp/callback to the RP.
		signedIn(t, p, email)
		if !b.visited("/idps/callback") || !b.visited("/login/idp/callback") {
			t.Fatalf("IdP path not taken: %v", b.chain)
		}
		var links struct {
			Result []struct {
				IDPID string `json:"idpId"`
			} `json:"result"`
		}
		if err := s.api("POST", "/v2/users/"+uid+"/links/_search", map[string]any{}, &links); err != nil {
			t.Fatal(err)
		}
		if len(links.Result) != 1 || links.Result[0].IDPID != s.idpID {
			t.Fatalf("links %+v", links)
		}
	})
	_ = pwUserID
}

var nativeRefresh string
