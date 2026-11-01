package web

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/velixio/idlogin/internal/zitadel"
)

func consentPending(t *testing.T, e *env, ar string, p page) {
	t.Helper()
	mustContain(t, p, `action="/login/consent"`, `value="allow"`, `value="deny"`, "Allow", "pw@example.com")
	e.z.mu.Lock()
	defer e.z.mu.Unlock()
	if e.z.done[ar] != "" {
		t.Fatalf("auth request finalized before Allow: %q", e.z.done[ar])
	}
}

func TestConsentRecentBrowserSSORequiresAllowForWebAndNative(t *testing.T) {
	for _, client := range []string{"web", "desktop"} {
		t.Run(client, func(t *testing.T) {
			e := newEnv(t, brandCfg{Registration: true})
			e.z.native["desktop"] = true
			e.z.addUser("pw@example.com", "Secret-123", true)
			b := e.browser()
			signInWithPassword(t, e, b, "pw@example.com", "Secret-123", true)
			ma := 24 * time.Hour
			for range 2 {
				ar := e.z.newAuthRequest(client, []string{zitadel.PromptConsent}, &ma, "")
				p := b.start(ar)
				consentPending(t, e, ar, p)
				cb := mustCallback(t, b.post(p, "/login/consent", url.Values{"action": {"allow"}}), ar)
				if cb.Query().Get("remember_me") != "1" {
					t.Fatal("remembered browser session lost")
				}
			}
		})
	}
}

func TestConsentFreshLoginAndSignupWaitForAllow(t *testing.T) {
	for _, signup := range []bool{false, true} {
		t.Run(map[bool]string{false: "password", true: "signup-code"}[signup], func(t *testing.T) {
			e := newEnv(t, brandCfg{Registration: true})
			b := e.browser()
			prompts := []string{zitadel.PromptConsent}
			if signup {
				prompts = append(prompts, zitadel.PromptCreate)
			} else {
				e.z.addUser("pw@example.com", "Secret-123", true)
			}
			ma := 24 * time.Hour
			ar := e.z.newAuthRequest("web", prompts, &ma, "")
			p := b.post(b.start(ar), "/login/email", url.Values{"email": {"pw@example.com"}})
			if signup {
				p = b.post(p, "/login/code", url.Values{"code": {e.mail.lastCode(t, "pw@example.com")}})
			} else {
				p = b.post(p, "/login/password", url.Values{"password": {"Secret-123"}, "action": {"password"}})
			}
			consentPending(t, e, ar, p)
			mustCallback(t, b.post(p, "/login/consent", url.Values{"action": {"allow"}}), ar)
		})
	}
}

func TestConsentDenyAndForgeryNeverFinalize(t *testing.T) {
	e := newEnv(t, brandCfg{})
	e.z.addUser("pw@example.com", "Secret-123", true)
	b := e.browser()
	signInWithPassword(t, e, b, "pw@example.com", "Secret-123", false)
	ma := 24 * time.Hour
	ar := e.z.newAuthRequest("web", []string{zitadel.PromptConsent}, &ma, "")
	p := b.start(ar)
	consentPending(t, e, ar, p)
	if bad := b.post(p, "/login/consent", url.Values{"action": {"allow"}, "csrf": {"forged"}}); bad.status != http.StatusForbidden {
		t.Fatalf("forged consent: %d", bad.status)
	}
	if bad := b.post(p, "/login/consent", url.Values{"action": {"unknown"}}); bad.status != http.StatusBadRequest {
		t.Fatalf("unknown consent action: %d", bad.status)
	}
	request, _ := http.NewRequest(http.MethodPost, b.abs("/login/consent"), strings.NewReader(url.Values{"authRequest": {ar}, "csrf": {csrfRe.FindStringSubmatch(p.body)[1]}, "action": {"allow"}}.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("Origin", "https://untrusted.example")
	if forged := b.do(request); forged.status != http.StatusForbidden {
		t.Fatalf("cross-origin consent: %d", forged.status)
	}
	consentPending(t, e, ar, b.start(ar))
	denied := b.post(p, "/login/consent", url.Values{"action": {"deny"}})
	if denied.status != http.StatusSeeOther || !strings.Contains(denied.location, "error=access_denied") || strings.Contains(denied.location, "code=") {
		t.Fatalf("deny: %+v", denied)
	}
	replay := b.post(p, "/login/consent", url.Values{"action": {"allow"}})
	if strings.Contains(replay.location, "code=") {
		t.Fatal("denied flow replay produced a code")
	}
}

func TestConsentTwentyFourHourLimitBeforeAndAfterPage(t *testing.T) {
	e := newEnv(t, brandCfg{})
	e.z.addUser("pw@example.com", "Secret-123", true)
	b := e.browser()
	signInWithPassword(t, e, b, "pw@example.com", "Secret-123", false)
	e.clock.add(23*time.Hour + 59*time.Minute)
	ma := 24 * time.Hour
	ar := e.z.newAuthRequest("web", []string{zitadel.PromptConsent}, &ma, "")
	p := b.start(ar)
	consentPending(t, e, ar, p)
	e.clock.add(2 * time.Minute)
	mustContain(t, b.post(p, "/login/consent", url.Values{"action": {"allow"}}), `action="/login/email"`)
	ar = e.z.newAuthRequest("web", []string{zitadel.PromptConsent}, &ma, "")
	mustContain(t, b.start(ar), `action="/login/email"`)
}

func TestConsentRevokedSessionDoesNotComplete(t *testing.T) {
	e := newEnv(t, brandCfg{})
	e.z.addUser("pw@example.com", "Secret-123", true)
	b := e.browser()
	cb := signInWithPassword(t, e, b, "pw@example.com", "Secret-123", false)
	e.z.mu.Lock()
	sid := e.z.done[strings.TrimPrefix(cb.Query().Get("code"), "c-")]
	e.z.mu.Unlock()
	ma := 24 * time.Hour
	ar := e.z.newAuthRequest("web", []string{zitadel.PromptConsent}, &ma, "")
	p := b.start(ar)
	consentPending(t, e, ar, p)
	if err := e.z.DeleteSession(context.Background(), zitadel.Instance{}, sid, ""); err != nil {
		t.Fatal(err)
	}
	mustContain(t, b.post(p, "/login/consent", url.Values{"action": {"allow"}}), `action="/login/email"`)
}

func TestConsentRegisteredAppAndPermissionsNotQueryMetadata(t *testing.T) {
	e := newEnv(t, brandCfg{})
	e.z.addUser("pw@example.com", "Secret-123", true)
	b := e.browser()
	signInWithPassword(t, e, b, "pw@example.com", "Secret-123", false)
	ar := e.z.newAuthRequest("web", []string{zitadel.PromptConsent}, nil, "")
	e.z.mu.Lock()
	e.z.ars[ar].Scope = []string{"openid", "profile", "email", "offline_access"}
	e.z.mu.Unlock()
	p := b.get("/login?authRequest=" + ar + "&appName=UntrustedApp")
	consentPending(t, e, ar, p)
	mustContain(t, p, "Example web", "Sign you in to this app", "Read your name and profile", "Read your email address", "Keep you signed in")
	if strings.Contains(p.body, "UntrustedApp") {
		t.Fatal("query metadata used as app identity")
	}
}

func TestConsentOldNativeApprovalCookieCannotBypassAllow(t *testing.T) {
	e := newEnv(t, brandCfg{})
	e.z.native["desktop"] = true
	e.z.addUser("pw@example.com", "Secret-123", true)
	b := e.browser()
	signInWithPassword(t, e, b, "pw@example.com", "Secret-123", false)
	ar := e.z.newAuthRequest("desktop", []string{zitadel.PromptConsent}, nil, "")
	p := b.start(ar)
	consentPending(t, e, ar, p)
	target, _ := url.Parse(b.origin)
	for _, cookie := range b.c.Jar.Cookies(target) {
		if !strings.Contains(cookie.Name, "idl-f-") {
			continue
		}
		var f flow
		if err := e.web.sealer.Open(cookie.Name, cookie.Value, &f); err != nil {
			t.Fatal(err)
		}
		f.Step, f.Consent, f.ClientID, f.AppName = stepApprove, false, "", ""
		token, err := e.web.sealer.Seal(cookie.Name, &f, flowTTL)
		if err != nil {
			t.Fatal(err)
		}
		b.c.Jar.SetCookies(target, []*http.Cookie{{Name: cookie.Name, Value: token, Path: "/"}})
	}
	consentPending(t, e, ar, b.post(p, "/login/approve", nil))
}

func TestConsentAppMetadataClient(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/zitadel.application.v2.ApplicationService/ListApplications" {
			t.Errorf("unexpected API path: %s", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"applications":[{"name":"Registered Desktop","oidcConfiguration":{"clientId":"desktop","applicationType":"OIDC_APP_TYPE_NATIVE"}}]}`))
	}))
	defer server.Close()
	client := zitadel.New(server.URL)
	app, err := client.GetApplication(context.Background(), zitadel.Instance{}, "desktop")
	if err != nil || app.Name != "Registered Desktop" || !app.Native {
		t.Fatalf("application: %+v %v", app, err)
	}
	if _, err := client.GetApplication(context.Background(), zitadel.Instance{}, "other"); err == nil {
		t.Fatal("unmatched client accepted")
	}
}

func TestConsentHTMLDoesNotTrustApplicationMarkup(t *testing.T) {
	e := newEnv(t, brandCfg{})
	e.z.addUser("pw@example.com", "Secret-123", true)
	b := e.browser()
	signInWithPassword(t, e, b, "pw@example.com", "Secret-123", false)
	ar := e.z.newAuthRequest("<script>alert(1)</script>", []string{zitadel.PromptConsent}, nil, "")
	p := b.start(ar)
	if strings.Contains(p.body, "<script>alert(1)") || !strings.Contains(p.body, "&lt;script&gt;") {
		t.Fatalf("application markup not escaped: %s", p.body)
	}
}
