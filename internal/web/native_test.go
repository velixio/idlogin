package web

import (
	"bytes"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/velixio/idlogin/internal/zitadel"
)

const nativeClient = "phone-app"

type nativeReply struct {
	Status   int
	Step     string `json:"step"`
	Flow     string `json:"flow"`
	Callback string `json:"callback"`
	Error    string `json:"error"`
	Retry    string
}

func nativeEnv(t *testing.T, registration bool) *env {
	t.Helper()
	e := newEnv(t, brandCfg{Registration: registration, Extra: map[string]any{"native_api_clients": []string{nativeClient}}})
	e.z.native[nativeClient] = true
	return e
}

func (e *env) nativeRaw(path string, body any, headers map[string]string) nativeReply {
	e.t.Helper()
	raw, _ := json.Marshal(body)
	req, _ := http.NewRequest(http.MethodPost, e.srv.URL+path, bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	defer resp.Body.Close()
	out := nativeReply{Status: resp.StatusCode, Retry: resp.Header.Get("Retry-After")}
	_ = json.NewDecoder(resp.Body).Decode(&out)
	if got := resp.Header.Get("Cache-Control"); got != "no-store" {
		e.t.Fatalf("Cache-Control = %q", got)
	}
	if len(resp.Cookies()) != 0 {
		e.t.Fatalf("native API set cookies: %v", resp.Cookies())
	}
	return out
}

func (e *env) nativeStart(ar, email string) nativeReply {
	e.t.Helper()
	return e.nativeRaw("/login/native/start", map[string]string{"auth_request": ar, "email": email}, nil)
}

func (e *env) nativeCode(flow, code string) nativeReply {
	e.t.Helper()
	return e.nativeRaw("/login/native/code", map[string]string{"flow": flow, "code": code}, nil)
}

func wantStep(t *testing.T, r nativeReply, step string) {
	t.Helper()
	if r.Status != http.StatusOK || r.Step != step {
		t.Fatalf("want step %q, got %+v", step, r)
	}
}

func wantError(t *testing.T, r nativeReply, status int, code string) {
	t.Helper()
	if r.Status != status || r.Error != code {
		t.Fatalf("want %d %q, got %+v", status, code, r)
	}
}

func wrongCode(right string) string {
	if right == "000000" {
		return "111111"
	}
	return "000000"
}

func TestNativeNewEmailSignsUpAfterCode(t *testing.T) {
	e := nativeEnv(t, true)
	ar := e.z.newAuthRequest(nativeClient, []string{zitadel.PromptLogin}, nil, "")
	r := e.nativeStart(ar, "New@Example.com")
	wantStep(t, r, "code")
	if e.z.userCount() != 0 {
		t.Fatal("account created before the code was entered")
	}
	done := e.nativeCode(r.Flow, " "+e.mail.lastCode(t, "new@example.com")+" ")
	wantStep(t, done, "done")
	if !strings.HasPrefix(done.Callback, "https://rp.test/cb?code=c-"+ar) {
		t.Fatalf("callback = %q", done.Callback)
	}
	if u := e.z.user("new@example.com"); u == nil || !u.Human.Email.IsVerified {
		t.Fatal("verified account not created")
	}
}

func TestNativePasswordUserGetsCode(t *testing.T) {
	e := nativeEnv(t, true)
	e.z.addUser("pw@example.com", "Secret-123", true)
	ar := e.z.newAuthRequest(nativeClient, nil, nil, "")
	r := e.nativeStart(ar, "pw@example.com")
	wantStep(t, r, "code")
	wantStep(t, e.nativeCode(r.Flow, e.mail.lastCode(t, "pw@example.com")), "done")
}

func TestNativeConsentPromptDoesNotBlockAllowedClient(t *testing.T) {
	e := nativeEnv(t, true)
	e.z.addUser("c@example.com", "", true)
	ar := e.z.newAuthRequest(nativeClient, []string{zitadel.PromptConsent}, nil, "")
	r := e.nativeStart(ar, "c@example.com")
	wantStep(t, e.nativeCode(r.Flow, e.mail.lastCode(t, "c@example.com")), "done")
}

func TestNativeTOTPStepRequired(t *testing.T) {
	e := nativeEnv(t, true)
	e.z.addUser("totp@example.com", "", true).totp = "424242"
	ar := e.z.newAuthRequest(nativeClient, nil, nil, "")
	r := e.nativeStart(ar, "totp@example.com")
	next := e.nativeCode(r.Flow, e.mail.lastCode(t, "totp@example.com"))
	wantStep(t, next, "totp")
	if next.Callback != "" {
		t.Fatal("callback issued before TOTP")
	}
	totp := func(code string) nativeReply {
		return e.nativeRaw("/login/native/totp", map[string]string{"flow": next.Flow, "code": code}, nil)
	}
	wantError(t, totp("111111"), http.StatusUnprocessableEntity, "wrong_code")
	wantStep(t, totp("424242"), "done")
}

func TestNativeRejectsBrowserRequests(t *testing.T) {
	e := nativeEnv(t, true)
	for name, headers := range map[string]map[string]string{
		"origin": {"Origin": e.srv.URL}, "fetch": {"Sec-Fetch-Site": "same-origin"},
		"referer": {"Referer": e.srv.URL + "/"}, "form": {"Content-Type": "text/plain"},
	} {
		t.Run(name, func(t *testing.T) {
			ar := e.z.newAuthRequest(nativeClient, nil, nil, "")
			r := e.nativeRaw("/login/native/start", map[string]string{"auth_request": ar, "email": "a@example.com"}, headers)
			if r.Status != http.StatusForbidden {
				t.Fatalf("got %+v", r)
			}
			if e.mail.count() != 0 {
				t.Fatal("mail sent")
			}
		})
	}
}

func TestNativeClientAllowlist(t *testing.T) {
	e := nativeEnv(t, true)
	e.z.native["other"] = true
	wantError(t, e.nativeStart(e.z.newAuthRequest("other", nil, nil, ""), "a@example.com"), http.StatusForbidden, "client_not_allowed")
	e.z.native[nativeClient] = false
	wantError(t, e.nativeStart(e.z.newAuthRequest(nativeClient, nil, nil, ""), "a@example.com"), http.StatusForbidden, "client_not_allowed")
	if e.mail.count() != 0 {
		t.Fatal("mail sent")
	}
}

func TestNativeOffByDefault(t *testing.T) {
	e := newEnv(t, brandCfg{Registration: true})
	e.z.native[nativeClient] = true
	wantError(t, e.nativeStart(e.z.newAuthRequest(nativeClient, nil, nil, ""), "a@example.com"), http.StatusForbidden, "client_not_allowed")
}

func TestNativeInputErrors(t *testing.T) {
	e := nativeEnv(t, true)
	ar := e.z.newAuthRequest(nativeClient, nil, nil, "")
	wantError(t, e.nativeStart(ar, "not an address"), http.StatusUnprocessableEntity, "invalid_email")
	wantError(t, e.nativeStart("nope", "a@example.com"), http.StatusGone, "expired")
	wantError(t, e.nativeCode("forged", "123456"), http.StatusGone, "expired")
}

func TestNativeWrongCodeLocks(t *testing.T) {
	e := nativeEnv(t, true)
	r := e.nativeStart(e.z.newAuthRequest(nativeClient, nil, nil, ""), "a@example.com")
	bad := wrongCode(e.mail.lastCode(t, "a@example.com"))
	wantError(t, e.nativeCode(r.Flow, bad), http.StatusUnprocessableEntity, "wrong_code")
	var last nativeReply
	for i := 0; i < 10; i++ {
		last = e.nativeCode(r.Flow, bad)
	}
	wantError(t, last, http.StatusUnprocessableEntity, "code_locked")
	wantError(t, e.nativeCode(r.Flow, e.mail.lastCode(t, "a@example.com")), http.StatusUnprocessableEntity, "code_locked")
}

func TestNativeExpiredCode(t *testing.T) {
	e := nativeEnv(t, true)
	r := e.nativeStart(e.z.newAuthRequest(nativeClient, nil, nil, ""), "a@example.com")
	e.clock.add(CodeTTL + time.Second)
	wantError(t, e.nativeCode(r.Flow, e.mail.lastCode(t, "a@example.com")), http.StatusUnprocessableEntity, "code_expired")
}

func TestNativeRateLimited(t *testing.T) {
	e := nativeEnv(t, true)
	ar := e.z.newAuthRequest(nativeClient, nil, nil, "")
	var last nativeReply
	for i := 0; i < DefaultLimits.SendsPerAddress.Max+1; i++ {
		last = e.nativeStart(ar, "a@example.com")
	}
	wantError(t, last, http.StatusTooManyRequests, "rate_limited")
	if last.Retry == "" {
		t.Fatal("no Retry-After")
	}
}

func TestNativeResendInvalidatesOldCode(t *testing.T) {
	e := nativeEnv(t, true)
	first := e.nativeStart(e.z.newAuthRequest(nativeClient, nil, nil, ""), "a@example.com")
	oldCode := e.mail.lastCode(t, "a@example.com")
	second := e.nativeRaw("/login/native/resend", map[string]string{"flow": first.Flow}, nil)
	wantStep(t, second, "code")
	if second.Flow == first.Flow || e.mail.count() != 2 {
		t.Fatalf("resend did not issue a new code: %+v", second)
	}
	newCode := e.mail.lastCode(t, "a@example.com")
	if oldCode != newCode {
		if r := e.nativeCode(second.Flow, oldCode); r.Step == "done" {
			t.Fatal("old code still works")
		}
	}
	if r := e.nativeCode(first.Flow, oldCode); r.Step == "done" {
		t.Fatal("old flow and code still work")
	}
	wantStep(t, e.nativeCode(second.Flow, newCode), "done")
}

func TestNativeFlowNotInterchangeableWithCookie(t *testing.T) {
	e := nativeEnv(t, true)
	r := e.nativeStart(e.z.newAuthRequest(nativeClient, nil, nil, ""), "a@example.com")
	b := brandForTest(t, e)
	var f flow
	if err := e.web.sealer.Open(cookieName(b, "idl-f-x"), r.Flow, &f); err == nil {
		t.Fatal("API flow opens as a browser cookie")
	}
	sealed, err := e.web.sealer.Seal(cookieName(b, "idl-f-x"), newFlow("V2_1"), flowTTL)
	if err != nil {
		t.Fatal(err)
	}
	wantError(t, e.nativeCode(sealed, "123456"), http.StatusGone, "expired")
}

func TestNativeReplayAfterFinalizeExpired(t *testing.T) {
	e := nativeEnv(t, true)
	r := e.nativeStart(e.z.newAuthRequest(nativeClient, nil, nil, ""), "a@example.com")
	code := e.mail.lastCode(t, "a@example.com")
	wantStep(t, e.nativeCode(r.Flow, code), "done")
	wantError(t, e.nativeCode(r.Flow, code), http.StatusGone, "expired")
}

func TestNativeDisabledAndAmbiguousNeutral(t *testing.T) {
	e := nativeEnv(t, false)
	e.z.addUser("locked@example.com", "", true).State = zitadel.UserStateLocked
	for _, email := range []string{"locked@example.com", "nobody@example.com"} {
		r := e.nativeStart(e.z.newAuthRequest(nativeClient, nil, nil, ""), email)
		wantError(t, r, http.StatusForbidden, "unavailable")
	}
	if e.mail.count() != 0 {
		t.Fatal("mail sent")
	}
}

func TestNativeLeavesNoBrowserSession(t *testing.T) {
	e := nativeEnv(t, true)
	r := e.nativeStart(e.z.newAuthRequest(nativeClient, nil, nil, ""), "a@example.com")
	wantStep(t, e.nativeCode(r.Flow, e.mail.lastCode(t, "a@example.com")), "done")
	b := e.browser()
	if list := e.web.browserSessionsForTest(t, b); len(list) != 0 {
		t.Fatalf("browser sessions: %v", list)
	}
}

func TestWebPasswordStepUnchanged(t *testing.T) {
	e := nativeEnv(t, true)
	e.z.addUser("pw@example.com", "Secret-123", true)
	b := e.browser()
	p := b.post(b.start(e.z.newAuthRequest("web", nil, nil, "")), "/login/email", map[string][]string{"email": {"pw@example.com"}})
	mustContain(t, p, "Enter your password")
}

func reviewEnv(t *testing.T) *env {
	t.Helper()
	e := newEnv(t, brandCfg{Registration: true,
		Extra: map[string]any{"native_api_clients": []string{nativeClient}, "native_review_logins_file": "review.json"},
		Files: map[string][]byte{"review.json": []byte(`[{"email":"Review@Example.com","code":"314159"}]`)}})
	e.z.native[nativeClient] = true
	e.z.addUser("review@example.com", "", true)
	return e
}

func TestReviewLoginUsesFixedCodeWithoutMail(t *testing.T) {
	e := reviewEnv(t)
	r := e.nativeStart(e.z.newAuthRequest(nativeClient, nil, nil, ""), "review@example.com")
	wantStep(t, r, "code")
	if e.mail.count() != 0 {
		t.Fatal("review login sent mail")
	}
	wantStep(t, e.nativeCode(r.Flow, "314159"), "done")
}

func TestReviewLoginResendKeepsFixedCode(t *testing.T) {
	e := reviewEnv(t)
	r := e.nativeStart(e.z.newAuthRequest(nativeClient, nil, nil, ""), "review@example.com")
	again := e.nativeRaw("/login/native/resend", map[string]string{"flow": r.Flow}, nil)
	wantStep(t, again, "code")
	if e.mail.count() != 0 {
		t.Fatal("review login sent mail")
	}
	wantStep(t, e.nativeCode(again.Flow, "314159"), "done")
}

func TestReviewLoginOnlyOnNativeAPI(t *testing.T) {
	e := reviewEnv(t)
	b := e.browser()
	p := b.post(b.start(e.z.newAuthRequest("web", nil, nil, "")), "/login/email", map[string][]string{"email": {"review@example.com"}})
	p = b.post(p, "/login/code", map[string][]string{"code": {"314159"}})
	if p.status == http.StatusSeeOther {
		t.Fatal("fixed code accepted by the web flow")
	}
	if e.mail.count() != 1 {
		t.Fatalf("web flow mails a normal code, sent %d", e.mail.count())
	}
}

func TestReviewLoginWrongCodeStillLocks(t *testing.T) {
	e := reviewEnv(t)
	r := e.nativeStart(e.z.newAuthRequest(nativeClient, nil, nil, ""), "review@example.com")
	var last nativeReply
	for i := 0; i < 10; i++ {
		last = e.nativeCode(r.Flow, "000000")
	}
	wantError(t, last, http.StatusUnprocessableEntity, "code_locked")
	wantError(t, e.nativeCode(r.Flow, "314159"), http.StatusUnprocessableEntity, "code_locked")
}

func TestReviewLoginAbsentByDefault(t *testing.T) {
	e := nativeEnv(t, true)
	e.z.addUser("review@example.com", "", true)
	r := e.nativeStart(e.z.newAuthRequest(nativeClient, nil, nil, ""), "review@example.com")
	if e.mail.count() != 1 {
		t.Fatal("normal address did not get mail")
	}
	if got := e.mail.lastCode(t, "review@example.com"); got != "314159" {
		wantError(t, e.nativeCode(r.Flow, "314159"), http.StatusUnprocessableEntity, "wrong_code")
	}
}
