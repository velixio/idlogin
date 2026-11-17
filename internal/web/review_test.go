package web

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"

	"github.com/velixio/idlogin/internal/config"
	"github.com/velixio/idlogin/internal/review"
	"github.com/velixio/idlogin/internal/store"
	"github.com/velixio/idlogin/internal/zitadel"
)

const reviewOrg = "org-review"

// fakeChecker is a stand-in for the vssaas check route. It answers with the
// configured result (or status) and records what it was asked.
type fakeChecker struct {
	mu     sync.Mutex
	result string // body result, default "ok"
	status int    // default 200
	calls  []map[string]string
	srv    *httptest.Server
}

func newFakeChecker(t *testing.T) *fakeChecker {
	t.Helper()
	c := &fakeChecker{result: "ok", status: http.StatusOK}
	c.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var in map[string]string
		_ = json.NewDecoder(r.Body).Decode(&in)
		c.mu.Lock()
		c.calls = append(c.calls, in)
		res, status := c.result, c.status
		c.mu.Unlock()
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(map[string]string{"result": res})
	}))
	t.Cleanup(c.srv.Close)
	return c
}

func (c *fakeChecker) set(result string, status int) {
	c.mu.Lock()
	c.result, c.status = result, status
	c.mu.Unlock()
}

func (c *fakeChecker) callList() []map[string]string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]map[string]string(nil), c.calls...)
}

// countingStore counts the codes put in the store.
type countingStore struct {
	store.Store
	puts int
}

func (c *countingStore) PutCode(ctx context.Context, code store.Code) error {
	c.puts++
	return c.Store.PutCode(ctx, code)
}

// hookEnv enables the review hook on a native-capable test server and adds
// one review-org user and one customer.
func hookEnv(t *testing.T, configured bool) (*env, *fakeChecker, string) {
	t.Helper()
	e := nativeEnv(t, false)
	fc := newFakeChecker(t)
	e.web.store = &countingStore{Store: e.web.store}
	if configured {
		e.web.review = review.New(fc.srv.URL, make([]byte, 32), nil)
		e.web.reviewOrg = reviewOrg
	}
	u := e.z.addUser("reviewer@example.com", "", true)
	u.Details.ResourceOwner = reviewOrg
	c := e.z.addUser("customer@example.com", "", true)
	c.Details.ResourceOwner = "org-customers"
	return e, fc, u.UserID
}

// reviewCodePage signs the reviewer in as far as the code page.
func reviewCodePage(t *testing.T, e *env, b *browser, email string) (page, string) {
	t.Helper()
	ar := e.z.newAuthRequest("web", nil, nil, "")
	p := b.post(b.start(ar), "/login/email", url.Values{"email": {email}})
	mustContain(t, p, "6-digit")
	return p, ar
}

func TestReviewUserGetsNoEmail(t *testing.T) {
	e, _, _ := hookEnv(t, true)
	reviewCodePage(t, e, e.browser(), "reviewer@example.com")
	if e.mail.count() != 0 {
		t.Fatalf("mails sent: %d", e.mail.count())
	}
	if n := e.web.store.(*countingStore).puts; n != 0 {
		t.Fatalf("%d code rows stored", n)
	}
}

func TestReviewCodeOK(t *testing.T) {
	e, fc, uid := hookEnv(t, true)
	b := e.browser()
	p, ar := reviewCodePage(t, e, b, "reviewer@example.com")
	p = b.post(p, "/login/code", url.Values{"code": {"123456"}})
	mustCallback(t, p, ar)
	calls := fc.callList()
	if len(calls) != 1 || calls[0]["zitadel_user_id"] != uid || calls[0]["code"] != "123456" || calls[0]["app"] != "web" {
		t.Fatalf("checker calls: %v", calls)
	}
}

func TestReviewCodeIgnoresPasswordStep(t *testing.T) {
	e, _, _ := hookEnv(t, true)
	e.z.user("reviewer@example.com").password = "Secret-123"
	b := e.browser()
	p, ar := reviewCodePage(t, e, b, "reviewer@example.com")
	mustCallback(t, b.post(p, "/login/code", url.Values{"code": {"123456"}}), ar)
}

func TestReviewCodeWrong(t *testing.T) {
	for _, res := range []string{"wrong", "locked", "disabled"} {
		e, fc, _ := hookEnv(t, true)
		fc.set(res, http.StatusOK)
		b := e.browser()
		p, _ := reviewCodePage(t, e, b, "reviewer@example.com")
		p = b.post(p, "/login/code", url.Values{"code": {"123456"}})
		mustContain(t, p, msgCodeWrong)
		if e.z.sessionCount() != 0 {
			t.Fatalf("%s: session created", res)
		}
	}
}

func TestReviewCheckUnavailable(t *testing.T) {
	e, fc, _ := hookEnv(t, true)
	fc.set("", http.StatusInternalServerError)
	b := e.browser()
	p, _ := reviewCodePage(t, e, b, "reviewer@example.com")
	p = b.post(p, "/login/code", url.Values{"code": {"123456"}})
	mustContain(t, p, msgCheckUnavailable, "6-digit")
	if e.z.sessionCount() != 0 {
		t.Fatal("session created")
	}
}

func TestReviewCodeWithSpaces(t *testing.T) {
	e, fc, _ := hookEnv(t, true)
	b := e.browser()
	p, ar := reviewCodePage(t, e, b, "reviewer@example.com")
	mustCallback(t, b.post(p, "/login/code", url.Values{"code": {" 123 456 "}}), ar)
	if calls := fc.callList(); len(calls) != 1 || calls[0]["code"] != "123456" {
		t.Fatalf("checker calls: %v", calls)
	}
}

func TestReviewBadFormatNeverReachesChecker(t *testing.T) {
	e, fc, _ := hookEnv(t, true)
	b := e.browser()
	p, _ := reviewCodePage(t, e, b, "reviewer@example.com")
	mustContain(t, b.post(p, "/login/code", url.Values{"code": {"12ab56"}}), msgCodeFormat)
	if len(fc.callList()) != 0 {
		t.Fatal("checker called")
	}
}

func TestReviewResendSendsNothing(t *testing.T) {
	e, _, _ := hookEnv(t, true)
	b := e.browser()
	p, _ := reviewCodePage(t, e, b, "reviewer@example.com")
	p = b.post(p, "/login/code", url.Values{"action": {"resend"}})
	mustContain(t, p, "A new code is on its way.")
	if e.mail.count() != 0 {
		t.Fatalf("mails sent: %d", e.mail.count())
	}
}

func TestCustomerFlowUnchangedWithReviewHook(t *testing.T) {
	e, fc, _ := hookEnv(t, true)
	b := e.browser()
	p, ar := reviewCodePage(t, e, b, "customer@example.com")
	if e.mail.count() != 1 {
		t.Fatalf("mails sent: %d", e.mail.count())
	}
	mustCallback(t, b.post(p, "/login/code", url.Values{"code": {e.mail.lastCode(t, "customer@example.com")}}), ar)
	if len(fc.callList()) != 0 {
		t.Fatal("checker called for a customer")
	}
}

func TestHookOffWhenUnconfigured(t *testing.T) {
	e, fc, _ := hookEnv(t, false)
	b := e.browser()
	p, ar := reviewCodePage(t, e, b, "reviewer@example.com")
	if e.mail.count() != 1 {
		t.Fatalf("mails sent: %d", e.mail.count())
	}
	mustCallback(t, b.post(p, "/login/code", url.Values{"code": {e.mail.lastCode(t, "reviewer@example.com")}}), ar)
	if len(fc.callList()) != 0 {
		t.Fatal("checker called")
	}
}

func TestNativeReviewCodeOK(t *testing.T) {
	e, fc, uid := hookEnv(t, true)
	ar := e.z.newAuthRequest(nativeClient, nil, nil, "")
	r := e.nativeStart(ar, "reviewer@example.com")
	wantStep(t, r, "code")
	if e.mail.count() != 0 {
		t.Fatal("mail sent")
	}
	wantStep(t, e.nativeRaw("/login/native/resend", map[string]string{"flow": r.Flow}, nil), "code")
	if e.mail.count() != 0 {
		t.Fatal("mail sent on resend")
	}
	done := e.nativeCode(r.Flow, " 123 456 ")
	wantStep(t, done, "done")
	calls := fc.callList()
	if len(calls) != 1 || calls[0]["zitadel_user_id"] != uid || calls[0]["code"] != "123456" || calls[0]["app"] != "native" {
		t.Fatalf("checker calls: %v", calls)
	}
}

func TestNativeReviewWrongAndUnavailable(t *testing.T) {
	e, fc, _ := hookEnv(t, true)
	r := e.nativeStart(e.z.newAuthRequest(nativeClient, nil, nil, ""), "reviewer@example.com")
	wantStep(t, r, "code")
	fc.set("locked", http.StatusOK)
	wantError(t, e.nativeCode(r.Flow, "123456"), http.StatusUnprocessableEntity, nativeWrongCode)
}

func TestNativeReviewUnavailableIsTemporary(t *testing.T) {
	e, fc, _ := hookEnv(t, true)
	r := e.nativeStart(e.z.newAuthRequest(nativeClient, nil, nil, ""), "reviewer@example.com")
	fc.set("", http.StatusInternalServerError)
	wantError(t, e.nativeCode(r.Flow, "123456"), http.StatusServiceUnavailable, nativeTemporary)
}

func TestNativeCustomerUnchanged(t *testing.T) {
	e, fc, _ := hookEnv(t, true)
	r := e.nativeStart(e.z.newAuthRequest(nativeClient, nil, nil, ""), "customer@example.com")
	wantStep(t, r, "code")
	wantStep(t, e.nativeCode(r.Flow, e.mail.lastCode(t, "customer@example.com")), "done")
	if len(fc.callList()) != 0 {
		t.Fatal("checker called for a customer")
	}
}

var resetForm = url.Values{"password": {"New-Pass-1"}, "password_confirm": {"New-Pass-1"}}

func resetCodeForm(code string) url.Values {
	v := url.Values{"code": {code}}
	for k, x := range resetForm {
		v[k] = x
	}
	return v
}

func TestResetForReviewAddressSendsNothingAndDoesNotSignIn(t *testing.T) {
	e, fc, _ := hookEnv(t, true)
	b := e.browser()
	ar := e.z.newAuthRequest("web", nil, nil, "")
	b.start(ar)
	p := b.get("/reset?authRequest=" + ar)
	p = b.post(p, "/reset", url.Values{"email": {"reviewer@example.com"}})
	if e.mail.count() != 0 {
		t.Fatalf("mails sent: %d", e.mail.count())
	}
	p = b.post(p, "/reset/code", resetCodeForm("123456"))
	if p.status == http.StatusSeeOther || p.status >= 500 || e.z.sessionCount() != 0 {
		t.Fatalf("signed in or failed: %d %q", p.status, p.location)
	}
	if len(fc.callList()) != 0 {
		t.Fatal("checker called")
	}
}

func TestResetAfterReviewEmailStepNeverCallsChecker(t *testing.T) {
	for _, target := range []string{"reviewer@example.com", "customer@example.com"} {
		e, fc, _ := hookEnv(t, true)
		b := e.browser()
		p, ar := reviewCodePage(t, e, b, "reviewer@example.com")
		p = b.get("/reset?authRequest=" + ar)
		p = b.post(p, "/reset", url.Values{"email": {target}})
		p = b.post(p, "/reset/code", resetCodeForm("123456"))
		if p.status >= 500 || p.status == http.StatusSeeOther {
			t.Fatalf("%s: status %d %q", target, p.status, p.location)
		}
		if len(fc.callList()) != 0 {
			t.Fatalf("%s: checker called", target)
		}
		if target == "customer@example.com" {
			// The customer's emailed code still works.
			p = b.post(p, "/reset/code", resetCodeForm(e.mail.lastCode(t, target)))
			mustCallback(t, p, ar)
		}
	}
}

func TestCustomerResetStillWorksWithReviewHook(t *testing.T) {
	e, fc, _ := hookEnv(t, true)
	b := e.browser()
	ar := e.z.newAuthRequest("web", nil, nil, "")
	b.start(ar)
	p := b.post(b.get("/reset?authRequest="+ar), "/reset", url.Values{"email": {"customer@example.com"}})
	p = b.post(p, "/reset/code", resetCodeForm(e.mail.lastCode(t, "customer@example.com")))
	mustCallback(t, p, ar)
	if len(fc.callList()) != 0 {
		t.Fatal("checker called")
	}
}

func TestIDPReviewUserRefused(t *testing.T) {
	for _, linked := range []bool{false, true} {
		e := newEnv(t, brandCfg{IDPs: []config.IDP{{Key: "google", ID: "idp-google"}}})
		fc := newFakeChecker(t)
		e.web.review, e.web.reviewOrg = review.New(fc.srv.URL, make([]byte, 32), nil), reviewOrg
		u := e.z.addUser("reviewer@example.com", "", true)
		u.Details.ResourceOwner = reviewOrg
		b := e.browser()
		ar := e.z.newAuthRequest("web", nil, nil, "")
		p := b.post(b.start(ar), "/login/idp", url.Values{"provider": {"google"}})
		loc, _ := url.Parse(p.location)
		in := zitadel.Intent{IDPID: "idp-google", ExtID: "g-r", Email: "reviewer@example.com", Verified: true}
		if linked {
			in.UserID = u.UserID
		}
		id, tok := e.z.finishIntent(in)
		p = b.get(loc.Query().Get("success") + "&id=" + url.QueryEscape(id) + "&token=" + url.QueryEscape(tok))
		if p.status == http.StatusSeeOther || e.z.sessionCount() != 0 || e.z.links["idp-google|g-r"] != "" {
			t.Fatalf("linked=%v: signed in or linked: %d %q", linked, p.status, p.location)
		}
	}
}
