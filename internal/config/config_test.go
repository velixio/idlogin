package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeBrands(t *testing.T, body string) string {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "pat"), []byte("tok\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, "brands.json")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

const brandsJSON = `{"brands":[{"id":"example","name":"Example","hosts":["ID.example.test"],
 "public_origin":"https://id.example.test","zitadel_host":"id.example.test","mail_from":"Example <no-reply@example.test>",
 "login_client_pat_file":"pat","return_urls":["https://app.example.test/","https://www.example.test/account"],
 "registration_enabled":true,"idps":[{"key":"google","id":"123"},{"key":"github","id":""}]}]}`

func TestLoadBrands(t *testing.T) {
	bs, err := LoadBrands(writeBrands(t, brandsJSON))
	if err != nil {
		t.Fatal(err)
	}
	b := bs.ByHost["id.example.test"]
	if b == nil || b.Token != "tok" || !b.Secure || b.Logo != nil {
		t.Fatalf("brand: %+v", b)
	}
	if len(b.EnabledIDPs()) != 1 || b.EnabledIDPs()[0].Label != "Google" {
		t.Fatalf("idps: %+v", b.EnabledIDPs())
	}
	if _, ok := b.IDP("github"); ok {
		t.Fatal("github without id enabled")
	}
}

func TestAllowedReturn(t *testing.T) {
	bs, err := LoadBrands(writeBrands(t, brandsJSON))
	if err != nil {
		t.Fatal(err)
	}
	b := bs.All[0]
	for raw, want := range map[string]bool{
		"https://app.example.test/":                     true,
		"https://app.example.test/settings?tab=pw":      true,
		"https://www.example.test/account":              true,
		"https://www.example.test/account/security":     true,
		"https://www.example.test/accounts":             false,
		"https://www.example.test/":                     false,
		"http://app.example.test/":                      false,
		"https://app.example.test.evil.test/":           false,
		"https://evil.test/?x=https://app.example.test": false,
		"https://user@app.example.test/":                false,
		"//app.example.test/":                           false,
		"/relative":                                     false,
		"javascript:alert(1)":                           false,
		"https://app.example.test\\@evil.test/":         false,
		"https://www.example.test/account/../admin":     false,
		"https://www.example.test/account/%2e%2e/admin": false,
		"https://app.example.test:444/":                 false,
		"":                                              false,
	} {
		if got := b.AllowedReturn(raw); got != want {
			t.Errorf("AllowedReturn(%q) = %v, want %v", raw, got, want)
		}
	}
}

func TestFromEnvValidation(t *testing.T) {
	env := map[string]string{}
	if _, err := FromEnv(func(k string) string { return env[k] }); err == nil {
		t.Fatal("empty env accepted")
	}
	env = map[string]string{
		"LOGIN_COOKIE_KEY": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", "LOGIN_DATABASE_URL": "postgres://x",
		"LOGIN_BRANDS_FILE": "/b.json", "LOGIN_MAIL_DIR": "/tmp/m",
	}
	c, err := FromEnv(func(k string) string { return env[k] })
	if err != nil || c.Addr != "127.0.0.1:8091" || c.Mailer != "log" {
		t.Fatalf("%v %+v", err, c)
	}
	// The retired loopback action listener must fail loudly, not be ignored.
	env["LOGIN_ACTIONS_ADDR"] = "127.0.0.2:8092"
	if _, err := FromEnv(func(k string) string { return env[k] }); err == nil || !strings.Contains(err.Error(), "LOGIN_ACTIONS_ADDR is no longer used") {
		t.Fatalf("LOGIN_ACTIONS_ADDR accepted: %v", err)
	}
}

func TestBrandLogoAndSubjects(t *testing.T) {
	body := func(extra string) string {
		return `{"brands":[{"id":"example","name":"Example","hosts":["id.example.test"],"public_origin":"https://id.example.test",
 "zitadel_host":"id.example.test","mail_from":"Example <no-reply@example.test>","login_client_pat_file":"pat"` + extra + `}]}`
	}
	p := writeBrands(t, body(`,"logo_file":"logo.svg","mail_subjects":{"reset":"{name} password reset"}`))
	if err := os.WriteFile(filepath.Join(filepath.Dir(p), "logo.svg"), []byte("<svg/>"), 0o600); err != nil {
		t.Fatal(err)
	}
	bs, err := LoadBrands(p)
	if err != nil {
		t.Fatal(err)
	}
	b := bs.All[0]
	if string(b.Logo) != "<svg/>" || b.LogoType != "image/svg+xml" || len(b.LogoVersion) != 12 {
		t.Fatalf("logo: %q %q %q", b.Logo, b.LogoType, b.LogoVersion)
	}
	if got := b.MailSubject("reset", "x"); got != "Example password reset" {
		t.Fatalf("subject %q", got)
	}
	if got := b.MailSubject("signin", "Your {name} code"); got != "Your Example code" {
		t.Fatalf("default subject %q", got)
	}
	for _, bad := range []string{`,"logo_file":"missing.svg"`, `,"logo_file":"logo.gif"`, `,"mail_subjects":{"other":"x"}`, `,"mail_subjects":{"reset":""}`, `,"logo":"x.svg"`} {
		if _, err := LoadBrands(writeBrands(t, body(bad))); err == nil {
			t.Errorf("accepted %s", bad)
		}
	}
}
