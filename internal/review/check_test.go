package review

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

var testKey = []byte("0123456789abcdef0123456789abcdef0123456789abcdef")

func serve(t *testing.T, h http.HandlerFunc) *Checker {
	t.Helper()
	s := httptest.NewServer(h)
	t.Cleanup(s.Close)
	return New(s.URL+"/internal/v1/review-sign-in/check", testKey, nil)
}

func TestCheckSignsRequest(t *testing.T) {
	c := serve(t, func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		ts := r.Header.Get("X-Review-Timestamp")
		n, err := strconv.ParseInt(ts, 10, 64)
		if err != nil || time.Since(time.Unix(n, 0)) > 10*time.Second {
			t.Errorf("timestamp %q", ts)
		}
		m := hmac.New(sha256.New, testKey)
		m.Write([]byte(ts + "." + string(body)))
		if want := hex.EncodeToString(m.Sum(nil)); r.Header.Get("X-Review-Signature") != want {
			t.Errorf("signature mismatch")
		}
		if r.Method != http.MethodPost || r.Header.Get("Content-Type") != "application/json" {
			t.Errorf("method/content type: %s %s", r.Method, r.Header.Get("Content-Type"))
		}
		if string(body) != `{"zitadel_user_id":"u1","code":"123456","app":"web"}` {
			t.Errorf("body %s", body)
		}
		w.Write([]byte(`{"result":"ok"}`))
	})
	res, err := c.Check(context.Background(), "u1", "123456", "web")
	if err != nil || res != ResultOK {
		t.Fatalf("%v %v", res, err)
	}
}

func TestCheckMapsResults(t *testing.T) {
	for in, want := range map[string]Result{"ok": ResultOK, "wrong": ResultWrong, "locked": ResultLocked, "disabled": ResultDisabled} {
		c := serve(t, func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(`{"result":"` + in + `"}`)) })
		if res, err := c.Check(context.Background(), "u", "1", "web"); err != nil || res != want {
			t.Fatalf("%s: %v %v", in, res, err)
		}
	}
	c := serve(t, func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(`{"result":"maybe"}`)) })
	if res, err := c.Check(context.Background(), "u", "1", "web"); err == nil || res != "" {
		t.Fatalf("unknown accepted: %v %v", res, err)
	}
	c = serve(t, func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(`not json`)) })
	if _, err := c.Check(context.Background(), "u", "1", "web"); err == nil {
		t.Fatal("bad json accepted")
	}
}

func TestCheckErrors(t *testing.T) {
	cases := map[string]http.HandlerFunc{
		"500": func(w http.ResponseWriter, r *http.Request) { http.Error(w, "x", 500) },
		"401": func(w http.ResponseWriter, r *http.Request) { http.Error(w, "x", 401) },
		"302": func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "/elsewhere", http.StatusFound)
		},
		"big": func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte(`{"result":"ok","pad":"` + strings.Repeat("a", 5<<10) + `"}`))
		},
	}
	for name, h := range cases {
		c := serve(t, h)
		if res, err := c.Check(context.Background(), "u", "1", "web"); err == nil {
			t.Fatalf("%s: accepted as %q", name, res)
		}
	}
	c := serve(t, func(w http.ResponseWriter, r *http.Request) { time.Sleep(3 * time.Second) })
	start := time.Now()
	if _, err := c.Check(context.Background(), "u", "1", "web"); err == nil {
		t.Fatal("slow server accepted")
	}
	if d := time.Since(start); d > 2500*time.Millisecond {
		t.Fatalf("took %v", d)
	}
}

func TestRedirectNotFollowed(t *testing.T) {
	hit := false
	c := serve(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/target" {
			hit = true
			w.Write([]byte(`{"result":"ok"}`))
			return
		}
		http.Redirect(w, r, "/target", http.StatusTemporaryRedirect)
	})
	if _, err := c.Check(context.Background(), "u", "1", "web"); err == nil || hit {
		t.Fatalf("redirect followed: err=%v hit=%v", err, hit)
	}
}
