package actions

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestPreAccessToken(t *testing.T) {
	keyFile := filepath.Join(t.TempDir(), "key")
	_ = os.WriteFile(keyFile, []byte("s3cret\n"), 0o600)
	now := time.Unix(1_800_000_000, 0)
	h := &Handler{KeyFile: keyFile, Now: func() time.Time { return now }, Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	body := []byte(`{"function":"function/preaccesstoken","user":{"id":"1","human":{"email":"a@b.test","is_email_verified":true}}}`)

	call := func(sig string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, Path, strings.NewReader(string(body)))
		if sig != "" {
			req.Header.Set("ZITADEL-Signature", sig)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec
	}

	rec := call(Sign(body, "s3cret", now))
	if rec.Code != 200 {
		t.Fatalf("status %d %s", rec.Code, rec.Body)
	}
	var out Response
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	if len(out.AppendClaims) != 2 || out.AppendClaims[0].Value != "a@b.test" || out.AppendClaims[1].Value != true {
		t.Fatalf("claims %+v", out)
	}
	for name, sig := range map[string]string{
		"unsigned":  "",
		"wrong key": Sign(body, "other", now),
		"old":       Sign(body, "s3cret", now.Add(-10*time.Minute)),
		"garbage":   "t=x,v1=zz",
	} {
		if rec := call(sig); rec.Code != http.StatusUnauthorized {
			t.Errorf("%s: status %d", name, rec.Code)
		}
	}
}
