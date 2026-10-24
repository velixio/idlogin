// Package actions implements a Zitadel Actions v2 target: the
// "preaccesstoken" function, which adds email and email_verified to JWT
// access tokens. It is served on idlogin's main listener under /login/, so
// Zitadel reaches it through the public hostname like any other caller and
// its SSRF deny list can stay at the default (no loopback exception). Every
// call must carry a valid ZITADEL-Signature (HMAC-SHA256 with the target's
// signing key, as in zitadel/pkg/actions); anything else is refused, and a
// valid call only gets back the email claims of the user in its own payload.
package actions

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

// Path is where the preaccesstoken target is served.
const Path = "/login/zitadel/preaccesstoken"

// Tolerance is the accepted clock difference for signatures (Zitadel's default).
const Tolerance = 300 * time.Second

// Handler serves the action target.
type Handler struct {
	KeyFile string // file holding the target's signing key (re-read per call)
	Now     func() time.Time
	Log     *slog.Logger
}

// ContextInfo is the part of Zitadel's payload this target reads
// (internal/api/oidc/userinfo.go ContextInfo, query.User JSON tags).
type ContextInfo struct {
	Function string `json:"function"`
	User     *struct {
		ID    string `json:"id"`
		Human *struct {
			Email           string `json:"email"`
			IsEmailVerified bool   `json:"is_email_verified"`
		} `json:"human"`
	} `json:"user"`
}

// AppendClaim is one claim to add.
type AppendClaim struct {
	Key   string `json:"key"`
	Value any    `json:"value"`
}

// Response is the ContextInfoResponse Zitadel merges into the token.
type Response struct {
	AppendClaims []AppendClaim `json:"append_claims,omitempty"`
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost || r.URL.Path != Path {
		http.NotFound(w, r)
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		http.Error(w, "read error", http.StatusBadRequest)
		return
	}
	key, err := os.ReadFile(h.KeyFile)
	if err != nil || len(strings.TrimSpace(string(key))) == 0 {
		h.Log.Error("action signing key unavailable", "file", h.KeyFile, "error", err)
		http.Error(w, "not configured", http.StatusServiceUnavailable)
		return
	}
	now := time.Now
	if h.Now != nil {
		now = h.Now
	}
	if err := Verify(body, r.Header.Get("ZITADEL-Signature"), strings.TrimSpace(string(key)), now()); err != nil {
		h.Log.Warn("action call refused", "error", err)
		http.Error(w, "invalid signature", http.StatusUnauthorized)
		return
	}
	var in ContextInfo
	if err := json.Unmarshal(body, &in); err != nil {
		http.Error(w, "bad payload", http.StatusBadRequest)
		return
	}
	out := Response{}
	if in.User != nil && in.User.Human != nil && in.User.Human.Email != "" {
		out.AppendClaims = []AppendClaim{
			{Key: "email", Value: in.User.Human.Email},
			{Key: "email_verified", Value: in.User.Human.IsEmailVerified},
		}
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(out)
}

// Sign computes a ZITADEL-Signature header value (used by tests).
func Sign(body []byte, key string, t time.Time) string {
	return "t=" + strconv.FormatInt(t.Unix(), 10) + ",v1=" + hex.EncodeToString(mac(body, key, t.Unix()))
}

func mac(body []byte, key string, ts int64) []byte {
	m := hmac.New(sha256.New, []byte(key))
	m.Write([]byte(strconv.FormatInt(ts, 10)))
	m.Write([]byte("."))
	m.Write(body)
	return m.Sum(nil)
}

// Verify checks a ZITADEL-Signature header: "t=<unix>,v1=<hex hmac>[,v1=...]".
func Verify(body []byte, header, key string, now time.Time) error {
	if header == "" {
		return errors.New("no signature")
	}
	var ts int64 = -1
	var sigs [][]byte
	for _, part := range strings.Split(header, ",") {
		k, v, ok := strings.Cut(part, "=")
		if !ok {
			return errors.New("malformed signature header")
		}
		switch k {
		case "t":
			n, err := strconv.ParseInt(v, 10, 64)
			if err != nil {
				return errors.New("malformed timestamp")
			}
			ts = n
		case "v1":
			if b, err := hex.DecodeString(v); err == nil {
				sigs = append(sigs, b)
			}
		}
	}
	if ts < 0 || len(sigs) == 0 {
		return errors.New("incomplete signature header")
	}
	d := now.Sub(time.Unix(ts, 0))
	if d > Tolerance || d < -Tolerance {
		return errors.New("signature timestamp out of tolerance")
	}
	want := mac(body, key, ts)
	for _, s := range sigs {
		if hmac.Equal(s, want) {
			return nil
		}
	}
	return errors.New("signature mismatch")
}
