// Package review asks the vssaas API whether the fixed sign-in code of an app
// store review account is right. The request is signed with a shared key; the
// code is never logged or kept here.
package review

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"
)

// Result is the verdict of one check.
type Result string

const (
	ResultOK       Result = "ok"
	ResultWrong    Result = "wrong"
	ResultLocked   Result = "locked"
	ResultDisabled Result = "disabled"
)

const (
	timeout  = 2 * time.Second
	maxBytes = 4 << 10
)

// Checker is a signed HTTP client for the check route.
type Checker struct {
	url    string
	key    []byte
	client *http.Client
}

// New returns a Checker for url. client may be nil; either way the checker
// uses a 2-second timeout and follows no redirects (a copy of client is made).
func New(url string, key []byte, client *http.Client) *Checker {
	var hc http.Client
	if client != nil {
		hc = *client
	}
	hc.Timeout = timeout
	hc.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &Checker{url: url, key: key, client: &hc}
}

type checkBody struct {
	UserID string `json:"zitadel_user_id"`
	Code   string `json:"code"`
	App    string `json:"app"`
}

// Check asks whether code is right for the Zitadel user. app is "web" or
// "native". Any transport problem, non-200 status, oversized or unknown
// answer is an error: the caller must not let the user in.
func (c *Checker) Check(ctx context.Context, userID, code, app string) (Result, error) {
	body, err := json.Marshal(checkBody{UserID: userID, Code: code, App: app})
	if err != nil {
		return "", errors.New("review check: encode request")
	}
	ts := strconv.FormatInt(time.Now().Unix(), 10)
	mac := hmac.New(sha256.New, c.key)
	mac.Write([]byte(ts + "." + string(body)))

	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.url, bytes.NewReader(body))
	if err != nil {
		return "", errors.New("review check: build request")
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Review-Timestamp", ts)
	req.Header.Set("X-Review-Signature", hex.EncodeToString(mac.Sum(nil)))

	resp, err := c.client.Do(req)
	if err != nil {
		// The error text can quote the URL; the request body is never in it.
		return "", errors.New("review check: request failed")
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("review check: status %d", resp.StatusCode)
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxBytes+1))
	if err != nil {
		return "", errors.New("review check: read response")
	}
	if len(raw) > maxBytes {
		return "", errors.New("review check: response too large")
	}
	var out struct {
		Result string `json:"result"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return "", errors.New("review check: bad response")
	}
	switch r := Result(out.Result); r {
	case ResultOK, ResultWrong, ResultLocked, ResultDisabled:
		return r, nil
	}
	return "", errors.New("review check: unknown result")
}
