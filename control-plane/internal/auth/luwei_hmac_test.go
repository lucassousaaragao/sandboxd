package auth

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"
)

func TestLuweiHMACContract(t *testing.T) {
	now := time.Unix(1792232400, 0)
	req := httptest.NewRequest("POST", "http://sandboxd/sandbox/abc/exec", nil)
	req.Header.Set("X-Luwei-Session-ID", "session-a")
	ts := strconv.FormatInt(now.Unix(), 10)
	req.Header.Set("X-Luwei-Session-Timestamp", ts)
	sign := func(method, path, id, timestamp string) string {
		mac := hmac.New(sha256.New, []byte("test-secret"))
		mac.Write([]byte(id + "\n" + method + "\n" + path + "\n" + timestamp))
		return hex.EncodeToString(mac.Sum(nil))
	}
	req.Header.Set("X-Luwei-Session-Signature", sign("POST", "/sandbox/abc/exec", "session-a", ts))
	if got, err := VerifyLuweiSessionSignature(req, "test-secret", now); err != nil || got != "session-a" {
		t.Fatalf("valid signature denied: %v", err)
	}
	for _, tc := range []struct {
		name   string
		mutate func()
	}{
		{"no secret", func() {}},
		{"wrong identity", func() { req.Header.Set("X-Luwei-Session-ID", "session-b") }},
		{"wrong signature", func() { req.Header.Set("X-Luwei-Session-Signature", "00") }},
		{"expired", func() {
			req.Header.Set("X-Luwei-Session-Timestamp", strconv.FormatInt(now.Add(-61*time.Second).Unix(), 10))
		}},
		{"wrong path", func() { req.URL.Path = "/sandbox/foreign/exec" }},
	} {
		req.Header.Set("X-Luwei-Session-ID", "session-a")
		req.Header.Set("X-Luwei-Session-Timestamp", ts)
		req.Header.Set("X-Luwei-Session-Signature", sign("POST", "/sandbox/abc/exec", "session-a", ts))
		req.URL.Path = "/sandbox/abc/exec"
		tc.mutate()
		secret := "test-secret"
		if tc.name == "no secret" {
			secret = ""
		}
		if _, err := VerifyLuweiSessionSignature(req, secret, now); err == nil {
			t.Errorf("%s: accepted", tc.name)
		}
	}
}
