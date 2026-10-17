package api

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"
)

func luweiSignedRequest(method, path, session, secret string) *http.Request {
	r := httptest.NewRequest(method, path, nil)
	ts := strconv.FormatInt(time.Now().Unix(), 10)
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(session + "\n" + method + "\n" + path + "\n" + ts))
	r.Header.Set("X-Luwei-Session-ID", session)
	r.Header.Set("X-Luwei-Session-Timestamp", ts)
	r.Header.Set("X-Luwei-Session-Signature", hex.EncodeToString(mac.Sum(nil)))
	return r
}

func TestLuweiSessionGuardFailClosed(t *testing.T) {
	s := &Server{}
	h := s.LuweiSessionGuard("secret", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) }))
	for _, tc := range []struct {
		name string
		r    *http.Request
		code int
	}{
		{"ready", httptest.NewRequest("GET", "/readyz", nil), 204},
		{"missing signature", httptest.NewRequest("POST", "/sandbox", nil), 401},
		{"signed create", luweiSignedRequest("POST", "/sandbox", "session-a", "secret"), 204},
		{"unsigned administrative route", httptest.NewRequest("GET", "/sandboxes", nil), 403},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			h.ServeHTTP(w, tc.r)
			if w.Code != tc.code {
				t.Fatalf("got %d want %d", w.Code, tc.code)
			}
		})
	}
}
