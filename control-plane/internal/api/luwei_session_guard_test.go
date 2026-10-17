package api

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"github.com/tastyeffectco/sandboxd/control-plane/internal/store"
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

func TestLuweiCrossSessionIsolation(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(ctx, "file:"+t.TempDir()+"/test.db?_fk=1", "../../migrations")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	for _, b := range []store.LuweiSessionBinding{
		{SandboxID: "box-a", SessionID: "session-a", UserID: "user-a", ProjectID: "project-a", WorkspaceID: "ws-a"},
		{SandboxID: "box-b", SessionID: "session-b", UserID: "user-b", ProjectID: "project-b", WorkspaceID: "ws-b"},
	} {
		if err := st.BindLuweiSession(ctx, b); err != nil {
			t.Fatal(err)
		}
	}
	server := &Server{Store: st}
	called := 0
	guard := server.LuweiSessionGuard("secret", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { called++; w.WriteHeader(204) }))
	cases := []struct {
		name, path, session string
		status              int
	}{
		{"owner A", "/sandbox/box-a/exec", "session-a", 204},
		{"owner B", "/sandbox/box-b/exec", "session-b", 204},
		{"A accesses B", "/sandbox/box-b/exec", "session-a", 403},
		{"B accesses A", "/sandbox/box-a/exec", "session-b", 403},
		{"missing binding", "/sandbox/unknown/exec", "session-a", 403},
		{"v1 cross session", "/v1/sandboxes/box-b/stop", "session-a", 403},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := luweiSignedRequest("POST", tc.path, tc.session, "secret")
			rec := httptest.NewRecorder()
			guard.ServeHTTP(rec, req)
			if rec.Code != tc.status {
				t.Fatalf("got %d want %d", rec.Code, tc.status)
			}
		})
	}
	if called != 2 {
		t.Fatalf("unexpected allowed operations: %d", called)
	}
}
