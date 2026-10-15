package authproxy

import (
	"context"
	"database/sql"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tastyeffectco/sandboxd/control-plane/internal/agentauth"
	"github.com/tastyeffectco/sandboxd/control-plane/internal/provideraccess"
	"github.com/tastyeffectco/sandboxd/control-plane/internal/secrets"
	"github.com/tastyeffectco/sandboxd/control-plane/internal/store"
)

func TestScopedGatewayHasNoLegacyCredentialBypass(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	s, err := store.Open(ctx, filepath.Join(dir, "state.db"), "../../migrations")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	c, err := secrets.Load("", filepath.Join(dir, "key"))
	if err != nil {
		t.Fatal(err)
	}
	b, err := provideraccess.New(s, c)
	if err != nil {
		t.Fatal(err)
	}
	if err = s.CreateApp(ctx, &store.App{ID: "app-a", OwnerToken: "owner", Name: "Test"}); err != nil {
		t.Fatal(err)
	}
	if err = s.Create(ctx, &store.Sandbox{ID: "sandbox-a", AppID: sql.NullString{String: "app-a", Valid: true}, Status: "running", Image: "fixture"}); err != nil {
		t.Fatal(err)
	}
	ct, nonce, err := c.Seal([]byte("installed-provider-secret"))
	if err != nil {
		t.Fatal(err)
	}
	if err = s.CreateAppConfig(ctx, &store.AppConfig{ID: "config-a", AppID: "app-a", Key: "MODEL_KEY", Sensitive: true, AccessPolicy: "runtime_access", ValueCiphertext: ct, ValueNonce: nonce}); err != nil {
		t.Fatal(err)
	}
	g, err := b.Issue(ctx, "owner", "app-a", "MODEL_KEY", "anthropic", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	tok, err := b.IssueTask(ctx, "owner", "app-a", "sandbox-a", "task-a", "claude-code", "anthropic", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	authStore := agentauth.NewStore(dir)
	writeAPIKey(t, authStore, "claude-code", "synthetic-global-provider-key")
	calls := 0
	upstreamStatus := 200
	stubUpstream(t, "anthropic", func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.Header.Get("X-Api-Key") != "synthetic-global-provider-key" {
			t.Error("provider key not injected")
		}
		for _, key := range []string{"Authorization", "Cookie", "Forwarded", "X-Forwarded-For", "X-Private"} {
			if r.Header.Get(key) != "" {
				t.Errorf("forwarded %s", key)
			}
		}
		body, _ := io.ReadAll(r.Body)
		if string(body) != "{}" {
			t.Errorf("body=%s", body)
		}
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Set-Cookie", "secret=synthetic-global-provider-key")
		w.WriteHeader(upstreamStatus)
		if upstreamStatus == 200 {
			_, _ = io.WriteString(w, "data: synthetic result\n\n")
			w.(http.Flusher).Flush()
		} else {
			_, _ = io.WriteString(w, "synthetic-global-provider-key")
		}
	})
	gate := b.Gateway(NewScoped(authStore, nil, b.AuthorizeTask))
	request := func(path, key string) *httptest.ResponseRecorder {
		r := httptest.NewRequest("POST", path, strings.NewReader("{}"))
		r.Header = http.Header{"X-Api-Key": {key}, "Cookie": {"private"}, "Connection": {"X-Api-Key"}, "X-Private": {"secret"}, "Forwarded": {"host=private"}, "X-Forwarded-For": {"private"}}
		w := httptest.NewRecorder()
		gate.ServeHTTP(w, r)
		return w
	}
	for _, tc := range []struct{ path, key string }{
		{"/claude-code/anthropic/v1/messages", "sandboxd-proxy-injected"},
		{"/claude-code/anthropic/v1/messages", g.Token},
		{"/apps/app-a/anthropic/v1/messages", tok},
		{"/opencode/zen/chat/completions", tok},
		{"/claude-code/minimax-anthropic/v1/messages", tok},
	} {
		if w := request(tc.path, tc.key); w.Code != 401 {
			t.Fatalf("bypass %s = %d", tc.path, w.Code)
		}
	}
	if calls != 0 {
		t.Fatal("denied request reached provider")
	}
	w := request("/claude-code/anthropic/v1/messages", tok)
	if w.Code != 200 || w.Body.String() != "data: synthetic result\n\n" || !w.Flushed || w.Header().Get("Set-Cookie") != "" {
		t.Fatalf("stream=%d %s", w.Code, w.Body)
	}
	upstreamStatus = 401
	w = request("/claude-code/anthropic/v1/messages", tok)
	if w.Code != 400 || strings.Contains(w.Body.String(), "synthetic-global-provider-key") {
		t.Fatal("upstream error leaked key")
	}
	if err = b.RevokeTask(ctx, "task-a"); err != nil {
		t.Fatal(err)
	}
	if w := request("/claude-code/anthropic/v1/messages", tok); w.Code != 401 {
		t.Fatal("revoked ticket accepted")
	}
	if calls != 2 {
		t.Fatalf("unexpected provider calls %d", calls)
	}
}

func TestScopedProxyNilAuthorizerFailsClosed(t *testing.T) {
	p := NewScoped(agentauth.NewStore(t.TempDir()), nil, nil)
	w := httptest.NewRecorder()
	p.ServeHTTP(w, httptest.NewRequest("POST", "/opencode/zen/chat/completions", nil))
	if w.Code != 401 {
		t.Fatalf("nil authorizer=%d", w.Code)
	}
}
