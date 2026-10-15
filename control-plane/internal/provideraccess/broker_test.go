package provideraccess

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tastyeffectco/sandboxd/control-plane/internal/secrets"
	"github.com/tastyeffectco/sandboxd/control-plane/internal/store"
)

const syntheticKey = "synthetic-provider-key-never-send-to-agent"

type fixture struct {
	s   *store.Store
	b   *Broker
	c   *secrets.Cipher
	dsn string
	now time.Time
}

func setup(t *testing.T) *fixture {
	t.Helper()
	dir := t.TempDir()
	f := &fixture{dsn: filepath.Join(dir, "state.db") + "?_busy_timeout=5000", now: time.Date(2026, 10, 15, 12, 0, 0, 0, time.UTC)}
	var err error
	f.c, err = secrets.Load("", filepath.Join(dir, "secrets.key"))
	if err != nil {
		t.Fatal(err)
	}
	f.open(t)
	t.Cleanup(func() {
		if f.s != nil {
			_ = f.s.Close()
		}
	})
	for _, id := range []string{"app-a", "app-b"} {
		if err := f.s.CreateApp(context.Background(), &store.App{ID: id, OwnerToken: "owner", Name: id}); err != nil {
			t.Fatal(err)
		}
		c := f.config(t, id, "runtime_access")
		if err := f.s.CreateAppConfig(context.Background(), c); err != nil {
			t.Fatal(err)
		}
	}
	return f
}

func (f *fixture) open(t *testing.T) {
	t.Helper()
	var err error
	f.s, err = store.Open(context.Background(), f.dsn, "../../migrations")
	if err != nil {
		t.Fatal(err)
	}
	f.b, err = New(f.s, f.c)
	if err != nil {
		t.Fatal(err)
	}
	f.b.now = func() time.Time { return f.now }
}

func (f *fixture) config(t *testing.T, app, policy string) *store.AppConfig {
	t.Helper()
	ct, nonce, err := f.c.Seal([]byte(syntheticKey))
	if err != nil {
		t.Fatal(err)
	}
	return &store.AppConfig{ID: app + "-credential", AppID: app, Key: "MODEL_KEY", Sensitive: true, AccessPolicy: policy, ValueCiphertext: ct, ValueNonce: nonce}
}

func (f *fixture) issue(t *testing.T) Grant {
	t.Helper()
	g, err := f.b.Issue(context.Background(), "owner", "app-a", "MODEL_KEY", "anthropic", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	return g
}

func request(b *Broker, method, path, tok, body string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	if tok != "" {
		r.Header.Set("X-Api-Key", tok)
	}
	w := httptest.NewRecorder()
	b.ServeHTTP(w, r)
	return w
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func fakeSuccess(b *Broker) {
	b.transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": {"application/json"}}, Body: io.NopCloser(strings.NewReader(`{"ok":true}`))}, nil
	})
}

func requireStatus(t *testing.T, w *httptest.ResponseRecorder, status int) {
	t.Helper()
	if w.Code != status {
		t.Fatalf("status=%d want=%d body=%s", w.Code, status, w.Body.String())
	}
	if strings.Contains(w.Body.String(), syntheticKey) {
		t.Fatal("credential leaked")
	}
}

func TestIssuanceRequiresOwnerEncryptedConfigAndRuntimeConsent(t *testing.T) {
	f := setup(t)
	for _, test := range []struct {
		owner, app, key, provider string
		ttl                       time.Duration
	}{
		{"other", "app-a", "MODEL_KEY", "anthropic", time.Hour},
		{"owner", "missing", "MODEL_KEY", "anthropic", time.Hour},
		{"owner", "app-a", "missing", "anthropic", time.Hour},
		{"owner", "app-a", "MODEL_KEY", "openai", time.Hour},
		{"owner", "app-a", "MODEL_KEY", "anthropic", 25 * time.Hour},
		{"owner", "app-a", "MODEL_KEY", "anthropic", time.Second},
	} {
		if _, err := f.b.Issue(context.Background(), test.owner, test.app, test.key, test.provider, test.ttl); !errors.Is(err, ErrDenied) {
			t.Fatalf("expected denial: %v", err)
		}
	}
	for _, policy := range []string{"control_plane_only", "agent_access", "runtime_access", "both"} {
		c := f.config(t, "app-a", policy)
		if err := f.s.UpdateAppConfig(context.Background(), "app-a", "MODEL_KEY", c); err != nil {
			t.Fatal(err)
		}
		_, err := f.b.Issue(context.Background(), "owner", "app-a", "MODEL_KEY", "anthropic", time.Hour)
		allowed := policy == "runtime_access" || policy == "both"
		if (err == nil) != allowed {
			t.Fatalf("policy=%s err=%v", policy, err)
		}
	}
	c := f.config(t, "app-a", "runtime_access")
	c.Sensitive = false
	c.ValueCiphertext, c.ValueNonce = nil, nil
	c.ValuePlaintext = sql.NullString{String: syntheticKey, Valid: true}
	if err := f.s.UpdateAppConfig(context.Background(), "app-a", "MODEL_KEY", c); err != nil {
		t.Fatal(err)
	}
	if _, err := f.b.Issue(context.Background(), "owner", "app-a", "MODEL_KEY", "anthropic", time.Hour); !errors.Is(err, ErrDenied) {
		t.Fatalf("plaintext permitted: %v", err)
	}
}

func TestAuthorizationRoutesAndTokenAmbiguity(t *testing.T) {
	f := setup(t)
	g := f.issue(t)
	fakeSuccess(f.b)
	for _, tc := range []struct {
		method, path, tok string
		status            int
	}{
		{"POST", "/apps/app-a/anthropic/v1/messages", g.Token, 200},
		{"POST", "/apps/app-a/anthropic/v1/messages/count_tokens", g.Token, 200},
		{"GET", "/apps/app-a/anthropic/v1/models", g.Token, 200},
		{"POST", "/apps/app-a/anthropic/v1/messages", "", 401},
		{"POST", "/apps/app-a/anthropic/v1/messages", "not-a-grant", 401},
		{"POST", "/apps/app-b/anthropic/v1/messages", g.Token, 401},
		{"POST", "/apps/missing/anthropic/v1/messages", g.Token, 401},
		{"POST", "/apps/app-a/openai/v1/messages", g.Token, 404},
		{"POST", "/claude-code/anthropic/v1/messages", g.Token, 404},
		{"POST", "/apps/app-a/anthropic/v1/messages?url=https://evil.test", g.Token, 404},
		{"POST", "/apps/app-a/anthropic/v1/messages?", g.Token, 404},
		{"POST", "/apps/app-a/anthropic/v1/%6dessages", g.Token, 404},
		{"POST", "/apps/app-a/anthropic/v1/../messages", g.Token, 404},
		{"POST", "/apps/app-a/anthropic/v1/messages/", g.Token, 404},
		{"DELETE", "/apps/app-a/anthropic/v1/messages", g.Token, 404},
		{"GET", "/apps/app-a/anthropic/v1/messages", g.Token, 404},
	} {
		t.Run(tc.method+tc.path+tc.tok[:min(len(tc.tok), 4)], func(t *testing.T) { requireStatus(t, request(f.b, tc.method, tc.path, tc.tok, ""), tc.status) })
	}
	for _, headers := range []http.Header{
		{"Authorization": {"Bearer " + g.Token}, "X-Api-Key": {g.Token}},
		{"X-Api-Key": {g.Token, g.Token}},
		{"Authorization": {"Bearer " + g.Token, "Bearer " + g.Token}},
	} {
		r := httptest.NewRequest("POST", "/apps/app-a/anthropic/v1/messages", nil)
		r.Header = headers
		w := httptest.NewRecorder()
		f.b.ServeHTTP(w, r)
		requireStatus(t, w, 401)
	}
	r := httptest.NewRequest("POST", "/apps/app-a/anthropic/v1/messages", nil)
	r.Header.Set("Authorization", "Bearer "+g.Token)
	w := httptest.NewRecorder()
	f.b.ServeHTTP(w, r)
	requireStatus(t, w, 200)
}

func TestGrantPersistsWithoutPlaintextTokenAndExpires(t *testing.T) {
	f := setup(t)
	g := f.issue(t)
	var hash []byte
	var ct []byte
	if err := f.s.DB().QueryRow(`SELECT g.token_hash,c.value_ciphertext FROM provider_grant g JOIN app_config c ON c.id=g.config_id WHERE g.id=?`, g.ID).Scan(&hash, &ct); err != nil {
		t.Fatal(err)
	}
	want := sha256.Sum256([]byte(g.Token))
	if string(hash) != string(want[:]) || strings.Contains(string(ct), syntheticKey) {
		t.Fatal("invalid persisted secret material")
	}
	if err := f.s.Close(); err != nil {
		t.Fatal(err)
	}
	f.s = nil
	f.open(t)
	fakeSuccess(f.b)
	requireStatus(t, request(f.b, "POST", "/apps/app-a/anthropic/v1/messages", g.Token, "{}"), 200)
	f.now = g.ExpiresAt
	requireStatus(t, request(f.b, "POST", "/apps/app-a/anthropic/v1/messages", g.Token, "{}"), 401)
}

func TestRevocationDoesNotReviveAfterConfigOrOwnerRestoration(t *testing.T) {
	for _, action := range []string{"explicit", "policy", "rotation", "delete-config", "delete-app", "owner"} {
		t.Run(action, func(t *testing.T) {
			f := setup(t)
			g := f.issue(t)
			fakeSuccess(f.b)
			ctx := context.Background()
			// A different owner/app cannot revoke this grant.
			if err := f.b.Revoke(ctx, "other", "app-a", g.ID); err != nil {
				t.Fatal(err)
			}
			if err := f.b.Revoke(ctx, "owner", "app-b", g.ID); err != nil {
				t.Fatal(err)
			}
			requireStatus(t, request(f.b, "POST", "/apps/app-a/anthropic/v1/messages", g.Token, "{}"), 200)
			switch action {
			case "explicit":
				if err := f.b.Revoke(ctx, "owner", "app-a", g.ID); err != nil {
					t.Fatal(err)
				}
			case "policy", "rotation":
				c := f.config(t, "app-a", "control_plane_only")
				if action == "rotation" {
					c.AccessPolicy = "runtime_access"
				}
				if err := f.s.UpdateAppConfig(ctx, "app-a", "MODEL_KEY", c); err != nil {
					t.Fatal(err)
				}
				c.AccessPolicy = "runtime_access"
				if err := f.s.UpdateAppConfig(ctx, "app-a", "MODEL_KEY", c); err != nil {
					t.Fatal(err)
				}
			case "delete-config":
				if err := f.s.DeleteAppConfig(ctx, "app-a", "MODEL_KEY"); err != nil {
					t.Fatal(err)
				}
				if err := f.s.CreateAppConfig(ctx, f.config(t, "app-a", "runtime_access")); err != nil {
					t.Fatal(err)
				}
			case "delete-app":
				// Exercise triggers with foreign_keys disabled (the default DSN).
				if _, err := f.s.DB().Exec(`DELETE FROM app WHERE id='app-a'`); err != nil {
					t.Fatal(err)
				}
				if err := f.s.CreateApp(ctx, &store.App{ID: "app-a", OwnerToken: "owner", Name: "replacement"}); err != nil {
					t.Fatal(err)
				}
			case "owner":
				if _, err := f.s.DB().Exec(`UPDATE app SET owner_token='other' WHERE id='app-a'; UPDATE app SET owner_token='owner' WHERE id='app-a'`); err != nil {
					t.Fatal(err)
				}
			}
			requireStatus(t, request(f.b, "POST", "/apps/app-a/anthropic/v1/messages", g.Token, "{}"), 401)
			var n int
			if err := f.s.DB().QueryRow(`SELECT count(*) FROM provider_grant`).Scan(&n); err != nil || n != 0 {
				t.Fatalf("grant retained: %d %v", n, err)
			}
		})
	}
}

func TestProxyUsesFixedTargetAndStripsCallerHeaders(t *testing.T) {
	f := setup(t)
	g := f.issue(t)
	var calls int
	f.b.transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
		calls++
		if r.URL.String() != "https://api.anthropic.com/v1/messages" || r.Host != "api.anthropic.com" {
			t.Errorf("wrong target: %s %s", r.URL, r.Host)
		}
		if r.Header.Get("X-Api-Key") != syntheticKey || r.Header.Get("Anthropic-Version") != "2023-06-01" {
			t.Error("missing provider headers")
		}
		for _, h := range []string{"Authorization", "Cookie", "X-Forwarded-For", "Forwarded", "X-Leak", "Connection"} {
			if r.Header.Get(h) != "" {
				t.Errorf("forwarded %s", h)
			}
		}
		body, _ := io.ReadAll(r.Body)
		if string(body) != `{"stream":true}` {
			t.Errorf("body=%s", body)
		}
		return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": {"text/event-stream"}, "Set-Cookie": {syntheticKey}, "X-Leak": {syntheticKey}}, Body: io.NopCloser(strings.NewReader("data: first\n\ndata: second\n\n"))}, nil
	})
	r := httptest.NewRequest("POST", "/apps/app-a/anthropic/v1/messages", strings.NewReader(`{"stream":true}`))
	r.Header = http.Header{"X-Api-Key": {g.Token}, "Cookie": {"session=private"}, "X-Forwarded-For": {"private-host"}, "Forwarded": {"host=evil.test"}, "X-Leak": {"private"}, "Connection": {"X-Api-Key"}}
	w := httptest.NewRecorder()
	f.b.ServeHTTP(w, r)
	requireStatus(t, w, 200)
	if calls != 1 || w.Body.String() != "data: first\n\ndata: second\n\n" || !w.Flushed {
		t.Fatal("SSE did not stream unchanged")
	}
	if w.Header().Get("Set-Cookie") != "" || w.Header().Get("X-Leak") != "" {
		t.Fatal("response header leak")
	}
}

func TestProxyBoundsBodiesAndSanitizesErrors(t *testing.T) {
	f := setup(t)
	g := f.issue(t)
	var calls int
	f.b.transport = roundTripFunc(func(r *http.Request) (*http.Response, error) { calls++; return nil, errors.New(syntheticKey) })
	requireStatus(t, request(f.b, "POST", "/apps/app-a/anthropic/v1/messages", g.Token, strings.Repeat("a", maxBody+1)), 413)
	requireStatus(t, request(f.b, "GET", "/apps/app-a/anthropic/v1/models", g.Token, "body"), 400)
	if calls != 0 {
		t.Fatal("invalid body reached upstream")
	}
	requireStatus(t, request(f.b, "POST", "/apps/app-a/anthropic/v1/messages", g.Token, "{}"), 502)
	for _, status := range []int{301, 307, 401, 429, 500} {
		f.b.transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: status, Header: http.Header{"Location": {"https://evil.test/" + syntheticKey}, "Set-Cookie": {syntheticKey}}, Body: io.NopCloser(strings.NewReader(syntheticKey))}, nil
		})
		w := request(f.b, "POST", "/apps/app-a/anthropic/v1/messages", g.Token, "{}")
		requireStatus(t, w, 502)
		if w.Header().Get("Location") != "" || w.Header().Get("Set-Cookie") != "" {
			t.Fatal("error headers leaked")
		}
	}
}

func TestRealHTTPStreamAndClientCancellation(t *testing.T) {
	f := setup(t)
	g := f.issue(t)
	cancelled := make(chan struct{})
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Api-Key") != syntheticKey {
			t.Error("upstream missing credential")
		}
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, "data: first\n\n")
		w.(http.Flusher).Flush()
		<-r.Context().Done()
		close(cancelled)
	}))
	defer upstream.Close()
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	defer transport.CloseIdleConnections()
	var calls atomic.Int32
	f.b.transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
		calls.Add(1)
		r.URL.Scheme = "http"
		r.URL.Host = strings.TrimPrefix(upstream.URL, "http://")
		return transport.RoundTrip(r)
	})
	server := httptest.NewServer(f.b)
	defer server.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	r, _ := http.NewRequestWithContext(ctx, "POST", server.URL+"/apps/app-a/anthropic/v1/messages", strings.NewReader("{}"))
	r.Header.Set("X-Api-Key", g.Token)
	resp, err := http.DefaultClient.Do(r)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	first := make([]byte, len("data: first\n\n"))
	if _, err := io.ReadFull(resp.Body, first); err != nil {
		t.Fatal(err)
	}
	if string(first) != "data: first\n\n" {
		t.Fatalf("stream=%q", first)
	}
	cancel()
	select {
	case <-cancelled:
	case <-time.After(2 * time.Second):
		t.Fatal("upstream not cancelled")
	}
	if calls.Load() != 1 {
		t.Fatal("unexpected retry")
	}
}

func TestCorruptCredentialAndConcurrencyFailClosed(t *testing.T) {
	f := setup(t)
	g := f.issue(t)
	fakeSuccess(f.b)
	for i := 0; i < cap(f.b.active); i++ {
		f.b.active <- struct{}{}
	}
	requireStatus(t, request(f.b, "POST", "/apps/app-a/anthropic/v1/messages", g.Token, "{}"), 429)
	for len(f.b.active) > 0 {
		<-f.b.active
	}
	requireStatus(t, request(f.b, "POST", "/apps/app-a/anthropic/v1/messages", g.Token, "{}"), 200)
	c := f.config(t, "app-a", "runtime_access")
	c.ValueCiphertext[0] ^= 0xff
	if err := f.s.UpdateAppConfig(context.Background(), "app-a", "MODEL_KEY", c); err != nil {
		t.Fatal(err)
	}
	g = f.issue(t)
	requireStatus(t, request(f.b, "POST", "/apps/app-a/anthropic/v1/messages", g.Token, "{}"), 503)
}
