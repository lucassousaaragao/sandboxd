package provideraccess

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tastyeffectco/sandboxd/control-plane/internal/secrets"
	"github.com/tastyeffectco/sandboxd/control-plane/internal/store"
)

// External opt-in harness supplies the real pinned agent and protocol fixture
// inside an offline disposable container. Nothing here ships in the Go engine.
func TestLiveOpenClawScoped(t *testing.T) {
	if os.Getenv("SANDBOXD_LIVE_OPENCLAW_BROKER") != "1" {
		t.Skip("requires offline OpenClaw probe harness")
	}
	if os.Getuid() != 1000 {
		t.Fatal("non-root sandbox required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 210*time.Second)
	defer cancel()
	root := t.TempDir()
	s, err := store.Open(ctx, filepath.Join(root, "state.db"), "/home/sandbox/probe-migrations")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	c, err := secrets.Load("", filepath.Join(root, "key"))
	if err != nil {
		t.Fatal(err)
	}
	b, err := New(s, c)
	if err != nil {
		t.Fatal(err)
	}
	if err = s.CreateApp(ctx, &store.App{ID: "probe-app", OwnerToken: "probe-owner", Name: "OpenClaw probe"}); err != nil {
		t.Fatal(err)
	}
	ct, nonce, err := c.Seal([]byte("synthetic-probe-key"))
	if err != nil {
		t.Fatal(err)
	}
	if err = s.CreateAppConfig(ctx, &store.AppConfig{ID: "probe-key", AppID: "probe-app", Key: "MODEL_KEY", Sensitive: true, AccessPolicy: "runtime_access", ValueCiphertext: ct, ValueNonce: nonce}); err != nil {
		t.Fatal(err)
	}
	g, err := b.Issue(ctx, "probe-owner", "probe-app", "MODEL_KEY", "anthropic", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	defer transport.CloseIdleConnections()
	var calls atomic.Int32
	// Only this test substitutes the provider's transport. Production always
	// uses the fixed HTTPS provider. The Node fixture listens on guest loopback.
	b.transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.URL.Scheme != "https" || r.URL.Host != "api.anthropic.com" || r.URL.Path != "/v1/messages" {
			return nil, errors.New("unexpected provider target")
		}
		calls.Add(1)
		r.URL.Scheme = "http"
		r.URL.Host = "127.0.0.1:3100"
		return transport.RoundTrip(r)
	})
	proxy := httptest.NewServer(b)
	defer proxy.Close()
	connection := "/home/sandbox/probe/broker-connection.json"
	data, _ := json.Marshal(map[string]string{"baseUrl": proxy.URL + "/apps/probe-app/anthropic", "apiKey": g.Token})
	if err = os.WriteFile(connection, data, 0600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.CommandContext(ctx, "/home/sandbox/probe/node/bin/node", "/home/sandbox/probe/scoped-openclaw-boot.mjs")
	cmd.Env = []string{"PATH=/home/sandbox/probe/node/bin:/usr/bin:/bin", "HOME=/home/sandbox", "LANG=C.UTF-8", "SANDBOXD_PROBE_CONNECTION=" + connection}
	output, err := cmd.CombinedOutput()
	if strings.Contains(string(output), g.Token) {
		t.Fatal("agent fixture disclosed delegated token")
	}
	if err != nil {
		t.Fatalf("real OpenClaw broker probe failed: %v\n%s", err, output)
	}
	t.Log(strings.TrimSpace(string(output)))
	if calls.Load() != 4 {
		t.Fatalf("expected two real tool cycles through broker, got %d requests", calls.Load())
	}
	if err = b.Revoke(ctx, "probe-owner", "probe-app", g.ID); err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest("POST", "/apps/probe-app/anthropic/v1/messages", strings.NewReader("{}"))
	r.Header.Set("X-Api-Key", g.Token)
	w := httptest.NewRecorder()
	b.ServeHTTP(w, r)
	if w.Code != 401 || calls.Load() != 4 {
		t.Fatal("revoked app grant reached provider")
	}
	t.Log("Real OpenClaw SDK/tool/stream/restart passed through app-scoped broker; revocation denied before provider. Synthetic inference only.")
}
