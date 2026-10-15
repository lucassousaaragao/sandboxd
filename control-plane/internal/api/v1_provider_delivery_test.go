package api

import (
	"context"
	"database/sql"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tastyeffectco/sandboxd/control-plane/internal/auth"
	"github.com/tastyeffectco/sandboxd/control-plane/internal/idlock"
	"github.com/tastyeffectco/sandboxd/control-plane/internal/loopback"
	"github.com/tastyeffectco/sandboxd/control-plane/internal/provideraccess"
	"github.com/tastyeffectco/sandboxd/control-plane/internal/runtime"
	"github.com/tastyeffectco/sandboxd/control-plane/internal/store"
)

func TestProviderGrantPrivateDelivery(t *testing.T) {
	for _, mode := range []string{"delivered", "rejected", "old-runtime", "lost-response", "cancelled", "stopped", "wrong-sandbox", "busy"} {
		t.Run(mode, func(t *testing.T) {
			publicCtx, cancelPublic := context.WithCancel(context.Background())
			defer cancelPublic()
			s, appID := newConfigTestServer(t)
			var err error
			s.ProviderAccess, err = provideraccess.New(s.Store, s.Secrets)
			if err != nil {
				t.Fatal(err)
			}
			s.AgentProxyURL = "http://sandboxd:9100"
			s.Locks = idlock.New()
			root, err := os.MkdirTemp("", "sbx-deliver-")
			if err != nil {
				t.Fatal(err)
			}
			defer os.RemoveAll(root)
			s.Loopback = &loopback.Manager{Root: root}
			status := "running"
			if mode == "stopped" {
				status = "stopped"
			}
			if err := s.Store.Create(context.Background(), &store.Sandbox{ID: "sandbox-a", AppID: sql.NullString{String: appID, Valid: true}, Status: status, Image: "test"}); err != nil {
				t.Fatal(err)
			}
			w := do(s, "POST", "/v1/apps/"+appID+"/config", `{"key":"MODEL_KEY","value":"synthetic-provider-secret","sensitive":true,"access_policy":"runtime_access"}`, cfgTenant, map[string]string{"id": appID})
			if w.Code != 201 {
				t.Fatal(w.Code)
			}
			_, mnt := s.Loopback.Paths("sandbox-a")
			dir := filepath.Join(mnt, ".runtimed")
			if err := os.MkdirAll(dir, 0700); err != nil {
				t.Fatal(err)
			}
			ln, err := net.Listen("unix", filepath.Join(dir, "sock"))
			if err != nil {
				t.Fatal(err)
			}
			boot := time.Now().UTC()
			deliveries := make(chan runtime.ProviderConnection, 2)
			mux := http.NewServeMux()
			mux.HandleFunc("GET /status", func(w http.ResponseWriter, r *http.Request) {
				_ = json.NewEncoder(w).Encode(runtime.Status{ScopedProviderConnection: mode != "old-runtime", Runtimed: runtime.RuntimedInfo{BootedAt: boot}})
			})
			mux.HandleFunc("PUT /provider-connection", func(w http.ResponseWriter, r *http.Request) {
				var p runtime.ProviderConnection
				if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
					t.Error(err)
					w.WriteHeader(400)
					return
				}
				deliveries <- p
				if mode == "cancelled" {
					cancelPublic()
					select {
					case <-r.Context().Done():
					case <-time.After(2 * time.Second):
						t.Error("private delivery was not cancelled")
					}
					return
				}
				if mode == "lost-response" {
					conn, _, _ := w.(http.Hijacker).Hijack()
					conn.Close()
					return
				}
				if mode == "rejected" {
					w.WriteHeader(400)
					w.Write([]byte(p.Token))
					return
				}
				w.WriteHeader(204)
			})
			srv := &http.Server{Handler: mux}
			go srv.Serve(ln)
			defer srv.Close()
			body := `{"provider":"anthropic","config_key":"MODEL_KEY","ttl_seconds":3600,"runtime_sandbox_id":"sandbox-a"}`
			if w := grantRequest(s, appID, cfgTenant, "POST", strings.Replace(body, "sandbox-a", "", 1), ""); w.Code != 400 {
				t.Fatal("empty private-delivery target must not fall back to returning a token")
			}
			if w := grantRequest(s, appID, "other", "POST", body, ""); w.Code != 404 {
				t.Fatal("wrong owner accepted")
			}
			if mode == "wrong-sandbox" {
				body = strings.Replace(body, "sandbox-a", "sandbox-b", 1)
			}
			if mode == "busy" {
				s.Locks.Lock("sandbox-a")
				defer s.Locks.Unlock("sandbox-a")
			}
			if mode == "cancelled" {
				r := httptest.NewRequest("POST", "/v1/apps/"+appID+"/provider-grants", strings.NewReader(body))
				r.SetPathValue("id", appID)
				r = r.WithContext(auth.WithActor(publicCtx, auth.Actor{Name: cfgTenant, Kind: "service"}))
				w = httptest.NewRecorder()
				s.v1CreateProviderGrant(w, r)
			} else {
				w = grantRequest(s, appID, cfgTenant, "POST", body, "")
			}
			want := 503
			if mode == "delivered" {
				want = 201
			}
			if mode == "stopped" || mode == "wrong-sandbox" || mode == "busy" {
				want = 409
			}
			if w.Code != want {
				t.Fatalf("got %d: %s", w.Code, w.Body)
			}
			var count int
			if err := s.Store.DB().QueryRow(`SELECT count(*) FROM provider_grant`).Scan(&count); err != nil {
				t.Fatal(err)
			}
			wantCount := 0
			if mode == "delivered" {
				wantCount = 1
			}
			if count != wantCount {
				t.Fatalf("active grants=%d want=%d", count, wantCount)
			}
			if strings.Contains(w.Body.String(), `"token"`) || strings.Contains(w.Body.String(), "synthetic-provider-secret") {
				t.Fatal("public response disclosed credential")
			}
			select {
			case p := <-deliveries:
				if mode != "delivered" && mode != "rejected" && mode != "lost-response" && mode != "cancelled" {
					t.Fatal("invalid preflight reached runtime")
				}
				if !p.Valid(s.AgentProxyURL, boot, time.Now()) {
					t.Fatal("invalid private delivery")
				}
				if strings.Contains(w.Body.String(), p.Token) {
					t.Fatal("runtime error echoed token")
				}
			default:
				if mode == "delivered" || mode == "rejected" || mode == "lost-response" || mode == "cancelled" {
					t.Fatal("missing runtime delivery")
				}
			}
		})
	}
}
