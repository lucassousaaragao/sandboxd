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
	"sync/atomic"
	"testing"
	"time"

	"github.com/tastyeffectco/sandboxd/control-plane/internal/auth"
	"github.com/tastyeffectco/sandboxd/control-plane/internal/idlock"
	"github.com/tastyeffectco/sandboxd/control-plane/internal/loopback"
	"github.com/tastyeffectco/sandboxd/control-plane/internal/provideraccess"
	"github.com/tastyeffectco/sandboxd/control-plane/internal/runtime"
	"github.com/tastyeffectco/sandboxd/control-plane/internal/store"
)

func TestRuntimeConnectionRenewalAPI(t *testing.T) {
	for _, mode := range []string{"renewed", "read-only", "wrong-owner", "wrong-app", "wrong-runtime", "wrong-id", "stopped", "revoked", "expired", "busy", "old-runtime", "lost-connection", "different-boot", "different-expiry", "changed-during-check", "rejected", "lost-response", "cancelled", "unknown-field", "oversized", "trailing-json", "invalid-ttl"} {
		t.Run(mode, func(t *testing.T) {
			s, appID := newConfigTestServer(t)
			var err error
			s.ProviderAccess, err = provideraccess.New(s.Store, s.Secrets)
			if err != nil {
				t.Fatal(err)
			}
			s.AgentProxyURL = "http://sandboxd:9100"
			s.Locks = idlock.New()
			root, err := os.MkdirTemp("", "sbx-renew-")
			if err != nil {
				t.Fatal(err)
			}
			defer os.RemoveAll(root)
			s.Loopback = &loopback.Manager{Root: root}
			ctx := context.Background()
			if err := s.Store.Create(ctx, &store.Sandbox{ID: "sandbox-a", AppID: sql.NullString{String: appID, Valid: true}, Status: "running", Image: "test"}); err != nil {
				t.Fatal(err)
			}
			w := do(s, "POST", "/v1/apps/"+appID+"/config", `{"key":"MODEL_KEY","value":"synthetic-private-key","sensitive":true,"access_policy":"runtime_access"}`, cfgTenant, map[string]string{"id": appID})
			if w.Code != 201 {
				t.Fatal(w.Code)
			}
			g, err := s.ProviderAccess.IssueRuntime(ctx, cfgTenant, appID, "MODEL_KEY", "anthropic", "sandbox-a", time.Hour)
			if err != nil {
				t.Fatal(err)
			}
			boot := time.Now().UTC()
			publicCtx, cancel := context.WithCancel(ctx)
			defer cancel()
			_, mount := s.Loopback.Paths("sandbox-a")
			dir := filepath.Join(mount, ".runtimed")
			if err := os.MkdirAll(dir, 0700); err != nil {
				t.Fatal(err)
			}
			ln, err := net.Listen("unix", filepath.Join(dir, "sock"))
			if err != nil {
				t.Fatal(err)
			}
			var renewals atomic.Int32
			mux := http.NewServeMux()
			mux.HandleFunc("GET /status", func(w http.ResponseWriter, r *http.Request) {
				_ = json.NewEncoder(w).Encode(runtime.Status{ScopedProviderConnection: true, ScopedProviderRenewal: mode != "old-runtime", Runtimed: runtime.RuntimedInfo{BootedAt: boot}})
			})
			mux.HandleFunc("GET /provider-connection/status", func(w http.ResponseWriter, r *http.Request) {
				if mode == "lost-connection" {
					w.WriteHeader(404)
					return
				}
				p := runtime.ProviderConnectionStatus{ID: g.ID, ExpiresAt: g.ExpiresAt, BootedAt: boot}
				if mode == "different-boot" {
					p.BootedAt = boot.Add(time.Second)
				}
				if mode == "different-expiry" {
					p.ExpiresAt = g.ExpiresAt.Add(time.Second)
				}
				if mode == "changed-during-check" {
					if err := s.ProviderAccess.Revoke(ctx, cfgTenant, appID, g.ID); err != nil {
						t.Error(err)
					}
				}
				_ = json.NewEncoder(w).Encode(p)
			})
			mux.HandleFunc("POST /provider-connection/renew", func(w http.ResponseWriter, r *http.Request) {
				renewals.Add(1)
				var p runtime.ProviderConnectionRenewal
				if json.NewDecoder(r.Body).Decode(&p) != nil || p.ID != g.ID || !p.PreviousExpiresAt.Equal(g.ExpiresAt) || !p.BootedAt.Equal(boot) || !p.ExpiresAt.After(g.ExpiresAt) {
					t.Error("invalid private renewal")
				}
				if mode == "cancelled" {
					cancel()
					select {
					case <-r.Context().Done():
					case <-time.After(2 * time.Second):
						t.Error("renewal not cancelled")
					}
					return
				}
				if mode == "lost-response" {
					c, _, _ := w.(http.Hijacker).Hijack()
					c.Close()
					return
				}
				if mode == "rejected" {
					w.WriteHeader(400)
					_, _ = w.Write([]byte(g.Token))
					return
				}
				w.WriteHeader(204)
			})
			srv := &http.Server{Handler: mux}
			go srv.Serve(ln)
			defer srv.Close()
			body, _ := json.Marshal(map[string]any{"id": g.ID, "runtime_sandbox_id": "sandbox-a", "ttl_seconds": 86400})
			bodyText, owner, selectedApp, method, want := string(body), cfgTenant, appID, "POST", 200
			switch mode {
			case "read-only":
				method = "GET"
			case "wrong-owner":
				owner = "other"
				want = 404
			case "wrong-app":
				selectedApp = "other-app"
				want = 404
			case "wrong-runtime":
				bodyText = strings.Replace(bodyText, "sandbox-a", "sandbox-b", 1)
				want = 409
			case "wrong-id":
				bodyText = strings.Replace(bodyText, g.ID, "other-id", 1)
				want = 409
			case "stopped":
				_, err = s.Store.DB().Exec(`UPDATE sandbox SET status='stopped'`)
				want = 409
			case "revoked":
				err = s.ProviderAccess.Revoke(ctx, cfgTenant, appID, g.ID)
				want = 403
			case "expired":
				_, err = s.Store.DB().Exec(`UPDATE provider_grant SET created_at=?, expires_at=?`, time.Now().Add(-2*time.Hour).Unix(), time.Now().Add(-time.Hour).Unix())
				want = 403
			case "busy":
				s.Locks.Lock("sandbox-a")
				defer s.Locks.Unlock("sandbox-a")
				want = 409
			case "old-runtime", "rejected", "lost-response", "cancelled":
				want = 503
			case "lost-connection", "different-boot", "different-expiry":
				want = 409
			case "changed-during-check":
				want = 403
			case "unknown-field":
				bodyText = strings.TrimSuffix(bodyText, "}") + `,"token":"bad"}`
				want = 400
			case "oversized":
				bodyText = strings.Repeat(" ", 4096) + bodyText
				want = 400
			case "trailing-json":
				bodyText += `{}`
				want = 400
			case "invalid-ttl":
				bodyText = strings.Replace(bodyText, "86400", "86401", 1)
				want = 400
			}
			if err != nil {
				t.Fatal(err)
			}
			r := httptest.NewRequest(method, "/v1/apps/"+selectedApp+"/provider-connection/renew", strings.NewReader(bodyText))
			r.SetPathValue("id", selectedApp)
			r = r.WithContext(auth.WithActor(publicCtx, auth.Actor{Name: owner, Kind: "service"}))
			w = httptest.NewRecorder()
			s.v1RuntimeProviderConnection(w, r)
			if w.Code != want {
				t.Fatalf("status=%d expected=%d body=%s", w.Code, want, w.Body)
			}
			if w.Header().Get("Cache-Control") != "no-store" || strings.Contains(w.Body.String(), g.Token) || strings.Contains(w.Body.String(), "synthetic-private-key") || strings.Contains(w.Body.String(), `"token"`) {
				t.Fatal("secret/cache boundary broken")
			}
			mutates := mode == "renewed" || mode == "rejected" || mode == "lost-response" || mode == "cancelled"
			if (renewals.Load() == 1) != mutates {
				t.Fatal("unexpected renewal count", renewals.Load())
			}
			var expiry int64
			err = s.Store.DB().QueryRow(`SELECT expires_at FROM provider_grant WHERE id=?`, g.ID).Scan(&expiry)
			removed := mode == "stopped" || mode == "revoked" || mode == "changed-during-check" || mode == "rejected" || mode == "lost-response" || mode == "cancelled"
			if removed {
				if err != sql.ErrNoRows {
					t.Fatal("revocation not retained", err)
				}
			} else if err != nil {
				t.Fatal(err)
			} else if mode == "renewed" {
				if expiry <= g.ExpiresAt.Unix() {
					t.Fatal("lease not extended")
				}
			} else if mode != "expired" && expiry != g.ExpiresAt.Unix() {
				t.Fatal("failed/read request changed lease")
			}
			if mode == "renewed" || mode == "read-only" {
				var info map[string]any
				if json.Unmarshal(w.Body.Bytes(), &info) != nil || len(info) != 5 || info["id"] != g.ID || info["runtime_sandbox_id"] != "sandbox-a" || info["delivered"] != true {
					t.Fatal("invalid metadata receipt")
				}
			}
		})
	}
}
