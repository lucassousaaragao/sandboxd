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
	"github.com/tastyeffectco/sandboxd/control-plane/internal/loopback"
	"github.com/tastyeffectco/sandboxd/control-plane/internal/provideraccess"
	"github.com/tastyeffectco/sandboxd/control-plane/internal/runtime"
	"github.com/tastyeffectco/sandboxd/control-plane/internal/store"
)

func TestScopedTaskSubmissionDeliversPrivateGrantAndRevokes(t *testing.T) {
	for _, tc := range []struct {
		name            string
		accept, support bool
	}{{"runtime_rejected", false, true}, {"task_finished", true, true}, {"old_runtime", true, false}} {
		t.Run(tc.name, func(t *testing.T) {
			accept := tc.accept
			s, appID := newConfigTestServer(t)
			var err error
			s.ProviderAccess, err = provideraccess.New(s.Store, s.Secrets)
			if err != nil {
				t.Fatal(err)
			}
			// Short temporary root respects AF_UNIX's path length on Linux/macOS.
			root, err := os.MkdirTemp("", "sbx-task-")
			if err != nil {
				t.Fatal(err)
			}
			defer os.RemoveAll(root)
			s.Loopback = &loopback.Manager{Root: root}
			sbID := "sandbox-a"
			if err = s.Store.Create(context.Background(), &store.Sandbox{ID: sbID, AppID: sql.NullString{String: appID, Valid: true}, Status: "running", Image: "test"}); err != nil {
				t.Fatal(err)
			}
			_, mnt := s.Loopback.Paths(sbID)
			sockdir := filepath.Join(mnt, ".runtimed")
			if err = os.MkdirAll(sockdir, 0700); err != nil {
				t.Fatal(err)
			}
			ln, err := net.Listen("unix", filepath.Join(sockdir, "sock"))
			if err != nil {
				t.Fatal(err)
			}
			starts := make(chan runtime.StartTaskRequest, 1)
			mux := http.NewServeMux()
			mux.HandleFunc("GET /status", func(w http.ResponseWriter, r *http.Request) {
				_ = json.NewEncoder(w).Encode(runtime.Status{ScopedProviderTasks: tc.support})
			})
			mux.HandleFunc("POST /tasks", func(w http.ResponseWriter, r *http.Request) {
				var req runtime.StartTaskRequest
				if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
					t.Error(err)
					w.WriteHeader(400)
					return
				}
				starts <- req
				probe := httptest.NewRequest("POST", "/claude-code/anthropic/v1/messages", nil)
				probe.Header.Set("X-Api-Key", req.ProxyToken)
				if !s.ProviderAccess.AuthorizeTask(probe, "claude-code", "anthropic") {
					t.Error("delivered token not authorized")
				}
				if accept {
					w.WriteHeader(202)
				} else {
					w.WriteHeader(409)
				}
			})
			mux.HandleFunc("GET /tasks/{id}/events", func(w http.ResponseWriter, r *http.Request) {
				_ = json.NewEncoder(w).Encode(doneEvent(r.PathValue("id"), runtime.TaskSucceeded))
			})
			srv := &http.Server{Handler: mux}
			go srv.Serve(ln)
			defer srv.Close()
			request := func(owner string) *httptest.ResponseRecorder {
				r := httptest.NewRequest("POST", "/v1/sandboxes/"+sbID+"/tasks", strings.NewReader(`{"prompt":"test task","agent":"claude-code","proxy_token":"attacker-chosen","proxy_upstream":"minimax"}`))
				r.SetPathValue("id", sbID)
				r = r.WithContext(auth.WithActor(r.Context(), auth.Actor{Name: owner, Kind: "service"}))
				w := httptest.NewRecorder()
				s.v1SubmitTask(w, r)
				return w
			}
			if w := request("other"); w.Code != 404 {
				t.Fatalf("wrong owner=%d", w.Code)
			}
			select {
			case <-starts:
				t.Fatal("wrong owner reached runtime")
			default:
			}
			w := request(cfgTenant)
			if !tc.support {
				if w.Code != 503 || !strings.Contains(w.Body.String(), "runtime_incompatible") {
					t.Fatalf("old runtime=%d %s", w.Code, w.Body)
				}
				select {
				case <-starts:
					t.Fatal("old runtime received task")
				default:
				}
				var n int
				if err := s.Store.DB().QueryRow(`SELECT count(*) FROM task_proxy_grant`).Scan(&n); err != nil || n != 0 {
					t.Fatal("old runtime received grant")
				}
				return
			}
			want := 409
			if accept {
				want = 202
			}
			if w.Code != want {
				t.Fatalf("submit=%d %s", w.Code, w.Body)
			}
			var start runtime.StartTaskRequest
			select {
			case start = <-starts:
			case <-time.After(time.Second):
				t.Fatal("no runtime request")
			}
			if len(start.ProxyToken) != 43 || start.ProxyToken == "attacker-chosen" || start.ProxyUpstream != "anthropic" {
				t.Fatal("invalid internal grant")
			}
			if strings.Contains(w.Body.String(), start.ProxyToken) {
				t.Fatal("public response leaked grant")
			}
			deadline := time.Now().Add(2 * time.Second)
			for {
				var n int
				err := s.Store.DB().QueryRow(`SELECT count(*) FROM task_proxy_grant`).Scan(&n)
				if err != nil {
					t.Fatal(err)
				}
				if n == 0 {
					break
				}
				if time.Now().After(deadline) {
					t.Fatal("grant not revoked")
				}
				time.Sleep(5 * time.Millisecond)
			}
			if accept {
				task, err := s.Store.GetTask(context.Background(), start.TaskID)
				if err != nil {
					t.Fatal(err)
				}
				if task.Status != "succeeded" || strings.Contains(task.ResultJSON.String, start.ProxyToken) {
					t.Fatal("invalid durable task result")
				}
			}
		})
	}
}
