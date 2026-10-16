package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/tastyeffectco/sandboxd/control-plane/internal/docker"
	"github.com/tastyeffectco/sandboxd/control-plane/internal/idlock"
	"github.com/tastyeffectco/sandboxd/control-plane/internal/loopback"
	"github.com/tastyeffectco/sandboxd/control-plane/internal/store"
)

// Exercise the real app handler, delegation, SQLite persistence and public
// reads. Only Docker CLI responses are fixtures: no real daemon/host mounts.
func appIdleServer(t *testing.T) (*Server, string) {
	t.Helper()
	s := newPresetTestServer(t)
	root := t.TempDir()
	bin := filepath.Join(root, "docker-fixture")
	if err := os.WriteFile(bin, []byte(`#!/bin/sh
case "$1" in
  run) printf '%s\n' '0123456789abcdef' ;;
  inspect) printf '%s\n' '{"Id":"0123456789abcdef","State":{"Running":true,"Pid":0}}' ;;
  stop) exit 0 ;;
  *) exit 9 ;;
esac
`), 0700); err != nil {
		t.Fatal(err)
	}
	s.Docker = &docker.Client{Bin: bin}
	s.Loopback = &loopback.Manager{Root: filepath.Join(root, "workspaces"), DockerBin: bin, SeedImage: "fixture"}
	s.Locks = idlock.New()
	s.Image = "fixture"
	app := &store.App{ID: newULID(), OwnerToken: cfgTenant, Name: "Agent"}
	if err := s.Store.CreateApp(context.Background(), app); err != nil {
		t.Fatal(err)
	}
	return s, app.ID
}

func appIdleRequest(s *Server, appID, owner, body string) *httptest.ResponseRecorder {
	return presetReq(s, "POST", "/v1/apps/"+appID+"/sandbox", body, owner,
		map[string]string{"id": appID}, s.v1CreateAppSandbox)
}

func TestAppSandboxIdlePolicyPersistsAndControlsCandidates(t *testing.T) {
	for _, tc := range []struct{ name, body, policy string }{
		{"always-on", `{"template":"blank","idle_policy":"always_on"}`, "always_on"},
		{"sleep", `{"template":"blank","idle_policy":"sleep"}`, "sleep"},
		{"default", `{"template":"blank"}`, "sleep"},
		{"empty-body", "", "sleep"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, appID := appIdleServer(t)
			w := appIdleRequest(s, appID, cfgTenant, tc.body)
			if w.Code != http.StatusCreated {
				t.Fatalf("create: %d %s", w.Code, w.Body)
			}
			var created map[string]any
			if err := json.Unmarshal(w.Body.Bytes(), &created); err != nil {
				t.Fatal(err)
			}
			if created["idle_policy"] != tc.policy {
				t.Errorf("create policy = %v; want %s", created["idle_policy"], tc.policy)
			}
			sb, err := s.Store.CurrentSandboxForApp(context.Background(), appID)
			if err != nil || sb.IdlePolicy != tc.policy {
				t.Fatalf("stored policy: %+v, %v; want %s", sb, err, tc.policy)
			}
			read := presetReq(s, "GET", "/v1/sandboxes/"+sb.ID, "", cfgTenant,
				map[string]string{"id": sb.ID}, s.v1GetSandbox)
			var view map[string]any
			if err := json.Unmarshal(read.Body.Bytes(), &view); err != nil || read.Code != 200 || view["idle_policy"] != tc.policy {
				t.Errorf("public policy: %d %s (%v)", read.Code, read.Body, err)
			}
			// A future cutoff makes the newly created row idle without sleeping or
			// rewriting production timestamps. This is the reaper's real SQL query.
			rows, err := s.Store.ListIdleCandidates(context.Background(), time.Now().Add(time.Hour))
			if err != nil {
				t.Fatal(err)
			}
			if (len(rows) == 1) != (tc.policy == "sleep") {
				t.Errorf("idle candidates = %d for %s", len(rows), tc.policy)
			}
			// An exemption is not an auto-start policy or immunity from Stop.
			stopped := presetReq(s, "POST", "/v1/sandboxes/"+sb.ID+"/stop", "", cfgTenant,
				map[string]string{"id": sb.ID}, s.v1StopSandbox)
			if stopped.Code != 200 {
				t.Fatalf("explicit stop: %d %s", stopped.Code, stopped.Body)
			}
			sb, err = s.Store.Get(context.Background(), sb.ID)
			if err != nil || sb.Status != "stopped" || sb.IdlePolicy != tc.policy {
				t.Errorf("policy/stop persistence: %+v, %v", sb, err)
			}
		})
	}
}

func TestAppSandboxIdlePolicyInvalidRequestsDoNotCreate(t *testing.T) {
	for _, body := range []string{`{"idle_policy":"sometimes"}`, `{"idle_policy":123}`, `{"idle_policy":false}`,
		`{"idle_policy":"always_on",`, `{"idle_policy":"always_on"} {}`, `[]`} {
		t.Run(body, func(t *testing.T) {
			s, appID := appIdleServer(t)
			w := appIdleRequest(s, appID, cfgTenant, body)
			if w.Code != http.StatusBadRequest {
				t.Errorf("create: %d %s; want 400", w.Code, w.Body)
			}
			rows, err := s.Store.SandboxIDsForApp(context.Background(), appID)
			if err != nil || len(rows) != 0 {
				t.Errorf("invalid request created a sandbox: %v, %v", rows, err)
			}
		})
	}
}

func TestAppSandboxIdlePolicyPreservesOwnershipAndExistingRuntime(t *testing.T) {
	s, appID := appIdleServer(t)
	for _, owner := range []string{"other-tenant", ""} {
		if w := appIdleRequest(s, appID, owner, `{"idle_policy":"always_on"}`); w.Code != 404 {
			t.Fatalf("cross-owner create: %d %s", w.Code, w.Body)
		}
	}
	if w := appIdleRequest(s, appID, cfgTenant, `{"idle_policy":"sleep"}`); w.Code != 201 {
		t.Fatalf("create: %d %s", w.Code, w.Body)
	}
	if w := appIdleRequest(s, appID, cfgTenant, `{"idle_policy":"always_on"}`); w.Code != 409 {
		t.Fatalf("repeated create: %d %s", w.Code, w.Body)
	}
	sb, err := s.Store.CurrentSandboxForApp(context.Background(), appID)
	if err != nil || sb.IdlePolicy != "sleep" {
		t.Fatalf("existing runtime changed: %+v, %v", sb, err)
	}
}
