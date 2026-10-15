package api

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/tastyeffectco/sandboxd/control-plane/internal/provideraccess"
	"github.com/tastyeffectco/sandboxd/control-plane/internal/runtime"
)

// These endpoints belong on the authenticated control API, never on the
// workload proxy listener. Private runtime delivery returns metadata only;
// otherwise callers must keep the returned capability out of preview URLs.
// Provider credentials themselves stay write-only.
func (s *Server) v1CreateProviderGrant(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	app, ok := s.appForConfig(w, r)
	if !ok {
		return
	}
	if s.ProviderAccess == nil {
		writeV1Err(w, 503, "provider_unavailable", "scoped provider access is not enabled")
		return
	}
	var req struct {
		Provider         string  `json:"provider"`
		ConfigKey        string  `json:"config_key"`
		TTLSeconds       int     `json:"ttl_seconds"`
		RuntimeSandboxID *string `json:"runtime_sandbox_id,omitempty"`
	}
	d := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096))
	d.DisallowUnknownFields()
	if err := d.Decode(&req); err != nil {
		writeV1Err(w, 400, "invalid_request", "invalid provider grant request")
		return
	}
	var extra any
	if err := d.Decode(&extra); err != io.EOF || req.TTLSeconds < 60 || req.TTLSeconds > 86400 || req.Provider != "anthropic" || !validConfigKey(req.ConfigKey) {
		writeV1Err(w, 400, "invalid_request", "invalid provider grant request")
		return
	}
	if req.RuntimeSandboxID != nil {
		if *req.RuntimeSandboxID == "" {
			writeV1Err(w, 400, "invalid_request", "runtime_sandbox_id must not be empty")
			return
		}
		s.deliverProviderGrant(w, r, app.ID, req.ConfigKey, req.Provider, *req.RuntimeSandboxID, time.Duration(req.TTLSeconds)*time.Second)
		return
	}
	g, err := s.ProviderAccess.Issue(r.Context(), tenantToken(r), app.ID, req.ConfigKey, req.Provider, time.Duration(req.TTLSeconds)*time.Second)
	if err != nil {
		if errors.Is(err, provideraccess.ErrDenied) {
			writeV1Err(w, 403, "provider_denied", "credential must explicitly permit runtime access")
		} else {
			writeV1Err(w, 503, "provider_unavailable", "cannot issue provider grant")
		}
		return
	}
	// Path is deliberately relative to the separately configured workload proxy,
	// not the management API or a caller-supplied provider URL.
	writeJSON(w, http.StatusCreated, map[string]any{"id": g.ID, "token": g.Token, "expires_at": g.ExpiresAt, "provider": req.Provider, "base_path": "/apps/" + app.ID + "/anthropic"})
}

// This optional mode keeps delegated tokens out of the public response and
// project files. It deliberately does not wake workloads or start model calls.
func (s *Server) deliverProviderGrant(w http.ResponseWriter, r *http.Request, appID, configKey, provider, sandboxID string, ttl time.Duration) {
	if s.Locks == nil || s.Loopback == nil || s.AgentProxyURL == "" {
		writeV1Err(w, 503, "provider_unavailable", "runtime provider delivery is unavailable")
		return
	}
	current, err := s.Store.CurrentSandboxForApp(r.Context(), appID)
	if err != nil || current.ID != sandboxID {
		writeV1Err(w, 409, "runtime_changed", "open the app's current runtime before connecting a provider")
		return
	}
	if !s.Locks.TryLock(sandboxID) {
		writeV1Err(w, 409, "runtime_busy", "runtime lifecycle operation in progress; retry")
		return
	}
	defer s.Locks.Unlock(sandboxID)
	current, err = s.Store.CurrentSandboxForApp(r.Context(), appID)
	if err != nil || current.ID != sandboxID || current.Status != "running" {
		writeV1Err(w, 409, "runtime_changed", "open the app's current runtime before connecting a provider")
		return
	}
	client := s.runtimeClientFor(sandboxID)
	status, err := client.Status(r.Context())
	if err != nil || !status.ScopedProviderConnection || status.Runtimed.BootedAt.IsZero() {
		writeV1Err(w, 503, "runtime_incompatible", "runtime does not support private provider delivery")
		return
	}
	g, err := s.ProviderAccess.IssueRuntime(r.Context(), tenantToken(r), appID, configKey, provider, sandboxID, ttl)
	if err != nil {
		if errors.Is(err, provideraccess.ErrDenied) {
			writeV1Err(w, 403, "provider_denied", "credential must explicitly permit runtime access")
		} else {
			writeV1Err(w, 503, "provider_unavailable", "cannot issue provider grant")
		}
		return
	}
	p := runtime.ProviderConnection{ID: g.ID, Token: g.Token, ExpiresAt: g.ExpiresAt,
		BootedAt: status.Runtimed.BootedAt, BaseURL: strings.TrimRight(s.AgentProxyURL, "/") + "/apps/" + appID + "/anthropic"}
	if err := client.DeliverProviderConnection(r.Context(), p); err != nil {
		// A cancelled management request must not skip revocation. The runtime
		// may have accepted a delivery whose response was lost. Never echo it.
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := s.ProviderAccess.Revoke(ctx, tenantToken(r), appID, g.ID); err != nil {
			writeV1Err(w, 503, "provider_revoke_pending", "delivery failed and revocation could not be confirmed; revoke runtime access in app settings")
			return
		}
		writeV1Err(w, 503, "provider_delivery_failed", "provider delivery could not be confirmed; retry to reconnect")
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"id": g.ID, "expires_at": g.ExpiresAt,
		"provider": provider, "runtime_sandbox_id": sandboxID, "delivered": true})
}

func (s *Server) v1DeleteProviderGrant(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	app, ok := s.appForConfig(w, r)
	if !ok {
		return
	}
	if s.ProviderAccess == nil {
		writeV1Err(w, 503, "provider_unavailable", "scoped provider access is not enabled")
		return
	}
	if err := s.ProviderAccess.Revoke(r.Context(), tenantToken(r), app.ID, r.PathValue("grantId")); err != nil {
		writeV1Err(w, 500, "internal", "could not revoke provider grant")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
