package api

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"time"

	"github.com/tastyeffectco/sandboxd/control-plane/internal/provideraccess"
	"github.com/tastyeffectco/sandboxd/control-plane/internal/runtime"
)

// Read/renew existing delivered access without disclosing any credential or
// starting a stopped sandbox. Current config read permission and app ownership
// are checked on every request; the broker rechecks consent atomically.
func (s *Server) v1RuntimeProviderConnection(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	app, ok := s.appForConfig(w, r)
	if !ok {
		return
	}
	if s.ProviderAccess == nil || s.Locks == nil || s.Loopback == nil || s.AgentProxyURL == "" {
		writeV1Err(w, 503, "provider_unavailable", "runtime provider renewal unavailable")
		return
	}
	var req struct {
		ID               string `json:"id"`
		RuntimeSandboxID string `json:"runtime_sandbox_id"`
		TTLSeconds       int    `json:"ttl_seconds"`
	}
	if r.Method == http.MethodPost {
		d := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096))
		d.DisallowUnknownFields()
		var extra any
		if d.Decode(&req) != nil || d.Decode(&extra) != io.EOF || req.ID == "" || len(req.ID) > 128 || req.RuntimeSandboxID == "" || req.TTLSeconds < 60 || req.TTLSeconds > 86400 {
			writeV1Err(w, 400, "invalid_request", "invalid provider renewal request")
			return
		}
	}
	current, err := s.Store.CurrentSandboxForApp(r.Context(), app.ID)
	if err != nil || current.Status != "running" || (r.Method == http.MethodPost && current.ID != req.RuntimeSandboxID) {
		writeV1Err(w, 409, "runtime_changed", "open the app's running runtime before renewing access")
		return
	}
	if !s.Locks.TryLock(current.ID) {
		writeV1Err(w, 409, "runtime_busy", "runtime lifecycle operation in progress; retry")
		return
	}
	defer s.Locks.Unlock(current.ID)
	bound, err := s.Store.CurrentSandboxForApp(r.Context(), app.ID)
	if err != nil || bound.ID != current.ID || bound.Status != "running" {
		writeV1Err(w, 409, "runtime_changed", "runtime binding changed")
		return
	}
	client := s.runtimeClientFor(current.ID)
	status, err := client.Status(r.Context())
	if err != nil || !status.ScopedProviderRenewal || status.Runtimed.BootedAt.IsZero() {
		writeV1Err(w, 503, "runtime_incompatible", "runtime does not support provider renewal")
		return
	}
	info, err := s.ProviderAccess.RuntimeConnection(r.Context(), tenantToken(r), app.ID, current.ID)
	if err != nil {
		if errors.Is(err, provideraccess.ErrDenied) {
			writeV1Err(w, 403, "provider_denied", "existing model access is unavailable; review permissions before reconnecting")
		} else {
			writeV1Err(w, 503, "provider_unavailable", "model connection unavailable")
		}
		return
	}
	p, err := client.ProviderConnectionStatus(r.Context())
	if err != nil || p.ID != info.ID || !p.ExpiresAt.Equal(info.ExpiresAt) || !p.BootedAt.Equal(status.Runtimed.BootedAt) {
		writeV1Err(w, 409, "provider_connection_changed", "private model connection changed; reconnect explicitly")
		return
	}
	if r.Method == http.MethodPost {
		if req.ID != info.ID {
			writeV1Err(w, 409, "provider_connection_changed", "model connection changed")
			return
		}
		next, err := s.ProviderAccess.RenewRuntime(r.Context(), tenantToken(r), app.ID, current.ID, info, time.Duration(req.TTLSeconds)*time.Second)
		if err != nil {
			if errors.Is(err, provideraccess.ErrDenied) {
				writeV1Err(w, 403, "provider_denied", "model access is no longer authorized")
			} else {
				writeV1Err(w, 503, "provider_unavailable", "model access renewal unavailable")
			}
			return
		}
		if err := client.RenewProviderConnection(r.Context(), runtime.ProviderConnectionRenewal{
			ProviderConnectionStatus: runtime.ProviderConnectionStatus{ID: info.ID, ExpiresAt: next.ExpiresAt, BootedAt: p.BootedAt}, PreviousExpiresAt: info.ExpiresAt,
		}); err != nil {
			// A lost/cancelled response may have changed the runtime. Revoke the
			// extended grant using an independent context; never retry silently.
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if s.ProviderAccess.Revoke(ctx, tenantToken(r), app.ID, info.ID) != nil {
				writeV1Err(w, 503, "provider_revoke_pending", "renewal failed and revocation could not be confirmed; disable runtime access")
				return
			}
			writeV1Err(w, 503, "provider_renewal_failed", "renewal could not be confirmed; reconnect explicitly")
			return
		}
		info = next
	}
	writeJSON(w, http.StatusOK, map[string]any{"id": info.ID, "expires_at": info.ExpiresAt,
		"runtime_sandbox_id": current.ID, "provider": "anthropic", "delivered": true})
}
