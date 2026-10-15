package api

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"time"

	"github.com/tastyeffectco/sandboxd/control-plane/internal/provideraccess"
)

// These endpoints belong on the authenticated control API, never on the
// workload proxy listener. Callers must deliver the returned capability to the
// runtime, not to a preview URL. Provider credentials themselves stay write-only.
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
		Provider   string `json:"provider"`
		ConfigKey  string `json:"config_key"`
		TTLSeconds int    `json:"ttl_seconds"`
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
