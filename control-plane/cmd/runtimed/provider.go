package main

import (
	"encoding/json"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/tastyeffectco/sandboxd/control-plane/internal/runtime"
)

// Private same-sandbox RPC, on the existing Unix socket only. Like other
// runtimed operations this is reachable by that sandbox's UID; it is not a
// boundary between processes inside the same sandbox. Only the broker can
// authorize tokens. No management API credential or real provider key is sent.
func (a *app) handleProviderConnection(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if r.Method == http.MethodGet {
		a.providerMu.Lock()
		defer a.providerMu.Unlock()
		if a.provider == nil || !a.provider.ExpiresAt.After(time.Now()) {
			a.provider = nil
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "provider connection required"})
			return
		}
		writeJSON(w, http.StatusOK, a.provider)
		return
	}
	var p runtime.ProviderConnection
	d := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096))
	d.DisallowUnknownFields()
	err := d.Decode(&p)
	var extra any
	if err != nil || d.Decode(&extra) != io.EOF || !p.Valid(os.Getenv("RUNTIMED_ANTHROPIC_PROXY"), a.bootedAt, time.Now()) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid provider delivery"})
		return
	}
	a.providerMu.Lock()
	a.provider = &p
	a.providerMu.Unlock()
	w.WriteHeader(http.StatusNoContent)
}
