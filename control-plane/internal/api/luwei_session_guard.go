package api

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/tastyeffectco/sandboxd/control-plane/internal/auth"
)

type luweiSessionContextKey struct{}

func verifiedLuweiSession(ctx context.Context) string {
	id, _ := ctx.Value(luweiSessionContextKey{}).(string)
	return id
}

// LuweiSessionGuard isolates sandbox resource requests after service-token auth.
// Enable only after upstream create calls supply an authorized persistent session binding.
func (s *Server) LuweiSessionGuard(secret string, next http.Handler) http.Handler {
	replay := &auth.LuweiReplayGuard{}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/healthz" || r.URL.Path == "/readyz" || r.URL.Path == "/version" {
			next.ServeHTTP(w, r)
			return
		}
		if secret == "" {
			http.Error(w, "session security not configured", http.StatusServiceUnavailable)
			return
		}
		if r.Method == "POST" && r.URL.Path == "/sandbox" {
			session, err := auth.VerifyLuweiSessionSignature(r, secret, time.Now())
			if err != nil {
				http.Error(w, "invalid session", http.StatusUnauthorized)
				return
			}
			if !replay.Accept(r.Header.Get("X-Luwei-Session-Signature"), time.Now()) {
				http.Error(w, "replay", http.StatusConflict)
				return
			}
			next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), luweiSessionContextKey{}, session)))
			return
		}
		path := r.URL.Path
		if strings.HasPrefix(path, "/v1/sandboxes/") {
			path = "/sandbox/" + strings.TrimPrefix(path, "/v1/sandboxes/")
		}
		if !strings.HasPrefix(path, "/sandbox/") {
			http.Error(w, "route not allowed in session enforcement mode", http.StatusForbidden)
			return
		}
		remainder := strings.TrimPrefix(path, "/sandbox/")
		id := strings.SplitN(remainder, "/", 2)[0]
		if id == "" {
			http.Error(w, "invalid sandbox", http.StatusForbidden)
			return
		}
		session, err := auth.VerifyLuweiSessionSignature(r, secret, time.Now())
		if err != nil {
			http.Error(w, "invalid session", http.StatusUnauthorized)
			return
		}
		binding, err := s.Store.GetLuweiSessionBinding(r.Context(), id)
		if err != nil || auth.AuthorizeLuweiSandbox(session, binding.SessionID) != nil {
			http.Error(w, "session unauthorized for sandbox", http.StatusForbidden)
			return
		}
		if !replay.Accept(r.Header.Get("X-Luwei-Session-Signature"), time.Now()) {
			http.Error(w, "replayed session request", http.StatusConflict)
			return
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), luweiSessionContextKey{}, session)))
	})
}
