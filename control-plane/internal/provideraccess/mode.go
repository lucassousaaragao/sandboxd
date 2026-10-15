package provideraccess

import (
	"errors"
	"net/http"
	"net/url"
	"strings"
)

// ScopedMode is explicit and opt-in; an invalid configuration cannot silently
// start the legacy ungranted listener. It requires authenticated management.
func ScopedMode(mode string, authEnabled bool, proxyURL string) (bool, error) {
	switch mode {
	case "", "legacy":
		return false, nil
	case "scoped":
		u, err := url.Parse(proxyURL)
		if !authEnabled || err != nil || u.Hostname() == "" || (u.Scheme != "http" && u.Scheme != "https") || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
			return false, errors.New("scoped provider access requires authenticated API and a valid internal proxy URL")
		}
		return true, nil
	default:
		return false, errors.New("unknown provider access mode")
	}
}

// Gateway keeps management APIs off the workload listener. taskProxy must be
// the grant-enforcing authproxy.NewScoped handler, never authproxy.New.
func (b *Broker) Gateway(taskProxy http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/apps/") {
			b.ServeHTTP(w, r)
			return
		}
		if taskProxy == nil {
			deny(w, http.StatusUnauthorized)
			return
		}
		taskProxy.ServeHTTP(w, r)
	})
}
