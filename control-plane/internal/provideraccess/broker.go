// Package provideraccess provides an in-process, app-scoped API-key broker.
// It starts no listener and has no Electron dependency. sandboxd's opt-in
// scoped mode wires it beside a grant-enforcing CLI proxy, never a legacy proxy.
package provideraccess

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"io"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"

	"github.com/tastyeffectco/sandboxd/control-plane/internal/secrets"
	"github.com/tastyeffectco/sandboxd/control-plane/internal/store"
)

const maxBody = 8 << 20

var ErrDenied = errors.New("provider access denied")

type Broker struct {
	store     *store.Store
	cipher    *secrets.Cipher
	now       func() time.Time
	transport http.RoundTripper
	active    chan struct{}
}

func New(s *store.Store, c *secrets.Cipher) (*Broker, error) {
	if s == nil || c == nil {
		return nil, errors.New("provider broker requires store and cipher")
	}
	// No environment-derived HTTP proxy: only the fixed HTTPS provider gets keys.
	t := http.DefaultTransport.(*http.Transport).Clone()
	t.Proxy = nil
	t.ResponseHeaderTimeout = 60 * time.Second
	return &Broker{store: s, cipher: c, now: time.Now, transport: t, active: make(chan struct{}, 16)}, nil
}

// Grant is returned once to the trusted caller. Token is a bearer capability,
// not process identity: anybody possessing it can use this app's grant until
// expiration/revocation. Do not return it in list APIs, logs or preview URLs.
type Grant struct {
	ID        string    `json:"id"`
	Token     string    `json:"token"`
	ExpiresAt time.Time `json:"expires_at"`
}

// Issue requires explicit runtime_access/both on an encrypted app config key.
// owner must be the authenticated actor. This does not grant access to global
// provider connections, OAuth credentials, or a Claude subscription.
func (b *Broker) Issue(ctx context.Context, owner, appID, configKey, provider string, ttl time.Duration) (Grant, error) {
	if owner == "" || !identifier(appID) || configKey == "" || provider != "anthropic" || ttl < time.Minute || ttl > 24*time.Hour {
		return Grant{}, ErrDenied
	}
	var entropy [48]byte
	if _, err := rand.Read(entropy[:]); err != nil {
		return Grant{}, errors.New("cannot create provider grant")
	}
	now := b.now().UTC().Truncate(time.Second)
	g := Grant{ID: base64.RawURLEncoding.EncodeToString(entropy[:16]), Token: base64.RawURLEncoding.EncodeToString(entropy[16:]), ExpiresAt: now.Add(ttl).Truncate(time.Second)}
	hash := sha256.Sum256([]byte(g.Token))
	err := b.store.CreateProviderGrant(ctx, store.ProviderGrant{ID: g.ID, AppID: appID, OwnerToken: owner, Provider: provider, TokenHash: hash[:], CreatedAt: now, ExpiresAt: g.ExpiresAt}, configKey)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return Grant{}, ErrDenied
		}
		return Grant{}, errors.New("cannot persist provider grant")
	}
	return g, nil
}

func (b *Broker) Revoke(ctx context.Context, owner, appID, id string) error {
	return b.store.RevokeProviderGrant(ctx, owner, appID, id)
}

func identifier(s string) bool {
	if len(s) == 0 || len(s) > 128 {
		return false
	}
	for _, c := range s {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
			return false
		}
	}
	return true
}

func token(r *http.Request) string {
	a, x := r.Header.Values("Authorization"), r.Header.Values("X-Api-Key")
	var value string
	switch {
	case len(a) == 1 && len(x) == 0 && strings.HasPrefix(a[0], "Bearer "):
		value = strings.TrimPrefix(a[0], "Bearer ")
	case len(x) == 1 && len(a) == 0:
		value = x[0]
	}
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil || len(decoded) != 32 || base64.RawURLEncoding.EncodeToString(decoded) != value {
		return ""
	}
	return value
}

func deny(w http.ResponseWriter, status int) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	_, _ = io.WriteString(w, `{"error":"provider request unavailable"}`)
}

// ServeHTTP exposes only /apps/{id}/anthropic/v1/{messages,messages/count_tokens,models}.
// No catch-all provider URL, redirects, cookies, CORS, OAuth or legacy fallback.
// Revocation affects new requests; an already authorized stream may finish.
func (b *Broker) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	p := strings.Split(r.URL.Path, "/")
	if r.URL.RawPath != "" || r.URL.RawQuery != "" || r.URL.ForceQuery || len(p) < 6 || p[0] != "" || p[1] != "apps" || !identifier(p[2]) || p[3] != "anthropic" {
		deny(w, http.StatusNotFound)
		return
	}
	path := "/" + strings.Join(p[4:], "/")
	if !((r.Method == http.MethodPost && (path == "/v1/messages" || path == "/v1/messages/count_tokens")) || (r.Method == http.MethodGet && path == "/v1/models")) {
		deny(w, http.StatusNotFound)
		return
	}
	tok := token(r)
	if tok == "" {
		deny(w, http.StatusUnauthorized)
		return
	}
	hash := sha256.Sum256([]byte(tok))
	ciphertext, nonce, err := b.store.ProviderGrantSecret(r.Context(), p[2], "anthropic", hash[:], b.now())
	if err != nil {
		deny(w, http.StatusUnauthorized)
		return
	}
	// Bound concurrent authorized bodies and streams. This is a broker safety
	// limit, not a per-app spending budget or provider billing guarantee.
	select {
	case b.active <- struct{}{}:
		defer func() { <-b.active }()
	default:
		deny(w, http.StatusTooManyRequests)
		return
	}
	key, err := b.cipher.Open(ciphertext, nonce)
	if err != nil || len(key) == 0 || len(key) > 8192 || strings.ContainsAny(string(key), "\r\n") {
		deny(w, http.StatusServiceUnavailable)
		return
	}
	// Read the bounded request before contacting the provider. Do not forward
	// partial oversized bodies that could incur cost before rejection.
	r.Body = http.MaxBytesReader(w, r.Body, maxBody)
	body, err := io.ReadAll(r.Body)
	if err != nil {
		deny(w, http.StatusRequestEntityTooLarge)
		return
	}
	if r.Method == http.MethodGet && len(body) != 0 {
		deny(w, http.StatusBadRequest)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Minute)
	defer cancel()
	r = r.WithContext(ctx)
	r.Body = io.NopCloser(strings.NewReader(string(body)))
	r.ContentLength = int64(len(body))
	proxy := &httputil.ReverseProxy{
		Transport:     b.transport,
		FlushInterval: -1,
		ErrorLog:      log.New(io.Discard, "", 0), // transport errors can contain request details
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.Out.URL = &url.URL{Scheme: "https", Host: "api.anthropic.com", Path: path}
			pr.Out.Host = "api.anthropic.com"
			pr.Out.Header = http.Header{
				"Content-Type":      {"application/json"},
				"Accept":            {"application/json, text/event-stream"},
				"Accept-Encoding":   {"identity"},
				"Anthropic-Version": {"2023-06-01"},
				"X-Api-Key":         {string(key)},
				"User-Agent":        {"sandboxd-provider-broker"},
			}
			pr.Out.Trailer = nil
		},
		ModifyResponse: func(resp *http.Response) error {
			if resp.StatusCode < 200 || resp.StatusCode >= 300 {
				// Providers can reflect credentials in error text or redirect headers.
				return errors.New("provider rejected request")
			}
			contentType := resp.Header.Get("Content-Type")
			encoding := resp.Header.Get("Content-Encoding")
			resp.Header = http.Header{"Content-Type": {contentType}, "Cache-Control": {"no-store"}, "X-Content-Type-Options": {"nosniff"}}
			if encoding != "" {
				resp.Header.Set("Content-Encoding", encoding)
			}
			resp.Trailer = nil
			return nil
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) { deny(w, http.StatusBadGateway) },
	}
	proxy.ServeHTTP(w, r)
}
