package runtime

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

// ProviderConnection is private Unix-socket data, never public status metadata.
// The token is delegated, not a provider API key. runtimed retains it only in
// memory; an installed-agent launcher reads it locally and must not persist it
// into project files, logs or preview URLs.
type ProviderConnection struct {
	ID        string    `json:"id"`
	BaseURL   string    `json:"base_url"`
	Token     string    `json:"token"`
	ExpiresAt time.Time `json:"expires_at"`
	BootedAt  time.Time `json:"booted_at"`
}

// ProviderConnectionStatus omits tokens, hashes and provider URLs. It is only
// served over the private supervisor socket, not the ordinary status response.
type ProviderConnectionStatus struct {
	ID        string    `json:"id"`
	ExpiresAt time.Time `json:"expires_at"`
	BootedAt  time.Time `json:"booted_at"`
}

type ProviderConnectionRenewal struct {
	ProviderConnectionStatus
	PreviousExpiresAt time.Time `json:"previous_expires_at"`
}

func (c *Client) ProviderConnectionStatus(ctx context.Context) (ProviderConnectionStatus, error) {
	resp, err := c.do(ctx, c.http, http.MethodGet, "http://runtimed/provider-connection/status", nil)
	if err != nil {
		return ProviderConnectionStatus{}, errors.New("provider connection status unavailable")
	}
	defer resp.Body.Close()
	var status ProviderConnectionStatus
	if resp.StatusCode != http.StatusOK || json.NewDecoder(io.LimitReader(resp.Body, 4096)).Decode(&status) != nil {
		return ProviderConnectionStatus{}, errors.New("provider connection status unavailable")
	}
	return status, nil
}

func (c *Client) RenewProviderConnection(ctx context.Context, p ProviderConnectionRenewal) error {
	body, err := json.Marshal(p)
	if err != nil {
		return errors.New("invalid provider renewal")
	}
	resp, err := c.do(ctx, c.http, http.MethodPost, "http://runtimed/provider-connection/renew", body)
	if err != nil {
		return errors.New("provider renewal unavailable")
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		return errors.New("provider renewal rejected")
	}
	return nil
}

var providerPath = regexp.MustCompile(`^/apps/[A-Za-z0-9_-]{1,128}/anthropic$`)

// Valid binds a delivery to this supervisor boot and its operator-configured
// proxy. A workload cannot redirect the credential to an arbitrary provider.
func (p ProviderConnection) Valid(proxy string, boot, now time.Time) bool {
	u, err := url.Parse(p.BaseURL)
	if err != nil || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.RawPath != "" || !providerPath.MatchString(u.Path) {
		return false
	}
	base := strings.TrimRight(proxy, "/")
	if base == "" || p.BaseURL != base+u.Path || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" {
		return false
	}
	token, err := base64.RawURLEncoding.DecodeString(p.Token)
	if err != nil || len(token) != 32 || base64.RawURLEncoding.EncodeToString(token) != p.Token {
		return false
	}
	id, err := base64.RawURLEncoding.DecodeString(p.ID)
	return err == nil && len(id) == 16 && base64.RawURLEncoding.EncodeToString(id) == p.ID &&
		!boot.IsZero() && p.BootedAt.Equal(boot) && p.ExpiresAt.After(now) && !p.ExpiresAt.After(now.Add(24*time.Hour))
}

func (c *Client) DeliverProviderConnection(ctx context.Context, p ProviderConnection) error {
	body, err := json.Marshal(p)
	if err != nil {
		return errors.New("invalid provider connection")
	}
	resp, err := c.do(ctx, c.http, http.MethodPut, "http://runtimed/provider-connection", body)
	if err != nil {
		return errors.New("provider delivery unavailable")
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		return errors.New("provider delivery rejected")
	}
	return nil
}
