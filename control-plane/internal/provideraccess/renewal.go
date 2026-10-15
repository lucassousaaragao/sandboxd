package provideraccess

import (
	"context"
	"errors"
	"time"

	"github.com/tastyeffectco/sandboxd/control-plane/internal/store"
)

// ConnectionInfo is safe management metadata, never a bearer capability.
type ConnectionInfo struct {
	ID        string    `json:"id"`
	ExpiresAt time.Time `json:"expires_at"`
}

func (b *Broker) RuntimeConnection(ctx context.Context, owner, appID, sandboxID string) (ConnectionInfo, error) {
	if owner == "" || !identifier(appID) || !identifier(sandboxID) {
		return ConnectionInfo{}, ErrDenied
	}
	id, expiry, err := b.store.RuntimeProviderGrant(ctx, owner, appID, sandboxID, b.now())
	if errors.Is(err, store.ErrNotFound) {
		err = ErrDenied
	}
	return ConnectionInfo{ID: id, ExpiresAt: expiry}, err
}

// RenewRuntime preserves the token hash: a running agent need not reload its
// credentials or restart. Only the authenticated owner can extend this lease;
// workload tokens cannot renew themselves. Never resurrect expired access.
func (b *Broker) RenewRuntime(ctx context.Context, owner, appID, sandboxID string, expected ConnectionInfo, ttl time.Duration) (ConnectionInfo, error) {
	if owner == "" || !identifier(appID) || !identifier(sandboxID) || !identifier(expected.ID) || ttl < time.Minute || ttl > 24*time.Hour {
		return ConnectionInfo{}, ErrDenied
	}
	now := b.now().UTC().Truncate(time.Second)
	expiry := now.Add(ttl)
	// A retry/shorter request must not shorten the existing authorization.
	if expiry.Before(expected.ExpiresAt) {
		expiry = expected.ExpiresAt
	}
	if !expected.ExpiresAt.After(now) || expected.ExpiresAt.After(now.Add(24*time.Hour)) {
		return ConnectionInfo{}, ErrDenied
	}
	err := b.store.RenewRuntimeProviderGrant(ctx, owner, appID, sandboxID, expected.ID, expected.ExpiresAt, expiry, now)
	if errors.Is(err, store.ErrNotFound) {
		err = ErrDenied
	}
	if err != nil {
		return ConnectionInfo{}, err
	}
	return ConnectionInfo{ID: expected.ID, ExpiresAt: expiry}, nil
}
