package store

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

// ProviderGrant contains no bearer token or plaintext credential. OwnerToken
// must come from the authenticated control-plane actor, never a workload.
type ProviderGrant struct {
	ID, AppID, OwnerToken, Provider string
	TokenHash                       []byte
	CreatedAt, ExpiresAt            time.Time
}

// CreateProviderGrant atomically checks current ownership and runtime consent.
// Config changes revoke grants in the same transaction (migration 0028).
func (s *Store) CreateProviderGrant(ctx context.Context, g ProviderGrant, configKey string) error {
	return s.submit(ctx, func(db *sql.DB) error {
		res, err := db.ExecContext(ctx, `INSERT INTO provider_grant
			(id, app_id, config_id, owner_token, provider, token_hash, created_at, expires_at)
			SELECT ?, a.id, c.id, a.owner_token, ?, ?, ?, ?
			FROM app a JOIN app_config c ON c.app_id = a.id
			WHERE a.id = ? AND a.owner_token = ? AND c.key = ?
			AND c.sensitive = 1 AND c.value_plaintext IS NULL
			AND length(c.value_ciphertext) > 0 AND length(c.value_nonce) > 0
			AND c.access_policy IN ('runtime_access', 'both')`,
			g.ID, g.Provider, g.TokenHash, g.CreatedAt.Unix(), g.ExpiresAt.Unix(),
			g.AppID, g.OwnerToken, configKey)
		if err != nil {
			return err
		}
		n, err := res.RowsAffected()
		if err == nil && n == 0 {
			return ErrNotFound
		}
		return err
	})
}

// ProviderGrantSecret returns encrypted material only when the grant, app and
// current config all match. Expiration is checked on every request. The caller
// must hash the presented token and decrypt outside the persistence layer.
func (s *Store) ProviderGrantSecret(ctx context.Context, appID, provider string, hash []byte, now time.Time) (ciphertext, nonce []byte, err error) {
	err = s.db.QueryRowContext(ctx, `SELECT c.value_ciphertext, c.value_nonce
		FROM provider_grant g JOIN app a ON a.id = g.app_id AND a.owner_token = g.owner_token
		JOIN app_config c ON c.id = g.config_id AND c.app_id = a.id
		WHERE g.app_id = ? AND g.provider = ? AND g.token_hash = ? AND g.expires_at > ?
		AND c.sensitive = 1 AND c.value_plaintext IS NULL
		AND c.access_policy IN ('runtime_access', 'both')`, appID, provider, hash, now.Unix()).Scan(&ciphertext, &nonce)
	if errors.Is(err, sql.ErrNoRows) {
		err = ErrNotFound
	}
	return
}

// RevokeProviderGrant is tenant-scoped and idempotent, including unknown IDs.
func (s *Store) RevokeProviderGrant(ctx context.Context, owner, appID, id string) error {
	return s.submit(ctx, func(db *sql.DB) error {
		_, err := db.ExecContext(ctx, `DELETE FROM provider_grant
			WHERE id = ? AND app_id = ? AND owner_token = ?`, id, appID, owner)
		return err
	})
}
