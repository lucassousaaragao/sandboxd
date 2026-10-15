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
	RuntimeSandboxID                string // optional; one delivered connection per sandbox
	TokenHash                       []byte
	CreatedAt, ExpiresAt            time.Time
}

// RuntimeProviderGrant is non-secret connection metadata. It excludes both the
// bearer token and its hash and rechecks current ownership, binding and consent.
func (s *Store) RuntimeProviderGrant(ctx context.Context, owner, appID, sandboxID string, now time.Time) (id string, expiry time.Time, err error) {
	var unix int64
	err = s.db.QueryRowContext(ctx, `SELECT g.id, g.expires_at FROM provider_grant g
		JOIN app a ON a.id = g.app_id AND a.owner_token = g.owner_token
		JOIN app_config c ON c.id = g.config_id AND c.app_id = a.id
		JOIN sandbox s ON s.id = g.runtime_sandbox_id AND s.app_id = a.id
		WHERE g.owner_token = ? AND g.app_id = ? AND g.runtime_sandbox_id = ?
		AND g.provider = 'anthropic' AND g.expires_at > ? AND s.status = 'running'
		AND c.sensitive = 1 AND c.value_plaintext IS NULL
		AND length(c.value_ciphertext) > 0 AND length(c.value_nonce) > 0
		AND c.access_policy IN ('runtime_access', 'both')`, owner, appID, sandboxID, now.Unix()).Scan(&id, &unix)
	if errors.Is(err, sql.ErrNoRows) {
		err = ErrNotFound
	}
	if err == nil {
		expiry = time.Unix(unix, 0).UTC()
	}
	return
}

// RenewRuntimeProviderGrant extends only an existing, still-authorized lease.
// Compare-and-swap prevents renewal from reviving an expired/replaced grant.
// Existing atomic config/lifecycle revocation triggers remain authoritative.
func (s *Store) RenewRuntimeProviderGrant(ctx context.Context, owner, appID, sandboxID, id string, previous, expiry, now time.Time) error {
	return s.submit(ctx, func(db *sql.DB) error {
		res, err := db.ExecContext(ctx, `UPDATE provider_grant SET expires_at = ?
			WHERE id = ? AND owner_token = ? AND app_id = ? AND runtime_sandbox_id = ?
			AND provider = 'anthropic' AND expires_at = ? AND expires_at > ?
			AND EXISTS (SELECT 1 FROM app a JOIN app_config c ON c.app_id = a.id
			  JOIN sandbox s ON s.app_id = a.id
			  WHERE a.id = provider_grant.app_id AND a.owner_token = provider_grant.owner_token
			  AND c.id = provider_grant.config_id AND c.sensitive = 1 AND c.value_plaintext IS NULL
			  AND length(c.value_ciphertext) > 0 AND length(c.value_nonce) > 0
			  AND c.access_policy IN ('runtime_access', 'both')
			  AND s.id = provider_grant.runtime_sandbox_id AND s.status = 'running')`,
			expiry.Unix(), id, owner, appID, sandboxID, previous.Unix(), now.Unix())
		if err != nil {
			return err
		}
		n, err := res.RowsAffected()
		if err == nil && n != 1 {
			return ErrNotFound
		}
		return err
	})
}

// CreateProviderGrant atomically checks current ownership and runtime consent.
// Config changes revoke grants in the same transaction (migration 0028).
func (s *Store) CreateProviderGrant(ctx context.Context, g ProviderGrant, configKey string) error {
	return s.submit(ctx, func(db *sql.DB) error {
		tx, err := db.BeginTx(ctx, nil)
		if err != nil {
			return err
		}
		defer tx.Rollback()
		res, err := tx.ExecContext(ctx, `INSERT INTO provider_grant
			(id, app_id, config_id, owner_token, provider, token_hash, created_at, expires_at, runtime_sandbox_id)
			SELECT ?, a.id, c.id, a.owner_token, ?, ?, ?, ?, NULLIF(?, '')
			FROM app a JOIN app_config c ON c.app_id = a.id
			WHERE a.id = ? AND a.owner_token = ? AND c.key = ?
			AND c.sensitive = 1 AND c.value_plaintext IS NULL
			AND length(c.value_ciphertext) > 0 AND length(c.value_nonce) > 0
			AND c.access_policy IN ('runtime_access', 'both')
			AND (? = '' OR EXISTS (SELECT 1 FROM sandbox s
			  WHERE s.id = ? AND s.app_id = a.id AND s.status = 'running'))`,
			g.ID, g.Provider, g.TokenHash, g.CreatedAt.Unix(), g.ExpiresAt.Unix(), g.RuntimeSandboxID,
			g.AppID, g.OwnerToken, configKey, g.RuntimeSandboxID, g.RuntimeSandboxID)
		if err != nil {
			return err
		}
		n, err := res.RowsAffected()
		if err == nil && n == 0 {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		if g.RuntimeSandboxID != "" {
			// Renewal cannot accumulate live credentials. In-flight requests may
			// finish; every new request with an older token is denied immediately.
			if _, err = tx.ExecContext(ctx, `DELETE FROM provider_grant WHERE runtime_sandbox_id = ? AND id != ?`, g.RuntimeSandboxID, g.ID); err != nil {
				return err
			}
		}
		return tx.Commit()
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
		AND c.access_policy IN ('runtime_access', 'both')
		AND (g.runtime_sandbox_id IS NULL OR EXISTS (SELECT 1 FROM sandbox s
		 WHERE s.id = g.runtime_sandbox_id AND s.app_id = a.id AND s.status = 'running'))`, appID, provider, hash, now.Unix()).Scan(&ciphertext, &nonce)
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
