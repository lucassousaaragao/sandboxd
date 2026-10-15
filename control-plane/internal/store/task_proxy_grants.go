package store

import (
	"context"
	"database/sql"
	"time"
)

// TaskProxyGrant authorizes one task's use of an existing global CLI connection.
// The HTTP caller never supplies it: the authenticated task controller does.
type TaskProxyGrant struct {
	TaskID, SandboxID, AppID, OwnerToken, Agent, Upstream string
	TokenHash                                             []byte
	ExpiresAt                                             time.Time
}

func (s *Store) CreateTaskProxyGrant(ctx context.Context, g TaskProxyGrant) error {
	return s.submit(ctx, func(db *sql.DB) error {
		res, err := db.ExecContext(ctx, `INSERT INTO task_proxy_grant
		(task_id,sandbox_id,app_id,owner_token,agent,upstream,token_hash,expires_at)
		SELECT ?, sb.id, a.id, a.owner_token, ?, ?, ?, ? FROM sandbox sb
		JOIN app a ON a.id=sb.app_id WHERE sb.id=? AND a.id=? AND a.owner_token=? AND sb.status='running'`,
			g.TaskID, g.Agent, g.Upstream, g.TokenHash, g.ExpiresAt.Unix(), g.SandboxID, g.AppID, g.OwnerToken)
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

func (s *Store) CheckTaskProxyGrant(ctx context.Context, agent, upstream string, hash []byte, now time.Time) bool {
	var found int
	err := s.db.QueryRowContext(ctx, `SELECT 1 FROM task_proxy_grant g
	JOIN sandbox sb ON sb.id=g.sandbox_id AND sb.app_id=g.app_id AND sb.status='running'
	JOIN app a ON a.id=g.app_id AND a.owner_token=g.owner_token
	WHERE g.agent=? AND g.upstream=? AND g.token_hash=? AND g.expires_at>?`, agent, upstream, hash, now.Unix()).Scan(&found)
	return err == nil && found == 1
}

func (s *Store) RevokeTaskProxyGrant(ctx context.Context, taskID string) error {
	return s.submit(ctx, func(db *sql.DB) error {
		_, err := db.ExecContext(ctx, `DELETE FROM task_proxy_grant WHERE task_id=?`, taskID)
		return err
	})
}
