package store

import (
 "context"
 "database/sql"
 "errors"
 "time"
)

var ErrLuweiBindingConflict = errors.New("luwei session binding conflict")

type LuweiSessionBinding struct {
 SandboxID string
 SessionID string
 UserID string
 ProjectID string
 WorkspaceID string
}

// BindLuweiSession records one immutable relationship. Legacy resources remain unbound.
// The caller must authenticate and authorize the upstream actor before calling this.
func (s *Store) BindLuweiSession(ctx context.Context, b LuweiSessionBinding) error {
 if b.SandboxID==""||b.SessionID==""||b.UserID==""||b.ProjectID==""||b.WorkspaceID=="" {return ErrLuweiBindingConflict}
 result,err:=s.db.ExecContext(ctx,`INSERT OR IGNORE INTO luwei_session_binding
 (sandbox_id,session_id,external_user_id,external_project_id,external_workspace_id,created_at)
 VALUES (?,?,?,?,?,?)`,b.SandboxID,b.SessionID,b.UserID,b.ProjectID,b.WorkspaceID,time.Now().Unix())
 if err!=nil{return err}
 n,err:=result.RowsAffected();if err!=nil{return err}
 if n==0 {
  existing,err:=s.GetLuweiSessionBinding(ctx,b.SandboxID)
  if err==nil && existing==b {return nil}
  return ErrLuweiBindingConflict
 }
 return nil
}

func (s *Store) GetLuweiSessionBinding(ctx context.Context, sandboxID string) (LuweiSessionBinding,error) {
 var b LuweiSessionBinding
 err:=s.db.QueryRowContext(ctx,`SELECT sandbox_id,session_id,external_user_id,external_project_id,external_workspace_id
 FROM luwei_session_binding WHERE sandbox_id=?`,sandboxID).Scan(&b.SandboxID,&b.SessionID,&b.UserID,&b.ProjectID,&b.WorkspaceID)
 if errors.Is(err,sql.ErrNoRows){return b,ErrNotFound}
 return b,err
}
