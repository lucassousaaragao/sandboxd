-- Coding-task capabilities are distinct from installed-app provider grants.
-- They authorize only one existing CLI/provider route, never grant issuance.
CREATE TABLE task_proxy_grant (
    task_id TEXT PRIMARY KEY,
    sandbox_id TEXT NOT NULL,
    app_id TEXT NOT NULL,
    owner_token TEXT NOT NULL,
    agent TEXT NOT NULL,
    upstream TEXT NOT NULL,
    token_hash BLOB NOT NULL UNIQUE CHECK(length(token_hash) = 32),
    expires_at INTEGER NOT NULL
);
CREATE INDEX task_proxy_grant_app ON task_proxy_grant(app_id);
CREATE INDEX task_proxy_grant_sandbox ON task_proxy_grant(sandbox_id);
CREATE TRIGGER task_proxy_grant_done AFTER UPDATE OF status ON task
WHEN NEW.status != 'running' BEGIN
    DELETE FROM task_proxy_grant WHERE task_id = NEW.task_id;
END;
CREATE TRIGGER task_proxy_grant_task_delete AFTER DELETE ON task BEGIN
    DELETE FROM task_proxy_grant WHERE task_id = OLD.task_id;
END;
CREATE TRIGGER task_proxy_grant_app_delete AFTER DELETE ON app BEGIN
    DELETE FROM task_proxy_grant WHERE app_id = OLD.id;
END;
CREATE TRIGGER task_proxy_grant_owner_update AFTER UPDATE OF owner_token ON app
WHEN NEW.owner_token != OLD.owner_token BEGIN
    DELETE FROM task_proxy_grant WHERE app_id = OLD.id;
END;
CREATE TRIGGER task_proxy_grant_sandbox_delete AFTER DELETE ON sandbox BEGIN
    DELETE FROM task_proxy_grant WHERE sandbox_id = OLD.id;
END;
CREATE TRIGGER task_proxy_grant_sandbox_stop AFTER UPDATE OF status, app_id ON sandbox
WHEN NEW.status != 'running' OR NEW.app_id IS NOT OLD.app_id BEGIN
    DELETE FROM task_proxy_grant WHERE sandbox_id = OLD.id;
END;
