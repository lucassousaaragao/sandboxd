-- A delivered grant belongs to one running sandbox. NULL retains the existing
-- explicitly issued app-grant semantics. Raw tokens are never persisted here.
ALTER TABLE provider_grant ADD COLUMN runtime_sandbox_id TEXT;
CREATE INDEX idx_provider_grant_runtime ON provider_grant(runtime_sandbox_id);
CREATE TRIGGER provider_grant_runtime_delete AFTER DELETE ON sandbox BEGIN
    DELETE FROM provider_grant WHERE runtime_sandbox_id = OLD.id;
END;
CREATE TRIGGER provider_grant_runtime_stop AFTER UPDATE OF status, app_id ON sandbox
WHEN NEW.status != 'running' OR NEW.app_id IS NOT OLD.app_id BEGIN
    DELETE FROM provider_grant WHERE runtime_sandbox_id = OLD.id;
END;
