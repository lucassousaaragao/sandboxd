-- Opaque runtime capabilities. Only SHA-256 token digests are persisted;
-- provider credentials remain encrypted in app_config.
CREATE TABLE provider_grant (
    id TEXT PRIMARY KEY,
    app_id TEXT NOT NULL,
    config_id TEXT NOT NULL,
    owner_token TEXT NOT NULL,
    provider TEXT NOT NULL CHECK (provider = 'anthropic'),
    token_hash BLOB NOT NULL UNIQUE CHECK (length(token_hash) = 32),
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL CHECK (expires_at > created_at)
);
CREATE INDEX idx_provider_grant_app ON provider_grant(app_id);
CREATE INDEX idx_provider_grant_config ON provider_grant(config_id);

-- Triggers make revocation atomic with existing config writes, including
-- permission changes followed immediately by restoration. No reliance on
-- second-resolution timestamps or on SQLite foreign_keys being enabled.
CREATE TRIGGER provider_grant_config_update AFTER UPDATE ON app_config BEGIN
    DELETE FROM provider_grant WHERE config_id = OLD.id;
END;
CREATE TRIGGER provider_grant_config_delete AFTER DELETE ON app_config BEGIN
    DELETE FROM provider_grant WHERE config_id = OLD.id;
END;
CREATE TRIGGER provider_grant_app_delete AFTER DELETE ON app BEGIN
    DELETE FROM provider_grant WHERE app_id = OLD.id;
END;
CREATE TRIGGER provider_grant_owner_update AFTER UPDATE OF owner_token ON app
WHEN NEW.owner_token != OLD.owner_token BEGIN
    DELETE FROM provider_grant WHERE app_id = OLD.id;
END;
