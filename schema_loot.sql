-- Table audit_loot : fichiers exfiltrés par le module Loot (--loot opt-in)
CREATE TABLE IF NOT EXISTS audit_loot (
    id BIGSERIAL PRIMARY KEY,
    scan_id BIGINT REFERENCES audit_scans(id) ON DELETE CASCADE,
    url TEXT NOT NULL,
    local_path TEXT NOT NULL,
    size_bytes BIGINT NOT NULL,
    sha256 VARCHAR(64) NOT NULL,
    content_type TEXT,
    status_code SMALLINT NOT NULL,
    severity VARCHAR(16) NOT NULL,
    category VARCHAR(32) NOT NULL,
    timestamp TIMESTAMPTZ NOT NULL,
    first_64_bytes_hex TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_audit_loot_scan_id ON audit_loot(scan_id);
CREATE INDEX IF NOT EXISTS idx_audit_loot_severity ON audit_loot(severity);
CREATE INDEX IF NOT EXISTS idx_audit_loot_sha256 ON audit_loot(sha256);
