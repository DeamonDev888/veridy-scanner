-- Table pour enregistrer les exécutions et résultats bruts des outils de sécurité externes
BEGIN;

CREATE TABLE IF NOT EXISTS audit_tool_outputs (
    id BIGSERIAL PRIMARY KEY,
    scan_id BIGINT REFERENCES audit_scans(id) ON DELETE CASCADE,
    tool_name VARCHAR(32) NOT NULL,
    status VARCHAR(16) NOT NULL,
    items_count INT DEFAULT 0,
    execution_time_seconds REAL DEFAULT 0.0,
    summary TEXT,
    raw_output TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_audit_tool_outputs_scan_id ON audit_tool_outputs(scan_id);
CREATE INDEX IF NOT EXISTS idx_audit_tool_outputs_tool_name ON audit_tool_outputs(tool_name);

COMMIT;
