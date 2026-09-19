CREATE TABLE IF NOT EXISTS audit_scans (
    id BIGSERIAL PRIMARY KEY,
    target VARCHAR(255) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    overall_score SMALLINT NOT NULL,
    open_ports INT[] DEFAULT '{}',
    tls_valid BOOLEAN DEFAULT TRUE,
    spf_ok BOOLEAN DEFAULT FALSE,
    dmarc_ok BOOLEAN DEFAULT FALSE,
    http_status INT DEFAULT 0,
    payload JSONB NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_audit_scans_target_created ON audit_scans(target, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_scans_payload_gin ON audit_scans USING GIN (payload);
