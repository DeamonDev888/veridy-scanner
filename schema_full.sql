-- Migration du schéma vers un modèle de catalogage complet
BEGIN;

-- 1. Table principale de scan
CREATE TABLE IF NOT EXISTS audit_scans (
    id BIGSERIAL PRIMARY KEY,
    target VARCHAR(255) NOT NULL -- rétro-compat : longueur max cible raisonnable (un nom de domaine + sous-domaines),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    overall_score SMALLINT NOT NULL,
    duration_seconds REAL DEFAULT 0.0,
    open_ports_count INT DEFAULT 0,
    findings_count INT DEFAULT 0,
    payload JSONB NOT NULL
);

-- 2. Catalogage DNS (A, AAAA, MX, NS, TXT, CAA, DNSSEC, SPF, DMARC)
CREATE TABLE IF NOT EXISTS audit_dns_records (
    id BIGSERIAL PRIMARY KEY,
    scan_id BIGINT REFERENCES audit_scans(id) ON DELETE CASCADE,
    record_type VARCHAR(16) NOT NULL,
    record_value TEXT NOT NULL,
    is_secure BOOLEAN DEFAULT TRUE
);

-- 3. Catalogage des Ports & Services
CREATE TABLE IF NOT EXISTS audit_ports (
    id BIGSERIAL PRIMARY KEY,
    scan_id BIGINT REFERENCES audit_scans(id) ON DELETE CASCADE,
    port INT NOT NULL,
    protocol VARCHAR(8) DEFAULT 'TCP',
    service VARCHAR(64) NOT NULL,
    state VARCHAR(16) DEFAULT 'OPEN',
    banner TEXT
);

-- 4. Catalogage des En-têtes HTTP
CREATE TABLE IF NOT EXISTS audit_http_headers (
    id BIGSERIAL PRIMARY KEY,
    scan_id BIGINT REFERENCES audit_scans(id) ON DELETE CASCADE,
    header_name VARCHAR(128) NOT NULL,
    header_value TEXT,
    evaluation VARCHAR(32) NOT NULL -- PASS, MISSING, WARNING, INFO
);

-- 5. Catalogage TLS & Certificats
CREATE TABLE IF NOT EXISTS audit_tls_certs (
    id BIGSERIAL PRIMARY KEY,
    scan_id BIGINT REFERENCES audit_scans(id) ON DELETE CASCADE,
    protocol VARCHAR(32),
    cipher VARCHAR(128),
    issuer TEXT,
    subject TEXT,
    valid_until TIMESTAMPTZ,
    days_remaining INT,
    sans TEXT[],
    is_valid BOOLEAN DEFAULT TRUE,
    supports_tls10 BOOLEAN DEFAULT FALSE,
    supports_tls11 BOOLEAN DEFAULT FALSE,
    supports_tls12 BOOLEAN DEFAULT TRUE,
    supports_tls13 BOOLEAN DEFAULT TRUE
);

-- 6. Catalogage des Sous-domaines
CREATE TABLE IF NOT EXISTS audit_subdomains (
    id BIGSERIAL PRIMARY KEY,
    scan_id BIGINT REFERENCES audit_scans(id) ON DELETE CASCADE,
    subdomain TEXT NOT NULL,
    ip_address VARCHAR(45),
    http_status INT,
    is_alive BOOLEAN DEFAULT FALSE
);

-- 7. Catalogage des Constatations & Recommandations (Findings)
CREATE TABLE IF NOT EXISTS audit_findings (
    id BIGSERIAL PRIMARY KEY,
    scan_id BIGINT REFERENCES audit_scans(id) ON DELETE CASCADE,
    severity VARCHAR(16) NOT NULL, -- CRITICAL, HIGH, MEDIUM, LOW, INFO
    category VARCHAR(32) NOT NULL, -- DNS, PORT, HTTP, TLS, COOKIE
    title TEXT NOT NULL,
    recommendation TEXT NOT NULL
);

-- Index pour requêtes instantanées
CREATE INDEX IF NOT EXISTS idx_audit_scans_target_created ON audit_scans(target, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_dns_scan_id ON audit_dns_records(scan_id);
CREATE INDEX IF NOT EXISTS idx_audit_ports_scan_id ON audit_ports(scan_id);
CREATE INDEX IF NOT EXISTS idx_audit_http_scan_id ON audit_http_headers(scan_id);
CREATE INDEX IF NOT EXISTS idx_audit_tls_scan_id ON audit_tls_certs(scan_id);
CREATE INDEX IF NOT EXISTS idx_audit_subdomains_scan_id ON audit_subdomains(scan_id);
CREATE INDEX IF NOT EXISTS idx_audit_findings_scan_id ON audit_findings(scan_id);

COMMIT;
