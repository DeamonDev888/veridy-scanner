-- Tables d'approfondissement sécurité
BEGIN;

-- 1. Table Géolocalisation et ASN
CREATE TABLE IF NOT EXISTS audit_geo_compliance (
    id BIGSERIAL PRIMARY KEY,
    scan_id BIGINT REFERENCES audit_scans(id) ON DELETE CASCADE,
    ip_address VARCHAR(45) NOT NULL,
    asn VARCHAR(32),
    org_name TEXT,
    country_code VARCHAR(8),
    region VARCHAR(64),
    city VARCHAR(64),
    is_canada BOOLEAN DEFAULT TRUE,
    is_quebec BOOLEAN DEFAULT FALSE
);

-- 2. Table Sécurité Avancée Email & Anti-Spoofing (MTA-STS, DKIM, BIMI, DMARC alignment)
CREATE TABLE IF NOT EXISTS audit_email_sec (
    id BIGSERIAL PRIMARY KEY,
    scan_id BIGINT REFERENCES audit_scans(id) ON DELETE CASCADE,
    spf_lookup_count INT DEFAULT 0,
    spf_lookup_valid BOOLEAN DEFAULT TRUE,
    dkim_selectors_tested INT DEFAULT 0,
    dkim_selectors_found TEXT[],
    mta_sts_present BOOLEAN DEFAULT FALSE,
    mta_sts_mode VARCHAR(16),
    smtp_tls_reporting BOOLEAN DEFAULT FALSE,
    bimi_present BOOLEAN DEFAULT FALSE,
    dmarc_sp_policy VARCHAR(16),
    dmarc_adkim VARCHAR(8),
    dmarc_aspf VARCHAR(8)
);

-- 3. Table Endpoints Web Sensibles & Méthodes HTTP
CREATE TABLE IF NOT EXISTS audit_web_endpoints (
    id BIGSERIAL PRIMARY KEY,
    scan_id BIGINT REFERENCES audit_scans(id) ON DELETE CASCADE,
    security_txt_present BOOLEAN DEFAULT FALSE,
    security_txt_url TEXT,
    robots_txt_present BOOLEAN DEFAULT FALSE,
    robots_disallowed_paths TEXT[],
    allowed_http_methods TEXT[],
    dangerous_methods_found BOOLEAN DEFAULT FALSE,
    http2_supported BOOLEAN DEFAULT FALSE,
    alpn_negotiated VARCHAR(32)
);

-- 4. Table Durcissement DNS (Open Resolver check)
CREATE TABLE IF NOT EXISTS audit_dns_hardening (
    id BIGSERIAL PRIMARY KEY,
    scan_id BIGINT REFERENCES audit_scans(id) ON DELETE CASCADE,
    is_open_resolver_risk BOOLEAN DEFAULT FALSE,
    recursion_denied BOOLEAN DEFAULT TRUE,
    zone_transfer_denied BOOLEAN DEFAULT TRUE
);

-- Index
CREATE INDEX IF NOT EXISTS idx_audit_geo_scan_id ON audit_geo_compliance(scan_id);
CREATE INDEX IF NOT EXISTS idx_audit_email_sec_scan_id ON audit_email_sec(scan_id);
CREATE INDEX IF NOT EXISTS idx_audit_web_endpoints_scan_id ON audit_web_endpoints(scan_id);
CREATE INDEX IF NOT EXISTS idx_audit_dns_hardening_scan_id ON audit_dns_hardening(scan_id);

COMMIT;
