use crate::report::FullAuditReport;

pub struct DatabaseManager;

#[allow(dead_code)]
#[derive(Debug, Default)]
#[derive(serde::Serialize, serde::Deserialize)]
pub struct ScanHistoryEntry {
    pub id: i64,
    pub target: String,
    pub created_at: String,
    pub overall_score: i32,
    pub duration_seconds: f32,
    pub open_ports_count: i32,
    pub findings_count: i32,
}

impl DatabaseManager {
    /// Insère l'ensemble du scan et catalogue tous les artefacts dans les 12 tables relationnelles.
    pub fn save_scan(report: &FullAuditReport, db_name: &str) -> Result<i64, String> {
        let raw_json = report.to_json();
        let open_port_numbers: Vec<u16> = report.ports.iter().map(|p| p.port).collect();
        let open_ports_array = sql_int_array(&open_port_numbers);

        let mut script = String::new();

        // 1. Insertion dans audit_scans (auto-commit pour garantir l'attribution de l'ID)
        script.push_str(&format!(
            "INSERT INTO audit_scans (target, overall_score, open_ports, tls_valid, spf_ok, dmarc_ok, http_status, duration_seconds, open_ports_count, findings_count, payload) \
             VALUES ('{}', {}, {}, {}, {}, {}, {}, {:.2}, {}, {}, $JSON${}$JSON$::jsonb) \
             RETURNING id;\n",
            sql_esc(&report.target),
            report.overall_score,
            open_ports_array,
            report.tls.is_valid,
            report.dns.spf_found,
            report.dns.dmarc_found,
            report.http.http_status,
            report.duration_seconds,
            report.ports.len(),
            report.findings.len(),
            raw_json
        ));

        // 2. Exécution pour récupérer l'ID généré
        let output = crate::utils::run_tool_stdin(
            "psql",
            &["-d", db_name, "-v", "ON_ERROR_STOP=1", "-t", "-A", "-f", "-"],
            30,
            &script,
            &[
                ("PGCONNECT_TIMEOUT", "10"),
                ("PGOPTIONS", "-c statement_timeout=25000"),
            ],
        )
        .ok_or_else(|| "psql : timeout (30s) ou lancement impossible (scan_id)".to_string())?;

        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);

        if !output.status.success() {
            return Err(format!("Erreur SQL lors du scan_id : {}", stderr.trim()));
        }

        let scan_id = stdout
            .lines()
            .map(|l| l.trim())
            .find(|l| !l.is_empty() && l.chars().all(|c| c.is_ascii_digit()))
            .and_then(|l| l.parse::<i64>().ok())
            .ok_or_else(|| {
                format!(
                    "Impossible de lire scan_id. Stdout: '{}', Stderr: '{}'",
                    stdout.trim(),
                    stderr.trim()
                )
            })?;

        // 3. Insertion des sous-tables relationnelles
        let mut detail_sql = String::new();
        detail_sql.push_str("BEGIN;\n");

        // DNS Records
        for d in &report.dns.all_records {
            detail_sql.push_str(&format!(
                "INSERT INTO audit_dns_records (scan_id, record_type, record_value, is_secure) \
                 VALUES ({}, '{}', '{}', {});\n",
                scan_id,
                sql_esc(&d.record_type),
                sql_esc(&d.value),
                d.is_secure
            ));
        }

        // Ports
        for p in &report.ports {
            let banner_val = sql_esc(p.banner.as_deref().unwrap_or(""));
            detail_sql.push_str(&format!(
                "INSERT INTO audit_ports (scan_id, port, service, state, banner) \
                 VALUES ({}, {}, '{}', 'OPEN', '{}');\n",
                scan_id,
                p.port,
                sql_esc(p.service_hint),
                banner_val
            ));
        }

        // HTTP Headers
        for h in &report.http.all_headers {
            detail_sql.push_str(&format!(
                "INSERT INTO audit_http_headers (scan_id, header_name, header_value, evaluation) \
                 VALUES ({}, '{}', '{}', '{}');\n",
                scan_id,
                sql_esc(&h.name),
                sql_esc(&h.value),
                h.evaluation
            ));
        }

        // TLS Cert
        let sans_sql = sql_text_array(&report.tls.sans);
        let valid_until_sql = match &report.tls.valid_until {
            Some(v) => format!("'{}'::timestamptz", sql_esc(v)),
            None => "NULL".to_string(),
        };

        detail_sql.push_str(&format!(
            "INSERT INTO audit_tls_certs (scan_id, protocol, cipher, issuer, subject, valid_until, days_remaining, sans, is_valid, supports_tls10, supports_tls11, supports_tls12, supports_tls13) \
             VALUES ({}, '{}', '{}', '{}', '{}', {}, {}, {}, {}, {}, {}, {}, {});\n",
            scan_id,
            sql_esc(report.tls.protocol.as_deref().unwrap_or("")),
            sql_esc(report.tls.cipher.as_deref().unwrap_or("")),
            sql_esc(report.tls.issuer.as_deref().unwrap_or("")),
            sql_esc(report.tls.subject.as_deref().unwrap_or("")),
            valid_until_sql,
            report.tls.days_remaining.map(|d| d.to_string()).unwrap_or_else(|| "NULL".into()),
            sans_sql,
            report.tls.is_valid,
            report.tls.supports_tls10,
            report.tls.supports_tls11,
            report.tls.supports_tls12,
            report.tls.supports_tls13
        ));

        // Subdomains
        for s in &report.subdomains {
            let ip_sql = s.ip_address.as_deref().unwrap_or("");
            let http_sql = s
                .http_status
                .map(|h| h.to_string())
                .unwrap_or_else(|| "NULL".into());
            detail_sql.push_str(&format!(
                "INSERT INTO audit_subdomains (scan_id, subdomain, ip_address, http_status, is_alive) \
                 VALUES ({}, '{}', '{}', {}, {});\n",
                scan_id,
                sql_esc(&s.subdomain),
                ip_sql,
                http_sql,
                s.is_alive
            ));
        }

        // Findings
        for f in &report.findings {
            detail_sql.push_str(&format!(
                "INSERT INTO audit_findings (scan_id, severity, category, title, recommendation) \
                 VALUES ({}, '{}', '{}', '{}', '{}');\n",
                scan_id,
                f.severity,
                f.category,
                sql_esc(&f.title),
                sql_esc(&f.recommendation)
            ));
        }

        // Géolocalisation
        detail_sql.push_str(&format!(
            "INSERT INTO audit_geo_compliance (scan_id, ip_address, asn, org_name, country_code, region, city, is_canada, is_quebec) \
             VALUES ({}, '{}', '{}', '{}', '{}', '{}', '{}', {}, {});\n",
            scan_id,
            sql_esc(&report.geo.ip_address),
            sql_esc(report.geo.asn.as_deref().unwrap_or("")),
            sql_esc(report.geo.org_name.as_deref().unwrap_or("")),
            sql_esc(report.geo.country_code.as_deref().unwrap_or("")),
            sql_esc(report.geo.region.as_deref().unwrap_or("")),
            sql_esc(report.geo.city.as_deref().unwrap_or("")),
            report.geo.is_canada,
            report.geo.is_quebec,
        ));

        // Email Security
        let dkim_sql = sql_text_array(&report.email_sec.dkim_selectors_found);
        detail_sql.push_str(&format!(
            "INSERT INTO audit_email_sec (scan_id, spf_lookup_count, spf_lookup_valid, dkim_selectors_tested, dkim_selectors_found, mta_sts_present, mta_sts_mode, smtp_tls_reporting, bimi_present, dmarc_sp_policy, dmarc_adkim, dmarc_aspf) \
             VALUES ({}, {}, {}, {}, {}, {}, '{}', {}, {}, '{}', '{}', '{}');\n",
            scan_id,
            report.email_sec.spf_lookup_count,
            report.email_sec.spf_lookup_valid,
            report.email_sec.dkim_selectors_tested,
            dkim_sql,
            report.email_sec.mta_sts_present,
            sql_esc(report.email_sec.mta_sts_mode.as_deref().unwrap_or("")),
            report.email_sec.smtp_tls_reporting,
            report.email_sec.bimi_present,
            sql_esc(report.email_sec.dmarc_sp_policy.as_deref().unwrap_or("")),
            sql_esc(report.email_sec.dmarc_adkim.as_deref().unwrap_or("")),
            sql_esc(report.email_sec.dmarc_aspf.as_deref().unwrap_or(""))
        ));

        // Web Endpoints
        let disallow_sql = sql_text_array(&report.web_endpoints.robots_disallowed_paths);
        let methods_sql = sql_text_array(&report.web_endpoints.allowed_http_methods);
        detail_sql.push_str(&format!(
            "INSERT INTO audit_web_endpoints (scan_id, security_txt_present, security_txt_url, robots_txt_present, robots_disallowed_paths, allowed_http_methods, dangerous_methods_found, http2_supported, alpn_negotiated) \
             VALUES ({}, {}, '{}', {}, {}, {}, {}, {}, '{}');\n",
            scan_id,
            report.web_endpoints.security_txt_present,
            sql_esc(report.web_endpoints.security_txt_url.as_deref().unwrap_or("")),
            report.web_endpoints.robots_txt_present,
            disallow_sql,
            methods_sql,
            report.web_endpoints.dangerous_methods_found,
            report.web_endpoints.http2_supported,
            sql_esc(report.web_endpoints.alpn_negotiated.as_deref().unwrap_or(""))
        ));

        // DNS Hardening
        detail_sql.push_str(&format!(
            "INSERT INTO audit_dns_hardening (scan_id, ip_tested, is_open_resolver_risk, recursion_denied, zone_transfer_denied) \
             VALUES ({}, '{}', {}, {}, {});\n",
            scan_id,
            sql_esc(&report.dns_hardening.ip_tested),
            report.dns_hardening.is_open_resolver_risk,
            report.dns_hardening.recursion_denied,
            report.dns_hardening.zone_transfer_denied
        ));

        // Outils Kali (Nmap, Nuclei, Nikto, Wafw00f, WhatWeb, SSLScan, Dnstwist, Ffuf)
        if let Some(ref nmap) = report.nmap {
            append_tool_output(
                &mut detail_sql,
                scan_id,
                "nmap",
                nmap.success,
                nmap.services.len(),
                nmap.elapsed_seconds,
                &nmap.summary,
                &nmap.raw_output,
            );
        }
        if let Some(ref nuclei) = report.nuclei {
            append_tool_output(
                &mut detail_sql,
                scan_id,
                "nuclei",
                nuclei.success,
                nuclei.items.len(),
                nuclei.elapsed_seconds,
                &nuclei.summary,
                &nuclei.raw_output,
            );
        }
        if let Some(ref nikto) = report.nikto {
            append_tool_output(
                &mut detail_sql,
                scan_id,
                "nikto",
                nikto.success,
                nikto.vulnerabilities.len(),
                nikto.elapsed_seconds,
                &nikto.summary,
                &nikto.raw_output,
            );
        }
        if let Some(ref waf) = report.waf {
            let count = if waf.waf_detected { 1 } else { 0 };
            append_tool_output(
                &mut detail_sql,
                scan_id,
                "wafw00f",
                waf.success,
                count,
                waf.elapsed_seconds,
                &waf.summary,
                &waf.raw_output,
            );
        }
        if let Some(ref ts) = report.tech_stack {
            append_tool_output(
                &mut detail_sql,
                scan_id,
                "whatweb",
                ts.success,
                ts.detected_technologies.len(),
                ts.elapsed_seconds,
                &ts.summary,
                &ts.raw_output,
            );
        }
        if let Some(ref ss) = report.sslscan {
            let total = ss.strong_ciphers_count + ss.weak_ciphers.len();
            append_tool_output(
                &mut detail_sql,
                scan_id,
                "sslscan",
                ss.success,
                total,
                ss.elapsed_seconds,
                &ss.summary,
                &ss.raw_output,
            );
        }
        if let Some(ref bs) = report.brand_sec {
            append_tool_output(
                &mut detail_sql,
                scan_id,
                "dnstwist",
                bs.success,
                bs.registered_lookalikes.len(),
                bs.elapsed_seconds,
                &bs.summary,
                &bs.raw_output,
            );
        }
        if let Some(ref ff) = report.ffuf {
            append_tool_output(
                &mut detail_sql,
                scan_id,
                "ffuf",
                ff.success,
                ff.endpoints.len(),
                ff.elapsed_seconds,
                &ff.summary,
                &ff.raw_output,
            );
        }
        if let Some(ref wh) = report.whois {
            let count = if wh.registrar.is_some() { 1 } else { 0 };
            let summary = format!(
                "Whois: Registrar={}, Expiry={}, Locked={}",
                wh.registrar.as_deref().unwrap_or("Inconnu"),
                wh.expiry_date.as_deref().unwrap_or("Inconnu"),
                wh.is_transfer_locked
            );
            append_tool_output(
                &mut detail_sql,
                scan_id,
                "whois",
                true,
                count,
                wh.execution_time_seconds,
                &summary,
                &wh.raw_output,
            );
        }
        if let Some(ref dr) = report.dnsrecon {
            let summary = format!(
                "Dnsrecon: {} SRV, {} NS, Bind={:?}",
                dr.srv_records.len(),
                dr.nameservers.len(),
                dr.bind_versions
            );
            append_tool_output(
                &mut detail_sql,
                scan_id,
                "dnsrecon",
                true,
                dr.srv_records.len() + dr.nameservers.len(),
                dr.execution_time_seconds,
                &summary,
                &dr.raw_output,
            );
        }
        if let Some(ref th) = report.theharvester {
            let summary = format!(
                "theHarvester: {} hosts, {} emails trouvés via OSINT",
                th.hosts.len(),
                th.emails.len()
            );
            append_tool_output(
                &mut detail_sql,
                scan_id,
                "theharvester",
                true,
                th.hosts.len() + th.emails.len(),
                th.execution_time_seconds,
                &summary,
                &th.raw_output,
            );
        }
        if let Some(ref obs) = report.obscura {
            append_tool_output(
                &mut detail_sql,
                scan_id,
                "obscura",
                obs.success,
                obs.total_assets,
                obs.elapsed_seconds,
                &obs.summary,
                &obs.raw_output,
            );
        }
        if let Some(ref hp) = report.http_probe {
            let live = hp.iter().filter(|r| r.status_code.is_some()).count();
            let techs: std::collections::HashSet<String> = hp
                .iter()
                .flat_map(|r| r.technologies.iter().cloned())
                .collect();
            let tech_list: Vec<String> = techs.into_iter().collect();
            let summary = if hp.is_empty() {
                "Aucun hôte probed par httpx".to_string()
            } else {
                format!(
                    "{} hôte(s) vivants sur {} probed — technos: {}",
                    live,
                    hp.len(),
                    if tech_list.is_empty() { "-".to_string() } else { tech_list.join(", ") }
                )
            };
            let raw = serde_json::to_string_pretty(hp).unwrap_or_default();
            append_tool_output(
                &mut detail_sql,
                scan_id,
                "httpx",
                !hp.is_empty(),
                hp.len(),
                report.duration_seconds,
                &summary,
                &raw,
            );
        }
        if let Some(ref rs) = report.rustscan {
            let summary = if rs.success {
                format!(
                    "RustScan: {} port(s) ouvert(s) en {}ms",
                    rs.open_ports.len(),
                    rs.scan_duration_ms
                )
            } else {
                "RustScan: échec (rustscan absent ?)".to_string()
            };
            let raw = serde_json::to_string_pretty(rs).unwrap_or_default();
            append_tool_output(
                &mut detail_sql,
                scan_id,
                "rustscan",
                rs.success,
                rs.open_ports.len(),
                report.duration_seconds,
                &summary,
                &raw,
            );
        }
        if let Some(ref sq) = report.sqli {
            let summary = if sq.is_empty() {
                "SQLMap: aucune injection détectée".to_string()
            } else {
                format!("SQLMap: {} injection(s) SQL confirmée(s) !", sq.len())
            };
            let raw = serde_json::to_string_pretty(sq).unwrap_or_default();
            append_tool_output(
                &mut detail_sql,
                scan_id,
                "sqlmap",
                true,
                sq.len(),
                report.duration_seconds,
                &summary,
                &raw,
            );
        }

        detail_sql.push_str("COMMIT;\n");

        // Exécution du batch complet
        let output2 = crate::utils::run_tool_stdin(
            "psql",
            &["-d", db_name, "-v", "ON_ERROR_STOP=1", "-f", "-"],
            60,
            &detail_sql,
            &[
                ("PGCONNECT_TIMEOUT", "10"),
                ("PGOPTIONS", "-c statement_timeout=55000"),
            ],
        )
        .ok_or_else(|| "psql : timeout (60s) ou lancement impossible (détails)".to_string())?;

        if !output2.status.success() {
            let err2 = String::from_utf8_lossy(&output2.stderr);
            // Atomicité compensée : le batch de détail a échoué → on supprime la ligne
            // orpheline audit_scans (et ses filles) pour ne pas laisser un scan à moitié
            // catalogué qui fausserait l'historique.
            Self::cleanup_scan(db_name, scan_id);
            return Err(format!(
                "Erreur SQL lors du catalogage détaillé (rollback compensatoire effectué) : {}",
                err2.trim()
            ));
        }

        Ok(scan_id)
    }

    /// Supprime un scan partiellement catalogué (audit_scans + tables filles).
    fn cleanup_scan(db_name: &str, scan_id: i64) {
        let tables = [
            "audit_dns_records",
            "audit_ports",
            "audit_http_headers",
            "audit_tls_certs",
            "audit_subdomains",
            "audit_findings",
            "audit_geo_compliance",
            "audit_email_sec",
            "audit_web_endpoints",
            "audit_dns_hardening",
            "audit_tool_outputs",
        ];
        let mut sql = String::from("BEGIN;\n");
        for t in tables {
            sql.push_str(&format!("DELETE FROM {} WHERE scan_id = {};\n", t, scan_id));
        }
        sql.push_str(&format!("DELETE FROM audit_scans WHERE id = {};\n", scan_id));
        sql.push_str("COMMIT;\n");
        let _ = crate::utils::run_tool_stdin(
            "psql",
            &["-d", db_name, "-v", "ON_ERROR_STOP=1", "-f", "-"],
            20,
            &sql,
            &[("PGCONNECT_TIMEOUT", "10")],
        );
    }

    /// Récupère l'historique complet des scans pour un domaine
    pub fn get_history(
        target: &str,
        limit: usize,
        db_name: &str,
    ) -> Result<Vec<ScanHistoryEntry>, String> {
        // Cible vide = toutes cibles (aucun filtre WHERE)
        let where_clause = if target.trim().is_empty() {
            String::new()
        } else {
            format!("WHERE target = '{}'", sql_esc(target))
        };
        let query = format!(
            "SELECT id, target, to_char(created_at, 'YYYY-MM-DD HH24:MI:SS TZ'), overall_score, duration_seconds, open_ports_count, findings_count \
             FROM audit_scans \
             {} \
             ORDER BY created_at DESC \
             LIMIT {};",
            where_clause,
            limit
        );

        let output = crate::utils::run_tool_env(
            "psql",
            &["-d", db_name, "-F", "\u{1f}", "-t", "-A", "-c", &query],
            15,
            &[
                ("PGCONNECT_TIMEOUT", "10"),
                ("PGOPTIONS", "-c statement_timeout=10000"),
            ],
        )
        .ok_or_else(|| "psql : timeout (15s) ou lancement impossible (history)".to_string())?;

        if !output.status.success() {
            return Err(String::from_utf8_lossy(&output.stderr).trim().to_string());
        }

        let mut entries = Vec::new();
        let stdout = String::from_utf8_lossy(&output.stdout);
        for line in stdout.lines() {
            // Séparateur 0x1F : un '|' dans un nom de cible ne décale plus les colonnes
            let parts: Vec<&str> = line.split('\u{1f}').collect();
            if parts.len() >= 7 {
                let id = parts[0].parse::<i64>().unwrap_or(0);
                let target = parts[1].to_string();
                let created_at = parts[2].to_string();
                let score = parts[3].parse::<i32>().unwrap_or(0);
                let duration = parts[4].parse::<f32>().unwrap_or(0.0);
                let open_ports_count = parts[5].parse::<i32>().unwrap_or(0);
                let findings_count = parts[6].parse::<i32>().unwrap_or(0);

                entries.push(ScanHistoryEntry {
                    id,
                    target,
                    created_at,
                    overall_score: score,
                    duration_seconds: duration,
                    open_ports_count,
                    findings_count,
                });
            }
        }

        Ok(entries)
    }
}

// Helpers SQL réutilisables
pub(crate) fn sql_esc(s: &str) -> String {
    s.replace('\'', "''")
}

pub(crate) fn sql_text_array(items: &[String]) -> String {
    if items.is_empty() {
        "'{}'::text[]".to_string()
    } else {
        let list: Vec<String> = items.iter().map(|s| format!("'{}'", sql_esc(s))).collect();
        format!("ARRAY[{}]::text[]", list.join(","))
    }
}

pub(crate) fn sql_int_array<T: ToString>(items: &[T]) -> String {
    if items.is_empty() {
        "'{}'::int[]".to_string()
    } else {
        let list: Vec<String> = items.iter().map(|s| s.to_string()).collect();
        format!("ARRAY[{}]::int[]", list.join(","))
    }
}

#[allow(clippy::too_many_arguments)]
fn append_tool_output(
    sql: &mut String,
    scan_id: i64,
    tool_name: &str,
    success: bool,
    items_count: usize,
    elapsed: f32,
    summary: &str,
    raw_output: &str,
) {
    let status = if success { "SUCCESS" } else { "FAILED" };
    // Dollar-quote à tag unique : la preuve brute n'est JAMAIS mutilée
    // (l'ancien replace("$RAW$","") corrompait silencieusement les raw_output)
    let mut tag = "$raw$".to_string();
    let mut n = 0;
    while raw_output.contains(&tag) {
        n += 1;
        tag = format!("$raw{}$", n);
    }
    sql.push_str(&format!(
        "INSERT INTO audit_tool_outputs (scan_id, tool_name, status, items_count, execution_time_seconds, summary, raw_output) \
         VALUES ({}, '{}', '{}', {}, {:.2}, '{}', {}{}{});\n",
        scan_id,
        tool_name,
        status,
        items_count,
        elapsed,
        sql_esc(summary),
        tag,
        raw_output,
        tag
    ));
}
