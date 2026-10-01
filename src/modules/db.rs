use crate::report::FullAuditReport;
use postgres::types::Type;
use postgres::{Client, NoTls};
use std::time::Duration;

pub struct DatabaseManager;

#[allow(dead_code)]
#[derive(Debug, Default, serde::Serialize, serde::Deserialize)]
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
    /// Ouvre une connexion PostgreSQL via socket Unix (auth peer de l'OS :
    /// aucun mot de passe, aucun TCP exposé — le serveur écoute en loopback
    /// et la socket locale authentifie par UID). La chaîne de connexion est
    /// construite par l'API builder : le nom de base ne transite jamais par
    /// une interpolation de chaîne.
    fn connect(db_name: &str) -> Result<Client, String> {
        let mut last_err = String::new();
        for dir in ["/var/run/postgresql", "/tmp"] {
            let mut cfg = postgres::Config::new();
            cfg.dbname(db_name)
                .host(dir)
                .application_name("veridy_scanner")
                .connect_timeout(Duration::from_secs(10))
                .options("-c statement_timeout=55000");
            match cfg.connect(NoTls) {
                Ok(c) => return Ok(c),
                Err(e) => last_err = format!("socket {dir} : {e}"),
            }
        }
        Err(format!(
            "PostgreSQL injoignable via socket locale ({last_err})"
        ))
    }

    /// Insère l'ensemble du scan et catalogue tous les artefacts dans les
    /// 13 tables relationnelles, en UNE transaction atomique sur UNE
    /// connexion : soit le scan complet est catalogué, soit rien ne l'est.
    /// Fini la ligne orpheline audit_scans quand le batch de détail
    /// échouait à mi-chemin (l'ancienne compensation cleanup_scan n'a plus
    /// lieu d'être sur ce chemin normal).
    ///
    /// Toutes les valeurs transitent par des paramètres liés ($1..$n) :
    /// plus AUCUNE interpolation format!() de valeur dans le SQL.
    /// L'injection par la cible, une bannière de port, un en-tête HTTP ou
    /// la preuve brute d'un outil devient structurellement impossible (le
    /// protocole sépare code et données), et les apostrophes ou tagués
    /// dollar des preuves sont transportés tels quels, sans mutilation.
    pub fn save_scan(report: &FullAuditReport, db_name: &str) -> Result<i64, String> {
        let raw_json = strip_nul_json(&report.to_json());
        let open_ports: Vec<i32> = report.ports.iter().map(|p| p.port as i32).collect();

        let mut client = Self::connect(db_name)?;
        let mut tx = client
            .transaction()
            .map_err(|e| format!("PostgreSQL BEGIN : {e}"))?;

        // 1. audit_scans — l'ID est réservé DANS la transaction. Le payload
        //    part comme TEXT puis est converti ::jsonb côté serveur (les
        //    cast arguments gardent le paramètre en TEXT, jamais déduit
        //    jsonb par la colonne, sinon le binding d'un &str serait rejeté).
        let stmt_scans = tx
            .prepare_typed(
                "INSERT INTO audit_scans \
                 (target, overall_score, open_ports, tls_valid, spf_ok, dmarc_ok, http_status, \
                  duration_seconds, open_ports_count, findings_count, payload) \
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11::jsonb) \
                 RETURNING id",
                &[
                    Type::VARCHAR,
                    Type::INT2,
                    Type::INT4_ARRAY,
                    Type::BOOL,
                    Type::BOOL,
                    Type::BOOL,
                    Type::INT4,
                    Type::FLOAT4,
                    Type::INT4,
                    Type::INT4,
                    Type::TEXT,
                ],
            )
            .map_err(|e| format!("audit_scans (prepare) : {e}"))?;
        let row = tx
            .query_one(
                &stmt_scans,
                &[
                    &report.target,
                    &(report.overall_score as i16),
                    &open_ports,
                    &report.tls.is_valid,
                    &report.dns.spf_found,
                    &report.dns.dmarc_found,
                    &(report.http.http_status as i32),
                    &round2(report.duration_seconds),
                    &(report.ports.len() as i32),
                    &(report.findings.len() as i32),
                    &raw_json,
                ],
            )
            .map_err(|e| format!("audit_scans : {e}"))?;
        let scan_id: i64 = row.get(0);

        // 2. Tables filles — tout INSERT échoué fait tomber la transaction
        //    entière (rollback au drop) : aucun état partiel ne persiste.

        // DNS Records
        for d in &report.dns.all_records {
            tx.execute(
                "INSERT INTO audit_dns_records (scan_id, record_type, record_value, is_secure) \
                 VALUES ($1, $2, $3, $4)",
                &[
                    &scan_id,
                    &d.record_type,
                    &strip_nul_bytes(&d.value),
                    &d.is_secure,
                ],
            )
            .map_err(|e| format!("audit_dns_records : {e}"))?;
        }

        // Ports
        for p in &report.ports {
            tx.execute(
                "INSERT INTO audit_ports (scan_id, port, service, state, banner) \
                 VALUES ($1, $2, $3, 'OPEN', $4)",
                &[
                    &scan_id,
                    &(p.port as i32),
                    &strip_nul_bytes(p.service_hint),
                    &p.banner.as_deref().map(strip_nul_bytes),
                ],
            )
            .map_err(|e| format!("audit_ports : {e}"))?;
        }

        // HTTP Headers
        for h in &report.http.all_headers {
            tx.execute(
                "INSERT INTO audit_http_headers (scan_id, header_name, header_value, evaluation) \
                 VALUES ($1, $2, $3, $4)",
                &[
                    &scan_id,
                    &strip_nul_bytes(&h.name),
                    &strip_nul_bytes(&h.value),
                    &h.evaluation,
                ],
            )
            .map_err(|e| format!("audit_http_headers : {e}"))?;
        }

        // TLS Cert — valid_from/valid_until partent en TEXT et sont
        // convertis ::timestamptz par le serveur (même sémantique que
        // l'ancien quoting manuel, formats de dates libres acceptés).
        let stmt_tls = tx
            .prepare_typed(
                "INSERT INTO audit_tls_certs \
                 (scan_id, protocol, cipher, issuer, subject, valid_until, valid_from, \
                  days_remaining, sans, is_valid, is_self_signed, \
                  supports_tls10, supports_tls11, supports_tls12, supports_tls13) \
                 VALUES ($1, $2, $3, $4, $5, $6::timestamptz, $7::timestamptz, $8, $9, \
                         $10, $11, $12, $13, $14, $15)",
                &[
                    Type::INT8,
                    Type::TEXT,
                    Type::TEXT,
                    Type::TEXT,
                    Type::TEXT,
                    Type::TEXT,
                    Type::TEXT,
                    Type::INT4,
                    Type::TEXT_ARRAY,
                    Type::BOOL,
                    Type::BOOL,
                    Type::BOOL,
                    Type::BOOL,
                    Type::BOOL,
                    Type::BOOL,
                ],
            )
            .map_err(|e| format!("audit_tls_certs (prepare) : {e}"))?;
        tx.execute(
            &stmt_tls,
            &[
                &scan_id,
                &report.tls.protocol,
                &report.tls.cipher,
                &report.tls.issuer,
                &report.tls.subject,
                &report.tls.valid_until,
                &report.tls.valid_from,
                &report.tls.days_remaining,
                &report.tls.sans,
                &report.tls.is_valid,
                &report.tls.is_self_signed,
                &report.tls.supports_tls10,
                &report.tls.supports_tls11,
                &report.tls.supports_tls12,
                &report.tls.supports_tls13,
            ],
        )
        .map_err(|e| format!("audit_tls_certs : {e}"))?;

        // Subdomains
        for s in &report.subdomains {
            let http_status: Option<i32> = s.http_status.map(|h| h as i32);
            tx.execute(
                "INSERT INTO audit_subdomains (scan_id, subdomain, ip_address, http_status, is_alive) \
                 VALUES ($1, $2, $3, $4, $5)",
                &[
                    &scan_id,
                    &strip_nul_bytes(&s.subdomain),
                    &s.ip_address.as_deref().map(strip_nul_bytes),
                    &http_status,
                    &s.is_alive,
                ],
            )
            .map_err(|e| format!("audit_subdomains : {e}"))?;
        }

        // Findings (title/recommendation tronqués à 2000 chars côté Rust,
        // double protection contre la saturation des colonnes texte)
        for f in &report.findings {
            tx.execute(
                "INSERT INTO audit_findings (scan_id, severity, category, title, recommendation) \
                 VALUES ($1, $2, $3, $4, $5)",
                &[
                    &scan_id,
                    &f.severity,
                    &f.category,
                    &text_clipped_for_bind(&f.title, 2000),
                    &text_clipped_for_bind(&f.recommendation, 2000),
                ],
            )
            .map_err(|e| format!("audit_findings : {e}"))?;
        }

        // Géolocalisation (données factuelles de localisation IP uniquement)
        tx.execute(
            "INSERT INTO audit_geo \
             (scan_id, ip_address, asn, org_name, country_code, region, city, is_canada, is_quebec) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)",
            &[
                &scan_id,
                &report.geo.ip_address,
                &report.geo.asn,
                &report.geo.org_name,
                &report.geo.country_code,
                &report.geo.region,
                &report.geo.city,
                &report.geo.is_canada,
                &report.geo.is_quebec,
            ],
        )
        .map_err(|e| format!("audit_geo : {e}"))?;

        // Email Security
        tx.execute(
            "INSERT INTO audit_email_sec \
             (scan_id, spf_lookup_count, spf_lookup_valid, dkim_selectors_tested, dkim_selectors_found, \
              mta_sts_present, mta_sts_mode, smtp_tls_reporting, bimi_present, \
              dmarc_sp_policy, dmarc_adkim, dmarc_aspf) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)",
            &[
                &scan_id,
                &(report.email_sec.spf_lookup_count as i32),
                &report.email_sec.spf_lookup_valid,
                &(report.email_sec.dkim_selectors_tested as i32),
                &report.email_sec.dkim_selectors_found,
                &report.email_sec.mta_sts_present,
                &report.email_sec.mta_sts_mode,
                &report.email_sec.smtp_tls_reporting,
                &report.email_sec.bimi_present,
                &report.email_sec.dmarc_sp_policy,
                &report.email_sec.dmarc_adkim,
                &report.email_sec.dmarc_aspf,
            ],
        )
        .map_err(|e| format!("audit_email_sec : {e}"))?;

        // Web Endpoints
        tx.execute(
            "INSERT INTO audit_web_endpoints \
             (scan_id, security_txt_present, security_txt_url, robots_txt_present, \
              robots_disallowed_paths, allowed_http_methods, dangerous_methods_found, \
              http2_supported, alpn_negotiated) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)",
            &[
                &scan_id,
                &report.web_endpoints.security_txt_present,
                &report.web_endpoints.security_txt_url,
                &report.web_endpoints.robots_txt_present,
                &report.web_endpoints.robots_disallowed_paths,
                &report.web_endpoints.allowed_http_methods,
                &report.web_endpoints.dangerous_methods_found,
                &report.web_endpoints.http2_supported,
                &report.web_endpoints.alpn_negotiated,
            ],
        )
        .map_err(|e| format!("audit_web_endpoints : {e}"))?;

        // DNS Hardening
        tx.execute(
            "INSERT INTO audit_dns_hardening \
             (scan_id, ip_tested, is_open_resolver_risk, recursion_denied, zone_transfer_denied) \
             VALUES ($1, $2, $3, $4, $5)",
            &[
                &scan_id,
                &report.dns_hardening.ip_tested,
                &report.dns_hardening.is_open_resolver_risk,
                &report.dns_hardening.recursion_denied,
                &report.dns_hardening.zone_transfer_denied,
            ],
        )
        .map_err(|e| format!("audit_dns_hardening : {e}"))?;

        // Outils Kali (Nmap, Nuclei, Nikto, Wafw00f, WhatWeb, SSLScan, Dnstwist, Ffuf)
        if let Some(ref nmap) = report.nmap {
            append_tool_output(
                &mut tx,
                scan_id,
                "nmap",
                nmap.success,
                nmap.services.len(),
                nmap.elapsed_seconds,
                &nmap.summary,
                &nmap.raw_output,
            )?;
        }
        if let Some(ref nuclei) = report.nuclei {
            append_tool_output(
                &mut tx,
                scan_id,
                "nuclei",
                nuclei.success,
                nuclei.items.len(),
                nuclei.elapsed_seconds,
                &nuclei.summary,
                &nuclei.raw_output,
            )?;
        }
        if let Some(ref nikto) = report.nikto {
            append_tool_output(
                &mut tx,
                scan_id,
                "nikto",
                nikto.success,
                nikto.vulnerabilities.len(),
                nikto.elapsed_seconds,
                &nikto.summary,
                &nikto.raw_output,
            )?;
        }
        if let Some(ref waf) = report.waf {
            let count = if waf.waf_detected { 1 } else { 0 };
            append_tool_output(
                &mut tx,
                scan_id,
                "wafw00f",
                waf.success,
                count,
                waf.elapsed_seconds,
                &waf.summary,
                &waf.raw_output,
            )?;
        }
        if let Some(ref ts) = report.tech_stack {
            append_tool_output(
                &mut tx,
                scan_id,
                "whatweb",
                ts.success,
                ts.detected_technologies.len(),
                ts.elapsed_seconds,
                &ts.summary,
                &ts.raw_output,
            )?;
            // Composants versionnés -> audit_tech (verdict EOL calculé par le module)
            let verdicts =
                crate::modules::tech_stack::TechStackAuditor::version_verdicts(&ts.versioned);
            for comp in &ts.versioned {
                let v = verdicts
                    .iter()
                    .find(|v| v.name == comp.name && v.detected == comp.version);
                tx.execute(
                    "INSERT INTO audit_tech (scan_id, name, version, source, is_eol, branch_min) VALUES ($1, $2, $3, 'whatweb', $4, $5)",
                    &[
                        &scan_id,
                        &strip_nul_bytes(&comp.name),
                        &strip_nul_bytes(&comp.version),
                        &v.is_some(),
                        &v.map(|x| strip_nul_bytes(&x.branch_min)),
                    ],
                )
                .map_err(|e| format!("audit_tech : {e}"))?;
            }
        }

        // === audit_tech FALLBACK (post-livraison v0.5.5) ============================
        // whatweb echoue / est muet derriere Cloudflare/BitNinja (scan 487/488/489)
        // ou ne retourne AUCUN composant versionne (scan 480 dessinsdrummond).
        // On agrege alors les en-tetes HTTP deja collectes (Server, X-Powered-By)
        // et les technologies detectees par httpx sur les sous-domaines vivants
        // (cas 486 sunyouth WordPress 7.1.2 sur sous-domaine).
        //
        // Source 'whatweb' : cas normal, deja insere ci-dessus.
        // Source 'http-header' : fallback depuis en-tetes HTTP de la cible principale.
        // Source 'httpx' : technologies detectees sur sous-domaines via httpx.
        //
        // DEDUP stricte par (name, version) : un meme composant depuis plusieurs
        // sources n'est insere qu'une fois.
        let mut tech_seen: std::collections::HashSet<(String, String)> =
            std::collections::HashSet::new();
        if let Some(ref ts) = report.tech_stack {
            for c in &ts.versioned {
                tech_seen.insert((c.name.clone(), c.version.clone()));
            }
        }

        // Source: http-header (Server / X-Powered-By)
        let header_inserts: Vec<(String, String)> = {
            let mut v = Vec::new();
            if let Some(srv) = report.http.server_header.as_deref() {
                if let Some((n, vv)) = audit_tech_parse_token(srv) {
                    v.push((n, vv));
                }
            }
            if let Some(pb) = report.http.powered_by.as_deref() {
                if let Some((n, vv)) = audit_tech_parse_token(pb) {
                    v.push((n, vv));
                }
            }
            v
        };
        for (name, version) in &header_inserts {
            if !tech_seen.insert((name.clone(), version.clone())) {
                continue;
            }
            let v = crate::modules::tech_stack::TechStackAuditor::version_verdicts(&[
                crate::modules::tech_stack::TechComponent {
                    name: name.clone(),
                    version: version.clone(),
                },
            ]);
            let v0 = v.first();
            tx.execute(
                "INSERT INTO audit_tech (scan_id, name, version, source, is_eol, branch_min) VALUES ($1, $2, $3, 'http-header', $4, $5)",
                &[
                    &scan_id,
                    &strip_nul_bytes(name),
                    &strip_nul_bytes(version),
                    &v0.is_some(),
                    &v0.map(|x| strip_nul_bytes(&x.branch_min)),
                ],
            )
            .map_err(|e| format!("audit_tech http-header : {e}"))?;
        }

        // Source: httpx (technologies des sous-domaines vivants)
        if let Some(ref hp) = report.http_probe {
            for probe in hp.iter() {
                if probe.status_code.is_none() {
                    continue;
                }
                for t in &probe.technologies {
                    if let Some((name, version)) = audit_tech_parse_httpx_token(t) {
                        if !tech_seen.insert((name.clone(), version.clone())) {
                            continue;
                        }
                        let v = crate::modules::tech_stack::TechStackAuditor::version_verdicts(&[
                            crate::modules::tech_stack::TechComponent {
                                name: name.clone(),
                                version: version.clone(),
                            },
                        ]);
                        let v0 = v.first();
                        tx.execute(
                            "INSERT INTO audit_tech (scan_id, name, version, source, is_eol, branch_min) VALUES ($1, $2, $3, 'httpx', $4, $5)",
                            &[
                                &scan_id,
                                &strip_nul_bytes(&name),
                                &strip_nul_bytes(&version),
                                &v0.is_some(),
                                &v0.map(|x| strip_nul_bytes(&x.branch_min)),
                            ],
                        )
                        .map_err(|e| format!("audit_tech httpx : {e}"))?;
                    }
                }
            }
        }
        // === FIN audit_tech FALLBACK ==================================================

        if let Some(ref ss) = report.sslscan {
            let total = ss.strong_ciphers_count + ss.weak_ciphers.len();
            append_tool_output(
                &mut tx,
                scan_id,
                "sslscan",
                ss.success,
                total,
                ss.elapsed_seconds,
                &ss.summary,
                &ss.raw_output,
            )?;
        }
        if let Some(ref bs) = report.brand_sec {
            append_tool_output(
                &mut tx,
                scan_id,
                "dnstwist",
                bs.success,
                bs.registered_lookalikes.len(),
                bs.elapsed_seconds,
                &bs.summary,
                &bs.raw_output,
            )?;
        }
        if let Some(ref ff) = report.ffuf {
            append_tool_output(
                &mut tx,
                scan_id,
                "ffuf",
                ff.success,
                ff.endpoints.len(),
                ff.elapsed_seconds,
                &ff.summary,
                &ff.raw_output,
            )?;
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
                &mut tx,
                scan_id,
                "whois",
                true,
                count,
                wh.execution_time_seconds,
                &summary,
                &wh.raw_output,
            )?;
        }
        if let Some(ref dr) = report.dnsrecon {
            let summary = format!(
                "Dnsrecon: {} SRV, {} NS, Bind={:?}",
                dr.srv_records.len(),
                dr.nameservers.len(),
                dr.bind_versions
            );
            append_tool_output(
                &mut tx,
                scan_id,
                "dnsrecon",
                true,
                dr.srv_records.len() + dr.nameservers.len(),
                dr.execution_time_seconds,
                &summary,
                &dr.raw_output,
            )?;
        }
        if let Some(ref th) = report.theharvester {
            let summary = format!(
                "theHarvester: {} hosts, {} emails trouvés via OSINT",
                th.hosts.len(),
                th.emails.len()
            );
            append_tool_output(
                &mut tx,
                scan_id,
                "theharvester",
                true,
                th.hosts.len() + th.emails.len(),
                th.execution_time_seconds,
                &summary,
                &th.raw_output,
            )?;
        }
        if let Some(ref obs) = report.obscura {
            append_tool_output(
                &mut tx,
                scan_id,
                "obscura",
                obs.success,
                obs.total_assets,
                obs.elapsed_seconds,
                &obs.summary,
                &obs.raw_output,
            )?;
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
                    if tech_list.is_empty() {
                        "-".to_string()
                    } else {
                        tech_list.join(", ")
                    }
                )
            };
            let raw = serde_json::to_string_pretty(hp).unwrap_or_default();
            append_tool_output(
                &mut tx,
                scan_id,
                "httpx",
                !hp.is_empty(),
                hp.len(),
                report.duration_seconds,
                &summary,
                &raw,
            )?;
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
                &mut tx,
                scan_id,
                "rustscan",
                rs.success,
                rs.open_ports.len(),
                report.duration_seconds,
                &summary,
                &raw,
            )?;
        }
        if let Some(ref sq) = report.sqli {
            let summary = if sq.is_empty() {
                "SQLMap: aucune injection détectée".to_string()
            } else {
                format!("SQLMap: {} injection(s) SQL confirmée(s) !", sq.len())
            };
            let raw = serde_json::to_string_pretty(sq).unwrap_or_default();
            append_tool_output(
                &mut tx,
                scan_id,
                "sqlmap",
                true,
                sq.len(),
                report.duration_seconds,
                &summary,
                &raw,
            )?;
        }

        // Loot : persistance des fichiers exfiltrés (opt-in via --loot).
        // Timestamp ISO en TEXT converti ::timestamptz côté serveur.
        let stmt_loot = tx
            .prepare_typed(
                "INSERT INTO audit_loot \
                 (scan_id, url, local_path, size_bytes, sha256, content_type, status_code, \
                  severity, category, timestamp, first_64_bytes_hex) \
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10::timestamptz, $11)",
                &[
                    Type::INT8,
                    Type::TEXT,
                    Type::TEXT,
                    Type::INT8,
                    Type::VARCHAR,
                    Type::TEXT,
                    Type::INT2,
                    Type::VARCHAR,
                    Type::VARCHAR,
                    Type::TEXT,
                    Type::TEXT,
                ],
            )
            .map_err(|e| format!("audit_loot (prepare) : {e}"))?;
        if let Some(ref loot) = report.loot {
            for entry in &loot.entries {
                tx.execute(
                    &stmt_loot,
                    &[
                        &scan_id,
                        &entry.url,
                        &entry.local_path,
                        &(entry.size_bytes as i64),
                        &entry.sha256,
                        &entry.content_type,
                        &(entry.status_code as i16),
                        &entry.severity,
                        &entry.category,
                        &entry.timestamp,
                        &entry.first_64_bytes_hex,
                    ],
                )
                .map_err(|e| format!("audit_loot : {e}"))?;
            }
        }

        // 3. COMMIT — point d'atomicité : rien avant, tout après.
        tx.commit()
            .map_err(|e| format!("PostgreSQL COMMIT : {e}"))?;

        Ok(scan_id)
    }

    /// Supprime un scan complet (audit_scans + toutes ses tables filles) en
    /// une transaction. Conservé comme outil de maintenance : le flux
    /// save_scan étant désormais atomique, il n'y a plus d'orphelin à
    /// compenser sur le chemin normal.
    #[allow(dead_code)]
    fn cleanup_scan(db_name: &str, scan_id: i64) {
        let Ok(mut client) = Self::connect(db_name) else {
            return;
        };
        let Ok(mut tx) = client.transaction() else {
            return;
        };
        let tables = [
            "audit_tech",
            "audit_dns_records",
            "audit_ports",
            "audit_http_headers",
            "audit_tls_certs",
            "audit_subdomains",
            "audit_findings",
            "audit_geo",
            "audit_email_sec",
            "audit_web_endpoints",
            "audit_dns_hardening",
            "audit_tool_outputs",
            "audit_loot",
        ];
        for t in tables {
            let sql = format!("DELETE FROM {t} WHERE scan_id = $1");
            if tx.execute(&sql, &[&scan_id]).is_err() {
                return; // rollback implicite au drop
            }
        }
        if tx
            .execute("DELETE FROM audit_scans WHERE id = $1", &[&scan_id])
            .is_err()
        {
            return;
        }
        let _ = tx.commit();
    }

    /// Récupère l'historique complet des scans pour un domaine.
    /// La cible et la limite sont des paramètres liés : aucune valeur
    /// opérateur n'est interpolée dans le SQL, et les colonnes arrivent
    /// typées par le protocole (plus aucun parsing split fragile).
    pub fn get_history(
        target: &str,
        limit: usize,
        db_name: &str,
    ) -> Result<Vec<ScanHistoryEntry>, String> {
        let mut client = Self::connect(db_name)?;

        // Cible vide = toutes cibles (aucun filtre WHERE)
        let query_all = "SELECT id, target, to_char(created_at, 'YYYY-MM-DD HH24:MI:SS TZ'), \
                         overall_score::int, duration_seconds, open_ports_count, findings_count \
                         FROM audit_scans ORDER BY created_at DESC LIMIT $1";
        let query_target = "SELECT id, target, to_char(created_at, 'YYYY-MM-DD HH24:MI:SS TZ'), \
                            overall_score::int, duration_seconds, open_ports_count, findings_count \
                            FROM audit_scans WHERE target = $1 ORDER BY created_at DESC LIMIT $2";

        let lim: i64 = limit as i64;
        let target_owned = target.to_string();
        let rows = if target.trim().is_empty() {
            client.query(query_all, &[&lim])
        } else {
            client.query(query_target, &[&target_owned, &lim])
        }
        .map_err(|e| format!("SELECT historique : {e}"))?;

        Ok(rows
            .iter()
            .map(|row| ScanHistoryEntry {
                id: row.get(0),
                target: row.get(1),
                created_at: row.get(2),
                overall_score: row.get(3),
                duration_seconds: row.get(4),
                open_ports_count: row.get(5),
                findings_count: row.get(6),
            })
            .collect())
    }

    /// Accès de test à la connexion socket (vérifie le chemin d'auth peer
    /// sans mot de passe). Public pour les tests d'invariants DB ; aucun
    /// rôle en production.
    #[cfg(test)]
    pub fn connect_for_tests(db_name: &str) -> Result<postgres::Client, String> {
        Self::connect(db_name)
    }

    /// Accès de test au nettoyage transactionnel d'un scan (maintenance).
    #[cfg(test)]
    pub fn cleanup_scan_for_tests(db_name: &str, scan_id: i64) {
        Self::cleanup_scan(db_name, scan_id)
    }
}

// Helpers SQL conservés pour les tests d'invariants et la rétrocompatibilité
// des embedders. Le chemin d'écriture DB utilise désormais exclusivement des
// paramètres liés : ces helpers n'y jouent plus aucun rôle d'échappement.
#[allow(dead_code)]
pub(crate) fn sql_esc(s: &str) -> String {
    s.replace('\'', "''")
}

/// Tronque une chaîne pour rester sous une limite de longueur, en gardant la
/// sémantique (suffixe "…" si coupé). Double protection contre la saturation
/// de colonnes : on coupe côté Rust avant d'envoyer au serveur.
#[allow(dead_code)]
pub(crate) fn sql_text_clipped(s: &str, max_len: usize) -> String {
    sql_esc(&text_clipped_for_bind(s, max_len))
}

#[allow(dead_code)]
pub(crate) fn sql_text_array(items: &[String]) -> String {
    if items.is_empty() {
        "'{}'::text[]".to_string()
    } else {
        let list: Vec<String> = items.iter().map(|s| format!("'{}'", sql_esc(s))).collect();
        format!("ARRAY[{}]::text[]", list.join(","))
    }
}

#[allow(dead_code)]
pub(crate) fn sql_int_array<T: ToString>(items: &[T]) -> String {
    if items.is_empty() {
        "'{}'::int[]".to_string()
    } else {
        let list: Vec<String> = items.iter().map(|s| s.to_string()).collect();
        format!("ARRAY[{}]::int[]", list.join(","))
    }
}

/// Les bannières de services peuvent véhiculer des octets NUL bruts ou des
/// séquences d'échappement \u0000 que PostgreSQL refuse (jsonb ET text).
/// Sanitisation au point unique de passage vers la DB : le NUL devient
/// la séquence de remplacement visible «␀» (preuve lisible, jamais silencieuse).
pub(crate) fn strip_nul_bytes(s: &str) -> String {
    s.replace('\u{0}', "\u{2400}")
}

/// Variante dédiée au payload jsonb : les NUL littéraux ET les échappements
/// \u0000 déjà présents dans le document sérialisé doivent disparaître,
/// sinon le cast serveur ::jsonb échoue (séquence d'échappement non supportée).
pub(crate) fn strip_nul_json(s: &str) -> String {
    s.replace('\u{0}', "").replace("\\u0000", "")
}

/// Troncature UTF-8 safe AVANT binding paramétré. Aucun échappement SQL ici :
/// le protocole des paramètres liés transporte la valeur telle quelle
/// (apostrophes, guillemets, dollar-quotes des preuves brutes).
fn text_clipped_for_bind(s: &str, max_len: usize) -> String {
    let s = strip_nul_bytes(s);
    let s = s.as_str();
    if s.chars().count() > max_len {
        let cut: String = s.chars().take(max_len.saturating_sub(1)).collect();
        format!("{cut}…")
    } else {
        s.to_string()
    }
}

/// Arrondi à 2 décimales — préserve la granularité historiquement stockée
/// dans duration_seconds / execution_time_seconds (l'ancien format! {:.2}).
fn round2(v: f32) -> f32 {
    (v * 100.0).round() / 100.0
}

/// Persiste la sortie d'un outil Kali avec paramètres liés. La preuve brute
/// (raw_output) voyage intégralement via le protocole binaire : aucun
/// dollar-quote manuel, aucun replace, aucune mutilation possible.
#[allow(clippy::too_many_arguments)]
fn append_tool_output(
    tx: &mut postgres::Transaction<'_>,
    scan_id: i64,
    tool_name: &str,
    success: bool,
    items_count: usize,
    elapsed: f32,
    summary: &str,
    raw_output: &str,
) -> Result<(), String> {
    let status = if success { "SUCCESS" } else { "FAILED" };
    tx.execute(
        "INSERT INTO audit_tool_outputs \
         (scan_id, tool_name, status, items_count, execution_time_seconds, summary, raw_output) \
         VALUES ($1, $2, $3, $4, $5, $6, $7)",
        &[
            &scan_id,
            &tool_name,
            &status,
            &(items_count as i32),
            &round2(elapsed),
            &strip_nul_bytes(summary),
            &strip_nul_bytes(raw_output),
        ],
    )
    .map_err(|e| format!("audit_tool_outputs ({tool_name}) : {e}"))?;
    Ok(())
}

/// Extrait (name, version) depuis un token "Product/1.2.3".
/// Retourne None si le token est vide, ressemble a un placeholder (cloudflare),
/// ou ne contient pas de version exploitable.
///
/// Utilise pour audit_tech fallback depuis http.server_header et X-Powered-By.
/// Ex: "Apache/2.4.7 (Ubuntu)" -> Some(("Apache", "2.4.7"))
///     "PHP/8.2.0"            -> Some(("PHP", "8.2.0"))
///     "cloudflare"           -> None (placeholder sans version)
///     "Apache"               -> None (pas de version dans le token)
fn audit_tech_parse_token(raw: &str) -> Option<(String, String)> {
    let s = raw.trim();
    if s.is_empty() {
        return None;
    }
    let head = s.split([' ', '(', ',', ';']).next().unwrap_or("");
    let head = head.trim();
    if head.is_empty() || !head.contains('/') {
        return None;
    }
    let (name, ver_part) = head.split_once('/')?;
    let name = name.trim();
    if name.is_empty() || name.len() > 64 {
        return None;
    }
    let lower = name.to_ascii_lowercase();
    if matches!(
        lower.as_str(),
        "cloudflare"
            | "varnish"
            | "bunnynet"
            | "ddos-guard"
            | "imperva"
            | "incapsula"
            | "bitninja"
            | "akamai"
            | "fastly"
            | "sucuri"
    ) {
        return None;
    }
    let ver = ver_part.trim().trim_start_matches('v');
    let mut acc = String::new();
    let mut saw_digit = false;
    let mut saw_dot = false;
    for c in ver.chars() {
        if c.is_ascii_digit() {
            acc.push(c);
            saw_digit = true;
        } else if c == '.' && saw_digit {
            acc.push(c);
            saw_dot = true;
        } else {
            break;
        }
    }
    if !saw_digit || !saw_dot {
        return None;
    }
    let ver = acc.trim_end_matches('.').to_string();
    if ver.is_empty() {
        return None;
    }
    Some((name.to_string(), ver))
}

/// Extrait (name, version) depuis une entree httpx "Name:Version".
fn audit_tech_parse_httpx_token(raw: &str) -> Option<(String, String)> {
    let s = raw.trim();
    if s.is_empty() {
        return None;
    }
    if let Some((name, ver)) = s.split_once(':') {
        let name = name.trim();
        let ver = ver.trim();
        if name.is_empty() || name.len() > 64 || ver.is_empty() {
            return None;
        }
        if !ver.chars().any(|c| c.is_ascii_digit()) || !ver.contains('.') {
            return None;
        }
        return Some((name.to_string(), ver.to_string()));
    }
    None
}

#[cfg(test)]
mod tests_fallback {
    use super::*;

    #[test]
    fn parse_token_php_version() {
        assert_eq!(
            audit_tech_parse_token("PHP/8.2.0"),
            Some(("PHP".into(), "8.2.0".into()))
        );
    }

    #[test]
    fn parse_token_apache_with_parens() {
        assert_eq!(
            audit_tech_parse_token("Apache/2.4.7 (Ubuntu)"),
            Some(("Apache".into(), "2.4.7".into()))
        );
    }

    #[test]
    fn parse_token_no_version_returns_none() {
        assert_eq!(audit_tech_parse_token("Apache"), None);
        assert_eq!(audit_tech_parse_token(""), None);
    }

    #[test]
    fn parse_token_filters_waf_placeholders() {
        assert_eq!(audit_tech_parse_token("cloudflare"), None);
        assert_eq!(audit_tech_parse_token("Imperva"), None);
        assert_eq!(audit_tech_parse_token("BitNinja"), None);
        assert_eq!(audit_tech_parse_token("Cloudflare/1.0"), None);
    }

    #[test]
    fn parse_token_v_prefix() {
        assert_eq!(
            audit_tech_parse_token("TLS/v1.3"),
            Some(("TLS".into(), "1.3".into()))
        );
    }

    #[test]
    fn parse_token_comma_in_string() {
        assert_eq!(
            audit_tech_parse_token("Apache/2.4.7, nginx/1.22.1"),
            Some(("Apache".into(), "2.4.7".into()))
        );
    }

    #[test]
    fn parse_httpx_wordpress_version() {
        assert_eq!(
            audit_tech_parse_httpx_token("WordPress:7.1.2"),
            Some(("WordPress".into(), "7.1.2".into()))
        );
    }

    #[test]
    fn parse_httpx_site_kit() {
        assert_eq!(
            audit_tech_parse_httpx_token("Site Kit:1.188.0"),
            Some(("Site Kit".into(), "1.188.0".into()))
        );
    }

    #[test]
    fn parse_httpx_no_version_returns_none() {
        assert_eq!(audit_tech_parse_httpx_token("Apache HTTP Server"), None);
        assert_eq!(audit_tech_parse_httpx_token("Laravel"), None);
        assert_eq!(audit_tech_parse_httpx_token(""), None);
    }

    #[test]
    fn parse_httpx_version_too_short_returns_none() {
        assert_eq!(audit_tech_parse_httpx_token("Foo:1"), None);
    }
}
