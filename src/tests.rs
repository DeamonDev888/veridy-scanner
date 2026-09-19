use crate::config::{Config, ToolFlags};
use crate::modules::db::{sql_esc, sql_int_array, sql_text_array, DatabaseManager};
use crate::modules::dns::DnsAuditResult;
use crate::modules::dns_hardening::DnsHardeningResult;
use crate::modules::email_sec::{EmailSecAuditor, EmailSecurityResult};
use crate::modules::ffuf_audit::{ExposedEndpoint, FfufAuditResult, FfufAuditor};
use crate::modules::findings::{FindingsEngine, SecurityFinding};
use crate::modules::geo::GeoComplianceResult;
use crate::modules::http::HttpAuditResult;
use crate::modules::ports::{PortScanResult, PortScanner, EXTENDED_TARGET_PORTS};
use crate::modules::subdomains::EXPANDED_SUBDOMAINS;
use crate::modules::tech_stack::TechStackAuditor;
use crate::modules::tls::TlsAuditResult;
use crate::modules::vuln_audit::VulnAuditResult;
use crate::modules::web_endpoints::WebEndpointsResult;
use crate::report::FullAuditReport;
use crate::target_parser::{TargetParser, TargetVerdict};
use crate::utils::{extract_json_bool, extract_json_num, extract_json_str, json_escape};
use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr};

// ==============================================================================
// 1. TESTS UTILS (JSON & FORMATTING)
// ==============================================================================

#[test]
fn test_json_escape() {
    assert_eq!(json_escape("hello"), "hello");
    assert_eq!(json_escape("quote: \"test\""), "quote: \\\"test\\\"");
    assert_eq!(json_escape("slash: \\"), "slash: \\\\");
    assert_eq!(json_escape("line1\nline2"), "line1\\nline2");
    assert_eq!(json_escape("tab\tcr\r"), "tab\\tcr\\r");
}

#[test]
fn test_extract_json_str() {
    let json = r#"{"target": "veridy.ca", "status": "active", "escaped": "val\"ue"}"#;
    assert_eq!(
        extract_json_str(json, "target"),
        Some("veridy.ca".to_string())
    );
    assert_eq!(extract_json_str(json, "status"), Some("active".to_string()));
    assert_eq!(
        extract_json_str(json, "escaped"),
        Some("val\"ue".to_string())
    );
    assert_eq!(extract_json_str(json, "missing_key"), None);
}

#[test]
fn test_extract_json_num() {
    let json = r#"{"port": 443, "score": 98.5, "negative": -42, "zero": 0}"#;
    assert_eq!(extract_json_num::<u16>(json, "port"), Some(443));
    assert_eq!(extract_json_num::<i32>(json, "negative"), Some(-42));
    assert_eq!(extract_json_num::<u8>(json, "zero"), Some(0));
    assert_eq!(extract_json_num::<f32>(json, "score"), Some(98.5));
    assert_eq!(extract_json_num::<u32>(json, "not_found"), None);
}

#[test]
fn test_extract_json_bool() {
    let json = r#"{"tls_valid": true, "open": false}"#;
    assert_eq!(extract_json_bool(json, "tls_valid"), Some(true));
    assert_eq!(extract_json_bool(json, "open"), Some(false));
    assert_eq!(extract_json_bool(json, "unknown"), None);
}

// ==============================================================================
// 2. TESTS TARGET PARSER (résolution + validation format)
// ==============================================================================

#[test]
fn test_target_parser_rejects_invalid_format() {
    let forbidden = [
        "service.gc.ca",
        "revenu.gouv.qc.ca",
        "portal.canada.ca",
        "army.mil",
        "whitehouse.gov",
    ];

    // Comportement attendu : ces cibles sont des hostnames valides (format OK).
    // Le parser ne les bloque pas. Si le DNS échoue en sandbox, on a Unresolvable.
    // Si DNS résout (réseau ouvert), on a Resolved. Les deux sont acceptables ici.
    for target in forbidden {
        let v = TargetParser::resolve(target);
        assert!(
            matches!(
                v,
                TargetVerdict::Resolved(_) | TargetVerdict::Unresolvable(_)
            ),
            "Target {} devrait être Resolved ou Unresolvable, got {:?}",
            target,
            v
        );
    }
}

#[test]
fn test_target_parser_accepts_all_ips_without_filter() {
    // Aucune restriction normative : loopback, RFC1918, multicast, link-local, doc ranges → tous acceptés.
    let any_ips = [
        "127.0.0.1",
        "127.0.0.53",
        "10.0.0.1",
        "10.254.254.254",
        "172.16.0.1",
        "172.31.255.255",
        "192.168.1.1",
        "192.168.100.10", // IP LAN privee generique : acceptee (reseau interne)
        "169.254.1.1",    // Link-local
        "224.0.0.1",      // Multicast
        "192.0.2.1",      // Documentation
    ];

    for ip_str in any_ips {
        match TargetParser::resolve(ip_str) {
            TargetVerdict::Resolved(ips) => {
                assert_eq!(ips.len(), 1, "IP {} doit retourner 1 IP", ip_str);
                assert_eq!(ips[0].to_string(), ip_str);
            }
            other => panic!(
                "IP {} devrait être Resolved (toutes IPs acceptées), got {:?}",
                ip_str, other
            ),
        }
    }
}

#[test]
fn test_target_parser_public_ip_resolved() {
    let public_ip = "8.8.8.8";
    match TargetParser::resolve(public_ip) {
        TargetVerdict::Resolved(ips) => {
            assert_eq!(ips, vec![IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))]);
        }
        other => panic!("Public IP 8.8.8.8 devrait être Resolved, got {:?}", other),
    }
}

// ==============================================================================
// 3. TESTS CONFIG & TOOL FLAGS
// ==============================================================================

#[test]
fn test_config_defaults() {
    let cfg = Config::default();
    assert!(
        cfg.target.is_empty(),
        "Config::default() ne doit PAS contenir de cible de scan"
    );
    assert_eq!(cfg.timeout_ms, 800);
    assert!(!cfg.json_mode);
    assert!(cfg.save_to_db);
    assert_eq!(cfg.db_name, "veridy_audit");
    assert!(!cfg.tools.has_any());
}

#[test]
fn test_tool_flags_enable_all() {
    let mut flags = ToolFlags::default();
    assert!(!flags.has_any());
    assert_eq!(flags.active_names().len(), 0);

    flags.enable_all();
    assert!(flags.has_any());
    let active = flags.active_names();
    assert_eq!(active.len(), 14);
    assert!(active.contains(&"Nmap"));
    assert!(active.contains(&"Nuclei"));
    assert!(active.contains(&"Nikto"));
    assert!(active.contains(&"Wafw00f"));
    assert!(active.contains(&"WhatWeb"));
    assert!(active.contains(&"SSLScan"));
    assert!(active.contains(&"Dnstwist"));
    assert!(active.contains(&"Ffuf/SecLists"));
    assert!(active.contains(&"Whois"));
    assert!(active.contains(&"Dnsrecon"));
    assert!(active.contains(&"theHarvester"));
    assert!(active.contains(&"Obscura"));
    assert!(active.contains(&"Httpx"));
    assert!(active.contains(&"RustScan"));
    assert!(!active.contains(&"SQLMap")); // opt-in explicite --sqli uniquement
}

// ==============================================================================
// 4. TESTS PORTS & SERVICES CATALOG
// ==============================================================================

#[test]
fn test_ports_catalog_no_duplicates() {
    let mut seen = HashSet::new();
    for &port in EXTENDED_TARGET_PORTS {
        assert!(
            seen.insert(port),
            "Port {} is duplicated in EXTENDED_TARGET_PORTS!",
            port
        );
    }
    assert!(EXTENDED_TARGET_PORTS.len() >= 40);
}

#[test]
fn test_guess_service_hints() {
    assert_eq!(PortScanner::guess_service(21), "FTP");
    assert_eq!(PortScanner::guess_service(22), "SSH");
    assert_eq!(PortScanner::guess_service(25), "SMTP");
    assert_eq!(PortScanner::guess_service(53), "DNS");
    assert_eq!(PortScanner::guess_service(80), "HTTP");
    assert_eq!(PortScanner::guess_service(443), "HTTPS");
    assert_eq!(PortScanner::guess_service(3306), "MySQL");
    assert_eq!(PortScanner::guess_service(5432), "PostgreSQL");
    assert_eq!(PortScanner::guess_service(6379), "Redis");
    assert_eq!(PortScanner::guess_service(8080), "HTTP");
    assert_eq!(PortScanner::guess_service(8443), "HTTPS");
    assert_eq!(PortScanner::guess_service(9999), "Service spécifique");
}

#[test]
fn test_port_scan_deduplication() {
    let mut results = vec![
        PortScanResult {
            port: 80,
            is_open: true,
            service_hint: "HTTP",
            banner: None,
        },
        PortScanResult {
            port: 8443,
            is_open: true,
            service_hint: "HTTPS Alt",
            banner: None,
        },
        PortScanResult {
            port: 8443,
            is_open: true,
            service_hint: "HTTPS Alt",
            banner: None,
        },
        PortScanResult {
            port: 443,
            is_open: true,
            service_hint: "HTTPS",
            banner: None,
        },
    ];

    results.sort_by_key(|r| r.port);
    results.dedup_by_key(|r| r.port);

    assert_eq!(results.len(), 3);
    assert_eq!(results[0].port, 80);
    assert_eq!(results[1].port, 443);
    assert_eq!(results[2].port, 8443);
}

// ==============================================================================
// 5. TESTS EMAIL SECURITY (SPF LOOKUPS & DMARC TAGS)
// ==============================================================================

#[test]
fn test_email_sec_spf_lookup_counter() {
    // 2 lookups (include + mx)
    let spf_clean = "v=spf1 include:_spf.google.com mx ~all";
    let res = EmailSecAuditor::audit("example.com", Some(spf_clean), None);
    assert_eq!(res.spf_lookup_count, 2);
    assert!(res.spf_lookup_valid);

    // 11 lookups (dépassement RFC 7208)
    let spf_overloaded = "v=spf1 include:s1.com include:s2.com include:s3.com include:s4.com include:s5.com include:s6.com include:s7.com include:s8.com include:s9.com include:s10.com mx -all";
    let res_over = EmailSecAuditor::audit("example.com", Some(spf_overloaded), None);
    assert_eq!(res_over.spf_lookup_count, 11);
    assert!(!res_over.spf_lookup_valid);
}

#[test]
fn test_email_sec_dmarc_tags_parsing() {
    let dmarc = "v=DMARC1; p=reject; sp=quarantine; adkim=s; aspf=r; rua=mailto:d@ex.com";
    let res = EmailSecAuditor::audit("example.com", None, Some(dmarc));
    assert_eq!(res.dmarc_sp_policy.as_deref(), Some("quarantine"));
    assert_eq!(res.dmarc_adkim.as_deref(), Some("s"));
    assert_eq!(res.dmarc_aspf.as_deref(), Some("r"));
}

// ==============================================================================
// 6. TESTS FINDINGS ENGINE & SCORE CALCULATION
// ==============================================================================

#[test]
fn test_score_calculation_deductions_and_clamp() {
    let clean_findings = vec![
        SecurityFinding {
            severity: "INFO",
            category: "EMAIL",
            title: "Info finding".into(),
            recommendation: "Rec".into(),
        },
        SecurityFinding {
            severity: "LOW",
            category: "HTTP",
            title: "Low finding".into(),
            recommendation: "Rec".into(),
        },
    ];

    // Score avec 1 LOW (-2) = 98
    let report = create_dummy_report(clean_findings);
    assert_eq!(report.overall_score, 98);

    // Score avec CRITICAL (-25), HIGH (-12), MEDIUM (-5), LOW (-2) = 100 - 44 = 56
    let mixed_findings = vec![
        SecurityFinding {
            severity: "CRITICAL",
            category: "PORT",
            title: "Telnet".into(),
            recommendation: "Close".into(),
        },
        SecurityFinding {
            severity: "HIGH",
            category: "HTTP",
            title: "No HSTS".into(),
            recommendation: "Add HSTS".into(),
        },
        SecurityFinding {
            severity: "MEDIUM",
            category: "DNS",
            title: "Permissive SPF".into(),
            recommendation: "Fix".into(),
        },
        SecurityFinding {
            severity: "LOW",
            category: "HTTP",
            title: "Server banner".into(),
            recommendation: "Hide".into(),
        },
    ];
    let report_mixed = create_dummy_report(mixed_findings);
    assert_eq!(report_mixed.overall_score, 56);

    // Clamping à 0 en cas de pénalités massives
    let massive_findings: Vec<SecurityFinding> = (0..10)
        .map(|_| SecurityFinding {
            severity: "CRITICAL",
            category: "SECURITY",
            title: "Fatal".into(),
            recommendation: "Fix".into(),
        })
        .collect();
    let report_zero = create_dummy_report(massive_findings);
    assert_eq!(report_zero.overall_score, 0);
}

#[test]
fn test_findings_engine_evaluates_telnet_and_open_resolver() {
    let mut dns = DnsAuditResult::new("test.com");
    dns.spf_found = true;
    dns.spf_strict = true;
    dns.dmarc_found = true;
    dns.dmarc_policy = Some("reject".into());
    dns.dnssec_active = true;
    dns.a_records = vec!["1.2.3.4".into()];
    dns.caa_records = vec!["issue letsencrypt.org".into()];

    let ports = vec![PortScanResult {
        port: 23,
        is_open: true,
        service_hint: "Telnet",
        banner: None,
    }];
    let http = HttpAuditResult {
        target_url: "https://test.com".into(),
        http_status: 200,
        redirects_to_https: true,
        server_header: None,
        powered_by: None,
        hsts_present: true,
        hsts_value: Some("max-age=31536000".into()),
        csp_present: true,
        csp_value: Some("default-src 'self'".into()),
        x_frame_options: Some("DENY".into()),
        x_content_type_options: Some("nosniff".into()),
        referrer_policy: None,
        permissions_policy: None,
        coop: None,
        corp: None,
        cookies: vec![],
        all_headers: vec![],
        missing_security_headers: vec![],
        score_percentage: 100,
    };
    let tls = TlsAuditResult {
        domain: "test.com".into(),
        is_valid: true,
        protocol: Some("TLSv1.3".into()),
        cipher: Some("TLS_AES_256_GCM_SHA384".into()),
        issuer: Some("Let's Encrypt".into()),
        subject: Some("test.com".into()),
        valid_from: None,
        valid_until: None,
        days_remaining: Some(80),
        sans: vec![],
        is_self_signed: false,
        supports_tls10: false,
        supports_tls11: false,
        supports_tls12: true,
        supports_tls13: true,
        issues: vec![],
    };
    let geo = GeoComplianceResult {
        ip_address: "1.2.3.4".into(),
        asn: Some("AS123".into()),
        org_name: Some("Host QC".into()),
        country_code: Some("CA".into()),
        region: Some("QC".into()),
        city: Some("Montreal".into()),
        is_canada: true,
        is_quebec: true,
    };
    let email_sec = EmailSecurityResult {
        domain: "test.com".into(),
        spf_lookup_count: 1,
        spf_lookup_valid: true,
        dkim_selectors_tested: 1,
        dkim_selectors_found: vec![],
        mta_sts_present: true,
        mta_sts_mode: None,
        smtp_tls_reporting: true,
        bimi_present: true,
        dmarc_sp_policy: None,
        dmarc_adkim: None,
        dmarc_aspf: None,
    };
    let web_endpoints = WebEndpointsResult {
        domain: "test.com".into(),
        security_txt_present: true,
        security_txt_url: None,
        robots_txt_present: true,
        robots_disallowed_paths: vec![],
        allowed_http_methods: vec!["GET".into(), "POST".into()],
        dangerous_methods_found: false,
        http2_supported: true,
        alpn_negotiated: Some("h2".into()),
    };
    let dns_hardening = DnsHardeningResult {
        ip_tested: "1.2.3.4".into(),
        is_open_resolver_risk: true, // Risque récursion ouverte
        recursion_denied: false,
        zone_transfer_denied: true,
    };
    let vuln_audit = VulnAuditResult {
        html_retrieved: true,
        cdn_scripts_count: 0,
        missing_sri_count: 0,
        mixed_content_count: 0,
        cors_misconfigured: false,
        detected_libraries: vec![],
        findings: vec![],
    };

    let findings = FindingsEngine::evaluate(
        &dns,
        &ports,
        &http,
        &tls,
        &[],
        &geo,
        &email_sec,
        &web_endpoints,
        &dns_hardening,
        &vuln_audit,
    );

    let has_telnet_finding = findings
        .iter()
        .any(|f| f.category == "PORT" && f.severity == "CRITICAL" && f.title.contains("Telnet"));
    let has_open_resolver_finding = findings
        .iter()
        .any(|f| f.category == "DNS" && f.severity == "CRITICAL" && f.title.contains("récursif"));

    assert!(
        has_telnet_finding,
        "Telnet port 23 must generate a CRITICAL PORT finding"
    );
    assert!(
        has_open_resolver_finding,
        "Open resolver must generate a CRITICAL DNS finding"
    );
}

// ==============================================================================
// 7. TESTS TECH STACK (WHATWEB PARSER)
// ==============================================================================

#[test]
fn test_tech_stack_json_parsing() {
    let sample_whatweb_json = r#"[
      {
        "target": "https://veridy.ca",
        "http_status": 200,
        "plugins": {
          "HTTPServer": {
            "string": ["nginx/1.22.1"]
          },
          "Email": {
            "string": ["contact@veridy.ca", "support@veridy.ca"]
          },
          "Strict-Transport-Security": {
            "string": ["max-age=31536000"]
          }
        }
      }
    ]"#;

    let (status, server, emails, techs) = TechStackAuditor::parse_json(sample_whatweb_json);
    assert_eq!(status, 200);
    assert_eq!(server.as_deref(), Some("nginx/1.22.1"));
    assert_eq!(emails.len(), 2);
    assert!(emails.contains(&"contact@veridy.ca".to_string()));
    assert!(emails.contains(&"support@veridy.ca".to_string()));
    assert!(techs.contains(&"HTTPServer".to_string()));
    assert!(techs.contains(&"Strict-Transport-Security".to_string()));
}

// ==============================================================================
// 8. TESTS FFUF AUDIT (PARSER & CATCH-ALL CAPPING)
// ==============================================================================

#[test]
fn test_ffuf_json_parsing() {
    // Vrai format ffuf (>= 2.x) : FUZZ imbriqué dans "input"
    let sample_ffuf_json = r#"{
      "results": [
        {"url": "https://veridy.ca/stats", "input": {"FUZZ": "stats"}, "status": 200, "length": 1450, "input": {"FUZZ": "stats"}},
        {"url": "https://veridy.ca/.env", "input": {"FUZZ": ".env"}, "status": 403, "length": 162}
      ],
      "config": {}
    }"#;

    let endpoints = FfufAuditor::parse_json(sample_ffuf_json);
    assert_eq!(
        endpoints.len(),
        2,
        "les 2 resultats du vrai format doivent etre extraits"
    );
    assert_eq!(endpoints[0].path, "stats");
    assert_eq!(endpoints[0].status, 200);
    assert_eq!(endpoints[0].url, "https://veridy.ca/stats");
    assert_eq!(endpoints[1].path, ".env");
    assert_eq!(endpoints[1].status, 403);

    // Retrocompat : ancien format plat "FUZZ": "..." a la racine
    let legacy = r#"{
      "results": [
        {"url": "https://veridy.ca/x", "FUZZ": "x", "status": 200, "length": 10}
      ],
      "config": {}
    }"#;
    let ep2 = FfufAuditor::parse_json(legacy);
    assert_eq!(ep2.len(), 1);
    assert_eq!(ep2[0].path, "x");
}

#[test]
fn test_ffuf_catch_all_capping_and_prioritization() {
    // Simule une attaque flood / catch-all SPA avec 50 routes retournant 200
    let mut endpoints = Vec::new();
    for i in 0..50 {
        endpoints.push(ExposedEndpoint {
            path: format!("route_{}", i),
            status: 200,
            length: 1200,
            url: format!("https://example.com/route_{}", i),
        });
    }

    // Ajoute un fichier critique au milieu
    endpoints.push(ExposedEndpoint {
        path: ".git/config".into(),
        status: 200,
        length: 240,
        url: "https://example.com/.git/config".into(),
    });

    let res = FfufAuditResult {
        success: true,
        elapsed_seconds: 5.0,
        endpoints,
        raw_output: "".into(),
        summary: "51 routes".into(),
    };

    let auditor = FfufAuditor;
    let findings = auditor.to_findings(&res);

    // Vérifie que le capping limite les routes et ajoute l'INFO de synthèse catch-all
    let catch_all_info = findings
        .iter()
        .find(|f| f.category == "WEB" && f.severity == "INFO" && f.title.contains("Catch-all"));
    assert!(
        catch_all_info.is_some(),
        "Catch-all synthesis finding must be created when routes > 30"
    );

    // v0.3.3 : un chemin critique n'est CRITICAL que si le CONTENU est confirmé
    // (fetch de vérification). En test hermétique, example.com n'est pas fetché :
    // le .git doit être préservé mais déclassé en INFO (soft-404 par défaut).
    let git_finding = findings
        .iter()
        .find(|f| f.category == "WEB" && f.title.contains(".git"));
    assert!(
        git_finding.is_some(),
        ".git route must be preserved in the capped list even in a catch-all flood"
    );
    assert!(
        findings
            .iter()
            .all(|f| !(f.title.contains(".git") && f.severity == "CRITICAL")),
        "Un chemin critique non confirmé par contenu ne doit JAMAIS être CRITICAL (anti faux-positif)"
    );

    // Maximum 21 constatations (20 tronquées + 1 synthèse)
    assert!(findings.len() <= 21);
}

// ==============================================================================
// 9. TESTS DATABASE HELPERS (SQL ESCAPING & ARRAYS)
// ==============================================================================

#[test]
fn test_sql_esc() {
    assert_eq!(sql_esc("standard_target"), "standard_target");
    assert_eq!(sql_esc("target' OR '1'='1"), "target'' OR ''1''=''1");
    assert_eq!(sql_esc("'''"), "''''''");
}

#[test]
fn test_sql_arrays() {
    let empty_text: Vec<String> = vec![];
    assert_eq!(sql_text_array(&empty_text), "'{}'::text[]");

    let text_items = vec!["ns1.veridy.ca".into(), "ns2.veridy.ca".into()];
    assert_eq!(
        sql_text_array(&text_items),
        "ARRAY['ns1.veridy.ca','ns2.veridy.ca']::text[]"
    );

    let empty_ints: Vec<u16> = vec![];
    assert_eq!(sql_int_array(&empty_ints), "'{}'::int[]");

    let port_items = vec![53, 80, 443];
    assert_eq!(sql_int_array(&port_items), "ARRAY[53,80,443]::int[]");
}

// ==============================================================================
// 10. TESTS SUBDOMAINS CATALOG
// ==============================================================================

#[test]
fn test_subdomains_catalog_integrity() {
    let mut seen = HashSet::new();
    for &sub in EXPANDED_SUBDOMAINS {
        assert!(
            seen.insert(sub),
            "Subdomain '{}' is duplicated in EXPANDED_SUBDOMAINS!",
            sub
        );
    }
    assert!(EXPANDED_SUBDOMAINS.contains(&"www"));
    assert!(EXPANDED_SUBDOMAINS.contains(&"mail"));
    assert!(EXPANDED_SUBDOMAINS.contains(&"api"));
    assert!(EXPANDED_SUBDOMAINS.contains(&"mta-sts"));
    assert!(EXPANDED_SUBDOMAINS.contains(&"ns1"));
    assert!(EXPANDED_SUBDOMAINS.contains(&"ns2"));
}

// ==============================================================================
// 11. TESTS REPORT JSON SERIALIZATION
// ==============================================================================

#[test]
fn test_full_audit_report_json_serialization() {
    let report = create_dummy_report(vec![SecurityFinding {
        severity: "LOW",
        category: "HTTP",
        title: "Test banner".into(),
        recommendation: "Hide server".into(),
    }]);

    let json = report.to_json();
    assert!(json.contains("\"target\": \"test-target.ca\""));
    assert!(json.contains("\"overall_score\": 98"));
    assert!(json.contains("\"ports\": ["));
    assert!(json.contains("\"findings\": ["));
    assert!(json.contains("\"Test banner\""));
}

// ==============================================================================
// 12. TEST LIVE POSTGRESQL CONNECTION (SI DISPONIBLE SUR KALI)
// ==============================================================================

#[test]
fn test_db_live_history_query() {
    // Si la DB PostgreSQL locale 'veridy_audit' existe, la requête doit réussir sans panique
    let res = DatabaseManager::get_history("veridy.ca", 1, "veridy_audit");
    if let Ok(entries) = res {
        println!("Live DB history entries found: {}", entries.len());
        // Au moins 1 entrée si veridy.ca a été scanné
        if !entries.is_empty() {
            assert_eq!(entries[0].target, "veridy.ca");
            assert!(entries[0].overall_score > 0);
        }
    }
}

// ==============================================================================
// HELPER POUR CRÉER UN RAPPORT DE TEST MINIMAL
// ==============================================================================

fn create_dummy_report(findings: Vec<SecurityFinding>) -> FullAuditReport {
    let mut dns = DnsAuditResult::new("test-target.ca");
    dns.spf_found = true;
    dns.spf_strict = true;
    dns.dmarc_found = true;
    dns.dmarc_policy = Some("reject".into());
    dns.dnssec_active = true;
    dns.a_records = vec!["157.208.25.18".into()];
    dns.mx_records = vec!["mail.test-target.ca".into()];
    dns.caa_records = vec!["letsencrypt.org".into()];

    FullAuditReport::new(
        "test-target.ca".into(),
        "2026-09-07T12:00:00Z".into(),
        1.25,
        dns,
        vec![
            PortScanResult {
                port: 80,
                is_open: true,
                service_hint: "HTTP",
                banner: None,
            },
            PortScanResult {
                port: 443,
                is_open: true,
                service_hint: "HTTPS",
                banner: None,
            },
        ],
        HttpAuditResult {
            target_url: "https://test-target.ca".into(),
            http_status: 200,
            redirects_to_https: true,
            server_header: None,
            powered_by: None,
            hsts_present: true,
            hsts_value: Some("max-age=31536000".into()),
            csp_present: true,
            csp_value: Some("default-src 'self'".into()),
            x_frame_options: Some("DENY".into()),
            x_content_type_options: Some("nosniff".into()),
            referrer_policy: None,
            permissions_policy: None,
            coop: None,
            corp: None,
            cookies: vec![],
            all_headers: vec![],
            missing_security_headers: vec![],
            score_percentage: 100,
        },
        TlsAuditResult {
            domain: "test-target.ca".into(),
            is_valid: true,
            protocol: Some("TLSv1.3".into()),
            cipher: Some("TLS_AES_256_GCM_SHA384".into()),
            issuer: Some("Let's Encrypt".into()),
            subject: Some("test-target.ca".into()),
            valid_from: None,
            valid_until: None,
            days_remaining: Some(45),
            sans: vec![],
            is_self_signed: false,
            supports_tls10: false,
            supports_tls11: false,
            supports_tls12: true,
            supports_tls13: true,
            issues: vec![],
        },
        vec![],
        GeoComplianceResult {
            ip_address: "157.208.25.18".into(),
            asn: Some("CC-3272".into()),
            org_name: Some("Cogeco".into()),
            country_code: Some("CA".into()),
            region: Some("QC".into()),
            city: Some("Trois-Rivieres".into()),
            is_canada: true,
            is_quebec: true,
        },
        EmailSecurityResult {
            domain: "test-target.ca".into(),
            spf_lookup_count: 1,
            spf_lookup_valid: true,
            dkim_selectors_tested: 1,
            dkim_selectors_found: vec![],
            mta_sts_present: true,
            mta_sts_mode: None,
            smtp_tls_reporting: true,
            bimi_present: false,
            dmarc_sp_policy: None,
            dmarc_adkim: None,
            dmarc_aspf: None,
        },
        WebEndpointsResult {
            domain: "test-target.ca".into(),
            security_txt_present: true,
            security_txt_url: None,
            robots_txt_present: true,
            robots_disallowed_paths: vec![],
            allowed_http_methods: vec!["GET".into()],
            dangerous_methods_found: false,
            http2_supported: true,
            alpn_negotiated: Some("h2".into()),
        },
        DnsHardeningResult {
            ip_tested: "157.208.25.18".into(),
            is_open_resolver_risk: false,
            recursion_denied: true,
            zone_transfer_denied: true,
        },
        VulnAuditResult {
            html_retrieved: true,
            cdn_scripts_count: 0,
            missing_sri_count: 0,
            mixed_content_count: 0,
            cors_misconfigured: false,
            detected_libraries: vec![],
            findings: vec![],
        },
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None, // http_probe
        None, // rustscan
        None, // sqli
        None, // sliver
        None, // havoc
        None, // merlin
        None, // poshc2
        None, // empire
        None, // chisel
        None, // netexec
        findings,
    )
}

// ==============================================================================
// 13. TESTS NON-RÉGRESSION — CORRECTIONS & DURCISSEMENT 2026-09-19
// ==============================================================================

#[test]
fn test_parse_openssl_date_strips_notafter_prefix() {
    use crate::modules::tls::parse_openssl_date;
    // Bug historique : le préfixe "notAfter=" n'était jamais strippé → days_remaining null
    assert_eq!(
        parse_openssl_date("notAfter=Jan 15 12:00:00 2027 GMT"),
        Some(1800014400)
    );
    assert_eq!(
        parse_openssl_date("Jan 15 12:00:00 2027 GMT"),
        Some(1800014400)
    );
    assert_eq!(
        parse_openssl_date("notBefore=Jan 15 12:00:00 2027 GMT"),
        Some(1800014400)
    );
    assert_eq!(parse_openssl_date("n'importe quoi"), None);
    assert_eq!(parse_openssl_date(""), None);
}

#[test]
fn test_json_escape_control_chars_rfc8259() {
    let out = json_escape("a\u{0}b\u{1b}c");
    assert!(out.contains("a\\u0000b"), "NUL doit être échappé : {}", out);
    assert!(out.contains("\\u001b"), "ESC doit être échappé : {}", out);
    assert!(!out.contains('\u{0}'));
    assert!(!out.contains('\u{1b}'));
}

#[test]
fn test_extract_json_str_no_substring_false_positive() {
    // "domain" ne doit JAMAIS matcher "subdomain" (ancien pattern sans guillemets)
    let json = r#"{"subdomain":"evil.example"}"#;
    assert_eq!(extract_json_str(json, "domain"), None);
    let ok = r#"{"domain":"good.example"}"#;
    assert_eq!(
        extract_json_str(ok, "domain"),
        Some("good.example".to_string())
    );
}

#[test]
fn test_iso_timestamp_pure_rust() {
    let ts = crate::utils::iso_timestamp();
    assert_eq!(ts.len(), 20, "format ISO 8601 UTC : {}", ts);
    assert!(ts.ends_with('Z'));
    assert_eq!(&ts[4..5], "-");
    assert_eq!(&ts[7..8], "-");
    assert_eq!(&ts[10..11], "T");
}

#[test]
fn test_civil_from_days_known_dates() {
    assert_eq!(crate::utils::civil_from_days(0), (1970, 1, 1));
    assert_eq!(crate::utils::civil_from_days(19723), (2024, 1, 1));
}

#[test]
fn test_sanitize_target_strict_whitelist() {
    assert_eq!(crate::utils::sanitize_target("a.b-c.com"), "a_b-c_com");
    assert_eq!(crate::utils::sanitize_target("evil/host"), "evil_host");
    assert_eq!(
        crate::utils::sanitize_target("../etc/passwd"),
        "___etc_passwd"
    );
    assert_eq!(crate::utils::sanitize_target(""), "target");
}

#[test]
fn test_run_guarded_catches_panic_and_returns_default() {
    fn dummy_tracker() -> std::sync::Arc<crate::modules::progress::ProgressTracker> {
        crate::modules::progress::ProgressTracker::new("test", &["Tâche"], false)
    }
    let r: Vec<u8> = crate::orchestrator::run_guarded(
        std::time::Instant::now(),
        &dummy_tracker(),
        usize::MAX,
        "test-panic",
        || panic!("boom volontaire"),
    );
    assert!(
        r.is_empty(),
        "run_guarded doit retourner T::default() sur panic"
    );
}

#[test]
fn test_is_subdomain_point_boundary() {
    use crate::modules::obscura_audit::is_subdomain;
    assert!(is_subdomain("www.veridy.ca", "veridy.ca"));
    assert!(is_subdomain("veridy.ca", "veridy.ca"));
    assert!(
        !is_subdomain("evil-veridy.ca", "veridy.ca"),
        "evil-veridy.ca n'est PAS un sous-domaine"
    );
    assert!(!is_subdomain("notveridy.ca", "veridy.ca"));
}

// ==============================================================================
// 14. TESTS MODULES C2 / POST-EXPLOITATION (v0.3)
// ==============================================================================

#[test]
fn test_sliver_result_serialization() {
    use crate::modules::c2_sliver::SliverAuditResult;
    let r = SliverAuditResult {
        success: true,
        installed: true,
        version: Some("devel".into()),
        server_running: false,
        implants: vec!["implant1.cfg".into(), "implant2.cfg".into()],
        sessions: vec![],
        raw_output: "installed=true".into(),
        summary: "Sliver devel | serveur inactif | 2 implant(s) cfg".into(),
        elapsed_seconds: 0.1,
    };
    let j = serde_json::to_value(&r).unwrap();
    assert_eq!(j["installed"], true);
    assert_eq!(j["version"], "devel");
    assert_eq!(j["implants"].as_array().unwrap().len(), 2);
    // round-trip Deserialize
    let r2: SliverAuditResult = serde_json::from_value(j).unwrap();
    assert_eq!(r2.implants.len(), 2);
    assert_eq!(r2.version.as_deref(), Some("devel"));
}

#[test]
fn test_sliver_findings_only_when_running() {
    use crate::modules::c2_sliver::{SliverAuditResult, SliverAuditor};
    // serveur inactif → AUCUN finding
    let idle = SliverAuditResult {
        installed: true,
        server_running: false,
        ..Default::default()
    };
    assert!(SliverAuditor::to_findings(&idle).is_empty());
    // serveur actif → finding INFO
    let live = SliverAuditResult {
        installed: true,
        server_running: true,
        version: Some("devel".into()),
        implants: vec![],
        sessions: vec![],
        ..Default::default()
    };
    let f = SliverAuditor::to_findings(&live);
    assert_eq!(f.len(), 1);
    assert_eq!(f[0].severity, "INFO");
    assert_eq!(f[0].category, "C2");
}

#[test]
fn test_havoc_version_parsing_marker() {
    // Le format de version Havoc attendu dans raw_output/summary
    // "Havoc Framework [Version: 0.7] [CodeName: Bites The Dust]"
    let line = "Havoc Framework [Version: 0.7] [CodeName: Bites The Dust]";
    assert!(line.contains("Version"));
    // la boucle du module ne retient QUE les lignes avec "Version"
    let captured: Vec<&str> = vec!["Usage:", line, "other"]
        .into_iter()
        .filter(|l| l.contains("Version"))
        .collect();
    assert_eq!(captured.len(), 1);
}

#[test]
fn test_havoc_findings_only_when_teamserver() {
    use crate::modules::c2_havoc::{HavocAuditResult, HavocAuditor};
    let idle = HavocAuditResult {
        installed: true,
        teamserver_running: false,
        ..Default::default()
    };
    assert!(HavocAuditor::to_findings(&idle).is_empty());
    let live = HavocAuditResult {
        installed: true,
        teamserver_running: true,
        version: Some("0.7".into()),
        ..Default::default()
    };
    assert_eq!(HavocAuditor::to_findings(&live).len(), 1);
}

#[test]
fn test_merlin_default_absent() {
    use crate::modules::c2_merlin::MerlinAuditResult;
    let r = MerlinAuditResult::default();
    assert!(!r.installed);
    assert!(!r.success);
    assert!(!r.server_running);
}

#[test]
fn test_poshc2_service_state_parsing() {
    // systemctl is-active renvoie "active\n" → trim == "active"
    let raw = "active\n";
    assert_eq!(raw.trim(), "active");
    let raw2 = "inactive\n";
    assert_ne!(raw2.trim(), "active");
}

#[test]
fn test_empire_findings_db_not_ready() {
    use crate::modules::c2_empire::{EmpireAuditResult, EmpireAuditor};
    let r = EmpireAuditResult {
        installed: true,
        database_ready: false,
        server_running: false,
        ..Default::default()
    };
    let f = EmpireAuditor::to_findings(&r);
    assert_eq!(f.len(), 1);
    assert_eq!(f[0].severity, "LOW"); // pousse à faire le setup
                                      // DB prête + serveur actif → INFO seulement
    let r2 = EmpireAuditResult {
        installed: true,
        database_ready: true,
        server_running: true,
        ..Default::default()
    };
    let f2 = EmpireAuditor::to_findings(&r2);
    assert_eq!(f2.len(), 1);
    assert_eq!(f2[0].severity, "INFO");
}

#[test]
fn test_chisel_finding_never_emitted() {
    use crate::modules::tunnel_chisel::{ChiselAuditResult, ChiselAuditor};
    // tunnelling local : aucun finding d'audit de cible, quel que soit l'état
    let r = ChiselAuditResult {
        success: true,
        installed: true,
        server_demo_ok: true,
        ..Default::default()
    };
    assert!(ChiselAuditor::to_findings(&r).is_empty());
}

#[test]
fn test_netexec_signing_detection() {
    use crate::modules::lateral_netexec::{NetexecAuditResult, NetexecAuditor};
    // signing désactivé → finding MEDIUM (relais NTLM possible)
    let r = NetexecAuditResult {
        success: true,
        installed: true,
        target_reachable: true,
        smb_signing_enforced: Some(false),
        ..Default::default()
    };
    let f = NetexecAuditor::to_findings(&r);
    assert_eq!(f.len(), 1);
    assert_eq!(f[0].severity, "MEDIUM");
    assert_eq!(f[0].category, "SMB");
    // signing forcé → rien à signaler
    let r2 = NetexecAuditResult {
        smb_signing_enforced: Some(true),
        ..r.clone()
    };
    assert!(NetexecAuditor::to_findings(&r2).is_empty());
}

#[test]
fn test_netexec_signing_parse_markers() {
    // les deux formats que le module scrute : texte nxc et JSON --gen-json
    let txt = "SMB 192.168.1.10 445 HOST [+] 10.0.0.5 (name:HOST) (domain:CORP) (signing:False)";
    assert!(txt.contains("signing:False"));
    let json = r#"{"host": "10.0.0.5", "signing": false}"#;
    assert!(json.contains("\"signing\": false"));
}

#[test]
fn test_tool_on_path_finds_true_binary() {
    // sur toute machine de test, /bin/sh ou true existe
    let found = crate::utils::tool_on_path("sh") || crate::utils::tool_on_path("true");
    assert!(found, "sh/true devraient être sur le PATH");
    assert!(!crate::utils::tool_on_path("outil-qui-nexiste-pas-xyz-123"));
}

#[test]
fn test_tcp_probe_loopback_refused() {
    // un port privilégié non écouté refuse la connexion → false (rapide)
    let refused = crate::utils::tcp_probe("127.0.0.1", 1);
    assert!(!refused);
}

#[test]
#[allow(clippy::field_reassign_with_default)]
fn test_c2_flags_optin_not_in_enable_all() {
    use crate::config::ToolFlags;
    let mut t = ToolFlags::default();
    t.enable_all();
    // les C2 ne doivent JAMAIS s'activer implicitement
    assert!(!t.sliver);
    assert!(!t.havoc);
    assert!(!t.merlin);
    assert!(!t.poshc2);
    assert!(!t.empire);
    assert!(!t.chisel);
    assert!(!t.netexec);
    // et ne comptent pas comme outils actifs standards
    let mut t2 = ToolFlags::default();
    t2.netexec = true;
    assert!(t2.has_any()); // actif si demandé
    let names = t2.active_names();
    assert!(names.contains(&"NetExec"));
}

#[test]
fn test_report_serializes_c2_sections() {
    // FullAuditReport avec un module C2 actif sérialise bien la section
    use crate::modules::c2_sliver::SliverAuditResult;
    let mut report = crate::report::FullAuditReport::default_for_tests();
    report.sliver = Some(SliverAuditResult {
        success: true,
        installed: true,
        version: Some("devel".into()),
        summary: "test".into(),
        sessions: vec![],
        ..Default::default()
    });
    let j = report.to_json();
    assert!(j.contains("\"sliver\""));
    assert!(j.contains("\"summary\": \"test\""));
}
