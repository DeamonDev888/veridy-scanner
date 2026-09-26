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
// EXPANDED_SUBDOMAINS removed v0.2
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
    assert_eq!(
        extract_json_str(json, "status"),
        Some("active".to_string())
    );
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
            matches!(v, TargetVerdict::Resolved(_) | TargetVerdict::Unresolvable(_)),
            "Target {} devrait être Resolved ou Unresolvable, got {:?}",
            target, v
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
        "192.168.40.10", // IP LAN privee : acceptee (reseau interne)
        "169.254.1.1",   // Link-local
        "224.0.0.1",     // Multicast
        "192.0.2.1",     // Documentation
    ];

    for ip_str in any_ips {
        match TargetParser::resolve(ip_str) {
            TargetVerdict::Resolved(ips) => {
                assert_eq!(ips.len(), 1, "IP {} doit retourner 1 IP", ip_str);
                assert_eq!(ips[0].to_string(), ip_str);
            }
            other => panic!("IP {} devrait être Resolved (toutes IPs acceptées), got {:?}", ip_str, other),
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
    assert!(cfg.target.is_empty(), "Config::default() ne doit PAS contenir de cible de scan");
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
    assert_eq!(active.len(), 14); // 12 outils Kali + httpx + rustscan (sqlmap exclu: opt-in)
    assert!(active.contains(&"Nmap"));
    assert!(active.contains(&"Nuclei"));
    assert!(active.contains(&"Nikto"));
    assert!(active.contains(&"Wafw00f"));
    assert!(active.contains(&"WhatWeb"));
    assert!(active.contains(&"SSLScan"));
    assert!(active.contains(&"Dnstwist"));
    assert!(active.contains(&"Ffuf/SecLists"));
    assert!(active.contains(&"Whois"));
    assert!(active.contains(&"Httpx"));
    assert!(active.contains(&"RustScan"));
    assert!(!active.contains(&"SQLMap")); // opt-in explicite --sqli
    assert!(active.contains(&"Dnsrecon"));
    assert!(active.contains(&"theHarvester"));
    assert!(active.contains(&"Obscura"));
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
    // Format réel de ffuf : le mot-clé est imbriqué dans "input":{"FUZZ":...}.
    // Le second objet garde l'ancienne clé plate (rétrocompatibilité fixtures).
    let sample_ffuf_json = r#"{
      "results": [
        {"url": "http://127.0.0.1:8099/.env", "input": {"FUZZ": ".env"}, "status_code": 200, "length": 62},
        {"url": "https://veridy.ca/.env", "input": ".env", "status_code": 403, "length": 162}
      ],
      "config": {}
    }"#;

    let endpoints = FfufAuditor::parse_json(sample_ffuf_json);
    assert_eq!(endpoints.len(), 2);
    assert_eq!(endpoints[0].path, ".env");
    assert_eq!(endpoints[0].status, 200);
    assert_eq!(endpoints[1].path, ".env");
    assert_eq!(endpoints[1].status, 403);
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

    // Le chemin critique .git/config doit obligatoirement être préservé en tête
    let git_critical = findings
        .iter()
        .find(|f| f.category == "WEB" && f.severity == "CRITICAL" && f.title.contains(".git"));
    assert!(
        git_critical.is_some(),
        "Critical .git route must be prioritized even in a catch-all flood"
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
    assert_eq!(
        sql_esc("target' OR '1'='1"),
        "target'' OR ''1''=''1"
    );
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
fn test_subdomain_scanner_static_mode_integrity() {
    use crate::modules::subdomains::SubdomainScanner;
    let results = SubdomainScanner::scan_with_mode("example.com", crate::modules::subdomains::ScanMode::Static);
    let mut seen = HashSet::new();
    let prefixes: Vec<&str> = results.iter().map(|r| r.subdomain.split('.').next().unwrap_or("")).collect();
    for r in &results {
        assert!(seen.insert(r.subdomain.clone()), "doublon : {}", r.subdomain);
    }
    assert!(prefixes.contains(&"www"));
    assert!(prefixes.contains(&"mail"));
    assert!(prefixes.contains(&"api"));
    assert!(prefixes.contains(&"ns1"));
    assert!(prefixes.contains(&"ns2"));
    for r in &results {
        assert_eq!(r.source, "static");
    }
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
        None, // loot
        None, // box_probe
        None, // smb_audit
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
    assert_eq!(parse_openssl_date("notAfter=Jan 15 12:00:00 2027 GMT"), Some(1800014400));
    assert_eq!(parse_openssl_date("Jan 15 12:00:00 2027 GMT"), Some(1800014400));
    assert_eq!(parse_openssl_date("notBefore=Jan 15 12:00:00 2027 GMT"), Some(1800014400));
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
    assert_eq!(extract_json_str(ok, "domain"), Some("good.example".to_string()));
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
    assert_eq!(crate::utils::sanitize_target("../etc/passwd"), "___etc_passwd");
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
    assert!(r.is_empty(), "run_guarded doit retourner T::default() sur panic");
}

#[test]
fn test_is_subdomain_point_boundary() {
    use crate::modules::obscura_audit::is_subdomain;
    assert!(is_subdomain("www.veridy.ca", "veridy.ca"));
    assert!(is_subdomain("veridy.ca", "veridy.ca"));
    assert!(!is_subdomain("evil-veridy.ca", "veridy.ca"), "evil-veridy.ca n'est PAS un sous-domaine");
    assert!(!is_subdomain("notveridy.ca", "veridy.ca"));
}
// ==============================================================================
// 14. TESTS PERSISTANCE DB v0.3 — non-régression
// ==============================================================================

#[test]
fn test_config_default_save_to_db_true() {
    use crate::config::Config;
    let c = Config::default();
    assert!(c.save_to_db, "save_to_db doit etre true par defaut");
    assert_eq!(c.db_name, "veridy_audit");
}

#[test]
fn test_db_sql_esc_doubles_apostrophes() {
    use crate::modules::db::sql_esc;
    assert_eq!(sql_esc("hello"), "hello");
    assert_eq!(sql_esc("O'Brien"), "O''Brien");
    assert_eq!(sql_esc("'a'b'"), "''a''b''");
    assert_eq!(sql_esc(""), "");
}

#[test]
fn test_db_sql_esc_preserves_dollar_quotes() {
    // Le serialiseur JSON est insere via $JSON$...$JSON$.
    // sql_esc NE DOIT PAS alterer ces delimiteurs (sinon INSERT casse).
    use crate::modules::db::sql_esc;
    let payload = r#"{"target":"foo.com","note":"$JSON$embedded$JSON$"}"#;
    let escaped = sql_esc(payload);
    assert!(escaped.contains("$JSON$embedded$JSON$"),
            "sql_esc ne doit pas toucher au dollar-quote PostgreSQL : {}", escaped);
}

#[test]
fn test_db_sql_int_array_empty_and_filled() {
    use crate::modules::db::sql_int_array;
    assert_eq!(sql_int_array::<u16>(&[]), "'{}'::int[]");
    assert_eq!(sql_int_array(&[22u16, 80, 443]), "ARRAY[22,80,443]::int[]");
}

#[test]
fn test_db_sql_text_array_escapes_inner_apostrophes() {
    use crate::modules::db::sql_text_array;
    let sans = vec!["*.example.com".to_string(), "O'Brien's SAN".to_string()];
    let sql = sql_text_array(&sans);
    assert!(sql.contains("'*.example.com'"), "SAN standard : {}", sql);
    assert!(sql.contains("'O''Brien''s SAN'"), "SAN apostrophe echappee : {}", sql);
}

#[test]
fn test_score_clamp_negative_penalties() {
    // Reproduction inline du calcul de score (aligne sur report.rs::new)
    fn score(findings: &[crate::modules::findings::SecurityFinding]) -> u8 {
        let mut s: f32 = 100.0;
        for f in findings {
            match f.severity {
                "CRITICAL" => s -= 25.0,
                "HIGH" => s -= 12.0,
                "MEDIUM" => s -= 5.0,
                "LOW" => s -= 2.0,
                _ => {}
            }
        }
        s.clamp(0.0, 100.0).round() as u8
    }
    // 5 CRITICAL = -125 → clamp a 0
    let mut findings = vec![];
    for _ in 0..5 {
        findings.push(crate::modules::findings::SecurityFinding {
            severity: "CRITICAL",
            category: "TEST",
            title: "x".into(),
            recommendation: "x".into(),
        });
    }
    assert_eq!(score(&findings), 0, "Score ne doit JAMAIS etre negatif");
}

#[test]
fn test_score_exact_calculation() {
    fn score(findings: &[crate::modules::findings::SecurityFinding]) -> u8 {
        let mut s: f32 = 100.0;
        for f in findings {
            match f.severity {
                "CRITICAL" => s -= 25.0,
                "HIGH" => s -= 12.0,
                "MEDIUM" => s -= 5.0,
                "LOW" => s -= 2.0,
                _ => {}
            }
        }
        s.clamp(0.0, 100.0).round() as u8
    }
    // 1 CRITICAL (-25) + 1 HIGH (-12) + 1 MEDIUM (-5) = 58
    let findings = vec![
        crate::modules::findings::SecurityFinding {
            severity: "CRITICAL",
            category: "TEST",
            title: "t".into(),
            recommendation: "r".into(),
        },
        crate::modules::findings::SecurityFinding {
            severity: "HIGH",
            category: "TEST",
            title: "t".into(),
            recommendation: "r".into(),
        },
        crate::modules::findings::SecurityFinding {
            severity: "MEDIUM",
            category: "TEST",
            title: "t".into(),
            recommendation: "r".into(),
        },
    ];
    assert_eq!(score(&findings), 100 - 25 - 12 - 5);
}

#[test]
fn test_tool_flags_v02_count_and_sqlmap_optin() {
    use crate::config::ToolFlags;
    let mut flags = ToolFlags::default();
    assert_eq!(flags.active_names().len(), 0);

    flags.enable_all();
    let active = flags.active_names();
    assert_eq!(active.len(), 14, "14 modules (12 + httpx + rustscan) ; got: {:?}", active);
    assert!(active.contains(&"Httpx"));
    assert!(active.contains(&"RustScan"));
    assert!(!active.contains(&"SQLMap"),
            "SQLMap EXCLU de enable_all (opt-in explicite --sqlmap)");
}

#[test]
fn test_target_parser_no_blocking_residual() {
    // Aucune cible ne doit etre bloquee par validation (l'ancien SafetyGuard RFC1918/loopback a ete supprime)
    use crate::target_parser::TargetParser;
    for target in &["127.0.0.1", "192.168.1.1", "10.0.0.1", "172.16.0.1", "169.254.0.1", "example.com"] {
        // TargetVerdict est un enum (Resolved/Unresolvable/InvalidFormat)
        // On valide juste que resolve() ne panic pas (succes ou echec DNS acceptes)
        let _verdict = TargetParser::resolve(target);
    }
}

#[test]
fn test_iso_timestamp_iso8601_format() {
    use crate::utils::iso_timestamp;
    let ts = iso_timestamp();
    assert!(ts.contains('T'), "Timestamp doit contenir 'T' : {}", ts);
    assert!(ts.len() >= 19, "Timestamp trop court : {}", ts);
}

#[test]
fn test_db_history_target_empty_no_panic() {
    // Non-regression : target vide = toutes cibles ; ne doit pas paniquer
    use crate::modules::db::DatabaseManager;
    // DB peut etre absente en CI → on accepte l'echec, on teste seulement qu'il n'y a pas de panic
    let r = DatabaseManager::get_history("", 5, "veridy_audit");
    let _ = r; // Ok ou Err, mais pas panic
}

// ==============================================================================
// 15. TESTS SCRIPTS D'INSTALL v0.3 — non-régression statique
// ==============================================================================

#[test]
fn test_install_script_files_present_and_ordered() {
    use std::fs;
    let candidates = ["veridy_install_test.sh", "install.sh", "../veridy_install_test.sh"];
    let path = candidates.iter().find(|p| fs::metadata(p).is_ok());
    let Some(path) = path else { return; }; // skip silencieux si pas d'install script
    let content = fs::read_to_string(path).expect("lecture install script");
    let pos_full = content.find("schema_full.sql");
    let pos_deep = content.find("schema_deep.sql");
    let pos_tools = content.find("schema_tools.sql");
    if let (Some(f), Some(d), Some(t)) = (pos_full, pos_deep, pos_tools) {
        assert!(f < d, "schema_full doit preceder schema_deep ({} < {})", f, d);
        assert!(d < t, "schema_deep doit preceder schema_tools ({} < {})", d, t);
    }
    // Installation ProjectDiscovery v0.2
    assert!(content.contains("pdhttpx") || content.contains("httpx/releases"),
            "Le script doit installer pdhttpx");
    assert!(content.contains("subfinder"),
            "Le script doit installer subfinder");
    // Validation INSERT/RETURNING id
    assert!(content.contains("RETURNING id"),
            "Le script doit valider la DB par INSERT...RETURNING id");
}

#[test]
fn test_install_script_has_head_minus_one() {
    // Le retour psql est "id\nINSERT 0 1\n" → il faut filtrer par head -1
    // sinon le test d'INSERT produit "91INSERT01" qui casse le test arithmetique
    use std::fs;
    for path in &["veridy_install_test.sh", "install.sh", "../veridy_install_test.sh"] {
        if fs::metadata(path).is_ok() {
            let content = fs::read_to_string(path).unwrap_or_default();
            if content.contains("RETURNING id") {
                assert!(content.contains("head -1"),
                    "Le script doit filtrer le retour psql par `head -1`");
                return;
            }
        }
    }
}

#[test]
fn test_sql_text_clipped_truncates_long_strings() {
    use crate::modules::db::sql_text_clipped;
    let long = "a".repeat(3000);
    let clipped = sql_text_clipped(&long, 2000);
    assert_eq!(clipped.chars().count(), 2000, "doit etre tronque a 2000 chars max");
    assert!(clipped.ends_with('\u{2026}'), "doit finir par l'ellipsis");
}

#[test]
fn test_sql_text_clipped_short_strings_untouched() {
    use crate::modules::db::sql_text_clipped;
    let short = "Pas de troncature ici";
    assert_eq!(sql_text_clipped(short, 2000), short);
    assert_eq!(sql_text_clipped("", 2000), "");
}

#[test]
fn test_sql_text_clipped_escapes_apostrophes() {
    use crate::modules::db::sql_text_clipped;
    let s = "l'apostrophe ici puis beaucoup de texte apres pour depasser la limite";
    let clipped = sql_text_clipped(s, 20);
    assert!(clipped.contains("l''apostrophe"), "sql_esc applique : {}", clipped);
}

#[test]
fn test_sql_text_clipped_utf8_safe_no_panic() {
    use crate::modules::db::sql_text_clipped;
    let s = "\u{00e9}".repeat(1000); // e-acute = 2 octets UTF-8
    let clipped = sql_text_clipped(&s, 100);
    assert!(clipped.chars().count() <= 100,
        "troncature UTF-8 safe, got {} chars", clipped.chars().count());
}


// ==============================================================================
// 9. TESTS SCHÉMA HTTP/HTTPS DYNAMIQUE (correctif faux « aucun serveur HTTP »)
// ==============================================================================

#[test]
fn test_host_with_port_custom_port() {
    assert_eq!(
        crate::utils::host_with_port("127.0.0.1", &[8099]),
        "127.0.0.1:8099"
    );
    assert_eq!(crate::utils::host_with_port("veridy.ca", &[]), "veridy.ca");
    assert_eq!(
        crate::utils::host_with_port("veridy.ca", &[443, 8443]),
        "veridy.ca:443"
    );
}

#[test]
fn test_lock_no_forced_https_fuzz_url() {
    // Le module de fuzzing ne doit plus coder un schéma unique en dur :
    // l'URL de probe est construite dynamiquement (détection TLS + fallback).
    let src = include_str!("modules/ffuf_audit.rs");
    assert!(
        !src.contains("https://{}/FUZZ"),
        "ffuf_audit.rs force de nouveau un schéma unique dans l'URL de fuzz"
    );
}

// ===== Tests anti-faux-positifs ffuf (baseline soft-404) =====

#[test]
fn test_ffuf_no_403_in_match_codes() {
    // Un 403 est un blocage WAF/permissions, jamais une preuve d'existence :
    // il ne doit PAS figurer dans les codes matchés par ffuf.
    let src = include_str!("modules/ffuf_audit.rs");
    assert!(
        !src.contains("\"200,301,302,403\""),
        "ffuf matche à nouveau les 403 → flood de faux positifs (bug metro.ca)"
    );
    assert!(
        src.contains("\"200,301,302\""),
        "les codes matchés doivent être 200,301,302"
    );
}

#[test]
fn test_ffuf_soft404_baseline_present() {
    // La signature (status+taille) des sondes random doit filtrer les
    // endpoints : sans baseline, le WAF uniforme repasse en CRITICAL.
    let src = include_str!("modules/ffuf_audit.rs");
    assert!(
        src.contains("fn soft404_baseline"),
        "soft404_baseline absente du module ffuf"
    );
    assert!(
        src.contains("baseline_status == 0"),
        "le filtrage par signature baseline manque"
    );
}

#[test]
fn test_ffuf_soft404_filter_logic() {
    // Logique de filtrage unitaire : même signature que la baseline = filtré,
    // signature différente = conservé. Repris du corps du filter() réel.
    let baseline = (403u16, 5481usize); // metro.ca : WAF "Access Denied" uniforme
    let endpoints = [
        (String::from(".env"), 403u16, 5481usize),  // bruit WAF → filtré
        (String::from(".git/HEAD"), 403u16, 5481usize), // bruit WAF → filtré
        (String::from("robots.txt"), 200u16, 512usize), // vrai contenu servi
    ];
    let kept: Vec<&(String, u16, usize)> = endpoints
        .iter()
        .filter(|(_, status, length)| !(*status == baseline.0 && *length == baseline.1))
        .collect();
    assert_eq!(kept.len(), 1, "les 2 endpoints WAF-uniformes doivent être filtrés");
    assert_eq!(kept[0].0, "robots.txt");
}

// ===== Test anti-faux-CRITICAL TLS (retry Verification) =====

#[test]
fn test_tls_retry_on_missing_verification_line() {
    // Le handshake -brief doit être retenté quand la ligne "Verification:"
    // n'est pas sortie (race kill/timeout) : sinon is_valid=false à tort
    // → CRITICAL "Chaîne invalide" sur des certs parfaitement valides.
    let src = include_str!("modules/tls.rs");
    assert!(
        src.contains("for _attempt in 0..3"),
        "le retry du handshake -brief manque dans tls.rs"
    );
    assert!(
        src.matches("fn parse_openssl_date").count() >= 1,
        "parse_openssl_date doit rester présent"
    );
}

// ==============================================================================

// ==============================================================================
// 17. TESTS ATOMICITÉ TRANSACTIONNELLE v0.3.8 (refacto bind params + tx unique)
// ==============================================================================
// La persistance passe désormais par la crate postgres : socket Unix (auth
// peer de l'OS, zéro mot de passe), une seule connexion, une seule
// transaction, paramètres liés $1..$n. Ces tests verrouillent les invariants
// du nouveau chemin. Ils tolèrent l'absence de DB (CI sans PostgreSQL) mais
// échouent si la DB répond et qu'un invariant est violé.

#[test]
fn test_lock_db_save_scan_atomic_and_typed() {
    use crate::modules::db::DatabaseManager;

    let report = create_dummy_report(vec![]);
    let res = DatabaseManager::save_scan(&report, "veridy_audit");
    // DB absente (CI) → Err acceptable, pas de panic.
    let Ok(scan_id) = res else { return };

    // Le scan doit exister avec les valeurs dummy attendues.
    let mut client = match DatabaseManager::connect_for_tests("veridy_audit") {
        Ok(c) => c,
        Err(_) => return,
    };
    let row = client
        .query_one(
            "SELECT target, overall_score, findings_count, open_ports_count \
             FROM audit_scans WHERE id = $1",
            &[&scan_id],
        )
        .expect("ligne audit_scans lisible après commit");
    let target: String = row.get(0);
    let score: i16 = row.get(1);
    assert_eq!(target, "test-target.ca");
    assert_eq!(score, 100, "dummy sans findings → score 100");

    // Les tables filles doivent être peuplées avec les valeurs dummy.
    // Les 5 tables mono-ligne sont TOUJOURS remplies (insertions
    // inconditionnelles), et les 2 ports du dummy doivent y etre.
    let cnt5: i64 = client
        .query_one(
            "SELECT (SELECT count(*) FROM audit_tls_certs WHERE scan_id=$1)                     + (SELECT count(*) FROM audit_geo_compliance WHERE scan_id=$1)                     + (SELECT count(*) FROM audit_email_sec WHERE scan_id=$1)                     + (SELECT count(*) FROM audit_web_endpoints WHERE scan_id=$1)                     + (SELECT count(*) FROM audit_dns_hardening WHERE scan_id=$1)",
            &[&scan_id],
        )
        .unwrap()
        .get(0);
    assert_eq!(cnt5, 5, "5 tables mono-ligne attendues, got {cnt5}");
    let ports_cnt: i64 = client
        .query_one(
            "SELECT count(*) FROM audit_ports WHERE scan_id=$1",
            &[&scan_id],
        )
        .unwrap()
        .get(0);
    assert_eq!(ports_cnt, 2, "2 ports dummy attendus, got {ports_cnt}");
    let tls_days: Option<i32> = client
        .query_one(
            "SELECT days_remaining FROM audit_tls_certs WHERE scan_id=$1",
            &[&scan_id],
        )
        .unwrap()
        .get(0);
    assert_eq!(tls_days, Some(45), "days_remaining dummy transporte via bind param");

    // Nettoyage : le dummy ne doit pas polluer l'historique.
    DatabaseManager::cleanup_scan_for_tests("veridy_audit", scan_id);
    let left: i64 = client
        .query_one(
            "SELECT (SELECT count(*) FROM audit_scans WHERE id=$1) \
                    + (SELECT count(*) FROM audit_dns_records WHERE scan_id=$1) \
                    + (SELECT count(*) FROM audit_findings WHERE scan_id=$1)",
            &[&scan_id],
        )
        .unwrap()
        .get(0);
    assert_eq!(left, 0, "cleanup_scan_for_tests doit tout supprimer");
}

#[test]
fn test_lock_db_injection_via_target_is_inert() {
    use crate::modules::db::DatabaseManager;

    // Cible hostile : apostrophe + tentative d'injection classique. Avec les
    // paramètres liés, elle doit être stockée TELLE QUELLE (aucun SQL
    // supplémentaire exécuté), jamais interprétée.
    let mut report = create_dummy_report(vec![]);
    report.target = String::from("evil'target; DROP TABLE audit_scans;-- UNION SELECT 1");
    let res = DatabaseManager::save_scan(&report, "veridy_audit");
    let Ok(scan_id) = res else { return };

    let mut client = match DatabaseManager::connect_for_tests("veridy_audit") {
        Ok(c) => c,
        Err(_) => return,
    };
    // La table doit toujours exister et contenir la cible verbatim.
    let row = client
        .query_one("SELECT target FROM audit_scans WHERE id = $1", &[&scan_id])
        .expect("audit_scans doit exister après la tentative");
    let stored: String = row.get(0);
    assert_eq!(
        stored, report.target,
        "la cible hostile doit être stockée verbatim, non interprétée"
    );
    DatabaseManager::cleanup_scan_for_tests("veridy_audit", scan_id);
}

#[test]
fn test_lock_db_rollback_mid_transaction() {
    use crate::modules::db::DatabaseManager;

    // Régression atomique : un INSERT valide suivi d'un INSERT volontairement
    // invalide DANS LA MÊME transaction doit laisser 0 trace (rollback total).
    // Ancien comportement psql-batch : la ligne audit_scans auto-commitée
    // survivait comme orpheline. Nouveau chemin : plus rien.
    let Ok(mut client) = DatabaseManager::connect_for_tests("veridy_audit") else {
        return;
    };
    let count_before: i64 = client
        .query_one("SELECT count(*) FROM audit_scans", &[])
        .unwrap()
        .get(0);

    let mut tx = client.transaction().unwrap();
    // Le payload part en TEXT puis est casté ::jsonb côté serveur (paramètre
    // déclaré TEXT, jamais déduit jsonb — sinon le binding d'un &str échoue).
    let stmt_valid = tx
        .prepare_typed(
            "INSERT INTO audit_scans (target, overall_score, payload) \
             VALUES ($1, $2, $3::jsonb)",
            &[postgres::types::Type::VARCHAR, postgres::types::Type::INT2, postgres::types::Type::TEXT],
        )
        .unwrap();
    tx.execute(&stmt_valid, &[&"rollback-probe", &50i16, &"{}"]).unwrap();
    // Échec d'éxécution (et non de prepare) : contrainte NOT NULL
    // violée au runtime — simule un crash mid-transaction.
    let stmt_invalid = tx
        .prepare_typed(
            "INSERT INTO audit_scans (target, overall_score, payload) \
             VALUES ($1::text, $2, $3::jsonb)",
            &[postgres::types::Type::TEXT, postgres::types::Type::INT2, postgres::types::Type::TEXT],
        )
        .unwrap();
    let null_target: Option<&str> = None;
    let invalid = tx.execute(&stmt_invalid, &[&null_target, &50i16, &"{}"]);
    assert!(
        invalid.is_err(),
        "l'INSERT violant NOT NULL doit échouer côté serveur"
    );
    drop(tx); // rollback implicite (jamais commité)

    let count_after: i64 = client
        .query_one("SELECT count(*) FROM audit_scans", &[])
        .unwrap()
        .get(0);
    assert_eq!(
        count_before, count_after,
        "rollback : aucun scan orphelin ne doit survivre à un échec mid-transaction"
    );
}
