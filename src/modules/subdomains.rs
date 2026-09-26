#![allow(dead_code)]
//! Énumération de sous-domaines via subfinder (ProjectDiscovery) avec fallback.
//! Version recréée après suppression accidentelle.

use std::collections::HashSet;

#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct SubdomainResult {
    pub subdomain: String,
    pub source: String,
    pub ip_address: Option<String>,
    pub http_status: Option<u16>,
    pub is_alive: bool,
}

pub enum ScanMode {
    Subfinder,
    Static,
    Auto,
}

pub struct SubdomainScanner;

impl SubdomainScanner {
    pub fn scan_with_mode(domain: &str, mode: ScanMode) -> Vec<SubdomainResult> {
        match mode {
            ScanMode::Subfinder => subfinder_scan(domain),
            ScanMode::Static => static_scan(domain),
            ScanMode::Auto => {
                if which("subfinder").is_some() {
                    subfinder_scan(domain)
                } else {
                    static_scan(domain)
                }
            }
        }
    }
}

fn which(tool: &str) -> Option<std::path::PathBuf> {
    if let Ok(p) = std::env::var("PATH") {
        for dir in std::env::split_paths(&p) {
            for ext in &["", ".exe"] {
                let candidate = dir.join(format!("{}{}", tool, ext));
                if candidate.is_file() {
                    return Some(candidate);
                }
            }
        }
    }
    None
}

fn subfinder_scan(domain: &str) -> Vec<SubdomainResult> {
    let output = match crate::utils::run_tool("subfinder", &["-d", domain, "-silent", "-nW"], 120)
    {
        Some(o) if o.status.success() => o,
        _ => return static_scan(domain),
    };
    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut results = Vec::new();
    let mut seen = HashSet::new();
    for line in stdout.lines() {
        let sub = line.trim();
        if sub.is_empty() || !sub.contains('.') {
            continue;
        }
        if seen.insert(sub.to_string()) {
            results.push(SubdomainResult {
                subdomain: sub.to_string(),
                source: "subfinder".into(),
                ip_address: None,
                http_status: None,
                is_alive: false,
            });
        }
    }
    results
}

fn static_scan(domain: &str) -> Vec<SubdomainResult> {
    let prefixes = [
        "www", "mail", "ftp", "smtp", "imap", "pop", "pop3",
        "webmail", "email", "mx", "mx1", "ns", "ns1", "ns2", "ns3",
        "vpn", "remote", "admin", "administrator", "portal",
        "dev", "test", "stage", "staging", "qa", "uat",
        "api", "app", "apps", "blog", "cdn", "cloud",
        "demo", "docs", "git", "gitlab", "github",
        "grafana", "jenkins", "jira", "kibana",
        "ldap", "login", "monitor", "monitoring",
        "shop", "store", "support", "web",
        "wiki", "wp", "wordpress",
    ];
    prefixes.iter().map(|p| SubdomainResult {
        subdomain: format!("{}.{}", p, domain),
        source: "static".into(),
        ip_address: None,
        http_status: None,
        is_alive: false,
    }).collect()
}
