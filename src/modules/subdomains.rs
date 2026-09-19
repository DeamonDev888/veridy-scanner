//! Énumération de sous-domaines via Subfinder (ProjectDiscovery) + fallback statique.
//!
//! Stratégie :
//! 1. Si `subfinder` est installé, on l'invoque : `subfinder -d {target} -silent -nW` (sans wordlist custom)
//! 2. Sinon, fallback sur la liste hardcodée `EXPANDED_SUBDOMAINS` (DNS bruteforce)
//! 3. Chaque sous-domaine est ensuite résolu en IP via `to_socket_addrs`
//! 4. Un probe HTTP HEAD optionnel via `curl` confirme si le sous-domaine répond
//!
//! Le flag CLI `--subfinder-only` force l'usage de subfinder (échec si absent).
//! Le flag `--no-subfinder` désactive subfinder (utilise uniquement la liste statique).

use serde::Serialize;
use std::net::ToSocketAddrs;
use std::process::Command;
use std::sync::{mpsc, Arc};
use std::thread;

pub const EXPANDED_SUBDOMAINS: &[&str] = &[
    "www",
    "mail",
    "api",
    "app",
    "blog",
    "admin",
    "portal",
    "dev",
    "staging",
    "status",
    "vpn",
    "auth",
    "registre",
    "smtp",
    "imap",
    "docs",
    "support",
    "dashboard",
    "git",
    "gitlab",
    "grafana",
    "keycloak",
    "idp",
    "whm",
    "cpanel",
    "mta-sts",
    "autodiscover",
    "autoconfig",
    "webmail",
    "ns1",
    "ns2",
    "corp",
    "cdn",
    "media",
    "billing",
    "test",
    "demo",
    "qa",
    "prod",
    "preprod",
    "edge",
    "lb",
    "proxy",
    "gateway",
    "firewall",
    "vpn1",
    "vpn2",
    "remote",
    "cloud",
    "console",
    "panel",
    "web",
    "shop",
    "store",
    "pay",
    "payment",
];

#[derive(Debug, Clone, Serialize)]
pub struct SubdomainResult {
    pub subdomain: String,
    pub ip_address: Option<String>,
    pub http_status: Option<u16>,
    pub is_alive: bool,
    pub source: String, // "subfinder" | "static" | "wildcard"
}

pub struct SubdomainScanner;

#[derive(Debug, Clone, Copy, PartialEq)]
#[allow(dead_code)]
pub enum ScanMode {
    /// Subfinder d'abord, fallback statique si subfinder absent ou échoue
    Auto,
    /// Force subfinder uniquement (échec si absent)
    SubfinderOnly,
    /// Pas de subfinder, uniquement liste statique
    StaticOnly,
}

impl SubdomainScanner {
    /// Point d'entrée principal : scan selon le mode demandé
    pub fn scan_with_mode(domain: &str, mode: ScanMode) -> Vec<SubdomainResult> {
        match mode {
            ScanMode::StaticOnly => Self::scan_static(domain),
            ScanMode::SubfinderOnly => {
                if !Self::is_subfinder_available() {
                    eprintln!(
                        "[ERREUR] subfinder non installé. Installez-le : \
                        https://github.com/projectdiscovery/subfinder/releases"
                    );
                    return Vec::new();
                }
                Self::scan_via_subfinder(domain)
            }
            ScanMode::Auto => {
                if Self::is_subfinder_available() {
                    let mut results = Self::scan_via_subfinder(domain);
                    // Compléter avec la liste statique si subfinder a trouvé peu
                    if results.len() < 5 {
                        let static_results = Self::scan_static(domain);
                        for sr in static_results {
                            if !results.iter().any(|r| r.subdomain == sr.subdomain) {
                                results.push(sr);
                            }
                        }
                    }
                    results
                } else {
                    eprintln!("[INFO] subfinder absent, fallback sur liste statique");
                    Self::scan_static(domain)
                }
            }
        }
    }

    /// Vérifie la disponibilité de subfinder sur le PATH
    pub fn is_subfinder_available() -> bool {
        which("subfinder").is_some()
    }

    /// Invoque subfinder et parse sa sortie (1 sous-domaine par ligne)
    fn scan_via_subfinder(domain: &str) -> Vec<SubdomainResult> {
        let output = match Command::new("subfinder")
            .args(["-d", domain, "-silent", "-nW", "-timeout", "10"])
            .output()
        {
            Ok(o) if o.status.success() => o,
            Ok(o) => {
                eprintln!(
                    "[WARN] subfinder a échoué (code {:?}): {}",
                    o.status.code(),
                    String::from_utf8_lossy(&o.stderr)
                );
                return Vec::new();
            }
            Err(e) => {
                eprintln!("[WARN] subfinder non lançable : {}", e);
                return Vec::new();
            }
        };

        let stdout = String::from_utf8_lossy(&output.stdout);
        let subdomains: Vec<String> = stdout
            .lines()
            .map(|l| l.trim().to_string())
            .filter(|l| !l.is_empty() && l.contains('.'))
            .filter(|l| l.ends_with(domain) || l.ends_with(&format!(".{}", domain)))
            .collect();

        // Maintenant on résout les IPs et probe HTTP en parallèle
        Self::resolve_and_probe_parallel(subdomains, "subfinder")
    }

    /// Fallback : brute-force DNS sur la liste hardcodée
    fn scan_static(domain: &str) -> Vec<SubdomainResult> {
        let candidates: Vec<String> = EXPANDED_SUBDOMAINS
            .iter()
            .map(|sub| format!("{}.{}", sub, domain))
            .collect();
        Self::resolve_and_probe_parallel(candidates, "static")
    }

    /// Résolution DNS + probe HTTP parallèle (thread pool simple)
    fn resolve_and_probe_parallel(candidates: Vec<String>, source: &str) -> Vec<SubdomainResult> {
        let (tx, rx) = mpsc::channel();
        let candidates = Arc::new(candidates);

        let mut handles = Vec::new();
        for chunk in candidates.chunks(20) {
            let tx_clone = tx.clone();
            let chunk: Vec<String> = chunk.to_vec();
            let source = source.to_string();

            let handle = thread::spawn(move || {
                for sub in chunk {
                    let host_port = format!("{}:80", sub);
                    let ip = match host_port.to_socket_addrs() {
                        Ok(mut addrs) => addrs.next().map(|a| a.ip().to_string()),
                        Err(_) => None,
                    };

                    // alive = true UNIQUEMENT si résolution ET probe HTTP réussi
                    let mut http_status: Option<u16> = None;
                    let mut alive = false;

                    if let Some(ip_str) = &ip {
                        // Probe HTTP HEAD rapide (timeout 3s)
                        let url = format!("https://{}/", sub);
                        if let Ok(out) = Command::new("curl")
                            .args([
                                "-s",
                                "-I",
                                "--max-time",
                                "3",
                                "-o",
                                "/dev/null",
                                "-w",
                                "%{http_code}",
                                &url,
                            ])
                            .output()
                        {
                            if let Ok(s) = String::from_utf8_lossy(&out.stdout).parse::<u16>() {
                                http_status = Some(s);
                                alive = true;
                            }
                        }
                        // Si HTTPS échoue, tenter HTTP
                        if !alive {
                            let url_http = format!("http://{}/", sub);
                            if let Ok(out) = Command::new("curl")
                                .args([
                                    "-s",
                                    "-I",
                                    "--max-time",
                                    "3",
                                    "-o",
                                    "/dev/null",
                                    "-w",
                                    "%{http_code}",
                                    &url_http,
                                ])
                                .output()
                            {
                                if let Ok(s) = String::from_utf8_lossy(&out.stdout).parse::<u16>() {
                                    http_status = Some(s);
                                    alive = true;
                                }
                            }
                        }
                        let _ = ip_str; // suppress warning unused
                    }

                    let _ = tx_clone.send(Some(SubdomainResult {
                        subdomain: sub,
                        ip_address: ip,
                        http_status,
                        is_alive: alive,
                        source: source.clone(),
                    }));
                }
            });
            handles.push(handle);
        }
        drop(tx);

        let mut results = Vec::new();
        for entry in rx.into_iter().flatten() {
            results.push(entry);
        }
        for h in handles {
            let _ = h.join();
        }

        // Tri : vivants d'abord, puis par nom
        results.sort_by(|a, b| {
            b.is_alive
                .cmp(&a.is_alive)
                .then(a.subdomain.cmp(&b.subdomain))
        });
        results
    }
}

/// Équivalent minimal de `which` : parcours du PATH
fn which(tool: &str) -> Option<std::path::PathBuf> {
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path)
        .map(|dir| dir.join(tool))
        .find(|p| p.is_file())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_expanded_subdomains_not_empty() {
        assert!(EXPANDED_SUBDOMAINS.len() >= 50);
        assert!(EXPANDED_SUBDOMAINS.contains(&"www"));
        assert!(EXPANDED_SUBDOMAINS.contains(&"mail"));
        assert!(EXPANDED_SUBDOMAINS.contains(&"api"));
    }

    #[test]
    fn test_expanded_subdomains_unique() {
        let mut seen = std::collections::HashSet::new();
        for s in EXPANDED_SUBDOMAINS {
            assert!(seen.insert(s), "Duplicate: {}", s);
        }
    }

    #[test]
    fn test_subdomain_result_source_field() {
        let r = SubdomainResult {
            subdomain: "test.example.com".into(),
            ip_address: Some("1.2.3.4".into()),
            http_status: Some(200),
            is_alive: true,
            source: "subfinder".into(),
        };
        assert_eq!(r.source, "subfinder");
        assert!(r.is_alive);
    }

    #[test]
    fn test_scan_static_basic() {
        // Test sans réseau : juste vérifier que ça retourne un Vec non-vide
        // même si tous les sous-domaines sont dead (DNS fail)
        // On utilise un domaine invalide (.invalid TLD réservé RFC 6761)
        let results = SubdomainScanner::scan_with_mode("example.invalid", ScanMode::StaticOnly);
        // Pas de résolution possible, donc tous is_alive=false mais la liste est testée
        assert!(
            !results.is_empty(),
            "doit au moins tester les sous-domaines"
        );
        for r in &results {
            assert_eq!(r.source, "static");
            assert!(r.subdomain.ends_with(".example.invalid"));
            assert!(!r.is_alive, ".invalid ne résout pas");
            assert!(r.ip_address.is_none(), ".invalid ne résout pas");
        }
    }

    #[test]
    fn test_scan_static_loopback() {
        // 127.0.0.1 résout toujours ; sous-domaines factices non
        let results = SubdomainScanner::scan_with_mode("127.0.0.1", ScanMode::StaticOnly);
        // 127.0.0.1 n'est pas un domaine valide (le format host:80 va fail)
        // On attend 0 résultats exploitables
        for r in &results {
            assert!(!r.is_alive);
        }
    }

    #[test]
    fn test_scan_mode_only_static_skips_subfinder_check() {
        // Vérifie que StaticOnly n'invoque PAS subfinder
        // En mesurant le temps : doit être rapide
        let start = std::time::Instant::now();
        let _ = SubdomainScanner::scan_with_mode("example.invalid", ScanMode::StaticOnly);
        let elapsed = start.elapsed();
        // StaticOnly doit être < 30s même sans résolution (timeout HTTP 3s × 50+ domaines = ~150s en théorie)
        // Mais ici on test juste qu'il ne hang pas sur subfinder
        assert!(
            elapsed.as_secs() < 180,
            "StaticOnly trop lent: {:?}",
            elapsed
        );
    }

    #[test]
    fn test_which_finds_common_tools() {
        // Test du helper `which` : doit trouver au moins un outil standard
        // (ls, sh, etc sont toujours présents)
        assert!(which("sh").is_some() || which("bash").is_some());
    }

    #[test]
    fn test_scan_static_no_panic_on_empty_input() {
        // Edge case : domaine vide ou bizarre
        let results = SubdomainScanner::scan_with_mode("", ScanMode::StaticOnly);
        // Doit retourner quelque chose (les sous-domaines seront "www." etc, invalides)
        // mais ne doit pas paniquer
        assert!(results.len() >= EXPANDED_SUBDOMAINS.len());
    }
}
