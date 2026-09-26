#![allow(dead_code)]
//! Module box HTB / intrusif : regroupe les probes actifs pensés pour les
//! box de lab (HTB, THM). Chaque probe est NON-DESTRUCTIVE (lecture seule),
//! mais va là où les modules web génériques ne vont pas : headers exotiques,
//! chemins par défaut des services, dumps anonymes.
//!
//! Ces probes tournent uniquement quand l'opérateur scanne une IP (pas un
//! domaine) : cible ponctuelle d'un engagement, pas du balayage de masse.

use crate::modules::findings::SecurityFinding;
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct BoxProbeResult {
    pub success: bool,
    pub elapsed_seconds: f32,
    pub probed_services: Vec<String>,
    pub findings: Vec<SecurityFinding>,
    pub summary: String,
}

pub struct BoxProber;

impl BoxProber {
    /// Lance les probes actifs sur les ports ouverts d'une IP.
    pub fn audit(target: &str, open_ports: &[u16]) -> BoxProbeResult {
        let start = Instant::now();
        let mut res = BoxProbeResult {
            success: true,
            elapsed_seconds: 0.0,
            probed_services: Vec::new(),
            findings: Vec::new(),
            summary: String::new(),
        };

        let ip_target = target.parse::<std::net::IpAddr>().is_ok();

        // --- 1. FTP anonymous sur 21 (ou port custom FTP détecté) ---
        let ftp_port = open_ports.iter().copied().find(|&p| p == 21 || p == 2121);
        if let Some(port) = ftp_port {
            let banner = grpc_probe(target, port, &[], 3000)
                .map(|b| b.trim().to_string())
                .unwrap_or_default();
            res.probed_services.push(format!("ftp:{}", port));
            if banner.to_lowercase().contains("vsftpd") {
                if let Some(v) = extract_version(&banner, "vsftpd") {
                    // vsftpd 2.3.4 = backdoor célèbre (HTB Becker-style)
                    if v.starts_with("2.3.4") {
                        res.findings.push(SecurityFinding {
                            severity: "CRITICAL",
                            category: "FTP",
                            title: "vsftpd 2.3.4 — backdoor connue (CVE-2011-2523)".into(),
                            recommendation: "Version exactement 2.3.4 : smiley :) sur le port de commande ouvre un shell root sur 6200. Exploit msf: unix/misc/vsftpd_234_backdoor.".into(),
                        });
                    }
                }
            }
            if banner.to_lowercase().contains("proftpd") {
                if let Some(v) = extract_version(&banner, "ProFTPD") {
                    if v.starts_with("1.3.5") {
                        res.findings.push(SecurityFinding {
                            severity: "CRITICAL",
                            category: "FTP",
                            title: "ProFTPD 1.3.5 — copies de fichiers arbitraires (CVE-2015-3306)".into(),
                            recommendation: "site CPFR/CPTO permet la copie de n'importe quel fichier → récupération de clés/configs. Exploit msf: linux/proftpd/modcopy.".into(),
                        });
                    }
                }
            }
        }

        // --- 2. Redis non authentifié (6379) ---
        if open_ports.contains(&6379) {
            if let Some(resp) = raw_cmd(target, 6379, b"PING\r\n", 2500) {
                res.probed_services.push("redis:6379".into());
                if resp.contains("+PONG") {
                    res.findings.push(SecurityFinding {
                        severity: "CRITICAL",
                        category: "REDIS",
                        title: "Redis accessible SANS authentification (PING → +PONG)".into(),
                        recommendation: "Accès complet à la DB : INFO, CONFIG GET dir (webshell via CONFIG SET dir + dbfilename), ou clés SSH via ~/.ssh/authorized_keys. Le dump complet est possible (KEYS *).".into(),
                    });
                }
            }
        }

        // --- 3. MongoDB sans auth (27017) ---
        if open_ports.contains(&27017) {
            // Hello MongoDB wire protocol (OP_MSG) : trop complexe en raw —
            // on tente une bannière spontanée ou on relance un HELLO JSON.
            // Astuce : beaucoup de MongoDB écoutent HTTP sur 28017 (REST).
            if open_ports.contains(&28017) {
                res.findings.push(SecurityFinding {
                    severity: "HIGH",
                    category: "MONGODB",
                    title: "Interface REST HTTP MongoDB exposée (28017)".into(),
                    recommendation: "L'ancienne interface REST de MongoDB liste bases et collections : /listDatabases, /db/. Désactiver --rest.".into(),
                });
            }
            res.probed_services.push("mongodb:27017".into());
        }

        // --- 4. SMB null session (445/139) — via rpcclient-style banner ---
        if open_ports.contains(&445) || open_ports.contains(&139) {
            res.probed_services.push("smb:445".into());
            // La vraie énumération SMB requiert netexec ; on note le service.
        }

        // --- 5. Services web sur ports exotiques : index fingerprint ---
        let web_ports: Vec<u16> = open_ports
            .iter()
            .copied()
            .filter(|&p| {
                crate::modules::ports::PortScanner::guess_service(p) == "HTTP"
                    || crate::modules::ports::PortScanner::titles_probe_worthy(p)
            })
            .collect();
        for port in web_ports {
            for scheme in ["http", "https"] {
                let url = format!("{}://{}:{}/", scheme, target, port);
                let out = crate::utils::run_tool("curl", &["-s", "-k", "--max-time", "5", &url], 8);
                if let Some(o) = out {
                    let body = String::from_utf8_lossy(&o.stdout).to_string();
                    let lower = body.to_lowercase();
                    if lower.contains("<title>") {
                        let title = lower
                            .split("<title>")
                            .nth(1)
                            .and_then(|s| s.split("</title>").next())
                            .unwrap_or("")
                            .trim()
                            .to_string();
                        res.probed_services
                            .push(format!("http-title:{}:{} = \"{}\"", scheme, port, title));
                        res.findings.push(SecurityFinding {
                            severity: "INFO",
                            category: "BOX",
                            title: format!("Service web {}:{} — titre « {} »", scheme, port, title),
                            recommendation: "Fingerprint du service : le titre révèle l'application (login Jenkins, Tomcat manager, Grafana...) → chercher l'exploit correspondant.".into(),
                        });
                        break; // un schéma suffit pour ce port
                    } else if !body.trim().is_empty() {
                        res.probed_services.push(format!(
                            "http-body:{}:{} ({}o)",
                            scheme,
                            port,
                            body.len()
                        ));
                        break;
                    }
                }
            }
        }

        // --- 6. SNMP (161) : community string public ---
        if open_ports.contains(&161) {
            res.probed_services.push("snmp:161".into());
            // snmpwalk via run_tool si présent
            if let Some(o) = crate::utils::run_tool(
                "snmpwalk",
                &["-v2c", "-c", "public", target, "1.3.6.1.2.1.1.1.0"],
                15,
            ) {
                let s = String::from_utf8_lossy(&o.stdout).to_string();
                if !s.trim().is_empty() && s.contains("::=") {
                    res.findings.push(SecurityFinding {
                        severity: "HIGH",
                        category: "SNMP",
                        title: "SNMP accessible avec community « public »".into(),
                        recommendation: "Divulgation d'informations système : version OS, interfaces, processus, parfois credentials. snmpwalk -c public -v2c <ip> pour le dump complet.".into(),
                    });
                }
            }
        }

        // --- 7. cible IP : rappel des services internes détectés ---
        let db_exposed = open_ports.contains(&6379)
            || open_ports.contains(&27017)
            || open_ports.contains(&5432)
            || open_ports.contains(&3306);
        if ip_target && db_exposed {
            res.findings.push(SecurityFinding {
                severity: "MEDIUM",
                category: "BOX",
                title: "Service(s) de base de données exposé(s) sur IP directe".into(),
                recommendation: databased_recommendation_placeholder().to_string(),
            });
        }

        res.elapsed_seconds = start.elapsed().as_secs_f32();
        res.summary = format!(
            "BoxProber : {} service(s) probed(s), {} finding(s) en {:.1}s",
            res.probed_services.len(),
            res.findings.len(),
            res.elapsed_seconds
        );
        res
    }
}

/// Lecture spontanée de bannière (FTP/SSH/SMTP répondent en premier).
fn grpc_probe(target: &str, port: u16, _payload: &[u8], timeout_ms: u64) -> Option<String> {
    use std::io::Read;
    use std::net::TcpStream;
    let sockaddr = format!("{}:{}", target, port);
    let mut addrs = sockaddr.to_socket_addrs().ok()?;
    let sock = addrs.next()?;
    let mut stream = TcpStream::connect_timeout(&sock, Duration::from_millis(timeout_ms)).ok()?;
    let _ = stream.set_read_timeout(Some(Duration::from_millis(1200)));
    let mut buf = vec![0u8; 512];
    let n = stream.read(&mut buf).ok()?;
    if n > 0 {
        Some(String::from_utf8_lossy(&buf[..n]).to_string())
    } else {
        None
    }
}

/// Commande brute + réponse (Redis, memcached...).
fn raw_cmd(target: &str, port: u16, payload: &[u8], timeout_ms: u64) -> Option<String> {
    use std::io::{Read, Write};
    use std::net::TcpStream;
    let sockaddr = format!("{}:{}", target, port);
    let mut addrs = sockaddr.to_socket_addrs().ok()?;
    let sock = addrs.next()?;
    let mut stream = TcpStream::connect_timeout(&sock, Duration::from_millis(timeout_ms)).ok()?;
    let _ = stream.set_read_timeout(Some(Duration::from_millis(1500)));
    let _ = stream.set_write_timeout(Some(Duration::from_millis(1500)));
    stream.write_all(payload).ok()?;
    let mut buf = vec![0u8; 2048];
    let n = stream.read(&mut buf).ok()?;
    Some(String::from_utf8_lossy(&buf[..n]).to_string())
}

/// Extrait la version d'une bannière : "220 (vsFTPd 3.0.3)" → "3.0.3".
fn extract_version(banner: &str, product: &str) -> Option<String> {
    let idx = banner.to_lowercase().find(&product.to_lowercase())?;
    let after = &banner[idx + product.len()..];
    let version: String = after
        .trim_start_matches(|c: char| !c.is_ascii_digit())
        .chars()
        .take_while(|c| c.is_ascii_digit() || *c == '.')
        .collect();
    if version.is_empty() {
        None
    } else {
        Some(version)
    }
}

use std::net::ToSocketAddrs;

#[allow(dead_code)]
fn databased_recommendation_placeholder() -> &'static str {
    "Bases de données exposées : tenter les logins par défaut (root:PASS, admin:admin) et les dumps anonymes (psql -l, mysql NULL session sur anciennes versions)."
}
