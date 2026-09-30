//! Audit FTP : declenche si port 21 detecte dans `port_results`. Appelle
//! les binaires `ftpx` (auth probe) et `ftplx` (anonymous loot) de
//! l'arsenal Kali local, parse leur sortie textuelle, emet les findings
//! adaptes. Aucun ajout CLI : zero bruit sur les cibles sans FTP.

use crate::modules::findings::SecurityFinding;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct FtpAuditResult {
    pub target: String,
    pub port_open: bool,
    pub anonymous_allowed: bool,
    pub tls_supported: bool,
    pub tls_required: bool,
    pub auth_cleartext_forced: bool,
    pub banner: String,
    pub loot_attempted: bool,
    pub loot_files: usize,
    pub raw_output: String,
    pub summary: String,
    pub elapsed_seconds: f32,
}

pub struct FtpAuditor;

impl FtpAuditor {
    /// Decide si on doit lancer l'audit : cible = nom d'hote + port 21
    /// present dans la liste des ports ouverts.
    pub fn should_audit(target: &str, port_results: &[crate::modules::ports::PortScanResult]) -> bool {
        if target.parse::<std::net::IpAddr>().is_ok() {
            return false;
        }
        port_results.iter().any(|p| p.port == 21)
    }

    /// Test AUTH TLS en Rust pur : envoie la commande FTP AUTH TLS sur le
    /// port 21 et observe la reponse. Retourne true si le serveur repond 234.
    /// Necessaire car le binaire `ftpx` ne teste pas cette commande.
    fn probe_auth_tls(target: &str) -> bool {
        use std::net::ToSocketAddrs;
        let addr = match (target, 21u16).to_socket_addrs() {
            Ok(mut it) => match it.next() {
                Some(a) => a,
                None => return false,
            },
            Err(_) => return false,
        };
        let mut stream = match TcpStream::connect_timeout(&addr, Duration::from_secs(5)) {
            Ok(s) => s,
            Err(_) => return false,
        };
        let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
        let _ = stream.set_write_timeout(Some(Duration::from_secs(5)));

        // Lire la banniere 220 (laisser le serveur parler d abord).
        let mut buf = [0u8; 1024];
        let _ = stream.read(&mut buf);

        // Envoyer AUTH TLS\r\n
        if stream.write_all(b"AUTH TLS\r\n").is_err() {
            return false;
        }

        // Lire la reponse.
        let mut resp = [0u8; 256];
        let n = match stream.read(&mut resp) {
            Ok(n) if n > 0 => n,
            _ => return false,
        };
        let text = String::from_utf8_lossy(&resp[..n]);
        // 234 = AUTH TLS OK ; sur certaines implementations 220 peut suivre.
        text.contains("234") || text.contains("220 AUTH TLS")
    }

    /// Lance ftpx + ftplx, parse, retourne le resultat complet.
    pub fn audit(target: &str) -> FtpAuditResult {
        let start = Instant::now();
        let ftpx_out = crate::utils::run_tool("ftpx", &[target], 60);
        let ftpx_text = ftpx_out
            .as_ref()
            .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
            .unwrap_or_default();

        let mut banner = String::new();
        let mut anonymous_allowed = false;
        let mut tls_supported = false;
        let mut tls_required = false;

        for line in ftpx_text.lines() {
            let t = line.trim();
            if let Some(rest) = t.strip_prefix("banner   :") {
                banner = rest.trim().to_string();
            } else if t.contains("anonymous OK") || t.contains("AUTORISÉ") || t.contains("AUTORISE") {
                anonymous_allowed = true;
            } else if t.contains("AUTH TLS OK") {
                tls_supported = true;
            } else if t.contains("AUTH TLS requis") || t.contains("OBLIGATOIRE") {
                tls_required = true;
            }
        }
        // Fallback : si ftpx ne dit rien sur TLS, on le teste nous-memes
        // en Rust pur (probe AUTH TLS sur la socket FTP).
        if !tls_supported && !banner.is_empty() {
            tls_supported = Self::probe_auth_tls(target);
        }
        let auth_cleartext_forced = !banner.is_empty() && tls_supported && !tls_required;

        let ftplx_out = crate::utils::run_tool("ftplx", &[target], 90);
        let (loot_attempted, loot_files) = match &ftplx_out {
            Some(o) => {
                let txt = String::from_utf8_lossy(&o.stdout).to_string();
                let attempted =
                    !txt.contains("REFUSÉ") && !txt.contains("REFUSE") && !txt.contains("rien à looter");
                let n = txt
                    .lines()
                    .find(|l| l.contains("manifeste :"))
                    .and_then(|l| l.split_whitespace().nth(1).and_then(|s| s.parse::<usize>().ok()))
                    .unwrap_or(0);
                (attempted, n)
            }
            None => (false, 0),
        };

        let raw_output = format!(
            "=== ftpx ===
{ftpx}
=== ftplx ===
{loot}",
            ftpx = ftpx_text,
            loot = ftplx_out
                .as_ref()
                .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
                .unwrap_or_default()
        );

        let summary = if anonymous_allowed {
            format!("FTP anonymous AUTORISÉ sur {target} - exposition publique critique")
        } else if auth_cleartext_forced {
            format!("FTP {target} : auth en clair forcée (TLS supporté mais non exigé)")
        } else if tls_required {
            format!("FTP {target} : TLS exigé, auth chiffrée OK")
        } else if !banner.is_empty() {
            format!("FTP {target} : port ouvert, banner récupéré")
        } else {
            format!("FTP {target} : audit injoignable ou binaire ftpx/ftplx manquant")
        };

        FtpAuditResult {
            target: target.to_string(),
            port_open: true,
            anonymous_allowed,
            tls_supported,
            tls_required,
            auth_cleartext_forced,
            banner,
            loot_attempted,
            loot_files,
            raw_output,
            summary,
            elapsed_seconds: start.elapsed().as_secs_f32(),
        }
    }

    pub fn to_findings(&self, res: &FtpAuditResult) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();

        if res.anonymous_allowed {
            findings.push(SecurityFinding {
                severity: "CRITICAL",
                category: "FTP",
                title: format!("FTP anonymous autorisé sur {}", res.target),
                recommendation: "Désactiver l'anonymous FTP immédiatement : Pure-FTPd -> NoAnonymous yes ; vsftpd -> anonymous_enable=NO. Lister le contenu public et le purger si sensible.".into(),
            });
        }

        if res.auth_cleartext_forced {
            findings.push(SecurityFinding {
                severity: "HIGH",
                category: "FTP",
                title: "Authentification FTP en clair forcée (port 21)".into(),
                recommendation: format!(
                    "Le serveur {} répond AUTH TLS (234) mais ne l'exige pas : les clients non-SSL envoient USER/PASS en clair. Forcer TLSRequired on dans pure-ftpd.conf (ou TLS 2). Alternative : fermer :21 au firewall et n'exposer que FTPS implicite sur :990.",
                    res.target
                ),
            });
        }

        if !res.banner.is_empty()
            && !res.anonymous_allowed
            && !res.auth_cleartext_forced
            && res.banner.chars().any(|c| c.is_ascii_digit())
            && (res.banner.contains("Pure-FTPd")
                || res.banner.contains("vsftpd")
                || res.banner.contains("ProFTPD"))
        {
            findings.push(SecurityFinding {
                severity: "LOW",
                category: "FTP",
                title: format!("Bannière FTP divulguant le serveur : {}", res.banner),
                recommendation: "Masquer la version du serveur FTP dans la bannière 220 (Pure-FTPd: directive -H ; vsftpd: ftpd_banner= configurable).".into(),
            });
        }

        findings
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::modules::ports::PortScanResult;

    fn port(p: u16) -> PortScanResult {
        PortScanResult { port: p, is_open: true, service_hint: "x", banner: None, is_phantom_edge: false }
    }

    #[test]
    fn test_lock_ftp_should_audit_only_when_port_21_and_domain() {
        let with = vec![port(21)];
        let without = vec![port(22)];
        assert!(FtpAuditor::should_audit("example.com", &with));
        assert!(!FtpAuditor::should_audit("example.com", &without));
        assert!(!FtpAuditor::should_audit("8.8.8.8", &with));
    }

    #[test]
    fn test_lock_ftp_findings_critical_when_anonymous_allowed() {
        let r = FtpAuditResult { target: "victim.ca".into(), anonymous_allowed: true, ..Default::default() };
        let f = FtpAuditor.to_findings(&r);
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].severity, "CRITICAL");
        assert!(f[0].title.contains("anonymous"));
    }

    #[test]
    fn test_lock_ftp_findings_high_when_cleartext_forced() {
        let r = FtpAuditResult {
            target: "victim.ca".into(),
            banner: "Pure-FTPd [privsep] [TLS]".into(),
            tls_supported: true,
            tls_required: false,
            auth_cleartext_forced: true,
            ..Default::default()
        };
        let f = FtpAuditor.to_findings(&r);
        assert!(f.iter().any(|x| x.severity == "HIGH" && x.title.contains("clair")));
    }

    #[test]
    fn test_lock_ftp_findings_low_for_version_disclosure_only() {
        let r = FtpAuditResult {
            target: "victim.ca".into(),
            banner: "vsftpd 3.0.5".into(),
            ..Default::default()
        };
        let f = FtpAuditor.to_findings(&r);
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].severity, "LOW");
    }

    #[test]
    fn test_lock_ftp_no_finding_when_tls_required() {
        let r = FtpAuditResult {
            target: "victim.ca".into(),
            banner: "Pure-FTPd [privsep] [TLS]".into(),
            tls_supported: true,
            tls_required: true,
            ..Default::default()
        };
        assert!(FtpAuditor.to_findings(&r).is_empty());
    }

    #[test]
    fn test_lock_ftp_cleartext_high_even_without_explicit_tls_required() {
        // Cas 8brains.ca : TLS supporte mais pas exige -> finding HIGH.
        let r = FtpAuditResult {
            target: "victim.ca".into(),
            banner: "Pure-FTPd [privsep] [TLS]".into(),
            tls_supported: true,
            tls_required: false,
            auth_cleartext_forced: true,
            ..Default::default()
        };
        let f = FtpAuditor.to_findings(&r);
        assert!(f.iter().any(|x| x.severity == "HIGH"));
        // Pas de double-emission LOW banner quand HIGH deja present.
        assert!(!f.iter().any(|x| x.severity == "LOW"));
    }

    #[test]
    fn test_lock_ftp_probe_auth_tls_returns_false_on_closed_port() {
        // Cible inexistante -> false (pas de faux positif).
        assert!(!FtpAuditor::probe_auth_tls("127.0.0.1:1"));
    }
}
