//! Module d'impact intégré : vérification de contenu des endpoints sensibles
//! découverts par ffuf. CRITICAL uniquement si le CONTENU réel est prouvé —
//! un statut 200 seul ne suffit jamais (leçon metro.ca : WAF servant une page
//! HTML uniforme sur .env/.git).
//!
//! Règles : lecture seule (GET), timeout dur, taille plafonnée, nombre de
//! vérifications par scan plafonné, secrets jamais recopiés dans les findings.

use crate::modules::ffuf_audit::ExposedEndpoint;
use std::process::{Command, Stdio};

/// Nombre max d'endpoints re-vérifiés par scan (budget réseau).
pub const MAX_VERIFICATIONS_PER_SCAN: usize = 5;
/// Taille max du contenu re-fetché pour vérification (octets).
pub const MAX_VERIFY_BYTES: usize = 8192;

/// Signature de contenu attendue pour un type de fichier sensible.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContentSignature {
    EnvFile,
    GitConfig,
    GitHead,
    SqlDump,
    WpConfig,
    YmlConfig,
    GenericText,
}

impl ContentSignature {
    /// Signatures candidates pour un chemin donné, de la plus spécifique à la
    /// plus générique.
    pub fn for_path(path: &str) -> Vec<ContentSignature> {
        let p = path.to_lowercase();
        let mut v = Vec::new();
        if p.starts_with(".env") {
            v.push(ContentSignature::EnvFile);
        }
        if p.contains(".git/config") {
            v.push(ContentSignature::GitConfig);
        }
        if p.contains(".git/head") || p.ends_with(".git/head") {
            v.push(ContentSignature::GitHead);
        }
        if p.ends_with(".sql") || p.contains("backup") && p.ends_with(".old") {
            v.push(ContentSignature::SqlDump);
        }
        if p.contains("wp-config") {
            v.push(ContentSignature::WpConfig);
        }
        if p.ends_with(".yml") || p.ends_with(".yaml") {
            v.push(ContentSignature::YmlConfig);
        }
        v.push(ContentSignature::GenericText);
        v
    }

    /// Le contenu matche-t-il cette signature ?
    pub fn matches(self, body: &str) -> bool {
        let low = body.to_lowercase();
        // Un contenu HTML n'est JAMAIS une preuve (page d'erreur WAF/catch-all)
        let is_html = low.contains("<html") || low.contains("<!doctype html");
        match self {
            ContentSignature::EnvFile => !is_html && looks_like_env(body),
            ContentSignature::GitConfig => !is_html && body.contains("[core]"),
            ContentSignature::GitHead => !is_html && body.trim_start().starts_with("ref: refs/"),
            ContentSignature::SqlDump => {
                !is_html
                    && (low.contains("insert into")
                        || low.contains("create table")
                        || low.contains("dump")
                        || low.contains("-- mysql dump"))
            }
            ContentSignature::WpConfig => {
                !is_html && (low.contains("db_password") || low.contains("define("))
            }
            ContentSignature::YmlConfig => {
                !is_html && body.contains(":") && body.lines().count() >= 3
            }
            ContentSignature::GenericText => !is_html && !body.trim().is_empty(),
        }
    }
}

/// Un .env plausible : >= 2 lignes KEY=VALUE, pas de HTML.
fn looks_like_env(body: &str) -> bool {
    let pairs = body
        .lines()
        .filter(|l| {
            let l = l.trim();
            !l.is_empty()
                && !l.starts_with('#')
                && l.split_once('=').is_some_and(|(k, _)| !k.trim().is_empty())
        })
        .count();
    pairs >= 2
}

/// GET plafonné : timeout dur + taille max via curl --max-filesize.
fn fetch_head(url: &str, timeout_secs: u64) -> Option<(u16, String)> {
    let out = Command::new("curl")
        .args([
            "-s",
            "-L",
            "--max-time",
            &timeout_secs.to_string(),
            "--max-filesize",
            &MAX_VERIFY_BYTES.to_string(),
            "--range",
            &format!("0-{}", MAX_VERIFY_BYTES - 1),
            "-w",
            "\n%{http_code}",
            url,
        ])
        .stdin(Stdio::null())
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let raw = String::from_utf8_lossy(&out.stdout).to_string();
    let idx = raw.rfind('\n')?;
    let status: u16 = raw[idx + 1..].trim().parse().ok()?;
    Some((status, raw[..idx].to_string()))
}

/// Niveau de preuve du contenu d'un endpoint sensible.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProofLevel {
    /// Contenu sensible CONFIRMÉ (signature présente, pas de HTML).
    Confirmed,
    /// 2xx mais contenu HTML/générique = soft-404 probable.
    Soft404,
    /// Non 2xx après re-fetch : bloqué ou disparu.
    Blocked,
    /// Re-fetch impossible (réseau/timeout) : incertain.
    Unknown,
}

/// Re-vérifie le contenu d'un endpoint et retourne son niveau de preuve.
pub fn verify_endpoint(ep: &ExposedEndpoint) -> ProofLevel {
    if ep.url.is_empty() {
        return ProofLevel::Unknown;
    }
    match fetch_head(&ep.url, 10) {
        None => ProofLevel::Unknown,
        Some((status, body)) => {
            if !(200..=299).contains(&status) {
                return ProofLevel::Blocked;
            }
            let sigs = ContentSignature::for_path(&ep.path);
            for sig in sigs {
                if sig.matches(&body) {
                    return ProofLevel::Confirmed;
                }
            }
            ProofLevel::Soft404
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ep(path: &str, status: u16, url: &str) -> ExposedEndpoint {
        ExposedEndpoint {
            path: path.to_string(),
            status,
            length: 100,
            url: url.to_string(),
        }
    }

    #[test]
    fn env_signature_needs_pairs_no_html() {
        assert!(ContentSignature::EnvFile.matches("A=1\nB=2\n"));
        assert!(!ContentSignature::EnvFile.matches("<html>Access Denied</html>"));
        assert!(!ContentSignature::EnvFile.matches("A=1 seul"));
    }

    #[test]
    fn git_signatures() {
        assert!(ContentSignature::GitConfig.matches("[core]\nrepositoryformatversion = 0\n"));
        assert!(ContentSignature::GitHead.matches("ref: refs/heads/main\n"));
        assert!(!ContentSignature::GitConfig.matches("<html>404</html>"));
    }

    #[test]
    fn sql_signature() {
        assert!(ContentSignature::SqlDump.matches("INSERT INTO users VALUES (1);"));
        assert!(!ContentSignature::SqlDump.matches("<html>ok</html>"));
    }

    #[test]
    fn html_never_a_proof() {
        // page WAF uniforme 5481 bytes : aucune signature ne doit matcher
        let waf_page = "<html><head><title>Access Denied</title></head><body>You don't have permission</body></html>";
        for sig in [
            ContentSignature::EnvFile,
            ContentSignature::GitConfig,
            ContentSignature::GitHead,
            ContentSignature::SqlDump,
            ContentSignature::WpConfig,
        ] {
            assert!(
                !sig.matches(waf_page),
                "{sig:?} ne doit jamais matcher du HTML"
            );
        }
    }

    #[test]
    fn for_path_ordering() {
        let sigs = ContentSignature::for_path(".git/config");
        assert_eq!(sigs[0], ContentSignature::GitConfig);
        let sigs = ContentSignature::for_path(".env");
        assert_eq!(sigs[0], ContentSignature::EnvFile);
    }

    #[test]
    fn verify_endpoint_empty_url_is_unknown() {
        assert_eq!(verify_endpoint(&ep(".env", 200, "")), ProofLevel::Unknown);
    }
}
