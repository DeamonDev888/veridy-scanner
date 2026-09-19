use crate::modules::findings::SecurityFinding;
use std::fs;
use std::time::Instant;

#[derive(Debug, Clone, Default)]
#[derive(serde::Serialize, serde::Deserialize)]
pub struct TechStackResult {
    pub success: bool,
    pub elapsed_seconds: f32,
    pub http_status: u16,
    pub server: Option<String>,
    pub emails_exposed: Vec<String>,
    pub detected_technologies: Vec<String>,
    pub raw_output: String,
    pub summary: String,
}

pub struct TechStackAuditor;

impl TechStackAuditor {
    pub fn audit(target: &str) -> TechStackResult {
        let start = Instant::now();
        let target_url = format!("https://{}", target);
        let pid = std::process::id();
        let tmp_output = format!("/tmp/whatweb_{}_{}.json", crate::utils::sanitize_target(target), pid);

        let output = match crate::utils::run_tool(
            "whatweb",
            &[&format!("--log-json={}", tmp_output), &target_url],
            60,
        ) {
            Some(o) => o,
            None => {
                return TechStackResult {
                    success: false,
                    elapsed_seconds: start.elapsed().as_secs_f32(),
                    http_status: 0,
                    server: None,
                    emails_exposed: Vec::new(),
                    detected_technologies: Vec::new(),
                    raw_output: "whatweb : timeout (60s) ou binaire introuvable".into(),
                    summary: "WhatWeb interrompu : deadline dépassée".into(),
                };
            }
        };

        let elapsed = start.elapsed().as_secs_f32();
        let raw_json = fs::read_to_string(&tmp_output)
            .unwrap_or_else(|_| String::from_utf8_lossy(&output.stdout).to_string());
        let _ = fs::remove_file(&tmp_output);

        let (http_status, server, emails, techs) = Self::parse_json(&raw_json);
        let summary = format!(
            "WhatWeb a identifié {} composant(s)/technologie(s) et {} adresse(s) email en {:.2}s",
            techs.len(),
            emails.len(),
            elapsed
        );

        TechStackResult {
            success: output.status.success(),
            elapsed_seconds: elapsed,
            http_status,
            server,
            emails_exposed: emails,
            detected_technologies: techs,
            raw_output: raw_json,
            summary,
        }
    }

    pub(crate) fn parse_json(json: &str) -> (u16, Option<String>, Vec<String>, Vec<String>) {
        let mut server = None;
        let mut emails = Vec::new();
        let mut techs = Vec::new();

        // 0 = inconnu : ne jamais inventer un 200 OK qui masquerait un échec
        let http_status = crate::utils::extract_json_num::<u16>(json, "http_status").unwrap_or(0);

        // Extraire Server
        if let Some(pos) = json.find("\"HTTPServer\":") {
            let rest = &json[pos + 13..];
            if let Some(str_pos) = rest.find("\"string\":") {
                let after = rest[str_pos + 9..].trim_start();
                if let Some(after_bracket) = after.strip_prefix('[') {
                    let after_bracket = after_bracket.trim_start();
                    if let Some(after_quote) = after_bracket.strip_prefix('"') {
                        if let Some(end) = after_quote.find('"') {
                            server = Some(after_quote[..end].to_string());
                        }
                    }
                }
            }
        }

        // Extraire Emails
        if let Some(pos) = json.find("\"Email\":") {
            let rest = &json[pos + 8..];
            if let Some(str_pos) = rest.find("\"string\":") {
                let after = rest[str_pos + 9..].trim_start();
                if let Some(after_bracket) = after.strip_prefix('[') {
                    if let Some(end) = after_bracket.find(']') {
                        let chunk = &after_bracket[..end];
                        for part in chunk.split(',') {
                            let cleaned = part.trim().trim_matches('"').trim_matches('\\');
                            if cleaned.contains('@') && !emails.contains(&cleaned.to_string()) {
                                emails.push(cleaned.to_string());
                            }
                        }
                    }
                }
            }
        }

        // Extraire la liste des clés de plugins
        if let Some(plugins_pos) = json.find("\"plugins\":") {
            let rest = json[plugins_pos + 10..].trim_start();
            if let Some(after_brace) = rest.strip_prefix('{') {
                for part in after_brace.split("\":") {
                    if let Some(last_quote) = part.rfind('"') {
                        let name = &part[last_quote + 1..];
                        if !name.is_empty()
                            && name.len() < 35
                            && name
                                .chars()
                                .all(|c| c.is_alphanumeric() || c == '-' || c == '_')
                            && !techs.contains(&name.to_string())
                        {
                            techs.push(name.to_string());
                        }
                    }
                }
            }
        }

        (http_status, server, emails, techs)
    }

    pub fn to_findings(&self, res: &TechStackResult) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();

        if !res.emails_exposed.is_empty() {
            findings.push(SecurityFinding {
                severity: "LOW",
                category: "WEB",
                title: format!("WhatWeb - {} adresse(s) de courriel publique(s) exposée(s) dans le code source : {}", res.emails_exposed.len(), res.emails_exposed.join(", ")),
                recommendation: "Protéger les adresses courriel contre le scraping automatisé (obfuscation HTML, formulaires de contact) pour prévenir le spam et le spear-phishing.".to_string(),
            });
        }

        if !res.detected_technologies.is_empty() {
            findings.push(SecurityFinding {
                severity: "INFO",
                category: "WEB",
                title: format!("WhatWeb - Inventaire d'empreinte technologique : {}", res.detected_technologies.join(", ")),
                recommendation: "Maintenir à jour l'inventaire des composants logiciels et des dépendances externes.".to_string(),
            });
        }

        if res.http_status >= 400 {
            findings.push(SecurityFinding {
                severity: "MEDIUM",
                category: "WEB",
                title: format!("WhatWeb - Réponse d'erreur HTTP inattendue : Code {}", res.http_status),
                recommendation: "Vérifier la configuration du serveur web et la disponibilité du site pour les requêtes publiques.".to_string(),
            });
        }

        findings
    }
}
