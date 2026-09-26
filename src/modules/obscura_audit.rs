use crate::modules::findings::SecurityFinding;
use crate::utils::extract_json_str;
use std::fs;
use std::time::Instant;

#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct ObscuraResult {
    pub success: bool,
    pub elapsed_seconds: f32,
    pub page_title: String,
    pub total_assets: usize,
    pub script_assets: usize,
    pub external_scripts: Vec<String>,
    pub insecure_assets: Vec<String>,
    pub console_warnings_count: usize,
    pub screenshot_path: Option<String>,
    pub screenshot_size_bytes: u64,
    pub raw_output: String,
    pub summary: String,
}

pub struct ObscuraAuditor;

impl ObscuraAuditor {
    pub fn audit(target: &str) -> ObscuraResult {
        let start = Instant::now();
        let pid = std::process::id();
        let clean_target = crate::utils::sanitize_target(target);
        let screenshot_file = format!("/tmp/obscura_{}_{}.png", clean_target, pid);

        let https_url = format!("https://{}", target);
        let mut output = crate::utils::run_tool(
            "obscura",
            &[
                "fetch",
                &https_url,
                "--dump",
                "assets",
                "--screenshot",
                &screenshot_file,
                "--timeout",
                "12",
            ],
            30,
        );

        let used_http = match &output {
            Some(o) if !o.status.success() => {
                let http_url = format!("http://{}", target);
                if let Some(o_http) = crate::utils::run_tool(
                    "obscura",
                    &[
                        "fetch",
                        &http_url,
                        "--dump",
                        "assets",
                        "--screenshot",
                        &screenshot_file,
                        "--timeout",
                        "12",
                    ],
                    30,
                ) {
                    if o_http.status.success() {
                        output = Some(o_http);
                        true
                    } else {
                        false
                    }
                } else {
                    false
                }
            }
            _ => false,
        };

        let output = match output {
            Some(o) => o,
            None => {
                return ObscuraResult {
                    success: false,
                    elapsed_seconds: start.elapsed().as_secs_f32(),
                    page_title: "Non disponible".into(),
                    summary: "Impossible d'exécuter obscura : timeout ou binaire introuvable"
                        .into(),
                    raw_output: "obscura : timeout (30s) ou binaire introuvable".into(),
                    ..Default::default()
                };
            }
        };

        let elapsed = start.elapsed().as_secs_f32();
        let stdout_str = String::from_utf8_lossy(&output.stdout);
        let stderr_str = String::from_utf8_lossy(&output.stderr);

        let mut total_assets = 0;
        let mut script_assets = 0;
        let mut external_scripts = Vec::new();
        let mut insecure_assets = Vec::new();

        // Analyse des sous-ressources DOM extraites
        for line in stdout_str.lines() {
            let trimmed = line.trim();
            if trimmed.starts_with('{') {
                if let Some(url) = extract_json_str(trimmed, "url") {
                    total_assets += 1;
                    if url.starts_with("http://") && !insecure_assets.contains(&url) {
                        insecure_assets.push(url.clone());
                    }

                    if let Some(typ) = extract_json_str(trimmed, "type") {
                        if typ == "script" {
                            script_assets += 1;
                            if let Some(domain) = Self::extract_domain(&url) {
                                if !is_subdomain(&domain, target)
                                    && !external_scripts.contains(&domain)
                                {
                                    external_scripts.push(domain);
                                }
                            }
                        }
                    }
                }
            }
        }

        // Analyse du flux stderr (logs de rendu V8, titre et console)
        let mut page_title = "Inconnu".to_string();
        let mut console_warnings_count = 0;

        for line in stderr_str.lines() {
            if line.contains("Page loaded:") {
                if let Some(idx) = line.find("- \"") {
                    let rest = &line[idx + 3..];
                    if let Some(end) = rest.rfind('"') {
                        page_title = rest[..end].to_string();
                    }
                }
            }
            if line.contains("WARN obscura::console:") || line.contains("ERROR obscura::console:") {
                console_warnings_count += 1;
            }
        }

        // Vérification de la capture d'écran
        let (screenshot_path, screenshot_size_bytes) =
            if let Ok(meta) = fs::metadata(&screenshot_file) {
                if meta.len() > 0 {
                    (Some(screenshot_file), meta.len())
                } else {
                    let _ = fs::remove_file(&screenshot_file);
                    (None, 0)
                }
            } else {
                (None, 0)
            };

        let proto_tag = if used_http { " via HTTP" } else { "" };
        let summary = format!(
            "Rendu V8 OK ('{}'{}) : {} sous-ressources ({script_assets} JS), {} alertes console, capture PNG ({} Ko) en {:.2}s",
            page_title,
            proto_tag,
            total_assets,
            console_warnings_count,
            screenshot_size_bytes / 1024,
            elapsed
        );

        ObscuraResult {
            success: output.status.success() || total_assets > 0,
            elapsed_seconds: elapsed,
            page_title,
            total_assets,
            script_assets,
            external_scripts,
            insecure_assets,
            console_warnings_count,
            screenshot_path,
            screenshot_size_bytes,
            raw_output: format!("STDOUT:\n{}\nSTDERR:\n{}", stdout_str, stderr_str),
            summary,
        }
    }

    fn extract_domain(url: &str) -> Option<String> {
        let stripped = url
            .strip_prefix("https://")
            .or_else(|| url.strip_prefix("http://"))?;
        let host = stripped.split('/').next()?;
        let clean_host = host.split(':').next()?.trim().to_lowercase();
        if !clean_host.is_empty() {
            Some(clean_host)
        } else {
            None
        }
    }

    pub fn to_findings(&self, res: &ObscuraResult) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();

        if !res.insecure_assets.is_empty() {
            findings.push(SecurityFinding {
                severity: "HIGH",
                category: "WEB",
                title: format!(
                    "Obscura - Contenu mixte non sécurisé ({} ressource(s) HTTP chargée(s))",
                    res.insecure_assets.len()
                ),
                recommendation: "Migrer toutes les sous-ressources (scripts, styles, images) en HTTPS pour éviter le blocage navigateur et les attaques MiTM.".into(),
            });
        }

        if !res.external_scripts.is_empty() {
            let domains_sample = res
                .external_scripts
                .iter()
                .take(3)
                .cloned()
                .collect::<Vec<_>>()
                .join(", ");
            findings.push(SecurityFinding {
                severity: "LOW",
                category: "SUPPLY_CHAIN",
                title: format!(
                    "Obscura - Dépendance envers {} domaine(s) tiers de scripts JS (ex: {})",
                    res.external_scripts.len(),
                    domains_sample
                ),
                recommendation: "Valider la confiance des CDN tiers hébergeant du code exécutable et déployer des attributs 'integrity' (Subresource Integrity - SRI).".into(),
            });
        }

        if res.console_warnings_count > 0 {
            findings.push(SecurityFinding {
                severity: "INFO",
                category: "FRONTEND",
                title: format!(
                    "Obscura - {} anomalie(s) ou avertissement(s) console JS intercepté(s) lors du rendu",
                    res.console_warnings_count
                ),
                recommendation: "Inspecter la console navigateur du frontend pour éliminer les erreurs d'exécution JavaScript et les avertissements de conformité.".into(),
            });
        }

        if res.screenshot_path.is_some() {
            findings.push(SecurityFinding {
                severity: "INFO",
                category: "OBSCURA",
                title: format!(
                    "Obscura - Rendu dynamique V8 et capture visuelle validés (Titre: '{}')",
                    res.page_title
                ),
                recommendation: "Rendu côté client validé. Le portail web s'exécute sans blocage critique du moteur JavaScript.".into(),
            });
        }

        findings
    }
}

/// Vrai sous-domaine : égal ou suffixe ".<target>" — frontière de point obligatoire
/// ("evil-veridy.ca" n'est PAS un sous-domaine de "veridy.ca").
pub(crate) fn is_subdomain(domain: &str, target: &str) -> bool {
    domain == target || domain.ends_with(&format!(".{}", target))
}
