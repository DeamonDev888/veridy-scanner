use crate::modules::findings::SecurityFinding;
use std::fs;
use std::time::Instant;

#[derive(Debug, Clone)]
#[derive(serde::Serialize, serde::Deserialize)]
pub struct ExposedEndpoint {
    pub path: String,
    pub status: u16,
    pub length: usize,
    pub url: String,
}

#[derive(Debug, Clone, Default)]
#[derive(serde::Serialize, serde::Deserialize)]
pub struct FfufAuditResult {
    pub success: bool,
    pub elapsed_seconds: f32,
    pub endpoints: Vec<ExposedEndpoint>,
    pub raw_output: String,
    pub summary: String,
}

pub struct FfufAuditor;

impl FfufAuditor {
    pub fn audit(target: &str) -> FfufAuditResult {
        let start = Instant::now();
        let target_url = format!("https://{}/FUZZ", target);
        let pid = std::process::id();
        let tmp_output = format!("/tmp/ffuf_{}_{}.json", crate::utils::sanitize_target(target), pid);
        let wordlist = "/usr/share/seclists/Discovery/Web-Content/quickhits.txt";

        if !std::path::Path::new(wordlist).exists() {
            return FfufAuditResult {
                success: false,
                elapsed_seconds: start.elapsed().as_secs_f32(),
                endpoints: Vec::new(),
                raw_output: "Wordlist SecLists non trouvée sur le système.".into(),
                summary: "Ffuf ignoré : SecLists non présent".into(),
            };
        }

        let output = match crate::utils::run_tool(
            "ffuf",
            &[
                "-u",
                &target_url,
                "-w",
                wordlist,
                "-ac",
                "-mc",
                "200,301,302,403",
                "-fc",
                "404",
                "-maxtime",
                "90",
                "-rate",
                "50",
                "-t",
                "10",
                "-of",
                "json",
                "-o",
                &tmp_output,
                "-s",
            ],
            120,
        ) {
            Some(o) => o,
            None => {
                return FfufAuditResult {
                    success: false,
                    elapsed_seconds: start.elapsed().as_secs_f32(),
                    endpoints: Vec::new(),
                    raw_output: "ffuf : timeout (120s) ou binaire introuvable".into(),
                    summary: "Ffuf interrompu : deadline dépassée".into(),
                };
            }
        };

        let elapsed = start.elapsed().as_secs_f32();
        let raw_json = fs::read_to_string(&tmp_output)
            .unwrap_or_else(|_| String::from_utf8_lossy(&output.stdout).to_string());
        let _ = fs::remove_file(&tmp_output);

        let endpoints = Self::parse_json(&raw_json);
        let summary = format!(
            "Ffuf + SecLists a testé 2500+ chemins sensibles en {:.2}s : {} route(s) découverte(s)",
            elapsed,
            endpoints.len()
        );

        FfufAuditResult {
            success: output.status.success(),
            elapsed_seconds: elapsed,
            endpoints,
            raw_output: raw_json,
            summary,
        }
    }

    pub(crate) fn parse_json(json: &str) -> Vec<ExposedEndpoint> {
        let mut list = Vec::new();

        if let Some(res_pos) = json.find("\"results\":") {
            let rest = json[res_pos + 10..].trim_start();
            if let Some(rest_after_bracket) = rest.strip_prefix('[') {
                if let Some(arr_end) = rest_after_bracket.find(']') {
                    let chunk = &rest_after_bracket[..arr_end];
                    let mut sub_rest = chunk;
                    while let Some(obj_start) = sub_rest.find('{') {
                        sub_rest = &sub_rest[obj_start..];
                        let obj_end = match sub_rest.find('}') {
                            Some(e) => e + 1,
                            None => break,
                        };
                        let obj_str = &sub_rest[..obj_end];
                        sub_rest = &sub_rest[obj_end..];

                        let url = crate::utils::extract_json_str(obj_str, "url").unwrap_or_default();
                        let path = crate::utils::extract_json_str(obj_str, "FUZZ").unwrap_or_default();
                        let status =
                            crate::utils::extract_json_num::<u16>(obj_str, "status").unwrap_or(200);
                        let length =
                            crate::utils::extract_json_num::<usize>(obj_str, "length").unwrap_or(0);

                        if !path.is_empty() {
                            list.push(ExposedEndpoint {
                                path,
                                status,
                                length,
                                url,
                            });
                        }
                    }
                }
            }
        }

        list
    }

    pub fn to_findings(&self, res: &FfufAuditResult) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();

        let is_flooded = res.endpoints.len() > 30;
        let mut endpoints = res.endpoints.clone();

        if is_flooded {
            // Trier par criticité : chemins hautement sensibles en premier
            endpoints.sort_by_key(|ep| {
                let p = ep.path.to_lowercase();
                if p.starts_with(".git") || p.starts_with(".env") || p.contains("backup") || p.contains("config") || p.ends_with(".sql") {
                    0
                } else if p.contains("admin") || p.contains("api") || p.contains("dashboard") || p.contains("login") {
                    1
                } else if ep.status == 200 {
                    2
                } else {
                    3
                }
            });
            endpoints.truncate(20);
        }

        for ep in &endpoints {
            let (severity, rec) = if ep.path.starts_with(".git")
                || ep.path.starts_with(".env")
                || ep.path.contains("backup")
                || ep.path.contains("config")
                || ep.path.ends_with(".sql")
            {
                ("CRITICAL", "Restreindre immédiatement l'accès à ce fichier sensible ou le supprimer du répertoire racine public.")
            } else if ep.status == 200 {
                ("LOW", "Vérifier que ce chemin public ne divulgue aucune donnée interne confidentielle.")
            } else {
                (
                    "INFO",
                    "Route exposée retournant un code de redirection ou restriction.",
                )
            };

            let rec_detail = if !ep.url.is_empty() {
                format!("{} (URL testée : {})", rec, ep.url)
            } else {
                rec.to_string()
            };

            findings.push(SecurityFinding {
                severity,
                category: "WEB",
                title: format!(
                    "SecLists / Ffuf - Route/Fichier sensible découvert : /{} (HTTP {})",
                    ep.path, ep.status
                ),
                recommendation: rec_detail,
            });
        }

        if is_flooded {
            findings.push(SecurityFinding {
                severity: "INFO",
                category: "WEB",
                title: format!(
                    "SecLists / Ffuf - Détection Catch-all / Réponse massive ({} routes)",
                    res.endpoints.len()
                ),
                recommendation: "Le serveur retourne un statut HTTP de succès sur un nombre inhabituel de chemins testés (comportement SPA ou réécriture d'URL). L'affichage a été limité aux 20 routes prioritaires afin de préserver l'intégrité de l'évaluation globale.".to_string(),
            });
        }

        findings
    }
}
