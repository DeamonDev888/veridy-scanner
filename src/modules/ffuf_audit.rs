use crate::modules::findings::SecurityFinding;
use std::fs;
use std::time::Instant;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ExposedEndpoint {
    pub path: String,
    pub status: u16,
    pub length: usize,
    pub url: String,
}

#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
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
        let tmp_output = format!(
            "/tmp/ffuf_{}_{}.json",
            crate::utils::sanitize_target(target),
            pid
        );
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
                "200,204",
                "-fc",
                "404,403,301,302",
                "-fs",
                "0",
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
        // Parsing avec serde_json : le JSON ffuf imbricre "input":{"FUZZ":...}
        // dans chaque resultat — le decoupage manuel par accolades confondait
        // l'objet parent et son fils (url systematiquement vide).
        let mut list = Vec::new();
        let Ok(v) = serde_json::from_str::<serde_json::Value>(json) else {
            return list;
        };
        let Some(results) = v.get("results").and_then(|r| r.as_array()) else {
            return list;
        };
        for r in results {
            // Vrai format ffuf : "input":{"FUZZ": "..."} — ancien format
            // plat "FUZZ": "..." accepté pour rétrocompatibilité.
            let path = r
                .pointer("/input/FUZZ")
                .and_then(|x| x.as_str())
                .or_else(|| r.get("FUZZ").and_then(|x| x.as_str()))
                .unwrap_or_default()
                .to_string();
            if path.is_empty() {
                continue;
            }
            list.push(ExposedEndpoint {
                url: r
                    .get("url")
                    .and_then(|x| x.as_str())
                    .unwrap_or("")
                    .to_string(),
                status: r.get("status").and_then(|x| x.as_u64()).unwrap_or(0) as u16,
                length: r.get("length").and_then(|x| x.as_u64()).unwrap_or(0) as usize,
                path,
            });
        }
        list
    }

    /// Vérifie qu'une réponse 200 contient BIEN le contenu attendu pour un
    /// chemin sensible — sinon c'est un soft-404 / catch-all (faux positif).
    /// Fetch GET court (timeout 10 s) sur l'URL rapportée par ffuf.
    fn response_matches_signature(path: &str, url: &str) -> Option<bool> {
        if url.is_empty() {
            return None; // pas vérifiable
        }
        let body = crate::utils::run_tool("curl", &["-s", "-L", "--max-time", "10", url], 15)?;
        let body = String::from_utf8_lossy(&body.stdout).to_string();
        let p = path.to_lowercase();
        let sigs: &[&str] = if p.starts_with(".env") {
            &[
                "DB_PASSWORD=",
                "APP_KEY=",
                "API_KEY=",
                "DATABASE_URL=",
                "SECRET_KEY=",
            ]
        } else if p.starts_with(".git/config") || p.starts_with(".git") {
            &["[core]", "[remote \"origin\"]", "repositoryformatversion"]
        } else if p.starts_with(".git/head") {
            &["ref: refs/"]
        } else if p.contains("backup") || p.ends_with(".sql") {
            &["INSERT INTO", "CREATE TABLE", "DROP TABLE", "-- MySQL dump"]
        } else if p.contains("config") {
            &[
                "DB_PASSWORD",
                "database",
                "password",
                "define('",
                "$cfg",
                "<?php",
            ]
        } else {
            return None; // chemin non critique : pas de signature
        };
        Some(sigs.iter().any(|sig| body.contains(sig)))
    }

    pub fn to_findings(&self, res: &FfufAuditResult) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();

        let is_flooded = res.endpoints.len() > 30;
        let mut endpoints = res.endpoints.clone();

        if is_flooded {
            // Trier par criticité : chemins hautement sensibles en premier
            endpoints.sort_by_key(|ep| {
                let p = ep.path.to_lowercase();
                if p.starts_with(".git")
                    || p.starts_with(".env")
                    || p.contains("backup")
                    || p.contains("config")
                    || p.ends_with(".sql")
                {
                    0
                } else if p.contains("admin")
                    || p.contains("api")
                    || p.contains("dashboard")
                    || p.contains("login")
                {
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
            // Chemin critique → CONFIRMER par le contenu avant de crier CRITICAL.
            // Un 200 catch-all (soft-404) sur /.env est un faux positif classique.
            let critical_candidate = ep.path.starts_with(".git")
                || ep.path.starts_with(".env")
                || ep.path.contains("backup")
                || ep.path.contains("config")
                || ep.path.ends_with(".sql");
            let content_confirmed = if critical_candidate {
                match Self::response_matches_signature(&ep.path, &ep.url) {
                    Some(true) => true,   // contenu sensible réellement servi
                    Some(false) => false, // soft-404 / page générique : déclasser
                    None => false,        // non vérifiable : prudence → pas CRITICAL
                }
            } else {
                false
            };

            let (severity, rec) = if content_confirmed {
                ("CRITICAL", "Contenu sensible CONFIRMÉ servi par le serveur : restreindre immédiatement l'accès et révoquer les secrets exposés.")
            } else if critical_candidate {
                ("INFO", "Chemin sensible accessible en HTTP 200 mais contenu non conforme (soft-404 probable / catch-all ou page générique). Vérification manuelle conseillée.")
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
