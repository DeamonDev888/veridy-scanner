use crate::modules::findings::SecurityFinding;
use crate::modules::impact::{self, ProofLevel};
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
    pub fn audit(target: &str, custom_ports: &[u16]) -> FfufAuditResult {
        let start = Instant::now();
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

        // Schéma réellement disponible au lieu d'un https/ forcé : TLS détecté
        // → https d'abord, sinon http. Le second schéma sert de fallback si la
        // première passe ne découvre rien (cible HTTP simple sur port custom).
        let hostport = crate::utils::host_with_port(target, custom_ports);
        let schemes: [&str; 2] = if Self::tls_answers(&hostport) {
            ["https", "http"]
        } else {
            ["http", "https"]
        };

        let mut endpoints: Vec<ExposedEndpoint> = Vec::new();
        let mut raw_json = String::new();
        let mut run_success = false;

        // BASELINE SOFT-404 : avant le fuzz, on sonde 2 chemins aléatoires
        // inexistants. Un serveur qui renvoie (status, taille) identique sur
        // ces sondes sert une réponse générique (WAF "Access Denied" 403
        // uniforme, SPA catch-all) : tout endpoint partageant cette signature
        // est du bruit, pas une découverte. C'est ce piège qui a généré ~140
        // faux CRITICAL ".env/.git accessibles" sur metro.ca (WAF → 403 de
        // 5481 bytes sur tous les chemins testés).
        let baseline = Self::soft404_baseline(&hostport, &schemes);
        let (baseline_status, baseline_len) = match &baseline {
            Some((s, l)) => (*s, *l),
            None => (0, usize::MAX),
        };

        for scheme in schemes {
            let target_url = format!("{}://{}/FUZZ", scheme, hostport);
            // 403 RETIRÉ du -mc : un 403 est un blocage (WAF/permissions),
            // jamais une preuve d'existence. Les vrais fichiers sensibles
            //servis sont en 2xx. Les redirections (301/302) restent utiles
            //pour la cartographie. -ac gère le catch-all calibré sur 200.
            let output = match crate::utils::run_tool(
                "ffuf",
                &[
                    "-u",
                    &target_url,
                    "-w",
                    wordlist,
                    "-ac",
                    "-mc",
                    "200,301,302",
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
                None => continue,
            };

            let json = fs::read_to_string(&tmp_output)
                .unwrap_or_else(|_| String::from_utf8_lossy(&output.stdout).to_string());
            let _ = fs::remove_file(&tmp_output);

            run_success = output.status.success();
            raw_json = json;
            // Filtrage soft-404 : on ne garde que les endpoints dont la
            // signature (status + taille) diffère de la réponse générique.
            endpoints = Self::parse_json(&raw_json)
                .into_iter()
                .filter(|ep| {
                    // Pas de baseline exploitable → on garde tout (comportement sûr)
                    if baseline_status == 0 {
                        return true;
                    }
                    // Signature identique à la sonde random = bruit WAF/catch-all
                    !(ep.status == baseline_status && ep.length == baseline_len)
                })
                .collect();
            if !endpoints.is_empty() {
                break;
            }
        }

        let elapsed = start.elapsed().as_secs_f32();

        if raw_json.is_empty() && !run_success {
            return FfufAuditResult {
                success: false,
                elapsed_seconds: elapsed,
                endpoints: Vec::new(),
                raw_output:
                    "ffuf : timeout (120s), binaire introuvable ou schéma http/https inaccessible"
                        .into(),
                summary: "Ffuf interrompu : deadline dépassée ou cible HTTP/HTTPS injoignable"
                    .into(),
            };
        }

        let summary = format!(
            "Ffuf + SecLists a testé 2500+ chemins sensibles en {:.2}s : {} route(s) découverte(s)",
            elapsed,
            endpoints.len()
        );

        FfufAuditResult {
            success: run_success,
            elapsed_seconds: elapsed,
            endpoints,
            raw_output: raw_json,
            summary,
        }
    }

    /// Détection TLS rapide (4 s) : vrai si le port répond en HTTPS
    /// (certificat non validé — un self-signed reste du TLS).
    fn tls_answers(hostport: &str) -> bool {
        let url = format!("https://{}/", hostport);
        crate::utils::run_tool(
            "curl",
            &[
                "-s",
                "-k",
                "-o",
                "/dev/null",
                "--max-time",
                "4",
                "-w",
                "%{http_code}",
                &url,
            ],
            6,
        )
        .is_some_and(|o| o.status.success() && String::from_utf8_lossy(&o.stdout).trim() != "000")
    }

    /// Sonde 2 chemins aléatoires inexistants pour établir la signature de la
    /// réponse générique du serveur (soft-404 / blocage WAF uniforme).
    /// Retourne Some((status, taille)) si les deux sondes s'accordent,
    /// sinon None (pas de baseline fiable → pas de filtrage).
    fn soft404_baseline(hostport: &str, schemes: &[&str]) -> Option<(u16, usize)> {
        let probes = [
            format!("zzqx-{}-nonexistent", std::process::id()),
            format!("vfyw-{}-404probe", std::process::id()),
        ];
        // Le schéma qui répond réellement (celui que ffuf fuzzera en premier)
        let mut probe_scheme = schemes.first().copied()?;
        {
            let url = format!("{}://{}/{}", probe_scheme, hostport, probes[0]);
            let out = crate::utils::run_tool(
                "curl",
                &[
                    "-s",
                    "-k",
                    "-o",
                    "/dev/null",
                    "--max-time",
                    "6",
                    "-w",
                    "%{http_code}",
                    &url,
                ],
                8,
            )?;
            if String::from_utf8_lossy(&out.stdout).trim() == "000" {
                probe_scheme = schemes.get(1).copied()?;
            }
        }
        let mut first: Option<(u16, usize)> = None;
        for p in &probes {
            let url = format!("{}://{}/{}", probe_scheme, hostport, p);
            let out = crate::utils::run_tool(
                "curl",
                &[
                    "-s",
                    "-k",
                    "-o",
                    "/dev/null",
                    "--max-time",
                    "6",
                    "-w",
                    "%{http_code} %{size_download}",
                    &url,
                ],
                8,
            )?;
            let s = String::from_utf8_lossy(&out.stdout);
            let mut it = s.split_whitespace();
            let status: u16 = it.next()?.parse().ok()?;
            let length: usize = it.next()?.parse().ok()?;
            match first {
                Some((s0, l0)) if s0 == status && l0 == length => return Some((status, length)),
                Some(_) => return None, // signatures divergentes → pas de baseline
                None => first = Some((status, length)),
            }
        }
        None
    }

    /// Parse la sortie JSON de ffuf via serde_json (plus de découpage manuel
    /// par accolades : le format réel de ffuf imbrique le mot-clé dans
    /// "input":{"FUZZ":"..."} et le premier '}' fermait l'objet parent trop
    /// tôt → path vide → 0 route découverte sur un scan pourtant fructueux).
    pub(crate) fn parse_json(json: &str) -> Vec<ExposedEndpoint> {
        let mut list = Vec::new();

        let Ok(v) = serde_json::from_str::<serde_json::Value>(json) else {
            return list;
        };
        let Some(results) = v.get("results").and_then(|r| r.as_array()) else {
            return list;
        };

        for r in results {
            // Format réel ffuf : "input":{"FUZZ":"<mot>"} ; rétrocompat
            // fixtures à clé plate : "input":"<mot>".
            let path = r
                .pointer("/input/FUZZ")
                .and_then(|p| p.as_str())
                .or_else(|| r.get("input").and_then(|i| i.as_str()))
                .unwrap_or_default()
                .to_string();
            let url = r
                .get("url")
                .and_then(|u| u.as_str())
                .unwrap_or_default()
                .to_string();
            // status_code (snake_case dans le JSON ffuf, pas status)
            let status = r
                .get("status_code")
                .and_then(|s| s.as_u64())
                .or_else(|| r.get("status").and_then(|s| s.as_u64()))
                .unwrap_or(0) as u16;
            let length = r.get("length").and_then(|l| l.as_u64()).unwrap_or(0) as usize;

            // Skip si path vide (parsing raté) OU status 0 (introuvable)
            if !path.is_empty() && status > 0 {
                list.push(ExposedEndpoint {
                    path,
                    status,
                    length,
                    url,
                });
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

        let mut verified_count: usize = 0;
        for ep in &endpoints {
            // CRITICAL exige DOUBLE preuve : path sensible ET status 2xx (contenu reellement servi)
            // Sans verification status, on declare a tort CRITICAL sur .git/.env bloques par Cloudflare (403)
            let is_sensitive_path = ep.path.starts_with(".git")
                || ep.path.starts_with(".env")
                || ep.path.contains("backup")
                || ep.path.contains("config")
                || ep.path.ends_with(".sql");
            let is_really_accessible = (200..=299).contains(&ep.status);
            let length = ep.length as i64;
            let rec_html_error = format!(
                "Path sensible repond 200 mais longueur suspecte ({} bytes, typique page HTML Cloudflare/WAF). VERIFICATION MANUELLE REQUISE : curl -i {} | head -30 pour confirmer le contenu reel.",
                length, ep.url
            );

            // ANTI-FAUX-POSITIF : si path sensible ET status 200 mais longueur typique d'une
            // page d'erreur HTML (4500-7000 bytes = Cloudflare "Access Denied" 5481 bytes, etc.),
            // c'est un piege : le serveur renvoie une page HTML meme pour /git/HEAD au lieu du contenu reel.
            // Sans re-fetch du contenu (coûteux), on degrade CRITICAL -> MEDIUM avec demande de verification manuelle.
            let is_html_error_page =
                is_really_accessible && is_sensitive_path && (4500..=7000).contains(&length);

            // ANTI-FAUX-POSITIF v2 : CRITICAL exige maintenant la PREUVE DE CONTENU.
            // On re-fetch l'URL (budget MAX_VERIFICATIONS_PER_SCAN) et on matche la
            // signature attendue (.env -> KEY=VALUE, .git/config -> [core], ...).
            // Un 200 sans contenu preuve = soft-404/WAF -> jamais CRITICAL (lecon metro.ca).
            let proof = if verified_count < impact::MAX_VERIFICATIONS_PER_SCAN
                && is_sensitive_path
                && is_really_accessible
            {
                verified_count += 1;
                impact::verify_endpoint(ep)
            } else {
                ProofLevel::Unknown
            };

            let rec_unverified = "Path sensible en 2xx mais contenu NON verifie (budget/timeout) - verifier manuellement: curl -i".to_string();
            let (severity, rec) = if is_sensitive_path
                && is_really_accessible
                && proof == ProofLevel::Confirmed
            {
                ("CRITICAL", "Fichier sensible CONFIRME par verification de contenu (signature presente, non-HTML) - restreindre immediatement.")
            } else if is_sensitive_path && is_really_accessible && proof == ProofLevel::Soft404 {
                // 2xx mais contenu HTML/generique au re-fetch : soft-404 probable
                ("MEDIUM", rec_html_error.as_str())
            } else if is_sensitive_path && is_really_accessible {
                // 2xx mais preuve Impossible (budget reseau epuise ou fetch rate) :
                // JAMAIS CRITICAL sans confirmation de contenu (lecon metro.ca)
                ("MEDIUM", rec_unverified.as_str())
            } else if is_html_error_page {
                // Longueur suspecte + budget de verification epuise : verification manuelle
                ("MEDIUM", rec_html_error.as_str())
            } else if is_sensitive_path {
                (
                    "INFO",
                    "Path sensible detecte mais bloque par WAF/auth - serveur protege.",
                )
            } else if ep.status == 200 {
                ("LOW", "Verifier que ce chemin public ne divulgue aucune donnee interne confidentielle.")
            } else {
                (
                    "INFO",
                    "Route exposee retournant un code de redirection ou restriction.",
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
