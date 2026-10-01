use crate::modules::findings::SecurityFinding;
use crate::utils::{extract_json_bool, extract_json_str};
use std::fs;
use std::time::Instant;

#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct WafResult {
    pub success: bool,
    pub elapsed_seconds: f32,
    /// Challenge edge detecte sur un port non standard (2083/2087/2096...) :
    /// page "One moment..." / cf-mitigated / __cf_chl. Lecons 8brains.ca :
    /// wafw00f sur 80/443 disait "aucun WAF" alors que tout etait proxifie.
    pub edge_challenge_ports: Vec<u16>,
    pub waf_detected: bool,
    pub firewall_name: String,
    pub manufacturer: String,
    pub raw_output: String,
    pub summary: String,
}

pub struct WafAuditor;

impl WafAuditor {
    pub fn audit(target: &str) -> WafResult {
        let start = Instant::now();
        // Schéma détecté : les box HTB servent souvent du HTTP pur sur un port
        // exotique — l ancien https:// forcé rendait l outil aveugle (0 findings).
        let hostport = crate::utils::host_with_port(target, &[]);
        let scheme_order = crate::modules::scheme_detect::detect_scheme(&hostport).order;
        let target_url = format!("{}://{}", scheme_order[0], hostport);
        let pid = std::process::id();
        let tmp_output = format!(
            "/tmp/waf_{}_{}.json",
            crate::utils::sanitize_target(target),
            pid
        );

        let output = match crate::utils::run_tool(
            "wafw00f",
            &["-o", &tmp_output, "-f", "json", &target_url],
            60,
        ) {
            Some(o) => o,
            None => {
                return WafResult {
                    success: false,
                    elapsed_seconds: start.elapsed().as_secs_f32(),
                    edge_challenge_ports: Vec::new(),
                    waf_detected: false,
                    firewall_name: "None".into(),
                    manufacturer: "None".into(),
                    raw_output: "wafw00f : timeout (60s) ou binaire introuvable".into(),
                    summary: "Wafw00f interrompu : deadline dépassée".into(),
                };
            }
        };

        let elapsed = start.elapsed().as_secs_f32();
        let raw_json = fs::read_to_string(&tmp_output)
            .unwrap_or_else(|_| String::from_utf8_lossy(&output.stdout).to_string());
        let _ = fs::remove_file(&tmp_output);

        let waf_detected = extract_json_bool(&raw_json, "detected").unwrap_or(false);
        let firewall_name =
            extract_json_str(&raw_json, "firewall").unwrap_or_else(|| "None".to_string());
        let manufacturer =
            extract_json_str(&raw_json, "manufacturer").unwrap_or_else(|| "None".to_string());

        // Multi-ports : wafw00f ne voit que le port principal ; les panneaux
        // d'admin (cPanel/WHM/webmail) sont souvent derriere un edge challenge.
        let host_only = hostport.split(':').next().unwrap_or(&hostport).to_string();
        let edge_challenge_ports = Self::probe_edge_challenges(&host_only);
        let edge_active = !edge_challenge_ports.is_empty();

        let summary = if waf_detected {
            format!(
                "WAF détecté : {} ({}) en {:.2}s",
                firewall_name, manufacturer, elapsed
            )
        } else if edge_active {
            let ports_str = edge_challenge_ports
                .iter()
                .map(|p| p.to_string())
                .collect::<Vec<_>>()
                .join(", ");
            format!(
                "Challenge edge (type Cloudflare) actif sur {} port(s) non standard : {}",
                edge_challenge_ports.len(),
                ports_str
            )
        } else {
            format!(
                "Aucun WAF détecté (infrastructure directe) en {:.2}s",
                elapsed
            )
        };

        WafResult {
            success: output.status.success() || edge_active,
            elapsed_seconds: elapsed,
            waf_detected: waf_detected || edge_active,
            edge_challenge_ports,
            firewall_name: if waf_detected {
                firewall_name
            } else if edge_active {
                "Edge Challenge (Cloudflare-like)".to_string()
            } else {
                firewall_name
            },
            manufacturer,
            raw_output: raw_json,
            summary,
        }
    }

    /// Sonde passive multi-ports : GET / sur 2083/2087/2096 (et 2082/2086/2095
    /// en http) et cherche les marqueurs de challenge edge. 1 requete par port.
    fn probe_edge_challenges(host: &str) -> Vec<u16> {
        let probes: &[(u16, &str)] = &[
            (2083, "https"),
            (2087, "https"),
            (2096, "https"),
            (2082, "http"),
            (2086, "http"),
            (2095, "http"),
        ];
        let mut hit = Vec::new();
        for (port, scheme) in probes {
            // -i : headers INCLUS dans stdout (le marqueur "One moment" vit
            // dans le BODY du challenge JS — -o /dev/null le jetait).
            let out = crate::utils::run_tool(
                "curl",
                &[
                    "-ski",
                    "--max-time",
                    "6",
                    &format!("{scheme}://{host}:{port}/"),
                ],
                10,
            );
            let Some(o) = out else { continue };
            let s = String::from_utf8_lossy(&o.stdout).to_string();
            let lower = s.to_lowercase();
            // Marqueurs : challenge JS (titre classique), headers Cloudflare/edge
            let challenged = lower.contains("one moment")
                || lower.contains("cf-mitigated")
                || lower.contains("__cf_chl")
                || lower.contains("cf-ray")
                || lower.contains("cloudflare")
                || lower.contains("attention required")
                || lower.contains("checking your browser");
            if challenged {
                hit.push(*port);
            }
        }
        hit
    }

    pub fn to_findings(&self, res: &WafResult) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();

        if res.waf_detected {
            findings.push(SecurityFinding {
                severity: "INFO",
                category: "WAF",
                title: format!(
                    "Pare-feu applicatif (WAF) actif : {} ({})",
                    res.firewall_name, res.manufacturer
                ),
                recommendation: "Prendre en compte le WAF dans les tests applicatifs ultérieurs : ses règles de filtrage peuvent nécessiter des techniques dévasion (encodage, fragmentation des requêtes).".to_string(),
            });
        } else {
            findings.push(SecurityFinding {
                severity: "INFO",
                category: "WAF",
                title: "Aucun pare-feu applicatif (WAF) périmétrique détecté".to_string(),
                recommendation: "Le serveur traite directement les requêtes. Évaluer le déploiement d'un WAF périmétrique (ModSecurity, Cloudflare, etc.) pour atténuer les attaques L7 et bots.".to_string(),
            });
        }

        findings
    }
}
