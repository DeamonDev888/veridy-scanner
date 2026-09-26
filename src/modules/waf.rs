use crate::modules::findings::SecurityFinding;
use crate::utils::{extract_json_bool, extract_json_str};
use std::fs;
use std::time::Instant;

#[derive(Debug, Clone, Default)]
#[derive(serde::Serialize, serde::Deserialize)]
pub struct WafResult {
    pub success: bool,
    pub elapsed_seconds: f32,
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
        let tmp_output = format!("/tmp/waf_{}_{}.json", crate::utils::sanitize_target(target), pid);

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

        let summary = if waf_detected {
            format!(
                "WAF détecté : {} ({}) en {:.2}s",
                firewall_name, manufacturer, elapsed
            )
        } else {
            format!(
                "Aucun WAF détecté (infrastructure directe) en {:.2}s",
                elapsed
            )
        };

        WafResult {
            success: output.status.success(),
            elapsed_seconds: elapsed,
            waf_detected,
            firewall_name,
            manufacturer,
            raw_output: raw_json,
            summary,
        }
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
                recommendation: "Vérifier que le WAF ne transite pas les données hors de la juridiction requise par votre politique interne.".to_string(),
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
