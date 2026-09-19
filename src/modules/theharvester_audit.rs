use std::fs;
use std::time::Instant;

#[derive(Debug, Clone, Default)]
#[derive(serde::Serialize, serde::Deserialize)]
pub struct TheHarvesterResult {
    pub hosts: Vec<String>,
    pub emails: Vec<String>,
    pub ips: Vec<String>,
    pub execution_time_seconds: f32,
    pub raw_output: String,
}

pub struct TheHarvesterAuditor;

impl TheHarvesterAuditor {
    pub fn audit(domain: &str) -> TheHarvesterResult {
        let start = Instant::now();
        let mut result = TheHarvesterResult::default();

        let base_path = format!(
            "/tmp/harvester_{}_{}",
            crate::utils::sanitize_target(domain),
            std::process::id()
        );

        let cmd_res = crate::utils::run_tool(
            "theHarvester",
            &["-d", domain, "-b", "duckduckgo,crtsh", "-f", &base_path],
            150,
        );

        result.execution_time_seconds = start.elapsed().as_secs_f32();

        if let Some(out) = cmd_res {
            result.raw_output = String::from_utf8_lossy(&out.stdout).to_string();
        }

        let json_path = format!("{base_path}.json");
        let xml_path = format!("{base_path}.xml");

        // Nettoyage inconditionnel des DEUX fichiers (le xml fuitait si le json
        // était absent — cas fréquent de crash partiel de theHarvester)
        let content = fs::read_to_string(&json_path);
        let _ = fs::remove_file(&json_path);
        let _ = fs::remove_file(&xml_path);
        if let Ok(content) = content {

            // Extract hosts array
            if let Some(pos) = content.find("\"hosts\":[") {
                let rest = &content[pos + 9..];
                if let Some(end) = rest.find(']') {
                    let array_str = &rest[..end];
                    for item in array_str.split(',') {
                        let clean = item.trim().trim_matches('"').trim().to_lowercase();
                        if !clean.is_empty() && !result.hosts.contains(&clean) {
                            result.hosts.push(clean);
                        }
                    }
                }
            }

            // Extract emails array
            if let Some(pos) = content.find("\"emails\":[") {
                let rest = &content[pos + 10..];
                if let Some(end) = rest.find(']') {
                    let array_str = &rest[..end];
                    for item in array_str.split(',') {
                        let clean = item.trim().trim_matches('"').trim().to_lowercase();
                        if !clean.is_empty() && !result.emails.contains(&clean) {
                            result.emails.push(clean);
                        }
                    }
                }
            }

            // Extract ips array
            if let Some(pos) = content.find("\"ips\":[") {
                let rest = &content[pos + 7..];
                if let Some(end) = rest.find(']') {
                    let array_str = &rest[..end];
                    for item in array_str.split(',') {
                        let clean = item.trim().trim_matches('"').trim();
                        if !clean.is_empty() && !result.ips.contains(&clean.to_string()) {
                            result.ips.push(clean.to_string());
                        }
                    }
                }
            }
        }

        result
    }

    pub fn to_findings(
        &self,
        res: &TheHarvesterResult,
    ) -> Vec<crate::modules::findings::SecurityFinding> {
        use crate::modules::findings::SecurityFinding;
        let mut findings = Vec::new();

        if !res.emails.is_empty() {
            findings.push(SecurityFinding {
                severity: "LOW",
                category: "OSINT",
                title: format!(
                    "theHarvester - {} adresse(s) email repérée(s) dans les moteurs OSINT ({})",
                    res.emails.len(),
                    res.emails.join(", ")
                ),
                recommendation: "Sensibiliser les collaborateurs associés à ces courriels contre le phishing ciblé et le spear-phishing.".into(),
            });
        }

        if !res.hosts.is_empty() {
            findings.push(SecurityFinding {
                severity: "INFO",
                category: "OSINT",
                title: format!(
                    "theHarvester - {} hôte(s) et sous-domaine(s) identifié(s) dans les certificats/moteurs OSINT",
                    res.hosts.len()
                ),
                recommendation: "Vérifier que tous les sous-domaines indexés publiquement sont sécurisés et à jour.".into(),
            });
        }

        findings
    }
}
