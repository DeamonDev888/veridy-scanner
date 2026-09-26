use crate::modules::findings::SecurityFinding;
use std::time::Instant;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct NucleiItem {
    pub template_id: String,
    pub name: String,
    pub severity: String,
    pub matched_at: String,
    pub description: String,
}

#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct NucleiAuditResult {
    pub success: bool,
    pub elapsed_seconds: f32,
    pub items: Vec<NucleiItem>,
    pub raw_output: String,
    pub summary: String,
}

pub struct NucleiAuditor;

impl NucleiAuditor {
    pub fn audit(target: &str) -> NucleiAuditResult {
        let start = Instant::now();
        // Schéma détecté : les box HTB servent souvent du HTTP pur sur un port
        // exotique — l ancien https:// forcé rendait l outil aveugle (0 findings).
        let hostport = crate::utils::host_with_port(target, &[]);
        let scheme_order = crate::modules::scheme_detect::detect_scheme(&hostport).order;
        let target_url = format!("{}://{}", scheme_order[0], hostport);

        let output = match crate::utils::run_tool(
            "nuclei",
            &[
                "-u",
                &target_url,
                "-tags",
                "cve,misconfig,exposure",
                "-severity",
                "info,low,medium,high,critical",
                "-jsonl",
                "-silent",
                "-timeout",
                "5",
                "-duc",
            ],
            300,
        ) {
            Some(o) => o,
            None => {
                return NucleiAuditResult {
                    success: false,
                    elapsed_seconds: start.elapsed().as_secs_f32(),
                    items: Vec::new(),
                    raw_output: "nuclei : timeout (300s) ou binaire introuvable".into(),
                    summary: "Nuclei interrompu : deadline dépassée".into(),
                };
            }
        };

        let elapsed = start.elapsed().as_secs_f32();
        let stdout_str = String::from_utf8_lossy(&output.stdout).to_string();
        let stderr_str = String::from_utf8_lossy(&output.stderr);

        let mut items = Vec::new();
        for line in stdout_str.lines() {
            let line = line.trim();
            if line.is_empty() || !line.starts_with('{') {
                continue;
            }

            if let Some(item) = Self::parse_json_line(line) {
                items.push(item);
            }
        }

        let summary = format!(
            "Nuclei a complété l'analyse en {:.2}s : {} constatation(s)/vulnérabilité(s) identifiée(s)",
            elapsed,
            items.len()
        );

        let raw_combined = if items.is_empty() && !output.status.success() {
            stderr_str.to_string()
        } else {
            stdout_str
        };

        NucleiAuditResult {
            success: output.status.success(),
            elapsed_seconds: elapsed,
            items,
            raw_output: raw_combined,
            summary,
        }
    }

    fn parse_json_line(line: &str) -> Option<NucleiItem> {
        let template_id = crate::utils::extract_json_str(line, "template-id")
            .or_else(|| crate::utils::extract_json_str(line, "template_id"))
            .unwrap_or_else(|| "unknown".to_string());

        let matched_at = crate::utils::extract_json_str(line, "matched-at")
            .or_else(|| crate::utils::extract_json_str(line, "host"))
            .unwrap_or_default();

        let name =
            crate::utils::extract_json_str(line, "name").unwrap_or_else(|| template_id.clone());

        let severity = crate::utils::extract_json_str(line, "severity")
            .unwrap_or_else(|| "info".to_string())
            .to_uppercase();

        let description = crate::utils::extract_json_str(line, "description").unwrap_or_default();

        Some(NucleiItem {
            template_id,
            name,
            severity,
            matched_at,
            description,
        })
    }

    pub fn to_findings(&self, result: &NucleiAuditResult) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();

        for it in &result.items {
            let sev_static: &'static str = match it.severity.as_str() {
                "CRITICAL" => "CRITICAL",
                "HIGH" => "HIGH",
                "MEDIUM" => "MEDIUM",
                "LOW" => "LOW",
                _ => "INFO",
            };

            let rec = if !it.description.is_empty() {
                format!(
                    "Description : {}. Remédier à cette vulnérabilité/exposition détectée sur {}.",
                    it.description, it.matched_at
                )
            } else {
                format!(
                    "Revue requise pour le template {} détecté à l'adresse {}.",
                    it.template_id, it.matched_at
                )
            };

            findings.push(SecurityFinding {
                severity: sev_static,
                category: "NUCLEI",
                title: format!("Nuclei [{}] - {}", it.template_id, it.name),
                recommendation: rec,
            });
        }

        findings
    }
}
