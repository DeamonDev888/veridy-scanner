use crate::modules::findings::SecurityFinding;
use std::fs;
use std::time::Instant;

#[derive(Debug, Clone)]
#[derive(serde::Serialize, serde::Deserialize)]
pub struct NiktoVulnerability {
    pub id: String,
    pub method: String,
    pub url: String,
    pub msg: String,
    pub references: String,
}

#[derive(Debug, Clone, Default)]
#[derive(serde::Serialize, serde::Deserialize)]
pub struct NiktoAuditResult {
    pub success: bool,
    pub elapsed_seconds: f32,
    pub vulnerabilities: Vec<NiktoVulnerability>,
    pub raw_output: String,
    pub summary: String,
}

pub struct NiktoAuditor;

impl NiktoAuditor {
    pub fn audit(target: &str) -> NiktoAuditResult {
        let start = Instant::now();
        // Schéma détecté : les box HTB servent souvent du HTTP pur sur un port
        // exotique — l ancien https:// forcé rendait l outil aveugle (0 findings).
        let hostport = crate::utils::host_with_port(target, &[]);
        let scheme_order = crate::modules::scheme_detect::detect_scheme(&hostport).order;
        let target_url = format!("{}://{}", scheme_order[0], hostport);
        let pid = std::process::id();
        let tmp_output = format!("/tmp/nikto_{}_{}.json", crate::utils::sanitize_target(target), pid);

        let output = match crate::utils::run_tool(
            "nikto",
            &[
                "-host",
                &target_url,
                "-maxtime",
                "35s",
                "-Tuning",
                "1,2,3,b",
                "-Format",
                "json",
                "-output",
                &tmp_output,
            ],
            60,
        ) {
            Some(o) => o,
            None => {
                return NiktoAuditResult {
                    success: false,
                    elapsed_seconds: start.elapsed().as_secs_f32(),
                    vulnerabilities: Vec::new(),
                    raw_output: "nikto : timeout (60s) ou binaire introuvable".into(),
                    summary: "Nikto interrompu : deadline dépassée".into(),
                };
            }
        };

        let elapsed = start.elapsed().as_secs_f32();
        let raw_json = fs::read_to_string(&tmp_output)
            .unwrap_or_else(|_| String::from_utf8_lossy(&output.stdout).to_string());

        // Nettoyer le fichier temporaire
        let _ = fs::remove_file(&tmp_output);

        let vulnerabilities = Self::parse_nikto_json(&raw_json);
        let summary = format!(
            "Nikto a terminé l'analyse web en {:.2}s : {} item(s) et anomalie(s) répertorié(s)",
            elapsed,
            vulnerabilities.len()
        );

        NiktoAuditResult {
            success: output.status.success(),
            elapsed_seconds: elapsed,
            vulnerabilities,
            raw_output: raw_json,
            summary,
        }
    }

    fn parse_nikto_json(json: &str) -> Vec<NiktoVulnerability> {
        let mut items = Vec::new();

        // Repérer le tableau "vulnerabilities" : [ ... ]
        if let Some(vuln_idx) = json.find("\"vulnerabilities\"") {
            let rest = &json[vuln_idx..];
            if let Some(arr_start) = rest.find('[') {
                let arr_content = &rest[arr_start + 1..];
                let mut chunk_rest = arr_content;
                while let Some(obj_start) = chunk_rest.find('{') {
                    chunk_rest = &chunk_rest[obj_start..];
                    let obj_end = match chunk_rest.find('}') {
                        Some(e) => e + 1,
                        None => break,
                    };
                    let obj_str = &chunk_rest[..obj_end];
                    chunk_rest = &chunk_rest[obj_end..];

                    let id = crate::utils::extract_json_str(obj_str, "id").unwrap_or_default();
                    let method =
                        crate::utils::extract_json_str(obj_str, "method").unwrap_or_default();
                    let url = crate::utils::extract_json_str(obj_str, "url").unwrap_or_default();
                    let msg = crate::utils::extract_json_str(obj_str, "msg").unwrap_or_default();
                    let references =
                        crate::utils::extract_json_str(obj_str, "references").unwrap_or_default();

                    if !msg.is_empty() || !url.is_empty() {
                        items.push(NiktoVulnerability {
                            id,
                            method,
                            url,
                            msg,
                            references,
                        });
                    }
                }
            }
        }

        items
    }

    pub fn to_findings(&self, result: &NiktoAuditResult) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();

        for v in &result.vulnerabilities {
            // Filtrer les entrées purement informatives si désiré, ou les catégoriser
            let severity = if v.msg.contains("vulnerable") || v.msg.contains("remote execution") {
                "HIGH"
            } else if v.msg.contains("Uncommon header")
                || v.msg.contains("interesting")
                || v.msg.contains("refresh")
            {
                "LOW"
            } else {
                "INFO"
            };

            let rec = if !v.references.is_empty() {
                format!("{} (Référence : {})", v.msg, v.references)
            } else {
                format!("Examiner la route '{}' signalée par Nikto.", v.url)
            };

            let method_prefix = if !v.method.is_empty() {
                format!("{} ", v.method)
            } else {
                String::new()
            };

            findings.push(SecurityFinding {
                severity,
                category: "NIKTO",
                title: format!("Nikto [{}] {}{} - {}", v.id, method_prefix, v.url, v.msg),
                recommendation: rec,
            });
        }

        findings
    }
}
