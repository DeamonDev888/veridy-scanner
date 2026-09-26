use crate::modules::findings::SecurityFinding;
use std::time::Instant;

#[derive(Debug, Clone)]
#[derive(serde::Serialize, serde::Deserialize)]
pub struct LookalikeDomain {
    pub domain: String,
    pub fuzzer: String,
    pub ip: Option<String>,
}

#[derive(Debug, Clone, Default)]
#[derive(serde::Serialize, serde::Deserialize)]
pub struct BrandSecResult {
    pub success: bool,
    pub elapsed_seconds: f32,
    pub registered_lookalikes: Vec<LookalikeDomain>,
    pub raw_output: String,
    pub summary: String,
}

pub struct BrandSecAuditor;

impl BrandSecAuditor {
    pub fn audit(target: &str) -> BrandSecResult {
        let start = Instant::now();

        let output = match crate::utils::run_tool("dnstwist", &["--registered", "-f", "json", target], 180) {
            Some(o) => o,
            None => {
                return BrandSecResult {
                    success: false,
                    elapsed_seconds: start.elapsed().as_secs_f32(),
                    registered_lookalikes: Vec::new(),
                    raw_output: "dnstwist : timeout (180s) ou binaire introuvable".into(),
                    summary: "Dnstwist interrompu : deadline dépassée".into(),
                };
            }
        };

        let elapsed = start.elapsed().as_secs_f32();
        let raw_json = String::from_utf8_lossy(&output.stdout).to_string();

        let lookalikes = Self::parse_json(&raw_json, target);
        let summary = format!(
            "dnstwist a identifié {} domaine(s) similaire(s) actif(s) en {:.2}s",
            lookalikes.len(),
            elapsed
        );

        BrandSecResult {
            success: output.status.success(),
            elapsed_seconds: elapsed,
            registered_lookalikes: lookalikes,
            raw_output: raw_json,
            summary,
        }
    }

    fn parse_json(json: &str, target: &str) -> Vec<LookalikeDomain> {
        let mut list = Vec::new();
        let mut rest = json;

        while let Some(obj_start) = rest.find('{') {
            rest = &rest[obj_start..];
            let obj_end = match rest.find('}') {
                Some(e) => e + 1,
                None => break,
            };
            let obj_str = &rest[..obj_end];
            rest = &rest[obj_end..];

            let domain = crate::utils::extract_json_str(obj_str, "domain").unwrap_or_default();
            let fuzzer = crate::utils::extract_json_str(obj_str, "fuzzer").unwrap_or_default();

            if !domain.is_empty() && domain != target && fuzzer != "*original" {
                // Extraire IP si présente dans dns_a
                let ip = if let Some(a_pos) = obj_str.find("\"dns_a\":") {
                    let a_part = &obj_str[a_pos + 8..];
                    if let Some(q_start) = a_part.find('"') {
                        let after_q = &a_part[q_start + 1..];
                        if let Some(q_end) = after_q.find('"') {
                            let ip_val = &after_q[..q_end];
                            if !ip_val.starts_with('!') {
                                Some(ip_val.to_string())
                            } else {
                                None
                            }
                        } else {
                            None
                        }
                    } else {
                        None
                    }
                } else {
                    None
                };

                list.push(LookalikeDomain { domain, fuzzer, ip });
            }
        }

        list
    }

    pub fn to_findings(&self, res: &BrandSecResult) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();

        if !res.registered_lookalikes.is_empty() {
            let sample: Vec<String> = res
                .registered_lookalikes
                .iter()
                .take(5)
                .map(|l| l.domain.clone())
                .collect();
            findings.push(SecurityFinding {
                severity: "LOW",
                category: "BRAND",
                title: format!("Protection de marque : {} domaine(s) similaire(s) actif(s) sur Internet (ex: {})", res.registered_lookalikes.len(), sample.join(", ")),
                recommendation: "Surveiller les dépôts de domaines typosquattés et envisager l'enregistrement défensif des variantes proches pour protéger la réputation de l'entreprise contre le phishing.".to_string(),
            });
        }

        findings
    }
}
