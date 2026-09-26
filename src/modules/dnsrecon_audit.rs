use std::fs;
use std::time::Instant;

use crate::utils::extract_json_str;

#[derive(Debug, Clone, Default)]
#[derive(serde::Serialize, serde::Deserialize)]
pub struct DnsreconSrv {
    pub name: String,
    pub target: String,
    pub port: u16,
    pub address: String,
}

#[derive(Debug, Clone, Default)]
#[derive(serde::Serialize, serde::Deserialize)]
pub struct DnsreconResult {
    pub srv_records: Vec<DnsreconSrv>,
    pub bind_versions: Vec<(String, String)>,
    pub nameservers: Vec<String>,
    pub soa_mname: Option<String>,
    pub execution_time_seconds: f32,
    pub raw_output: String,
}

pub struct DnsreconAuditor;

impl DnsreconAuditor {
    pub fn audit(domain: &str) -> DnsreconResult {
        let start = Instant::now();
        let mut result = DnsreconResult::default();

        let json_path = format!(
            "/tmp/dnsrecon_{}_{}.json",
            crate::utils::sanitize_target(domain),
            std::process::id()
        );

        let cmd_res = crate::utils::run_tool(
            "dnsrecon",
            &["-d", domain, "-t", "std", "-j", &json_path],
            120,
        );

        result.execution_time_seconds = start.elapsed().as_secs_f32();

        if let Some(out) = cmd_res {
            result.raw_output = String::from_utf8_lossy(&out.stdout).to_string();
        }

        // Nettoyage inconditionnel : même si la lecture échoue (fichier partiel, crash)
        let content = fs::read_to_string(&json_path);
        let _ = fs::remove_file(&json_path);
        if let Ok(content) = content {

            // Parse json array of objects
            for chunk in content.split('{') {
                if !chunk.contains('}') {
                    continue;
                }
                let obj = format!("{{{chunk}");
                let r_type = extract_json_str(&obj, "type").unwrap_or_default();

                match r_type.as_str() {
                    "SRV" => {
                        let target = extract_json_str(&obj, "target").unwrap_or_default();
                        let address = extract_json_str(&obj, "address").unwrap_or_default();
                        let domain_str = extract_json_str(&obj, "domain").unwrap_or_default();
                        let port_str = extract_json_str(&obj, "port").unwrap_or_default();
                        let port = port_str.parse::<u16>().unwrap_or(0);

                        result.srv_records.push(DnsreconSrv {
                            name: domain_str,
                            target,
                            port,
                            address,
                        });
                    }
                    "NS" => {
                        let target = extract_json_str(&obj, "target").unwrap_or_default();
                        if !target.is_empty() && !result.nameservers.contains(&target) {
                            result.nameservers.push(target.clone());
                        }

                        if let Some(version) = extract_json_str(&obj, "Version") {
                            let clean_v = version.trim_matches('"').trim().to_string();
                            if !clean_v.is_empty() {
                                result.bind_versions.push((target, clean_v));
                            }
                        }
                    }
                    "SOA" if result.soa_mname.is_none() => {
                        result.soa_mname = extract_json_str(&obj, "mname");
                    }
                    _ => {}
                }
            }
        }

        result
    }

    pub fn to_findings(
        &self,
        res: &DnsreconResult,
    ) -> Vec<crate::modules::findings::SecurityFinding> {
        use crate::modules::findings::SecurityFinding;
        let mut findings = Vec::new();

        for (target, version) in &res.bind_versions {
            findings.push(SecurityFinding {
                severity: "LOW",
                category: "DNS",
                title: format!("Dnsrecon - Divulgation de version DNS sur {target} : {version}"),
                recommendation: "Masquer la version du serveur de noms (Knot/BIND) dans le fichier de configuration pour limiter l'empreinte d'attaque.".into(),
            });
        }

        if !res.srv_records.is_empty() {
            let srv_list: Vec<String> = res
                .srv_records
                .iter()
                .map(|s| format!("{}:{}", s.target, s.port))
                .collect();
            findings.push(SecurityFinding {
                severity: "INFO",
                category: "DNS",
                title: format!(
                    "Dnsrecon - {} service(s) SRV cartographié(s) ({})",
                    res.srv_records.len(),
                    srv_list.join(", ")
                ),
                recommendation: "S'assurer que les flux vers ces services internes ou de messagerie sont chiffrés en TLS.".into(),
            });
        }

        findings
    }
}
