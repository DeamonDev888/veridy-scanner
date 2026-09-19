use crate::modules::findings::SecurityFinding;
use std::time::Instant;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct NmapPortService {
    pub port: u16,
    pub protocol: String,
    pub state: String,
    pub service: String,
    pub product: Option<String>,
    pub version: Option<String>,
    pub scripts: Vec<(String, String)>, // (script_id, output)
}

#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct NmapAuditResult {
    pub success: bool,
    pub elapsed_seconds: f32,
    pub services: Vec<NmapPortService>,
    pub raw_output: String,
    pub summary: String,
}

pub struct NmapAuditor;

impl NmapAuditor {
    pub fn audit(target: &str, open_ports: &[u16]) -> NmapAuditResult {
        let start = Instant::now();
        let port_spec = if open_ports.is_empty() {
            "53,80,443".to_string()
        } else {
            open_ports
                .iter()
                .map(|p| p.to_string())
                .collect::<Vec<_>>()
                .join(",")
        };

        let output = match crate::utils::run_tool(
            "nmap",
            &[
                "-sV",
                "--version-light",
                "-sC",
                "-Pn",
                "--host-timeout",
                "120s",
                "-p",
                &port_spec,
                "-oX",
                "-",
                target,
            ],
            240,
        ) {
            Some(o) => o,
            None => {
                return NmapAuditResult {
                    success: false,
                    elapsed_seconds: start.elapsed().as_secs_f32(),
                    services: Vec::new(),
                    raw_output: "nmap : timeout (240s) ou binaire introuvable".into(),
                    summary: "Nmap interrompu : deadline dépassée".into(),
                };
            }
        };

        let elapsed = start.elapsed().as_secs_f32();
        let xml_str = String::from_utf8_lossy(&output.stdout).to_string();
        let stderr = String::from_utf8_lossy(&output.stderr);

        if !output.status.success() && xml_str.trim().is_empty() {
            return NmapAuditResult {
                success: false,
                elapsed_seconds: elapsed,
                services: Vec::new(),
                raw_output: stderr.to_string(),
                summary: format!("Nmap a échoué (code {:?})", output.status.code()),
            };
        }

        let services = Self::parse_xml(&xml_str);
        let summary = format!(
            "Nmap a analysé {} service(s) sur les ports [{}] en {:.2}s",
            services.len(),
            port_spec,
            elapsed
        );

        NmapAuditResult {
            success: true,
            elapsed_seconds: elapsed,
            services,
            raw_output: xml_str,
            summary,
        }
    }

    /// Parse sommaire et robuste du XML de Nmap sans dépendance externe
    fn parse_xml(xml: &str) -> Vec<NmapPortService> {
        let mut services = Vec::new();

        // Découpage par bloc <port ...> ... </port>
        let mut rest = xml;
        while let Some(start_idx) = rest.find("<port ") {
            rest = &rest[start_idx..];
            let end_idx = match rest.find("</port>") {
                Some(idx) => idx + 7,
                None => break,
            };
            let port_block = &rest[..end_idx];
            rest = &rest[end_idx..];

            // Extraire portid et protocol
            let portid = Self::extract_attr(port_block, "portid")
                .and_then(|p| p.parse::<u16>().ok())
                .unwrap_or(0);
            let protocol =
                Self::extract_attr(port_block, "protocol").unwrap_or_else(|| "tcp".to_string());

            // Extraire état
            let state = if let Some(s_idx) = port_block.find("<state ") {
                Self::extract_attr(&port_block[s_idx..], "state")
                    .unwrap_or_else(|| "unknown".to_string())
            } else {
                "unknown".to_string()
            };

            // Extraire service, product, version
            let (service_name, product, version) =
                if let Some(srv_idx) = port_block.find("<service ") {
                    let srv_part = &port_block[srv_idx..];
                    let s_name = Self::extract_attr(srv_part, "name")
                        .unwrap_or_else(|| "unknown".to_string());
                    let prod = Self::extract_attr(srv_part, "product");
                    let ver = Self::extract_attr(srv_part, "version");
                    (s_name, prod, ver)
                } else {
                    ("unknown".to_string(), None, None)
                };

            // Extraire scripts NSE
            let mut scripts = Vec::new();
            let mut script_rest = port_block;
            while let Some(sc_idx) = script_rest.find("<script ") {
                script_rest = &script_rest[sc_idx..];
                let sc_end = match script_rest.find("</script>") {
                    Some(e) => e + 9,
                    None => match script_rest.find("/>") {
                        Some(e) => e + 2,
                        None => break,
                    },
                };
                let sc_block = &script_rest[..sc_end];
                script_rest = &script_rest[sc_end..];

                let sc_id = Self::extract_attr(sc_block, "id").unwrap_or_default();
                let sc_output = Self::extract_attr(sc_block, "output").unwrap_or_default();
                if !sc_id.is_empty() {
                    scripts.push((sc_id, sc_output));
                }
            }

            services.push(NmapPortService {
                port: portid,
                protocol,
                state,
                service: service_name,
                product,
                version,
                scripts,
            });
        }

        services
    }

    fn extract_attr(text: &str, attr: &str) -> Option<String> {
        let pattern = format!("{}=\"", attr);
        if let Some(start) = text.find(&pattern) {
            let val_start = start + pattern.len();
            if let Some(val_end) = text[val_start..].find('"') {
                let raw_val = &text[val_start..val_start + val_end];
                // Décodage basique des entités XML
                let unescaped = raw_val
                    .replace("&apos;", "'")
                    .replace("&quot;", "\"")
                    .replace("&lt;", "<")
                    .replace("&gt;", ">")
                    .replace("&amp;", "&");
                return Some(unescaped);
            }
        }
        None
    }

    pub fn to_findings(&self, result: &NmapAuditResult) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();

        for srv in &result.services {
            if srv.state != "open" {
                continue;
            }

            // Vérifier Knot DNS
            if srv.port == 53 {
                if let Some(ref prod) = srv.product {
                    if let Some(ref ver) = srv.version {
                        findings.push(SecurityFinding {
                            severity: "INFO",
                            category: "NMAP",
                            title: format!("Nmap - Détection de version DNS : {} {}", prod, ver),
                            recommendation: "Masquer ou obfusquer la bannière Knot DNS (version.bind / NSID) pour limiter l'empreinte de reconnaissance.".to_string(),
                        });
                    }
                }
            }

            // Vérifier Nginx / HTTP
            if srv.port == 80 || srv.port == 443 {
                if let Some(ref prod) = srv.product {
                    let ver_info = srv.version.as_deref().unwrap_or("non divulguée");
                    findings.push(SecurityFinding {
                        severity: "INFO",
                        category: "NMAP",
                        title: format!("Nmap - Détection Web (Port {}) : {} ({})", srv.port, prod, ver_info),
                        recommendation: "S'assurer que 'server_tokens off;' est bien actif pour masquer la version mineure du serveur.".to_string(),
                    });
                }
            }

            // Scripts NSE
            for (sc_id, sc_out) in &srv.scripts {
                if sc_id == "dns-nsid" && sc_out.contains("ubuntu-server") {
                    findings.push(SecurityFinding {
                        severity: "LOW",
                        category: "NMAP",
                        title: "Nmap NSE (dns-nsid) - Divulgation du nom d'hôte interne 'ubuntu-server'".to_string(),
                        recommendation: "Configurer Knot DNS avec 'server: identity: off' et 'version: off' pour ne pas exposer le hostname interne du serveur.".to_string(),
                    });
                }
            }
        }

        findings
    }
}
