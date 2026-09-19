use std::time::Instant;

#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct WhoisResult {
    pub registrar: Option<String>,
    pub creation_date: Option<String>,
    pub expiry_date: Option<String>,
    pub updated_date: Option<String>,
    pub domain_status: Vec<String>,
    pub name_servers: Vec<String>,
    pub is_privacy_protected: bool,
    pub is_transfer_locked: bool,
    pub execution_time_seconds: f32,
    pub raw_output: String,
}

pub struct WhoisAuditor;

impl WhoisAuditor {
    pub fn audit(domain: &str) -> WhoisResult {
        let start = Instant::now();
        let mut result = WhoisResult::default();

        let output = match crate::utils::run_tool("whois", &[domain], 30) {
            Some(out) => out,
            None => {
                result.execution_time_seconds = start.elapsed().as_secs_f32();
                result.raw_output = "whois : timeout (30s) ou binaire introuvable".into();
                return result;
            }
        };

        let stdout = String::from_utf8_lossy(&output.stdout).to_string();
        result.raw_output = stdout.clone();

        for line in stdout.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('%') || trimmed.starts_with('#') {
                continue;
            }

            let lower = trimmed.to_lowercase();
            if lower.contains("redacted for privacy")
                || lower.contains("privacy service")
                || lower.contains("withheld for privacy")
            {
                result.is_privacy_protected = true;
            }

            if let Some((key, val)) = trimmed.split_once(':') {
                let key_norm = key.trim().to_lowercase();
                let val_clean = val.trim();

                if val_clean.is_empty() {
                    continue;
                }

                if result.registrar.is_none()
                    && (key_norm == "registrar" || key_norm == "registrar name")
                {
                    result.registrar = Some(val_clean.to_string());
                } else if result.creation_date.is_none()
                    && (key_norm == "creation date"
                        || key_norm == "created"
                        || key_norm == "created on")
                {
                    result.creation_date = Some(val_clean.to_string());
                } else if result.expiry_date.is_none()
                    && (key_norm == "registry expiry date"
                        || key_norm == "expiry date"
                        || key_norm == "expiration date"
                        || key_norm == "paid-till")
                {
                    result.expiry_date = Some(val_clean.to_string());
                } else if result.updated_date.is_none()
                    && (key_norm == "updated date"
                        || key_norm == "last updated"
                        || key_norm == "modified")
                {
                    result.updated_date = Some(val_clean.to_string());
                } else if key_norm == "domain status" || key_norm == "status" {
                    let status_part = val_clean.split_whitespace().next().unwrap_or(val_clean);
                    if !result.domain_status.contains(&status_part.to_string()) {
                        if status_part.to_lowercase().contains("transferprohibited") {
                            result.is_transfer_locked = true;
                        }
                        result.domain_status.push(status_part.to_string());
                    }
                } else if key_norm == "name server" || key_norm == "nserver" {
                    let ns_part = val_clean.split_whitespace().next().unwrap_or(val_clean);
                    let ns_clean = ns_part.trim_end_matches('.').to_lowercase();
                    if !result.name_servers.contains(&ns_clean) {
                        result.name_servers.push(ns_clean);
                    }
                }
            }
        }

        result.execution_time_seconds = start.elapsed().as_secs_f32();
        result
    }

    pub fn to_findings(&self, res: &WhoisResult) -> Vec<crate::modules::findings::SecurityFinding> {
        use crate::modules::findings::SecurityFinding;
        let mut findings = Vec::new();

        if let Some(ref reg) = res.registrar {
            findings.push(SecurityFinding {
                severity: "INFO",
                category: "WHOIS",
                title: format!("Registrar officiel identifié : {reg}"),
                recommendation: "Vérifier périodiquement les accès administratifs auprès du bureau d'enregistrement.".into(),
            });
        }

        if let Some(ref exp) = res.expiry_date {
            findings.push(SecurityFinding {
                severity: "INFO",
                category: "WHOIS",
                title: format!("Date d'expiration du domaine : {exp}"),
                recommendation: "Activer le renouvellement automatique pour prévenir la perte accidentelle du domaine.".into(),
            });
        }

        if !res.domain_status.is_empty() && !res.is_transfer_locked {
            findings.push(SecurityFinding {
                severity: "MEDIUM",
                category: "WHOIS",
                title: "Verrouillage de transfert de domaine (TransferProhibited) inactif".into(),
                recommendation: "Activer le statut 'clientTransferProhibited' auprès du registrar pour immuniser le domaine contre le détournement illégitime (Domain Hijacking).".into(),
            });
        }

        if !res.raw_output.is_empty() && !res.is_privacy_protected {
            findings.push(SecurityFinding {
                severity: "LOW",
                category: "WHOIS",
                title: "Protection de la vie privée WHOIS (Privacy Guard) non détectée".into(),
                recommendation: "Activer la protection de confidentialité WHOIS pour masquer les données personnelles (nom, email, téléphone) des contacts administratifs et techniques.".into(),
            });
        }

        findings
    }
}
