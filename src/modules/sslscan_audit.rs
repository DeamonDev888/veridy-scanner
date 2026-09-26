use crate::modules::findings::SecurityFinding;
use std::fs;
use std::time::Instant;

#[derive(Debug, Clone, Default)]
#[derive(serde::Serialize, serde::Deserialize)]
pub struct SslscanResult {
    pub success: bool,
    pub elapsed_seconds: f32,
    pub heartbleed_vulnerable: bool,
    pub compression_enabled: bool,
    pub insecure_renegotiation: bool,
    pub fallback_scsv: bool,
    pub weak_ciphers: Vec<String>,
    pub strong_ciphers_count: usize,
    pub raw_output: String,
    pub summary: String,
}

pub struct SslscanAuditor;

impl SslscanAuditor {
    pub fn audit(target: &str) -> SslscanResult {
        let start = Instant::now();
        let target_host = format!("{}:443", target);
        let pid = std::process::id();
        let tmp_output = format!("/tmp/sslscan_{}_{}.xml", crate::utils::sanitize_target(target), pid);

        let output = match crate::utils::run_tool(
            "sslscan",
            &[&format!("--xml={}", tmp_output), "--no-failed", &target_host],
            90,
        ) {
            Some(o) => o,
            None => {
                return SslscanResult {
                    success: false,
                    elapsed_seconds: start.elapsed().as_secs_f32(),
                    heartbleed_vulnerable: false,
                    compression_enabled: false,
                    insecure_renegotiation: false,
                    fallback_scsv: false,
                    weak_ciphers: Vec::new(),
                    strong_ciphers_count: 0,
                    raw_output: "sslscan : timeout (90s) ou binaire introuvable".into(),
                    summary: "SSLScan interrompu : deadline dépassée".into(),
                };
            }
        };

        let elapsed = start.elapsed().as_secs_f32();
        let raw_xml = fs::read_to_string(&tmp_output)
            .unwrap_or_else(|_| String::from_utf8_lossy(&output.stdout).to_string());
        let _ = fs::remove_file(&tmp_output);

        let (hb, comp, reneg, fallback, weak, strong) = Self::parse_xml(&raw_xml);

        let summary = format!(
            "SSLScan a audité le chiffrement TLS en {:.2}s : Heartbleed={}, Ciphers forts={}, Faibles={}",
            elapsed,
            if hb { "VULNÉRABLE" } else { "NON" },
            strong,
            weak.len()
        );

        SslscanResult {
            success: output.status.success(),
            elapsed_seconds: elapsed,
            heartbleed_vulnerable: hb,
            compression_enabled: comp,
            insecure_renegotiation: reneg,
            fallback_scsv: fallback,
            weak_ciphers: weak,
            strong_ciphers_count: strong,
            raw_output: raw_xml,
            summary,
        }
    }

    fn parse_xml(xml: &str) -> (bool, bool, bool, bool, Vec<String>, usize) {
        // Heartbleed : uniquement l'élément <heartbleed .../> avec vulnerable="1"
        // (l'ancien contains global matchait n'importe quel attribut vulnerable)
        let heartbleed = xml
            .lines()
            .any(|l| l.contains("<heartbleed") && l.contains("vulnerable=\"1\""));
        let compression = xml.contains("<compression supported=\"1\"");
        let insecure_reneg = xml.contains("<renegotiation supported=\"1\" secure=\"0\"");
        let fallback = xml.contains("<fallback supported=\"1\"");

        let mut weak_ciphers = Vec::new();
        let mut strong_count = 0;

        for line in xml.lines() {
            if line.contains("<cipher ") {
                // Faible = avis sslscan (strength="weak") ou algo explicitement obsolète.
                // CBC/DES seuls ne suffisent pas : AES-CBC TLS1.2 n'est pas "faible".
                let is_weak = line.contains("strength=\"weak\"")
                    || line.contains("RC4")
                    || line.contains("3DES")
                    || line.contains("MD5")
                    || line.contains("NULL")
                    || line.contains("EXPORT");

                if let Some(pos) = line.find("cipher=\"") {
                    let rest = &line[pos + 8..];
                    if let Some(end) = rest.find('"') {
                        let c_name = &rest[..end];
                        if is_weak && !weak_ciphers.contains(&c_name.to_string()) {
                            weak_ciphers.push(c_name.to_string());
                        } else if !is_weak {
                            strong_count += 1;
                        }
                    }
                }
            }
        }

        (
            heartbleed,
            compression,
            insecure_reneg,
            fallback,
            weak_ciphers,
            strong_count,
        )
    }

    pub fn to_findings(&self, res: &SslscanResult) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();

        if res.heartbleed_vulnerable {
            findings.push(SecurityFinding {
                severity: "CRITICAL",
                category: "TLS",
                title: "Vulnérabilité Heartbleed (CVE-2014-0160) active sur OpenSSL".to_string(),
                recommendation: "Mettre à jour d'urgence OpenSSL et régénérer immédiatement la clé privée du certificat.".to_string(),
            });
        }

        if res.compression_enabled {
            findings.push(SecurityFinding {
                severity: "HIGH",
                category: "TLS",
                title: "Compression TLS activée (Vulnérabilité CRIME)".to_string(),
                recommendation: "Désactiver la compression TLS dans le serveur web pour empêcher l'extraction de cookies de session.".to_string(),
            });
        }

        if res.insecure_renegotiation {
            findings.push(SecurityFinding {
                severity: "MEDIUM",
                category: "TLS",
                title: "Renégociation TLS non sécurisée autorisée".to_string(),
                recommendation: "Désactiver la renégociation non sécurisée (RFC 5746) pour prévenir les attaques de type Man-in-the-Middle.".to_string(),
            });
        }

        if !res.weak_ciphers.is_empty() {
            findings.push(SecurityFinding {
                severity: "MEDIUM",
                category: "TLS",
                title: format!("Suites de chiffrement obsolètes acceptées : {}", res.weak_ciphers.join(", ")),
                recommendation: "Restreindre les suites de chiffrement aux algorithmes AEAD modernes (GCM, CHACHA20-POLY1305).".to_string(),
            });
        }

        if !res.fallback_scsv {
            findings.push(SecurityFinding {
                severity: "LOW",
                category: "TLS",
                title: "Absence de support TLS Fallback SCSV (Protection anti-rétrogradation)".to_string(),
                recommendation: "Activer le support du TLS Fallback SCSV dans OpenSSL pour empêcher les attaques de rétrogradation de protocole type POODLE.".to_string(),
            });
        }

        findings
    }
}
