use std::net::{IpAddr, ToSocketAddrs};

#[allow(dead_code)]
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DnsRecordEntry {
    pub record_type: String,
    pub value: String,
    pub is_secure: bool,
}

#[allow(dead_code)]
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct DnsAuditResult {
    pub domain: String,
    pub a_records: Vec<String>,
    pub aaaa_records: Vec<String>,
    pub mx_records: Vec<String>,
    pub txt_records: Vec<String>,
    pub ns_records: Vec<String>,
    pub soa_record: Option<String>,
    pub caa_records: Vec<String>,
    pub dnssec_active: bool,
    pub spf_found: bool,
    pub spf_strict: bool,
    pub spf_record: Option<String>,
    pub dmarc_found: bool,
    pub dmarc_policy: Option<String>,
    pub dmarc_record: Option<String>,
    pub reverse_ptr: Option<String>,
    pub all_records: Vec<DnsRecordEntry>,
    pub issues: Vec<String>,
}

impl DnsAuditResult {
    pub fn new(domain: &str) -> Self {
        Self {
            domain: domain.to_string(),
            a_records: Vec::new(),
            aaaa_records: Vec::new(),
            mx_records: Vec::new(),
            txt_records: Vec::new(),
            ns_records: Vec::new(),
            soa_record: None,
            caa_records: Vec::new(),
            dnssec_active: false,
            spf_found: false,
            spf_strict: false,
            spf_record: None,
            dmarc_found: false,
            dmarc_policy: None,
            dmarc_record: None,
            reverse_ptr: None,
            all_records: Vec::new(),
            issues: Vec::new(),
        }
    }
}

pub struct DnsAuditor;

impl DnsAuditor {
    pub fn audit(domain: &str) -> DnsAuditResult {
        let mut result = DnsAuditResult::new(domain);

        // 1. Résolution standard A / AAAA
        let host_port = format!("{}:80", domain);
        if let Ok(addrs) = host_port.to_socket_addrs() {
            for addr in addrs {
                match addr.ip() {
                    IpAddr::V4(v4) => {
                        let s = v4.to_string();
                        if !result.a_records.contains(&s) {
                            result.a_records.push(s.clone());
                            result.all_records.push(DnsRecordEntry {
                                record_type: "A".to_string(),
                                value: s,
                                is_secure: false,
                            });
                        }
                    }
                    IpAddr::V6(v6) => {
                        let s = v6.to_string();
                        if !result.aaaa_records.contains(&s) {
                            result.aaaa_records.push(s.clone());
                            result.all_records.push(DnsRecordEntry {
                                record_type: "AAAA".to_string(),
                                value: s,
                                is_secure: false,
                            });
                        }
                    }
                }
            }
        }

        // 2. Résolution approfondie via dig
        Self::enrich_via_dig(domain, &mut result);

        // 3. Reverse PTR sur la première IP
        if let Some(first_ip) = result.a_records.first() {
            if let Some(out) =
                crate::utils::run_tool("dig", &["+short", "-x", first_ip, "+time=2", "+tries=1"], 8)
            {
                let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
                if !s.is_empty() {
                    result.reverse_ptr = Some(s.clone());
                    result.all_records.push(DnsRecordEntry {
                        record_type: "PTR".to_string(),
                        value: s,
                        is_secure: false,
                    });
                }
            }
        }

        // 4. Analyse de conformité SPF
        for txt in &result.txt_records {
            if txt.starts_with("v=spf1") {
                result.spf_found = true;
                result.spf_record = Some(txt.clone());
                result.spf_strict = txt.contains("-all");
                break;
            }
        }

        if !result.spf_found {
            result
                .issues
                .push("Absence d'enregistrement SPF (Sender Policy Framework).".into());
        } else if !result.spf_strict {
            result.issues.push(
                "Politique SPF laxiste (utilise ~all ou ?all au lieu de -all strict).".into(),
            );
        }

        // 5. Analyse de conformité DMARC
        if !result.dmarc_found {
            result
                .issues
                .push("Absence d'enregistrement DMARC sur _dmarc.".into());
        } else if let Some(ref pol) = result.dmarc_policy {
            if pol == "none" {
                result
                    .issues
                    .push("Politique DMARC en mode surveillance uniquement (p=none).".into());
            }
        }

        // 6. Contrôle CAA & DNSSEC
        if result.caa_records.is_empty() {
            result.issues.push(
                "Absence d'enregistrements CAA (autorisations de CA non restreintes).".into(),
            );
        }

        if !result.dnssec_active {
            result
                .issues
                .push("DNSSEC non activé pour ce domaine.".into());
        }

        // Cohérence : is_secure reflète le flag AD réellement observé (jamais hardcodé)
        for r in &mut result.all_records {
            r.is_secure = result.dnssec_active;
        }

        result
    }

    fn enrich_via_dig(domain: &str, result: &mut DnsAuditResult) {
        // MX
        if let Some(output) =
            crate::utils::run_tool("dig", &["+short", "+time=2", "+tries=1", "MX", domain], 8)
        {
            for line in String::from_utf8_lossy(&output.stdout).lines() {
                let trimmed = line.trim();
                if !trimmed.is_empty() {
                    result.mx_records.push(trimmed.to_string());
                    result.all_records.push(DnsRecordEntry {
                        record_type: "MX".to_string(),
                        value: trimmed.to_string(),
                        is_secure: false,
                    });
                }
            }
        }

        // NS
        if let Some(output) =
            crate::utils::run_tool("dig", &["+short", "+time=2", "+tries=1", "NS", domain], 8)
        {
            for line in String::from_utf8_lossy(&output.stdout).lines() {
                let trimmed = line.trim();
                if !trimmed.is_empty() {
                    result.ns_records.push(trimmed.to_string());
                    result.all_records.push(DnsRecordEntry {
                        record_type: "NS".to_string(),
                        value: trimmed.to_string(),
                        is_secure: false,
                    });
                }
            }
        }

        // TXT
        if let Some(output) =
            crate::utils::run_tool("dig", &["+short", "+time=2", "+tries=1", "TXT", domain], 8)
        {
            for line in String::from_utf8_lossy(&output.stdout).lines() {
                let trimmed = line.trim().trim_matches('"');
                if !trimmed.is_empty() {
                    result.txt_records.push(trimmed.to_string());
                    result.all_records.push(DnsRecordEntry {
                        record_type: "TXT".to_string(),
                        value: trimmed.to_string(),
                        is_secure: false,
                    });
                }
            }
        }

        // SOA
        if let Some(output) =
            crate::utils::run_tool("dig", &["+short", "+time=2", "+tries=1", "SOA", domain], 8)
        {
            let s = String::from_utf8_lossy(&output.stdout).trim().to_string();
            if !s.is_empty() {
                result.soa_record = Some(s.clone());
                result.all_records.push(DnsRecordEntry {
                    record_type: "SOA".to_string(),
                    value: s,
                    is_secure: false,
                });
            }
        }

        // CAA
        if let Some(output) =
            crate::utils::run_tool("dig", &["+short", "+time=2", "+tries=1", "CAA", domain], 8)
        {
            for line in String::from_utf8_lossy(&output.stdout).lines() {
                let trimmed = line.trim();
                if !trimmed.is_empty() {
                    result.caa_records.push(trimmed.to_string());
                    result.all_records.push(DnsRecordEntry {
                        record_type: "CAA".to_string(),
                        value: trimmed.to_string(),
                        is_secure: false,
                    });
                }
            }
        }

        // DNSSEC : détection via le flag AD (Authentic Data) de la réponse DS.
        // Plus fiable que DNSKEY : certains résolveurs ne relaient pas les DNSKEY,
        // ce qui produisait des faux négatifs sur des zones pourtant signées.
        if let Some(out) = crate::utils::run_tool(
            "dig",
            &["+dnssec", "+comments", "+time=2", "+tries=1", "DS", domain],
            8,
        ) {
            let s = String::from_utf8_lossy(&out.stdout);
            let ad_flag = s.lines().any(|l| {
                l.trim_start().starts_with(";; flags:") && l.split_whitespace().any(|t| t == "ad")
            });
            if ad_flag {
                result.dnssec_active = true;
                result.all_records.push(DnsRecordEntry {
                    record_type: "DS".to_string(),
                    value: "DNSSEC actif (flag AD validé par le résolveur)".to_string(),
                    is_secure: false,
                });
            }
        }

        // DMARC (_dmarc.domain)
        let dmarc_target = format!("_dmarc.{}", domain);
        if let Some(output) = crate::utils::run_tool(
            "dig",
            &["+short", "+time=2", "+tries=1", "TXT", &dmarc_target],
            8,
        ) {
            for line in String::from_utf8_lossy(&output.stdout).lines() {
                let clean = line.trim().trim_matches('"');
                if clean.starts_with("v=DMARC1") {
                    result.dmarc_found = true;
                    result.dmarc_record = Some(clean.to_string());

                    // Détection politique p=
                    for part in clean.split(';') {
                        let p = part.trim();
                        if p.starts_with("p=") {
                            result.dmarc_policy = Some(p.trim_start_matches("p=").to_string());
                        }
                    }

                    result.all_records.push(DnsRecordEntry {
                        record_type: "DMARC".to_string(),
                        value: clean.to_string(),
                        is_secure: false,
                    });
                    break;
                }
            }
        }
    }
}
