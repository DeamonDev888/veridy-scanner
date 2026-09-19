
#[allow(dead_code)]
#[derive(Debug, Clone, Default)]
#[derive(serde::Serialize, serde::Deserialize)]
pub struct GeoComplianceResult {
    pub ip_address: String,
    pub asn: Option<String>,
    pub org_name: Option<String>,
    pub country_code: Option<String>,
    pub region: Option<String>,
    pub city: Option<String>,
    pub is_canada: bool,
    pub is_quebec: bool,
}


pub struct GeoAuditor;

impl GeoAuditor {
    /// Analyse de géolocalisation IP à partir du whois (ASN, organisation, pays, région).
    pub fn audit(ip: &str) -> GeoComplianceResult {
        let mut res = GeoComplianceResult {
            ip_address: ip.to_string(),
            asn: None,
            org_name: None,
            country_code: None,
            region: None,
            city: None,
            is_canada: false,
            is_quebec: false,
        };

        if let Some(output) = crate::utils::run_tool("whois", &[ip], 15) {
            let s = String::from_utf8_lossy(&output.stdout);
            for line in s.lines() {
                let trimmed = line.trim();
                let lower = trimmed.to_lowercase();

                if (lower.starts_with("orgname:") || lower.starts_with("descr:"))
                    && res.org_name.is_none()
                {
                    let parts: Vec<&str> = trimmed.splitn(2, ':').collect();
                    if parts.len() == 2 {
                        res.org_name = Some(parts[1].trim().to_string());
                    }
                } else if (lower.starts_with("origin:") || lower.starts_with("originas:"))
                    && res.asn.is_none()
                {
                    // ASN réel (RIPE origin: / ARIN OriginAS:) : doit matcher AS\d+
                    let parts: Vec<&str> = trimmed.splitn(2, ':').collect();
                    if parts.len() == 2 {
                        let v = parts[1].trim();
                        let as_num = v.trim_start_matches("AS");
                        if !as_num.is_empty() && as_num.chars().all(|c| c.is_ascii_digit()) {
                            res.asn = Some(format!("AS{}", as_num));
                        }
                    }
                } else if lower.starts_with("netname:") && res.asn.is_none() {
                    // netname n'est PAS un ASN : servait uniquement de libellé de repli
                    let parts: Vec<&str> = trimmed.splitn(2, ':').collect();
                    if parts.len() == 2 && res.org_name.is_none() {
                        res.org_name = Some(parts[1].trim().to_string());
                    }
                } else if lower.starts_with("country:") && res.country_code.is_none() {
                    let parts: Vec<&str> = trimmed.splitn(2, ':').collect();
                    if parts.len() == 2 {
                        let c = parts[1].trim().to_uppercase();
                        if c == "CA" {
                            res.is_canada = true;
                        }
                        res.country_code = Some(c);
                    }
                } else if (lower.starts_with("stateprov:") || lower.starts_with("state:"))
                    && res.region.is_none()
                {
                    let parts: Vec<&str> = trimmed.splitn(2, ':').collect();
                    if parts.len() == 2 {
                        let reg = parts[1].trim().to_uppercase();
                        if reg == "QC" || reg.contains("QUEBEC") {
                            res.is_quebec = true;
                        }
                        res.region = Some(reg);
                    }
                } else if lower.starts_with("city:") && res.city.is_none() {
                    let parts: Vec<&str> = trimmed.splitn(2, ':').collect();
                    if parts.len() == 2 {
                        res.city = Some(parts[1].trim().to_string());
                    }
                }
            }
        }

        res
    }
}
