use crate::modules::findings::SecurityFinding;
use std::time::Instant;

/// Verdict RDAP d'un sosie : tiers legitime vs typosquat probable.

#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct LookalikeVerdict {
    /// Registrant (organisation) vue au RDAP, si lue.
    pub registrant: Option<String>,
    /// Annee d'enregistrement du sosie, si lue.
    pub registered_year: Option<u32>,
    /// true = domaine ancien (> 5 ans) et registrant != cible -> tiers legitime.
    pub likely_legitimate: bool,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct LookalikeDomain {
    pub domain: String,
    pub fuzzer: String,
    pub ip: Option<String>,
}

#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
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

        let output = match crate::utils::run_tool(
            "dnstwist",
            &["--registered", "-f", "json", target],
            180,
        ) {
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


    /// Interroge rdap.org/domain/<sosie> (redirige vers le RDAP du TLD).
    /// 1 requete curl, 20s. Retourne None si RDAP muet/erreur.
    fn rdap_check(domain: &str) -> Option<LookalikeVerdict> {
        let url = format!("https://rdap.org/domain/{domain}");
        let out = crate::utils::run_tool(
            "curl",
            &["-sL", "--max-time", "20", "-H", "Accept: application/rdap+json", &url],
            25,
        )?;
        let body = String::from_utf8_lossy(&out.stdout).to_string();
        if body.trim().is_empty() || !out.status.success() {
            return None;
        }
        let v: serde_json::Value = serde_json::from_str(&body).ok()?;

        // Registrant : parcourt entities, role == "registrant"
        let mut registrant = None;
        if let Some(ents) = v.get("entities").and_then(|x| x.as_array()) {
            for e in ents {
                let roles = e
                    .get("roles")
                    .and_then(|x| x.as_array())
                    .map(|arr| arr.iter().filter_map(|r| r.as_str().map(|x| x.to_string())).collect::<Vec<_>>())
                    .unwrap_or_default();
                if roles.iter().any(|r| r == "registrant") {
                    // vcardArray [ "vcard", [ [...], ["fn", {}, "text", "NAME"] ] ]
                    if let Some(vc) = e.get("vcardArray").and_then(|x| x.as_array()) {
                        if let Some(items) = vc.get(1).and_then(|x| x.as_array()) {
                            for item in items {
                                if let Some(arr) = item.as_array() {
                                    if arr.first().and_then(|k| k.as_str()) == Some("fn") {
                                        if let Some(name) = arr.get(3).and_then(|x| x.as_str()) {
                                            registrant = Some(name.to_string());
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        // Annee : events[].eventAction == "registration" -> eventDate
        let mut registered_year = None;
        if let Some(events) = v.get("events").and_then(|x| x.as_array()) {
            for ev in events {
                let action = ev.get("eventAction").and_then(|x| x.as_str()).unwrap_or("");
                if action == "registration" {
                    if let Some(date) = ev.get("eventDate").and_then(|x| x.as_str()) {
                        registered_year = date.get(0..4).and_then(|y| y.parse::<u32>().ok());
                    }
                }
            }
        }
        // Tiers legitime = domaine ancien (> 5 ans) ET organisation identifiable
        // au RDAP. L age seul ne suffit pas : 8brain.ca (2019, registrant prive,
        // meme annee que la creation de la cible 8brains.ca) serait sinon
        // auto-legitime a tort.
        let has_registrant = registrant
            .as_deref()
            .map(|r| !r.trim().is_empty())
            .unwrap_or(false);
        let age_ok = registered_year.map(|y| y <= 2021).unwrap_or(false);
        Some(LookalikeVerdict {
            likely_legitimate: age_ok && has_registrant,
            registrant,
            registered_year,
        })
    }

    pub fn to_findings(&self, res: &BrandSecResult) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();

        if !res.registered_lookalikes.is_empty() {
            // Verdict RDAP par sosie (lecons 8brains.ca : brains.ca = Brains II
            // Inc depuis 2000 = tiers legitime, PAS un typosquat).
            let mut legit: Vec<String> = Vec::new();
            let mut typos: Vec<String> = Vec::new();
            for l in res.registered_lookalikes.iter().take(8) {
                match Self::rdap_check(&l.domain) {
                    Some(v) if v.likely_legitimate => {
                        let who = v.registrant.as_deref().unwrap_or("registrant privé");
                        let year = v.registered_year.map(|y| y.to_string()).unwrap_or_else(|| "?".into());
                        legit.push(format!("{} ({} , depuis {})", l.domain, who, year));
                    }
                    _ => typos.push(l.domain.clone()),
                }
            }
            if !typos.is_empty() {
                findings.push(SecurityFinding {
                    severity: "LOW",
                    category: "BRAND",
                    title: format!("Protection de marque : {} domaine(s) similaire(s) NON identifiés (typosquats probables : {})", typos.len(), typos.join(", ")),
                    recommendation: "Surveiller ces domaines actifs sans identité légitime retrouvée au RDAP et envisager l'enregistrement défensif des variantes proches contre le phishing.".to_string(),
                });
            }
            if !legit.is_empty() {
                findings.push(SecurityFinding {
                    severity: "INFO",
                    category: "BRAND",
                    title: format!("{} domaine(s) similaire(s) = tiers légitimes (RDAP vérifié) : {}", legit.len(), legit.join(" ; ")),
                    recommendation: "Domaines anciens détenus par d'autres organisations identifiables : à exclure de la surveillance typosquat, simple connaissance de voisinage DNS.".to_string(),
                });
            }
        }

        findings
    }
}
