use std::net::IpAddr;

#[allow(dead_code)]
#[derive(Debug, Clone, Default)]
#[derive(serde::Serialize, serde::Deserialize)]
pub struct DnsHardeningResult {
    pub ip_tested: String,
    pub is_open_resolver_risk: bool,
    pub recursion_denied: bool,
    pub zone_transfer_denied: bool,
}

pub struct DnsHardeningAuditor;

impl DnsHardeningAuditor {
    /// Test de durcissement sur le serveur DNS découvert
    pub fn audit(ip: &str, domain: &str) -> DnsHardeningResult {
        let mut res = DnsHardeningResult {
            ip_tested: ip.to_string(),
            is_open_resolver_risk: false,
            recursion_denied: true,
            zone_transfer_denied: true,
        };

        // 1. Test Open Resolver : NOERROR + au moins un vrai enregistrement A dans la
        //    réponse (l'en-tête "ANSWER SECTION:" est imprimé même vide — faux positif
        //    historique qui classait les résolveurs filtrants en open resolver).
        if let Some(out) = crate::utils::run_tool(
            "dig",
            &[
                &format!("@{}", ip),
                "google.com",
                "A",
                "+time=2",
                "+tries=1",
            ],
            8,
        ) {
            let s = String::from_utf8_lossy(&out.stdout);
            let has_answer_ip = s.lines().any(|l| {
                l.split_whitespace()
                    .last()
                    .map(|w| w.parse::<IpAddr>().is_ok())
                    .unwrap_or(false)
            });
            if s.contains("status: NOERROR") && has_answer_ip {
                res.is_open_resolver_risk = true;
                res.recursion_denied = false;
            } else if s.contains("status: REFUSED")
                || s.contains("recursion requested but not available")
            {
                res.recursion_denied = true;
                res.is_open_resolver_risk = false;
            }
        }

        // 2. Test AXFR (Transfert de zone)
        if let Some(out) = crate::utils::run_tool(
            "dig",
            &[&format!("@{}", ip), domain, "AXFR", "+time=2", "+tries=1"],
            8,
        ) {
            let s = String::from_utf8_lossy(&out.stdout);
            if s.contains("Transfer failed")
                || s.contains("connection refused")
                || s.contains("REFUSED")
            {
                res.zone_transfer_denied = true;
            } else if s.contains("IN\tSOA") && s.lines().count() > 5 {
                res.zone_transfer_denied = false;
            }
        }

        res
    }
}
