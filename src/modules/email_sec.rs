
#[allow(dead_code)]
#[derive(Debug, Clone, Default)]
#[derive(serde::Serialize, serde::Deserialize)]
pub struct EmailSecurityResult {
    pub domain: String,
    pub spf_lookup_count: usize,
    pub spf_lookup_valid: bool,
    pub dkim_selectors_tested: usize,
    pub dkim_selectors_found: Vec<String>,
    pub mta_sts_present: bool,
    pub mta_sts_mode: Option<String>,
    pub smtp_tls_reporting: bool,
    pub bimi_present: bool,
    pub dmarc_sp_policy: Option<String>,
    pub dmarc_adkim: Option<String>,
    pub dmarc_aspf: Option<String>,
}

pub struct EmailSecAuditor;

impl EmailSecAuditor {
    /// Résultat vide pour une cible IP nue (aucune zone DNS à interroger).
    pub fn audit_skipped_for_ip(domain: &str) -> EmailSecurityResult {
        EmailSecurityResult {
            domain: domain.to_string(),
            spf_lookup_count: 0,
            spf_lookup_valid: true,
            dkim_selectors_tested: 0,
            dkim_selectors_found: Vec::new(),
            mta_sts_present: false,
            mta_sts_mode: None,
            smtp_tls_reporting: false,
            bimi_present: false,
            dmarc_sp_policy: None,
            dmarc_adkim: None,
            dmarc_aspf: None,
        }
    }
}

impl EmailSecAuditor {
    pub fn audit(
        domain: &str,
        spf_raw: Option<&str>,
        dmarc_raw: Option<&str>,
    ) -> EmailSecurityResult {
        let mut res = EmailSecurityResult {
            domain: domain.to_string(),
            spf_lookup_count: 0,
            spf_lookup_valid: true,
            dkim_selectors_tested: 0,
            dkim_selectors_found: Vec::new(),
            mta_sts_present: false,
            mta_sts_mode: None,
            smtp_tls_reporting: false,
            bimi_present: false,
            dmarc_sp_policy: None,
            dmarc_adkim: None,
            dmarc_aspf: None,
        };

        // 1. Calcul du nombre de lookups SPF (RFC 7208 max 10)
        if let Some(spf) = spf_raw {
            let mut count = 0;
            for term in spf.split_whitespace() {
                let clean = term.trim_start_matches(['+', '-', '~', '?']);
                if clean.starts_with("include:")
                    || clean.starts_with("a:")
                    || clean == "a"
                    || clean.starts_with("mx:")
                    || clean == "mx"
                    || clean.starts_with("ptr")
                    || clean.starts_with("exists:")
                    || clean.starts_with("redirect=")
                {
                    count += 1;
                }
            }
            res.spf_lookup_count = count;
            res.spf_lookup_valid = count <= 10;
        }

        // 2. Analyse approfondie des tags DMARC
        if let Some(dmarc) = dmarc_raw {
            for part in dmarc.split(';') {
                let p = part.trim();
                if p.starts_with("sp=") {
                    res.dmarc_sp_policy = Some(p.trim_start_matches("sp=").to_string());
                } else if p.starts_with("adkim=") {
                    res.dmarc_adkim = Some(p.trim_start_matches("adkim=").to_string());
                } else if p.starts_with("aspf=") {
                    res.dmarc_aspf = Some(p.trim_start_matches("aspf=").to_string());
                }
            }
        }

        // 3. MTA-STS (_mta-sts.<domain>)
        let mta_target = format!("_mta-sts.{}", domain);
        if let Some(out) = crate::utils::run_tool(
            "dig",
            &["+short", "+time=2", "+tries=1", "TXT", &mta_target],
            8,
        ) {
            let s = String::from_utf8_lossy(&out.stdout);
            if s.contains("v=STSv1") {
                res.mta_sts_present = true;
                // Valeur réelle du tag mode= si présent dans le TXT (rare)
                for part in s.split(';') {
                    let p = part.trim();
                    if let Some(mode) = p.strip_prefix("mode=") {
                        res.mta_sts_mode = Some(mode.trim().to_string());
                    }
                }
                // RFC 8461 : le tag mode= vit dans la politique HTTPS
                // (https://mta-sts.<domaine>/.well-known/mta-sts.txt). On la
                // récupère aussi pour détecter les déploiements cassés
                // (TXT présent mais endpoint mort → mode=None → finding MEDIUM).
                if res.mta_sts_mode.is_none() {
                    let policy_url =
                        format!("https://mta-sts.{}/.well-known/mta-sts.txt", domain);
                    if let Some(out) =
                        crate::utils::run_tool("curl", &["-s", "--max-time", "5", &policy_url], 10)
                    {
                        if out.status.success() {
                            let body = String::from_utf8_lossy(&out.stdout).to_string();
                            for line in body.lines() {
                                let l = line.trim();
                                if let Some(mode) = l.strip_prefix("mode:") {
                                    res.mta_sts_mode = Some(mode.trim().to_string());
                                }
                            }
                        }
                    }
                }
            }
        }

        // 4. SMTP TLS Reporting (_smtp._tls.<domain>)
        let tlsrpt_target = format!("_smtp._tls.{}", domain);
        if let Some(out) = crate::utils::run_tool(
            "dig",
            &["+short", "+time=2", "+tries=1", "TXT", &tlsrpt_target],
            8,
        ) {
            let s = String::from_utf8_lossy(&out.stdout);
            if s.contains("v=TLSRPTv1") {
                res.smtp_tls_reporting = true;
            }
        }

        // 5. BIMI (default._bimi.<domain>)
        let bimi_target = format!("default._bimi.{}", domain);
        if let Some(out) = crate::utils::run_tool(
            "dig",
            &["+short", "+time=2", "+tries=1", "TXT", &bimi_target],
            8,
        ) {
            let s = String::from_utf8_lossy(&out.stdout);
            if s.contains("v=BIMI1") {
                res.bimi_present = true;
            }
        }

        // 6. Test sélecteurs DKIM courants
        let selectors = [
            "default",
            "v1-rsa-20260723",
            "k1",
            "mail",
            "s1",
            "veridy",
            "stalwart",
            "google",
            "selector1",
        ];
        res.dkim_selectors_tested = selectors.len();

        for sel in selectors {
            let dkim_query = format!("{}._domainkey.{}", sel, domain);
            if let Some(out) = crate::utils::run_tool(
                "dig",
                &["+short", "+time=2", "+tries=1", "TXT", &dkim_query],
                8,
            ) {
                let s = String::from_utf8_lossy(&out.stdout);
                // Signature DKIM réelle : l'enregistrement (1re ligne, déquotée)
                // commence par v=DKIM1 ou contient un tag p= — pas n'importe quel "p="
                let first = s.lines().next().unwrap_or("").trim().trim_matches('"');
                let has_dkim_key = first.starts_with("v=DKIM1")
                    || first.starts_with("p=")
                    || first.contains("; p=")
                    || first.contains(" p=");
                if has_dkim_key {
                    res.dkim_selectors_found.push(sel.to_string());
                } else {
                    // Vérifier si c'est un CNAME vers un autre enregistrement
                    if let Some(cname_out) = crate::utils::run_tool(
                        "dig",
                        &["+short", "+time=2", "+tries=1", "CNAME", &dkim_query],
                        8,
                    ) {
                        let cs = String::from_utf8_lossy(&cname_out.stdout)
                            .trim()
                            .to_string();
                        if cs.contains("._domainkey.") || cs.to_lowercase().contains("dkim") {
                            res.dkim_selectors_found
                                .push(format!("{} (CNAME -> {})", sel, cs));
                        }
                    }
                }
            }
        }

        res
    }
}
