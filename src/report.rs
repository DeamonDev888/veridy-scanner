use crate::modules::brand_sec::BrandSecResult;
use crate::modules::dns::DnsAuditResult;
use crate::modules::dns_hardening::DnsHardeningResult;
use crate::modules::dnsrecon_audit::DnsreconResult;
use crate::modules::email_sec::EmailSecurityResult;
use crate::modules::ffuf_audit::FfufAuditResult;
use crate::modules::findings::SecurityFinding;
use crate::modules::geo::GeoComplianceResult;
use crate::modules::http::HttpAuditResult;
use crate::modules::http_probe::HttpProbeResult;
use crate::modules::nikto_deep::NiktoAuditResult;
use crate::modules::nmap_deep::NmapAuditResult;
use crate::modules::nuclei_deep::NucleiAuditResult;
use crate::modules::obscura_audit::ObscuraResult;
use crate::modules::ports::PortScanResult;
use crate::modules::portscan_rustscan::RustScanResult;
use crate::modules::sqli_audit::SqliFinding;
use crate::modules::sslscan_audit::SslscanResult;
use crate::modules::subdomains::SubdomainResult;
use crate::modules::tech_stack::TechStackResult;
use crate::modules::theharvester_audit::TheHarvesterResult;
use crate::modules::tls::TlsAuditResult;
use crate::modules::vuln_audit::VulnAuditResult;
use crate::modules::waf::WafResult;
use crate::modules::web_endpoints::WebEndpointsResult;
use crate::modules::whois_audit::WhoisResult;
use serde::Serialize;

#[derive(Serialize)]
pub struct FullAuditReport {
    pub target: String,
    pub timestamp: String,
    pub duration_seconds: f32,
    pub dns: DnsAuditResult,
    pub ports: Vec<PortScanResult>,
    pub http: HttpAuditResult,
    pub tls: TlsAuditResult,
    pub subdomains: Vec<SubdomainResult>,
    pub geo: GeoComplianceResult,
    pub email_sec: EmailSecurityResult,
    pub web_endpoints: WebEndpointsResult,
    pub dns_hardening: DnsHardeningResult,
    pub vuln_audit: VulnAuditResult,
    pub nmap: Option<NmapAuditResult>,
    pub nuclei: Option<NucleiAuditResult>,
    pub nikto: Option<NiktoAuditResult>,
    pub waf: Option<WafResult>,
    pub tech_stack: Option<TechStackResult>,
    pub sslscan: Option<SslscanResult>,
    pub brand_sec: Option<BrandSecResult>,
    pub ffuf: Option<FfufAuditResult>,
    pub whois: Option<WhoisResult>,
    pub dnsrecon: Option<DnsreconResult>,
    pub theharvester: Option<TheHarvesterResult>,
    pub obscura: Option<ObscuraResult>,
    pub http_probe: Option<Vec<HttpProbeResult>>,
    pub rustscan: Option<RustScanResult>,
    pub sqli: Option<Vec<SqliFinding>>,
    pub sliver: Option<crate::modules::c2_sliver::SliverAuditResult>,
    pub havoc: Option<crate::modules::c2_havoc::HavocAuditResult>,
    pub merlin: Option<crate::modules::c2_merlin::MerlinAuditResult>,
    pub poshc2: Option<crate::modules::c2_poshc2::PoshC2AuditResult>,
    pub empire: Option<crate::modules::c2_empire::EmpireAuditResult>,
    pub chisel: Option<crate::modules::tunnel_chisel::ChiselAuditResult>,
    pub netexec: Option<crate::modules::lateral_netexec::NetexecAuditResult>,
    pub findings: Vec<SecurityFinding>,
    pub overall_score: u8,
}

impl FullAuditReport {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        target: String,
        timestamp: String,
        duration_seconds: f32,
        dns: DnsAuditResult,
        ports: Vec<PortScanResult>,
        http: HttpAuditResult,
        tls: TlsAuditResult,
        subdomains: Vec<SubdomainResult>,
        geo: GeoComplianceResult,
        email_sec: EmailSecurityResult,
        web_endpoints: WebEndpointsResult,
        dns_hardening: DnsHardeningResult,
        vuln_audit: VulnAuditResult,
        nmap: Option<NmapAuditResult>,
        nuclei: Option<NucleiAuditResult>,
        nikto: Option<NiktoAuditResult>,
        waf: Option<WafResult>,
        tech_stack: Option<TechStackResult>,
        sslscan: Option<SslscanResult>,
        brand_sec: Option<BrandSecResult>,
        ffuf: Option<FfufAuditResult>,
        whois: Option<WhoisResult>,
        dnsrecon: Option<DnsreconResult>,
        theharvester: Option<TheHarvesterResult>,
        obscura: Option<ObscuraResult>,
        http_probe: Option<Vec<HttpProbeResult>>,
        rustscan: Option<RustScanResult>,
        sqli: Option<Vec<SqliFinding>>,
        sliver: Option<crate::modules::c2_sliver::SliverAuditResult>,
        havoc: Option<crate::modules::c2_havoc::HavocAuditResult>,
        merlin: Option<crate::modules::c2_merlin::MerlinAuditResult>,
        poshc2: Option<crate::modules::c2_poshc2::PoshC2AuditResult>,
        empire: Option<crate::modules::c2_empire::EmpireAuditResult>,
        chisel: Option<crate::modules::tunnel_chisel::ChiselAuditResult>,
        netexec: Option<crate::modules::lateral_netexec::NetexecAuditResult>,
        findings: Vec<SecurityFinding>,
    ) -> Self {
        let mut score: f32 = 100.0;

        for f in &findings {
            match f.severity {
                "CRITICAL" => score -= 25.0,
                "HIGH" => score -= 12.0,
                "MEDIUM" => score -= 5.0,
                "LOW" => score -= 2.0,
                _ => {}
            }
        }

        let overall_score = score.clamp(0.0, 100.0).round() as u8;

        Self {
            target,
            timestamp,
            duration_seconds,
            dns,
            ports,
            http,
            tls,
            subdomains,
            geo,
            email_sec,
            web_endpoints,
            dns_hardening,
            vuln_audit,
            nmap,
            nuclei,
            nikto,
            waf,
            tech_stack,
            sslscan,
            brand_sec,
            ffuf,
            whois,
            dnsrecon,
            theharvester,
            obscura,
            http_probe,
            rustscan,
            sqli,
            sliver,
            havoc,
            merlin,
            poshc2,
            empire,
            chisel,
            netexec,
            findings,
            overall_score,
        }
    }

    /// Affichage formaté console exhaustif : une méthode privée par
    /// section, appelée dans l'ordre historique — aucune ligne affichée
    /// ne change (pure motion de code).
    pub fn print_console(&self) {
        self.print_c2_modules();
        println!(
            "================================================================================"
        );
        println!("        VERIDY CYBERSCAN 360° — AUDIT DE SURFACE APPROFONDI ");
        println!(
            "================================================================================"
        );
        println!("  Cible auditée     : {}", self.target);
        println!("  Horodatage        : {}", self.timestamp);
        println!(
            "  Temps d'exécution : {:.2} secondes",
            self.duration_seconds
        );
        println!("  Score de sécurité : {} / 100", self.overall_score);
        println!(
            "--------------------------------------------------------------------------------\n"
        );

        self.print_geo_section();
        self.print_waf_section();
        self.print_email_section();
        self.print_dns_section();
        self.print_ports_section();
        self.print_http_section();
        self.print_tech_stack_section();
        self.print_tls_section();
        self.print_brand_sec_section();
        self.print_ffuf_section();
        self.print_subdomains_section();
        self.print_vuln_section();
        self.print_tools_section();
        self.print_findings_section();
    }

    /// [1] GéoIP & localisation
    fn print_geo_section(&self) {
        // 1. GéoIP & Localisation
        println!("[1] GÉOIP & LOCALISATION");
        println!("    • Adresse IP Publique  : {}", self.geo.ip_address);
        println!(
            "    • Fournisseur / Org    : {}",
            self.geo.org_name.as_deref().unwrap_or("Inconnu")
        );
        println!(
            "    • Réseau / ASN         : {}",
            self.geo.asn.as_deref().unwrap_or("Inconnu")
        );
        println!(
            "    • Localisation         : {}, {} ({})",
            self.geo.city.as_deref().unwrap_or(""),
            self.geo.region.as_deref().unwrap_or(""),
            self.geo.country_code.as_deref().unwrap_or("")
        );
        println!(
            "    • Région détectée      : {}",
            if self.geo.is_quebec {
                "Québec (CA)"
            } else if self.geo.is_canada {
                "Canada (autre province)"
            } else {
                "Hors Canada"
            }
        );
        println!();
    }

    /// [2] Pare-feu applicatif (WAF / Wafw00f)
    fn print_waf_section(&self) {
        // 2. WAF & Périmètre
        if let Some(ref w) = self.waf {
            println!("[2] PARE-FEU APPLICATIF (WAF / WAFW00F)");
            println!(
                "    • WAF Détecté          : {}",
                if w.waf_detected {
                    format!("OUI [{} - {}]", w.firewall_name, w.manufacturer)
                } else {
                    "NON (Exposition directe de l'infrastructure)".to_string()
                }
            );
            println!("    • Résumé               : {}", w.summary);
            println!();
        }
    }

    /// [3] DNS, sécurité courriel & anti-usurpation (MX, SPF, DMARC, MTA-STS, DKIM)
    fn print_email_section(&self) {
        // 3. DNS & Messagerie
        println!("[3] DNS, SÉCURITÉ COURRIEL & ANTI-USURPATION");
        println!(
            "    • IPv4 (A)             : {}",
            if self.dns.a_records.is_empty() {
                "Aucune".into()
            } else {
                self.dns.a_records.join(", ")
            }
        );
        println!(
            "    • Reverse DNS (PTR)    : {}",
            self.dns.reverse_ptr.as_deref().unwrap_or("Non configuré")
        );
        println!(
            "    • Serveurs Mail (MX)   : {}",
            if self.dns.mx_records.is_empty() {
                "Aucun".into()
            } else {
                self.dns.mx_records.join("; ")
            }
        );
        println!(
            "    • DNSSEC               : {}",
            if self.dns.dnssec_active {
                "ACTIVÉ [OK]"
            } else {
                "NON SIGNÉ [INFO]"
            }
        );
        println!(
            "    • Enregistrements CAA  : {}",
            if self.dns.caa_records.is_empty() {
                "AUCUN [ATTENTION]".to_string()
            } else {
                self.dns.caa_records.join("; ")
            }
        );
        println!(
            "    • Politique SPF        : {}",
            if self.dns.spf_found {
                if self.dns.spf_strict {
                    "STRICTE (-all) [EXCELLENT]"
                } else {
                    "PERMISSIVE (~all) [ATTENTION]"
                }
            } else {
                "ABSENTE [ALERTE]"
            }
        );
        println!(
            "      Lookups SPF DNS      : {} / 10 (RFC 7208) [{}]",
            self.email_sec.spf_lookup_count,
            if self.email_sec.spf_lookup_valid {
                "CONFORME"
            } else {
                "DÉPASSÉ - ALERTE"
            }
        );
        println!(
            "    • Politique DMARC      : {}",
            if self.dns.dmarc_found {
                format!(
                    "PRÉSENTE (p={}) [OK]",
                    self.dns.dmarc_policy.as_deref().unwrap_or("inconnu")
                )
            } else {
                "ABSENTE [ALERTE]".into()
            }
        );
        println!(
            "    • MTA-STS (Anti-MITM)  : {}",
            if self.email_sec.mta_sts_present {
                "DÉPLOYÉ (_mta-sts) [EXCELLENT]"
            } else {
                "NON CONFIGURÉ [INFO]"
            }
        );
        println!(
            "    • SMTP TLS Reporting   : {}",
            if self.email_sec.smtp_tls_reporting {
                "ACTIF (_smtp._tls) [OK]"
            } else {
                "NON CONFIGURÉ"
            }
        );
        println!(
            "    • Sélecteurs DKIM      : {}",
            if self.email_sec.dkim_selectors_found.is_empty() {
                "Aucun sélecteur standard détecté".into()
            } else {
                self.email_sec.dkim_selectors_found.join(", ")
            }
        );
        println!();
    }

    /// [4] Durcissement du serveur DNS (récursion ouverte, transfert AXFR)
    fn print_dns_section(&self) {
        // 4. Durcissement DNS
        println!("[4] DURCISSEMENT DU SERVEUR DNS (Port 53)");
        println!(
            "    • Résolveur Récursif   : {}",
            if self.dns_hardening.recursion_denied {
                "Récursion désactivée (réponse standard)"
            } else {
                "RÉCURSIF OUVERT [CRITIQUE]"
            }
        );
        println!(
            "    • Transfert AXFR       : {}",
            if self.dns_hardening.zone_transfer_denied {
                "REFUSÉ [SÉCURISÉ]"
            } else {
                "AUTORISÉ [VULNÉRABILITÉ]"
            }
        );
        println!();
    }

    /// [5] Ports & services (scan étendu)
    fn print_ports_section(&self) {
        // 5. Ports & Services
        println!("[5] MODULE PORTS & SERVICES (Scan étendu 75+ cibles)");
        if self.ports.is_empty() {
            println!("    • Aucun port standard ouvert détecté.");
        } else {
            for p in &self.ports {
                let banner_info = p.banner.as_deref().unwrap_or("Pas de bannière spontanée");
                println!(
                    "    • Port {:<5}/tcp : {:<15} (Service: {})",
                    p.port, "[OUVERT]", p.service_hint
                );
                if p.banner.is_some() {
                    println!("      Bannière: {}", banner_info);
                }
            }
        }
        println!();
    }

    /// [6] Sécurité web, endpoints & en-têtes
    fn print_http_section(&self) {
        // 6. Web & Endpoints
        println!("[6] SÉCURITÉ WEB, ENDPOINTS & HEADERS");
        println!("    • Statut HTTP HTTPS    : {}", self.http.http_status);
        println!(
            "    • Protocole ALPN       : {}",
            self.web_endpoints
                .alpn_negotiated
                .as_deref()
                .unwrap_or("http/1.1")
        );
        println!(
            "    • Redirection HTTPS    : {}",
            if self.http.redirects_to_https {
                "OUI [OK]"
            } else {
                "NON [ATTENTION]"
            }
        );
        println!(
            "    • Fichier security.txt : {}",
            if self.web_endpoints.security_txt_present {
                "PRÉSENT (RFC 9116) [EXCELLENT]"
            } else {
                "NON TROUVÉ"
            }
        );
        println!(
            "    • Fichier robots.txt   : {}",
            if self.web_endpoints.robots_txt_present {
                "PRÉSENT [OK]"
            } else {
                "NON TROUVÉ"
            }
        );
        println!(
            "    • Serveur divulgué     : {}",
            self.http.server_header.as_deref().unwrap_or("Masqué [OK]")
        );
        println!(
            "    • HSTS                 : {}",
            if self.http.hsts_present {
                "PRÉSENT [OK]"
            } else {
                "MANQUANT [ALERTE]"
            }
        );
        println!(
            "    • CSP                  : {}",
            if self.http.csp_present {
                "PRÉSENT [OK]"
            } else {
                "MANQUANT [ATTENTION]"
            }
        );
        println!(
            "    • X-Frame-Options      : {}",
            self.http.x_frame_options.as_deref().unwrap_or("MANQUANT")
        );
        println!(
            "    • X-Content-Type-Opt   : {}",
            self.http
                .x_content_type_options
                .as_deref()
                .unwrap_or("MANQUANT")
        );
        println!();
    }

    /// [7] Empreinte technologique & composants (WhatWeb)
    fn print_tech_stack_section(&self) {
        // 7. Tech Stack (WhatWeb)
        if let Some(ref tw) = self.tech_stack {
            println!("[7] EMPREINTE TECHNOLOGIQUE & COMPOSANTS (WHATWEB)");
            println!(
                "    • Serveur web          : {}",
                tw.server.as_deref().unwrap_or("Non divulgué")
            );
            println!(
                "    • Composants détectés  : {}",
                if tw.detected_technologies.is_empty() {
                    "Aucun".into()
                } else {
                    tw.detected_technologies.join(", ")
                }
            );
            if !tw.emails_exposed.is_empty() {
                println!(
                    "    • Courriels repérés    : {}",
                    tw.emails_exposed.join(", ")
                );
            }
            println!();
        }
    }

    /// [8] TLS / SSL & chiffrement (+ SSLScan)
    fn print_tls_section(&self) {
        // 8. TLS & SSLScan
        println!("[8] MODULE TLS / SSL & CHIFFREMENT");
        println!(
            "    • Protocole négocié    : {}",
            self.tls.protocol.as_deref().unwrap_or("Inconnu")
        );
        println!(
            "    • Suite de chiffrement : {}",
            self.tls.cipher.as_deref().unwrap_or("Inconnue")
        );
        println!(
            "    • Émetteur (CA)        : {}",
            self.tls.issuer.as_deref().unwrap_or("Inconnu")
        );
        println!(
            "    • Jours restants       : {} jours",
            self.tls
                .days_remaining
                .map(|d| d.to_string())
                .unwrap_or_else(|| "Inconnu".into())
        );
        println!(
            "    • Noms alternatifs SAN : {}",
            if self.tls.sans.is_empty() {
                "Aucun".into()
            } else {
                self.tls.sans.join(", ")
            }
        );
        println!(
            "    • Support TLS 1.0 / 1.1: {}",
            if self.tls.supports_tls10 || self.tls.supports_tls11 {
                "DÉTECTÉ [VULNÉRABILITÉ]"
            } else {
                "DÉSACTIVÉ [CONFORME]"
            }
        );
        if let Some(ref ss) = self.sslscan {
            println!(
                "    • Heartbleed           : {}",
                if ss.heartbleed_vulnerable {
                    "VULNÉRABLE [CRITIQUE]"
                } else {
                    "NON VULNÉRABLE [OK]"
                }
            );
            println!(
                "    • Compression (CRIME)  : {}",
                if ss.compression_enabled {
                    "ACTIVÉE [VULNÉRABLE]"
                } else {
                    "DÉSACTIVÉE [SÉCURISÉ]"
                }
            );
            println!(
                "    • Renégociation        : {}",
                if ss.insecure_renegotiation {
                    "NON SÉCURISÉE [ATTENTION]"
                } else {
                    "SÉCURISÉE [OK]"
                }
            );
            println!(
                "    • Ciphers forts        : {} acceptés",
                ss.strong_ciphers_count
            );
            if !ss.weak_ciphers.is_empty() {
                println!(
                    "    • Ciphers faibles      : {} [ALERTE]",
                    ss.weak_ciphers.join(", ")
                );
            }
        }
        println!();
    }

    /// [9] Protection de marque & typosquatting (Dnstwist)
    fn print_brand_sec_section(&self) {
        // 9. Protection de Marque & Typosquatting
        if let Some(ref bs) = self.brand_sec {
            println!("[9] PROTECTION DE MARQUE & TYPOSQUATTING (DNSTWIST)");
            println!(
                "    • Domaines similaires  : {} actif(s) sur Internet",
                bs.registered_lookalikes.len()
            );
            for l in bs.registered_lookalikes.iter().take(6) {
                let ip_str = l.ip.as_deref().unwrap_or("Pas d'IP directe");
                println!("    • {:<24} ({}) -> {}", l.domain, l.fuzzer, ip_str);
            }
            if bs.registered_lookalikes.len() > 6 {
                println!(
                    "      ... (et {} autre(s) domaine(s))",
                    bs.registered_lookalikes.len() - 6
                );
            }
            println!();
        }
    }

    /// [10] Découverte de chemins & fichiers sensibles (Ffuf + SecLists)
    fn print_ffuf_section(&self) {
        // 10. Ffuf / SecLists (si actif)
        if let Some(ref ffuf_res) = self.ffuf {
            println!("[10] DÉCOUVERTE DE CHEMINS & FICHIERS SENSIBLES (FFUF + SECLISTS)");
            println!(
                "    • Statut exécution     : {}",
                if ffuf_res.success {
                    "SUCCÈS"
                } else {
                    "ÉCHEC"
                }
            );
            println!("    • Résumé               : {}", ffuf_res.summary);
            if ffuf_res.endpoints.is_empty() {
                println!("    • Aucune fuite de fichier sensible (.git, .env, backup) détectée.");
            } else {
                for ep in &ffuf_res.endpoints {
                    println!(
                        "    • Route exposée        : /{} (HTTP {}, {} octets)",
                        ep.path, ep.status, ep.length
                    );
                }
            }
            println!();
        }
    }

    /// [11] Sous-domaines & cartographie
    fn print_subdomains_section(&self) {
        // 11. Sous-domaines
        println!("[11] SOUS-DOMAINES & CARTOGRAPHIE");
        if self.subdomains.is_empty() {
            println!("    • Aucun sous-domaine additionnel identifié parmi les noms courants.");
        } else {
            for sub in &self.subdomains {
                let http_info = sub
                    .http_status
                    .map(|c| format!("HTTP {}", c))
                    .unwrap_or_else(|| "Pas de réponse HTTP".into());
                println!(
                    "    • {:<32} -> {:<16} ({})",
                    sub.subdomain,
                    sub.ip_address.as_deref().unwrap_or("?"),
                    http_info
                );
            }
        }
        println!();
    }

    /// [12] Vulnérabilités applicatives & front-end
    fn print_vuln_section(&self) {
        // 12. Vulnérabilités Applicatives & Front-end
        println!("[12] AUDIT DES VULNÉRABILITÉS APPLICATIVES & FRONT-END");
        println!(
            "    • Page HTML récupérée  : {}",
            if self.vuln_audit.html_retrieved {
                "OUI [200 OK]"
            } else {
                "NON"
            }
        );
        println!(
            "    • Scripts CDN détectés : {}",
            self.vuln_audit.cdn_scripts_count
        );
        println!(
            "    • Scripts sans SRI     : {}",
            if self.vuln_audit.missing_sri_count == 0 {
                "0 [SÉCURISÉ / INTÈGRE]".to_string()
            } else {
                format!("{} [ATTENTION]", self.vuln_audit.missing_sri_count)
            }
        );
        println!(
            "    • Contenu Mixte HTTP   : {}",
            if self.vuln_audit.mixed_content_count == 0 {
                "AUCUN [CONFORME]".to_string()
            } else {
                format!(
                    "{} ressource(s) en clair [ALERTE]",
                    self.vuln_audit.mixed_content_count
                )
            }
        );
        println!(
            "    • Configuration CORS   : {}",
            if self.vuln_audit.cors_misconfigured {
                "PERMISSIVE / VULNÉRABLE [ALERTE]"
            } else {
                "STRICTE / SÉCURISÉE [OK]"
            }
        );
        if !self.vuln_audit.detected_libraries.is_empty() {
            println!(
                "    • Bibliothèques JS     : {}",
                self.vuln_audit.detected_libraries.join(", ")
            );
        }
        println!();
    }

    /// [13] à [19] Outils d'orchestration Kali : Nmap, Nuclei, Nikto, Whois,
    fn print_tools_section(&self) {
        // 13. Nmap (si actif)
        if let Some(ref nmap_res) = self.nmap {
            println!("[13] ORCHESTRATION KALI : NMAP SERVICE & NSE AUDIT");
            println!(
                "    • Statut exécution     : {}",
                if nmap_res.success {
                    "SUCCÈS"
                } else {
                    "ÉCHEC"
                }
            );
            println!("    • Résumé               : {}", nmap_res.summary);
            for srv in &nmap_res.services {
                let ver_str = srv.version.as_deref().unwrap_or("");
                let prod_str = srv.product.as_deref().unwrap_or(&srv.service);
                println!(
                    "    • Port {:<5}/{} : {:<10} {} {}",
                    srv.port, srv.protocol, srv.state, prod_str, ver_str
                );
                for (sc_id, _) in &srv.scripts {
                    println!("      - Script NSE validé  : {}", sc_id);
                }
            }
            println!();
        }

        // 14. Nuclei (si actif)
        if let Some(ref nuclei_res) = self.nuclei {
            println!("[14] ORCHESTRATION KALI : NUCLEI VULNERABILITY SCANNER");
            println!(
                "    • Statut exécution     : {}",
                if nuclei_res.success {
                    "SUCCÈS"
                } else {
                    "ÉCHEC"
                }
            );
            println!("    • Résumé               : {}", nuclei_res.summary);
            if nuclei_res.items.is_empty() {
                println!(
                    "    • Aucune vulnérabilité ou anomalie détectée par les templates Nuclei."
                );
            } else {
                for it in &nuclei_res.items {
                    println!(
                        "    • [{:<8}] {:<25} ({})",
                        it.severity, it.template_id, it.name
                    );
                }
            }
            println!();
        }

        // 15. Nikto (si actif)
        if let Some(ref nikto_res) = self.nikto {
            println!("[15] ORCHESTRATION KALI : NIKTO WEB SERVER AUDITOR");
            println!(
                "    • Statut exécution     : {}",
                if nikto_res.success {
                    "SUCCÈS"
                } else {
                    "ÉCHEC"
                }
            );
            println!("    • Résumé               : {}", nikto_res.summary);
            if nikto_res.vulnerabilities.is_empty() {
                println!("    • Aucun problème spécifique signalé par Nikto.");
            } else {
                for v in &nikto_res.vulnerabilities {
                    println!("    • [{}] Route {} : {}", v.id, v.url, v.msg);
                }
            }
            println!();
        }

        // 16. Whois (si actif)
        if let Some(ref wh) = self.whois {
            println!("[16] REGISTRE DE NOM DE DOMAINE & EXPIRATION (WHOIS)");
            println!(
                "    • Registrar            : {}",
                wh.registrar.as_deref().unwrap_or("Non identifié")
            );
            println!(
                "    • Date de création     : {}",
                wh.creation_date.as_deref().unwrap_or("Non renseignée")
            );
            println!(
                "    • Date d'expiration    : {}",
                wh.expiry_date.as_deref().unwrap_or("Non renseignée")
            );
            println!(
                "    • Verrou anti-transfert: {}",
                if wh.is_transfer_locked {
                    "ACTIF (ClientTransferProhibited) [SÉCURISÉ]"
                } else {
                    "INACTIF [ATTENTION: Risque de hijacking]"
                }
            );
            println!(
                "    • Masquage Privacy     : {}",
                if wh.is_privacy_protected {
                    "ACTIF (Données personnelles masquées) [CONFORME]"
                } else {
                    "NON DÉTECTÉ"
                }
            );
            println!();
        }

        // 17. Dnsrecon (si actif)
        if let Some(ref dr) = self.dnsrecon {
            println!("[17] RECONNAISSANCE DNS AVANCÉE (DNSRECON)");
            if dr.bind_versions.is_empty() {
                println!("    • Version DNS / BIND   : Masquée [SÉCURISÉ]");
            } else {
                for (srv, ver) in &dr.bind_versions {
                    println!("    • Version DNS sur {}   : {}", srv, ver);
                }
            }
            if dr.srv_records.is_empty() {
                println!("    • Services SRV         : Aucun service SRV standard exposé.");
            } else {
                for srv in &dr.srv_records {
                    println!(
                        "    • Service SRV trouvé   : {} -> {}:{} ({})",
                        srv.name, srv.target, srv.port, srv.address
                    );
                }
            }
            println!();
        }

        // 18. theHarvester (si actif)
        if let Some(ref th) = self.theharvester {
            println!("[18] RENSEIGNEMENT OSINT & FUITE DE DONNÉES (THEHARVESTER)");
            if th.emails.is_empty() {
                println!(
                    "    • Emails indexés OSINT : Aucun email public découvert dans les moteurs."
                );
            } else {
                println!("    • Emails indexés OSINT : {}", th.emails.join(", "));
            }
            if th.hosts.is_empty() {
                println!("    • Hôtes indexés OSINT  : Aucun hôte supplémentaire découvert.");
            } else {
                println!("    • Hôtes indexés OSINT  : {}", th.hosts.join(", "));
            }
            println!();
        }

        // 19. Obscura (si actif)
        if let Some(ref obs) = self.obscura {
            println!("[19] MOTEUR DE RENDU DYNAMIQUE JAVASCRIPT & DOM (OBSCURA)");
            println!(
                "    • Statut exécution     : {}",
                if obs.success { "SUCCÈS" } else { "ÉCHEC" }
            );
            println!("    • Titre rendu DOM      : {}", obs.page_title);
            println!(
                "    • Sous-ressources DOM  : {} totale(s), dont {} script(s) JS",
                obs.total_assets, obs.script_assets
            );
            if !obs.external_scripts.is_empty() {
                println!(
                    "    • Dépendances tierces  : {} domaine(s) externe(s) (ex: {})",
                    obs.external_scripts.len(),
                    obs.external_scripts
                        .iter()
                        .take(3)
                        .cloned()
                        .collect::<Vec<_>>()
                        .join(", ")
                );
            }
            if !obs.insecure_assets.is_empty() {
                println!(
                    "    • Contenu Mixte HTTP   : {} ressource(s) non sécurisée(s) [ALERTE]",
                    obs.insecure_assets.len()
                );
            }
            println!(
                "    • Alertes Console JS   : {}",
                if obs.console_warnings_count == 0 {
                    "0 [AUCUNE ERREUR]".to_string()
                } else {
                    format!("{} anomalie(s) interceptée(s)", obs.console_warnings_count)
                }
            );
            if let Some(ref sc_path) = obs.screenshot_path {
                println!(
                    "    • Capture visuelle PNG : {} ({} Ko)",
                    sc_path,
                    obs.screenshot_size_bytes / 1024
                );
            }
            println!();
        }

        // 20. RustScan (si actif)
        if let Some(ref rs) = self.rustscan {
            println!("[20] BALAYAGE DE PORTS ULTRA-RAPIDE (RUSTSCAN 65535)");
            println!(
                "    • Statut exécution     : {}",
                if rs.success { "SUCCÈS" } else { "ÉCHEC" }
            );
            println!("    • Durée du scan SYN    : {} ms", rs.scan_duration_ms);
            if rs.open_ports.is_empty() {
                println!("    • Ports ouverts découverts : Aucun port additionnel");
            } else {
                let ports_str: Vec<String> = rs.open_ports.iter().map(|p| p.to_string()).collect();
                println!("    • Ports ouverts découverts : {}", ports_str.join(", "));
            }
            println!();
        }

        // 21. HTTPx (si actif)
        if let Some(ref probes) = self.http_probe {
            println!("[21] DÉCOUVERTE D'ENDPOINTS & PROBING HTTP (HTTPX)");
            println!("    • Endpoints audités    : {} URLs", probes.len());
            for p in probes.iter().take(10) {
                let code_str = p
                    .status_code
                    .map(|c| c.to_string())
                    .unwrap_or_else(|| "ERR".to_string());
                let title = p.title.as_deref().unwrap_or("Sans titre");
                println!("    • [{:>3}] {:<35} │ {}", code_str, p.url, title);
                if !p.technologies.is_empty() {
                    println!("      - Technologies       : {}", p.technologies.join(", "));
                }
            }
            if probes.len() > 10 {
                println!(
                    "    • ... et {} autres endpoints inspectés.",
                    probes.len() - 10
                );
            }
            println!();
        }

        // 22. SQLMap (si actif)
        if let Some(ref sqli_res) = self.sqli {
            println!("[22] AUDIT DE VULNÉRABILITÉS INJECTIONS SQL (SQLMAP)");
            if sqli_res.is_empty() {
                println!(
                    "    • Failles SQLi         : Aucune injection SQL exploitable identifiée."
                );
            } else {
                for s in sqli_res {
                    let dbms = s.dbms.as_deref().unwrap_or("Inconnu");
                    println!(
                        "    • [VULNÉRABLE] Paramètre '{}' sur {}",
                        s.parameter, s.url
                    );
                    println!(
                        "      - Type d'injection   : {}",
                        s.injection_type.join(", ")
                    );
                    println!("      - SGBD identifié     : {}", dbms);
                    if let Some(ref pay) = s.payload {
                        println!("      - Payload validé     : {}", pay);
                    }
                }
            }
            println!();
        }
    }

    /// [20] Constatations & recommandations d'audit
    fn print_findings_section(&self) {
        // 20. Constatations & Recommandations globales
        println!(
            "================================================================================"
        );
        println!(
            "             CONSTATATIONS & RECOMMANDATIONS D'AUDIT ({})                      ",
            self.findings.len()
        );
        println!(
            "================================================================================"
        );
        if self.findings.is_empty() {
            println!("  [EXCELLENT] Aucune faiblesse ou anomalie détectée sur la cible.");
        } else {
            for f in &self.findings {
                println!("  [{:<8}] [{:<9}] {}", f.severity, f.category, f.title);
                println!("    Action recommandée : {}\n", f.recommendation);
            }
        }
        println!(
            "--------------------------------------------------------------------------------\n"
        );
        println!(
            "{}",
            crate::ui::finale_banner(self.overall_score, &self.target)
        );
        println!(
            "  Hygiène globale : [{}]",
            crate::ui::score_bar(self.overall_score, 40)
        );
        println!();
    }

    /// Sérialisation JSON exhaustive du rapport complet (serde_json).
    /// [23. Modules C2 / post-exploitation] (opt-in)
    fn print_c2_modules(&self) {
        let mut lines: Vec<(&str, &str)> = Vec::new();
        if let Some(ref r) = self.sliver {
            lines.push(("Sliver", &r.summary));
        }
        if let Some(ref r) = self.havoc {
            lines.push(("Havoc", &r.summary));
        }
        if let Some(ref r) = self.merlin {
            lines.push(("Merlin", &r.summary));
        }
        if let Some(ref r) = self.poshc2 {
            lines.push(("PoshC2", &r.summary));
        }
        if let Some(ref r) = self.empire {
            lines.push(("Empire", &r.summary));
        }
        if let Some(ref r) = self.chisel {
            lines.push(("Chisel", &r.summary));
        }
        if let Some(ref r) = self.netexec {
            lines.push(("NetExec", &r.summary));
        }
        if !lines.is_empty() {
            println!("\n── MODULES C2 / POST-EXPLOITATION ──────────────────────");
            for (name, summary) in &lines {
                println!("  {} : {}", name, summary);
            }
        }
    }

    #[cfg(test)]
    pub fn default_for_tests() -> Self {
        Self {
            target: "test.local".into(),
            timestamp: "2026-01-01T00:00:00Z".into(),
            duration_seconds: 0.0,
            dns: Default::default(),
            ports: Default::default(),
            http: Default::default(),
            tls: Default::default(),
            subdomains: Default::default(),
            geo: Default::default(),
            email_sec: Default::default(),
            web_endpoints: Default::default(),
            dns_hardening: Default::default(),
            vuln_audit: Default::default(),
            nmap: None,
            nuclei: None,
            nikto: None,
            waf: None,
            tech_stack: None,
            sslscan: None,
            brand_sec: None,
            ffuf: None,
            whois: None,
            dnsrecon: None,
            theharvester: None,
            obscura: None,
            http_probe: None,
            rustscan: None,
            sqli: None,
            sliver: None,
            havoc: None,
            merlin: None,
            poshc2: None,
            empire: None,
            chisel: None,
            netexec: None,
            findings: vec![],
            overall_score: 100,
        }
    }

    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(self)
            .unwrap_or_else(|e| format!(r#"{{"error": "serialization failed: {}"}}"#, e))
    }
}
