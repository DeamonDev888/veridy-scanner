use crate::modules::dns::DnsAuditResult;
use crate::modules::dns_hardening::DnsHardeningResult;
use crate::modules::email_sec::EmailSecurityResult;
use crate::modules::geo::GeoComplianceResult;
use crate::modules::http::HttpAuditResult;
use crate::modules::ports::PortScanResult;
use crate::modules::subdomains::SubdomainResult;
use crate::modules::tls::TlsAuditResult;
use crate::modules::vuln_audit::VulnAuditResult;
use crate::modules::web_endpoints::WebEndpointsResult;

#[allow(dead_code)]
#[derive(Debug, Clone)]
#[derive(serde::Serialize)]
pub struct SecurityFinding {
    pub severity: &'static str, // CRITICAL, HIGH, MEDIUM, LOW, INFO
    pub category: &'static str, // DNS, PORT, HTTP, TLS, COOKIE, SUBDOMAIN, EMAIL, WEB, CVE, SRI, CORS, GEO, OSINT, NMAP, NUCLEI, NIKTO, WAF, BRAND, SECRETS, MIXED_CONTENT, WHOIS, SUPPLY_CHAIN, FRONTEND, OBSCURA
    pub title: String,
    pub recommendation: String,
}

pub struct FindingsEngine;

/// La cible est-elle une IP nue ? Une IP n'a pas de zone DNS — SPF/DMARC/CAA/
/// DKIM/MTA-STS/BIMI seraient des faux positifs absurdes (bruit de score).
fn is_bare_ip_target(domain: &str) -> bool {
    domain.parse::<std::net::IpAddr>().is_ok()
}

impl FindingsEngine {
    /// Orchestrateur : délègue chaque domaine d'audit à un sous-évaluateur
    /// privé, dans un ordre fixe qui garantit un comportement identique au
    /// moteur monolithique historique (mêmes findings, même ordre, même score).
    #[allow(clippy::too_many_arguments)]
    pub fn evaluate(
        dns: &DnsAuditResult,
        ports: &[PortScanResult],
        http: &HttpAuditResult,
        tls: &TlsAuditResult,
        subdomains: &[SubdomainResult],
        geo: &GeoComplianceResult,
        email_sec: &EmailSecurityResult,
        web_endpoints: &WebEndpointsResult,
        dns_hardening: &DnsHardeningResult,
        vuln_audit: &VulnAuditResult,
    ) -> Vec<SecurityFinding> {
        let is_bare_ip = is_bare_ip_target(&dns.domain);

        let mut findings = Vec::new();
        findings.extend(Self::eval_dns(dns, is_bare_ip));
        findings.extend(Self::eval_ports(ports, &dns.domain));
        findings.extend(Self::eval_dns_hardening(dns_hardening));
        findings.extend(Self::eval_email(email_sec, is_bare_ip));
        findings.extend(Self::eval_http(http));
        findings.extend(Self::eval_web_endpoints(web_endpoints, http.http_status > 0));
        findings.extend(Self::eval_tls(tls));
        findings.extend(Self::eval_geo(geo, dns));
        findings.extend(Self::eval_subdomains(subdomains));
        findings.extend(Self::eval_vuln_audit(vuln_audit));
        findings
    }

    /// 1. Audit DNS & SPF/DMARC/CAA/MX (spécifique à un domaine, pas une IP nue).
    fn eval_dns(dns: &DnsAuditResult, is_bare_ip: bool) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();

        if is_bare_ip {
            // Pas de zone DNS sur une IP : on saute tout le bloc email/DNS
        } else if !dns.spf_found {
            findings.push(SecurityFinding {
                severity: "HIGH",
                category: "DNS",
                title: "Absence d'enregistrement SPF (Sender Policy Framework)".into(),
                recommendation: "Ajouter un enregistrement TXT 'v=spf1 ... -all' pour empêcher l'usurpation d'identité d'expéditeur.".into(),
            });
        } else if !dns.spf_strict {
            findings.push(SecurityFinding {
                severity: "MEDIUM",
                category: "DNS",
                title: "Politique SPF permissive (~all ou ?all détecté)".into(),
                recommendation: "Basculer la terminaison SPF sur '-all' (Hard Fail) pour une protection maximale.".into(),
            });
        }

        if !is_bare_ip && !dns.dmarc_found {
            findings.push(SecurityFinding {
                severity: "HIGH",
                category: "DNS",
                title: "Absence d'enregistrement DMARC sur _dmarc".into(),
                recommendation: "Créer l'enregistrement TXT '_dmarc' avec une politique 'p=quarantine' ou 'p=reject' et rua pour le suivi.".into(),
            });
        } else if let Some(ref pol) = dns.dmarc_policy {
            if pol == "none" {
                findings.push(SecurityFinding {
                    severity: "LOW",
                    category: "DNS",
                    title: "Politique DMARC en mode passif (p=none)".into(),
                    recommendation: "Passer progressivement à 'p=quarantine' puis 'p=reject' pour bloquer les faux emails.".into(),
                });
            } else if pol == "reject" || pol == "quarantine" {
                findings.push(SecurityFinding {
                    severity: "INFO",
                    category: "DNS",
                    title: format!("Contrôle DMARC actif et contraignant (p={}) — usurpation d'identité bloquée", pol),
                    recommendation:
                        "Contrôle attesté : la politique DMARC en place bloque ou met en quarantaine les messages non conformes."
                            .into(),
                });
            }
        }

        if !is_bare_ip && !dns.dnssec_active {
            findings.push(SecurityFinding {
                severity: "LOW",
                category: "DNS",
                title: "DNSSEC non déployé sur la zone (empoisonnement DNS possible)".into(),
                recommendation:
                    "Signer la zone (DNSSEC) et publier l'enregistrement DS au registrar pour garantir l'intégrité des réponses DNS."
                        .into(),
            });
        }

        // Attestation positive : CAA présents = émission de certificats encadrée
        if !is_bare_ip && !dns.caa_records.is_empty() {
            findings.push(SecurityFinding {
                severity: "INFO",
                category: "DNS",
                title: format!("Enregistrements CAA actifs ({} règle(s)) — émission de certificats restreinte", dns.caa_records.len()),
                recommendation:
                    "Contrôle attesté : seules les autorités listées dans les CAA peuvent émettre des certificats pour ce domaine."
                        .into(),
            });
        }

        // Cartographie email : le MX définit le périmètre d'envoi (cible spoofing/relais)
        if !is_bare_ip && !dns.mx_records.is_empty() {
            let mx: Vec<String> = dns.mx_records.iter().take(3).cloned().collect();
            findings.push(SecurityFinding {
                severity: "INFO",
                category: "EMAIL",
                title: format!("Serveur(s) MX du domaine : {}", mx.join(", ")),
                recommendation:
                    "Périmètre d'envoi email identifié : auditer ce(s) serveur(s) (open relay, SMTP AUTH, TLS obligatoire)."
                        .into(),
            });
        }

        if !is_bare_ip && dns.caa_records.is_empty() {
            findings.push(SecurityFinding {
                severity: "LOW",
                category: "DNS",
                title: "Absence d'enregistrements CAA (Certification Authority Authorization)".into(),
                recommendation: "Définir des enregistrements CAA pour restreindre l'émission de certificats TLS aux autorités légitimes (ex: letsencrypt.org).".into(),
            });
        }

        findings
    }

    /// 2. Audit Ports & Services (bannières, ports à risque, bases de données).
    fn eval_ports(ports: &[PortScanResult], target_domain: &str) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();
        for p in ports {
            // Bannière de service : version logicielle + empreinte OS divulgées
            if let Some(ref b) = p.banner {
                let b = b.trim();
                if b.len() > 8 {
                    let short: String = b.chars().take(64).collect();
                    findings.push(SecurityFinding {
                        severity: "LOW",
                        category: "PORT",
                        title: format!("Bannière de service divulgée sur le port {} : {}", p.port, short),
                        recommendation:
                            "Désactiver la bannière de version du service (ex. sshd 'DebianBanner no', nginx server_tokens off) pour limiter le CVE matching direct."
                                .into(),
                    });
                }
            }
            if p.port == 21 {
                findings.push(SecurityFinding {
                    severity: "HIGH",
                    category: "PORT",
                    title: "Port FTP 21/tcp ouvert en clair".into(),
                    recommendation:
                        "Désactiver le service FTP obsolète et privilégier SFTP sur SSH.".into(),
                });
            } else if p.port == 23 {
                findings.push(SecurityFinding {
                    severity: "CRITICAL",
                    category: "PORT",
                    title: "Port Telnet 23/tcp ouvert (non chiffré)".into(),
                    recommendation:
                        "Fermer immédiatement le port 23 et utiliser exclusivement SSH.".into(),
                });
            } else if p.port == 3389 {
                findings.push(SecurityFinding {
                    severity: "HIGH",
                    category: "PORT",
                    title: "Port RDP 3389/tcp exposé sur Internet".into(),
                    recommendation: "Restreindre l'accès RDP via un VPN ou un bastion avec authentification MFA.".into(),
                });
            } else if p.port == 3306 || p.port == 5432 || p.port == 6379 || p.port == 27017 {
                // Anti-faux-positif : sur une cible loopback (127.0.0.0/8 ou ::1),
                // le port DB n'est PAS exposé publiquement — service local uniquement.
                let is_loopback_target = target_domain
                    .parse::<std::net::IpAddr>()
                    .map(|ip| ip.is_loopback())
                    .unwrap_or(false);
                if is_loopback_target {
                    findings.push(SecurityFinding {
                        severity: "INFO",
                        category: "PORT",
                        title: format!("Port de base de données {} ({}) en écoute — service local (loopback), non exposé publiquement", p.port, p.service_hint),
                        recommendation: "Service joignable uniquement en local : aucune exposition externe détectée.".into(),
                    });
                } else {
                    findings.push(SecurityFinding {
                        severity: "HIGH",
                        category: "PORT",
                        title: format!("Port de base de données {} ({}) exposé publiquement", p.port, p.service_hint),
                        recommendation: "Lier le service à localhost (127.0.0.1) ou filtrer l'accès via pare-feu (UFW).".into(),
                    });
                }
            }
        }
        findings
    }

    /// 3. Audit Durcissement DNS (Open Resolver check).
    fn eval_dns_hardening(dns_hardening: &DnsHardeningResult) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();
        if dns_hardening.is_open_resolver_risk {
            findings.push(SecurityFinding {
                severity: "CRITICAL",
                category: "DNS",
                title: "Serveur DNS agissant comme un résolveur récursif ouvert".into(),
                recommendation: "Désactiver la récursion dans Named/Knot/Bind ('recursion no;') pour éviter d'être exploité dans des attaques DDoS par amplification.".into(),
            });
        }
        findings
    }

    /// 4. Audit Messagerie Avancée (SPF lookups, DKIM, MTA-STS, BIMI).
    fn eval_email(email_sec: &EmailSecurityResult, is_bare_ip: bool) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();
        if !is_bare_ip && !email_sec.spf_lookup_valid {
            findings.push(SecurityFinding {
                severity: "CRITICAL",
                category: "EMAIL",
                title: format!("Limite des 10 lookups DNS SPF dépassée ({} lookups détectés, RFC 7208)", email_sec.spf_lookup_count),
                recommendation: "Aplatir la politique SPF (utiliser des sous-réseaux IP au lieu de multiples 'include' ou 'a') pour éviter le rejet PermError.".into(),
            });
        }

        if !is_bare_ip
            && email_sec.dkim_selectors_tested > 0
            && email_sec.dkim_selectors_found.is_empty()
        {
            findings.push(SecurityFinding {
                severity: "LOW",
                category: "EMAIL",
                title: format!(
                    "Aucun sélecteur DKIM trouvé parmi les {} testés",
                    email_sec.dkim_selectors_tested
                ),
                recommendation:
                    "Publier un enregistrement DKIM (sélecteur par défaut) pour signer les messages sortants."
                        .into(),
            });
        }

        if !is_bare_ip && !email_sec.dkim_selectors_found.is_empty() {
            let sels: Vec<String> = email_sec.dkim_selectors_found.iter().take(3).cloned().collect();
            findings.push(SecurityFinding {
                severity: "INFO",
                category: "EMAIL",
                title: format!("Signature DKIM active ({} sélecteur(s) : {}) — messages signés", email_sec.dkim_selectors_found.len(), sels.join(", ")),
                recommendation:
                    "Contrôle attesté : les messages sortants sont signés cryptographiquement (intégrité + expéditeur vérifiables)."
                        .into(),
            });
        }

        if !is_bare_ip
            && email_sec.mta_sts_present
            && email_sec.mta_sts_mode.is_none()
        {
            findings.push(SecurityFinding {
                severity: "MEDIUM",
                category: "EMAIL",
                title: "MTA-STS annoncé (TXT présent) mais politique HTTPS injoignable".into(),
                recommendation:
                    "Le DNS annonce MTA-STS mais https://mta-sts.<domaine>/.well-known/mta-sts.txt ne répond pas : les serveurs expéditeurs retomberont en SMTP opportuniste. Restaurer l'endpoint ou retirer l'enregistrement TXT."
                        .into(),
            });
        }

        if !is_bare_ip && !email_sec.mta_sts_present {
            findings.push(SecurityFinding {
                severity: "LOW",
                category: "EMAIL",
                title: "MTA-STS (RFC 8461) non configuré sur le domaine".into(),
                recommendation: "Configurer un enregistrement TXT '_mta-sts' et une politique HTTPS pour forcer le chiffrement TLS entre serveurs de messagerie.".into(),
            });
        }

        if !is_bare_ip && !email_sec.bimi_present {
            findings.push(SecurityFinding {
                severity: "INFO",
                category: "EMAIL",
                title: "Enregistrement BIMI (Brand Indicators) non détecté".into(),
                recommendation: "Optionnel : Configurer 'default._bimi' avec un logo SVG certifié pour afficher votre logo dans Gmail/Apple Mail.".into(),
            });
        }
        findings
    }

    /// 5. Audit HTTP & Headers (redirection, HSTS, CSP, cookies).
    fn eval_http(http: &HttpAuditResult) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();

        let http_service_present = http.http_status > 0;
        if !http_service_present {
            findings.push(SecurityFinding {
                severity: "INFO",
                category: "HTTP",
                title: "Aucun serveur HTTP/HTTPS accessible en tête de cible".into(),
                recommendation:
                    "Aucun port HTTP/HTTPS n'a répondu (80/443 ou ports spécifiés) : audit applicatif web non applicable."
                        .into(),
            });
        }
        if http_service_present && !http.redirects_to_https {
            findings.push(SecurityFinding {
                severity: "HIGH",
                category: "HTTP",
                title: "Pas de redirection forcée vers HTTPS".into(),
                recommendation: "Configurer une redirection 301 automatique du port 80 HTTP vers le port 443 HTTPS.".into(),
            });
        }

        if http_service_present && !http.hsts_present {
            findings.push(SecurityFinding {
                severity: "HIGH",
                category: "HTTP",
                title: "En-tête Strict-Transport-Security (HSTS) manquant".into(),
                recommendation: "Ajouter 'Strict-Transport-Security: max-age=31536000; includeSubDomains; preload'.".into(),
            });
        }

        if http_service_present
            && http.csp_present
            && http
                .csp_value
                .as_deref()
                .unwrap_or("")
                .to_lowercase()
                .contains("'unsafe-inline'")
        {
            findings.push(SecurityFinding {
                severity: "MEDIUM",
                category: "HTTP",
                title: "CSP présente mais contournable : directive 'unsafe-inline' active".into(),
                recommendation:
                    "Remplacer 'unsafe-inline' par des nonces ou des hashes de scripts (CSP niveau 3) — la directive actuelle n'empêche pas l'injection de code inline."
                        .into(),
            });
        }

        if http_service_present && !http.csp_present {
            findings.push(SecurityFinding {
                severity: "MEDIUM",
                category: "HTTP",
                title: "En-tête Content-Security-Policy (CSP) manquant".into(),
                recommendation:
                    "Définir une politique CSP stricte pour contrer les injections de scripts XSS."
                        .into(),
            });
        }

        if http_service_present && http.x_frame_options.is_none() {
            findings.push(SecurityFinding {
                severity: "MEDIUM",
                category: "HTTP",
                title: "En-tête X-Frame-Options manquant".into(),
                recommendation: "Définir 'X-Frame-Options: SAMEORIGIN' pour bloquer les attaques par Clickjacking.".into(),
            });
        }

        if http_service_present {
            if let Some(ref s) = http.server_header {
                findings.push(SecurityFinding {
                    severity: "LOW",
                    category: "HTTP",
                    title: format!("Divulgation du serveur Web : '{}'", s),
                    recommendation: "Masquer la signature 'Server' (ex: server_tokens off dans Nginx)."
                        .into(),
                });
            }
        }

        // HSTS : évaluation du max-age réel (trop court = protection dégradée)
        if http_service_present {
            if let Some(ref v) = http.hsts_value {
            let max_age = v
                .split(';')
                .find_map(|p| p.trim().strip_prefix("max-age="))
                .and_then(|s| s.trim().parse::<u64>().ok());
            if let Some(age) = max_age {
                if age < 15_768_000 {
                    findings.push(SecurityFinding {
                        severity: "MEDIUM",
                        category: "HTTP",
                        title: format!(
                            "HSTS max-age trop court ({} s < 6 mois recommandés)",
                            age
                        ),
                        recommendation:
                            "Porter max-age à au moins 31536000 (1 an) avec includeSubDomains."
                                .into(),
                    });
                }
            }
        }
        }

        // Cookies : chaque cookie sans Secure/HttpOnly est signalé (l'ancien
        // moteur listait les cookies mais ne générait AUCUN finding)
        if http_service_present {
        for c in &http.cookies {
            if !c.secure || !c.http_only || c.same_site.is_none() {
                let mut missing = Vec::new();
                if !c.secure {
                    missing.push("Secure");
                }
                if !c.http_only {
                    missing.push("HttpOnly");
                }
                if c.same_site.is_none() {
                    missing.push("SameSite");
                }
                findings.push(SecurityFinding {
                    severity: "MEDIUM",
                    category: "COOKIE",
                    title: format!(
                        "Cookie '{}' émis sans attribut(s) de sécurité : {}",
                        c.name,
                        missing.join(", ")
                    ),
                    recommendation:
                        "Ajouter Secure, HttpOnly et SameSite=Lax/Strict sur tous les cookies."
                            .into(),
                });
            }
        }
        }
        findings
    }

    /// 6. Audit Web Endpoints (robots.txt, security.txt, méthodes HTTP).
    fn eval_web_endpoints(
        web_endpoints: &WebEndpointsResult,
        http_service_present: bool,
    ) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();
        // robots.txt : les Disallow révèlent les chemins sensibles (recon passive)
        if http_service_present {
            let paths: Vec<&String> = web_endpoints
                .robots_disallowed_paths
                .iter()
                .filter(|p| !p.is_empty() && p.as_str() != "/")
                .take(6)
                .collect();
            if !paths.is_empty() {
                findings.push(SecurityFinding {
                    severity: "INFO",
                    category: "WEB",
                    title: format!(
                        "robots.txt révèle {} chemin(s) interne(s) : {}",
                        web_endpoints.robots_disallowed_paths.len(),
                        paths
                            .iter()
                            .map(|s| s.as_str())
                            .collect::<Vec<_>>()
                            .join(" ")
                    ),
                    recommendation:
                        "Inventaire passif : ces chemins (API, backoffices, préprod) sont connus de tout visiteur — vérifier leur protection par authentification."
                            .into(),
                });
            }
        }

        if http_service_present && !web_endpoints.security_txt_present {
            findings.push(SecurityFinding {
                severity: "LOW",
                category: "WEB",
                title: "Fichier de signalement de vulnérabilités RFC 9116 (security.txt) manquant".into(),
                recommendation: "Publier un fichier /.well-known/security.txt pour orienter les chercheurs de failles légitimes.".into(),
            });
        }

        if web_endpoints.dangerous_methods_found {
            findings.push(SecurityFinding {
                severity: "HIGH",
                category: "WEB",
                title: format!(
                    "Méthodes HTTP potentiellement dangereuses activées : {}",
                    web_endpoints.allowed_http_methods.join(", ")
                ),
                recommendation: "Désactiver TRACE, TRACK, PUT, DELETE au niveau de la configuration du serveur Web.".into(),
            });
        }
        findings
    }

    /// 7. Audit TLS.
    ///
    /// Unfinding si aucun certificat n'a pu être récupéré (443 fermé/filtré) :
    /// l'absence de service TLS n'est pas une faille.
    fn eval_tls(tls: &TlsAuditResult) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();
        let tls_service_present = tls.subject.is_some() || tls.issuer.is_some();
        if !tls_service_present {
            findings.push(SecurityFinding {
                severity: "INFO",
                category: "TLS",
                title: "Aucun service TLS accessible sur le port 443".into(),
                recommendation:
                    "Le port 443 est fermé ou filtré : aucun certificat à auditer sur cette cible."
                        .into(),
            });
        } else if !tls.is_valid {
            findings.push(SecurityFinding {
                severity: "CRITICAL",
                category: "TLS",
                title: "Chaîne de confiance du certificat TLS invalide ou compromise".into(),
                recommendation:
                    "Renouveler immédiatement le certificat auprès d'une autorité reconnue."
                        .into(),
            });
        }

        if tls.supports_tls10 || tls.supports_tls11 {
            findings.push(SecurityFinding {
                severity: "HIGH",
                category: "TLS",
                title: "Support des protocoles obsolètes TLS 1.0 / TLS 1.1 actif".into(),
                recommendation: "Désactiver TLS 1.0 et 1.1 dans la configuration SSL et n'autoriser que TLS 1.2 et TLS 1.3.".into(),
            });
        }

        // Expiration : la détection days_remaining est désormais fonctionnelle
        if let Some(days) = tls.days_remaining {
            if days <= 0 {
                findings.push(SecurityFinding {
                    severity: "CRITICAL",
                    category: "TLS",
                    title: format!("Certificat TLS EXPIRÉ depuis {} jour(s)", -days),
                    recommendation:
                        "Renouveler immédiatement le certificat : les navigateurs bloquent le site."
                            .into(),
                });
            } else if days < 15 {
                findings.push(SecurityFinding {
                    severity: "HIGH",
                    category: "TLS",
                    title: format!("Certificat TLS expirant dans {} jour(s)", days),
                    recommendation:
                        "Planifier le renouvellement automatique du certificat (ACME/Let's Encrypt)."
                            .into(),
                });
            } else if days < 30 {
                findings.push(SecurityFinding {
                    severity: "MEDIUM",
                    category: "TLS",
                    title: format!("Certificat TLS expirant dans {} jour(s)", days),
                    recommendation: "Vérifier la chaîne de renouvellement du certificat.".into(),
                });
            } else if days < 45 {
                findings.push(SecurityFinding {
                    severity: "LOW",
                    category: "TLS",
                    title: format!(
                        "Certificat TLS à renouveler dans {} jour(s) (échéance : {})",
                        days,
                        tls.valid_until.as_deref().unwrap_or("?")
                    ),
                    recommendation:
                        "Vérifier que le renouvellement automatique ACME est opérationnel avant l'échéance."
                            .into(),
                });
            }
        }

        if tls.is_self_signed {
            findings.push(SecurityFinding {
                severity: "HIGH",
                category: "TLS",
                title: "Certificat TLS auto-signé (confiance impossible côté clients)".into(),
                recommendation:
                    "Émettre un certificat via une autorité reconnue (Let's Encrypt / ACME)."
                        .into(),
            });
        }
        findings
    }

    /// 8. Localisation géographique de l'hébergement (informationnel uniquement).
    fn eval_geo(geo: &GeoComplianceResult, dns: &DnsAuditResult) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();
        let is_private_ip = geo
            .ip_address
            .parse::<std::net::IpAddr>()
            .ok()
            .map(|ip| match ip {
                std::net::IpAddr::V4(v4) => v4.is_private() || v4.is_loopback() || v4.is_link_local(),
                std::net::IpAddr::V6(v6) => v6.is_loopback() || v6.is_unicast_link_local(),
            })
            .unwrap_or(false);
        if !is_private_ip {
            if let Some(ref ptr) = dns.reverse_ptr {
                findings.push(SecurityFinding {
                    severity: "INFO",
                    category: "GEO",
                    title: format!("Reverse PTR (hébergeur réel de l'IP) : {}", ptr),
                    recommendation:
                        "Information d'hébergeur issue du PTR : utile pour délimiter le périmètre réseau du fournisseur."
                            .into(),
                });
            }
        }
        if is_private_ip {
            findings.push(SecurityFinding {
                severity: "INFO",
                category: "GEO",
                title: format!("IP privée (réseau interne) : {}", geo.ip_address),
                recommendation:
                    "Cible sur un réseau privé — géolocalisation et whois non applicables."
                        .into(),
            });
        } else if geo.is_canada {
            let region_info = geo.region.as_deref().unwrap_or("Canada");
            findings.push(SecurityFinding {
                severity: "INFO",
                category: "GEO",
                title: format!("Hébergement détecté au {} ({}, {})", region_info, geo.org_name.as_deref().unwrap_or(""), geo.city.as_deref().unwrap_or("")),
                recommendation: "Information géographique issue du whois — aucune action requise.".into(),
            });
        } else {
            findings.push(SecurityFinding {
                severity: "INFO",
                category: "GEO",
                title: format!("Hébergement hors Canada détecté : Pays '{}'", geo.country_code.as_deref().unwrap_or("Inconnu")),
                recommendation: "Information géographique issue du whois — vérifier la politique de transfert de données applicable à votre contexte.".into(),
            });
        }
        findings
    }

    /// 9. Sous-domaines : inventaire vivants/morts + IPs d'infrastructure.
    fn eval_subdomains(subdomains: &[SubdomainResult]) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();
        if !subdomains.is_empty() {
            let alive = subdomains.iter().filter(|s| s.is_alive).count();
            let dead: Vec<&str> = subdomains
                .iter()
                .filter(|s| !s.is_alive)
                .map(|s| s.subdomain.as_str())
                .take(4)
                .collect();
            let mut ips: Vec<&str> = Vec::new();
            for s in subdomains {
                if let Some(ip) = &s.ip_address {
                    for part in ip.split(',') {
                        let t = part.trim();
                        if !t.is_empty() && !ips.contains(&t) {
                            ips.push(t);
                        }
                    }
                }
            }
            let mut title = format!(
                "{} sous-domaines cartographiés : {} vivants, {} muets — infrastructure sur {} IP(s) ({})",
                subdomains.len(),
                alive,
                subdomains.len() - alive,
                ips.len(),
                ips.join(", ")
            );
            if !dead.is_empty() {
                title.push_str(&format!(" ; muets : {}", dead.join(", ")));
            }
            findings.push(SecurityFinding {
                severity: "INFO",
                category: "SUBDOMAIN",
                title,
                recommendation:
                    "Les hôtes muets (DNS résolu, service HTTP absent) restent des actifs à surveiller : takeover CNAME et réactivation à contrôler."
                        .into(),
            });
        }
        findings
    }

    /// 10. Vulnérabilités Applicatives (CVEs, SRI, Mixed Content, CORS).
    fn eval_vuln_audit(vuln_audit: &VulnAuditResult) -> Vec<SecurityFinding> {
        vuln_audit
            .findings
            .iter()
            .map(|v| SecurityFinding {
                severity: v.severity,
                category: v.category,
                title: v.title.clone(),
                recommendation: format!("{} (Réf: {})", v.fix, v.owasp),
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- Tests unitaires des sous-évaluateurs isolés (refactor evaluate) ---

    #[test]
    fn test_eval_tls_expiry_ladder() {
        // Présent + valide : ni CRITICAL chaîne, ni expiration
        let tls = TlsAuditResult {
            subject: Some("CN=example.com".into()),
            issuer: Some("Let's Encrypt".into()),
            is_valid: true,
            days_remaining: Some(90),
            ..Default::default()
        };
        let f = FindingsEngine::eval_tls(&tls);
        assert!(f.is_empty(), "certificat sain = aucun finding TLS, got {:?}", f);

        // Expiré depuis 3 jours : CRITICAL avec le titre exact du monolithe
        let tls = TlsAuditResult {
            subject: Some("CN=example.com".into()),
            is_valid: true,
            days_remaining: Some(-3),
            ..Default::default()
        };
        let f = FindingsEngine::eval_tls(&tls);
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].severity, "CRITICAL");
        assert_eq!(f[0].title, "Certificat TLS EXPIRÉ depuis 3 jour(s)");

        // 20 jours : MEDIUM (palier < 30)
        let tls = TlsAuditResult {
            subject: Some("CN=example.com".into()),
            is_valid: true,
            days_remaining: Some(20),
            ..Default::default()
        };
        let f = FindingsEngine::eval_tls(&tls);
        assert_eq!((f.len(), f[0].severity), (1, "MEDIUM"));

        // Aucun certificat récupéré : unfinding INFO, pas un CRITICAL
        let f = FindingsEngine::eval_tls(&TlsAuditResult::default());
        assert_eq!((f.len(), f[0].severity, f[0].category), (1, "INFO", "TLS"));
    }

    #[test]
    fn test_eval_ports_loopback_db_not_flagged() {
        // 5432 sur une cible loopback = INFO (service local), pas HIGH
        let ports = vec![PortScanResult {
            port: 5432,
            is_open: true,
            service_hint: "postgresql",
            banner: None,
        }];
        let f = FindingsEngine::eval_ports(&ports, "127.0.0.1");
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].severity, "INFO");
        assert!(f[0].title.contains("non exposé publiquement"));

        // Même port sur un domaine public = HIGH
        let f = FindingsEngine::eval_ports(&ports, "example.com");
        assert_eq!((f.len(), f[0].severity), (1, "HIGH"));

        // Bannière courte (<= 8 chars) ignorée ; Telnet = CRITICAL
        let ports = vec![
            PortScanResult { port: 80, is_open: true, service_hint: "http", banner: Some("ssh".into()) },
            PortScanResult { port: 23, is_open: true, service_hint: "telnet", banner: None },
        ];
        let f = FindingsEngine::eval_ports(&ports, "example.com");
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].severity, "CRITICAL");
        assert!(f[0].title.contains("Telnet"));
    }

    #[test]
    fn test_eval_dns_bare_ip_skips_all() {
        // Cible IP nue : tout le bloc DNS/email est sauté, quel que soit l'état
        // (réaliste : aucun audit DNS n'a lieu, dmarc_policy reste None)
        let dns = DnsAuditResult {
            domain: "192.0.2.10".into(),
            spf_found: false,
            mx_records: vec!["mail.example.com".into()],
            ..Default::default()
        };
        let f = FindingsEngine::eval_dns(&dns, true);
        assert!(f.is_empty(), "IP nue = zéro finding DNS, got {:?}", f);

        // Même état sur un domaine : findings dans l'ordre exact du monolithe
        let dns = DnsAuditResult {
            domain: "example.com".into(),
            dmarc_found: true,
            dmarc_policy: Some("none".into()),
            ..dns
        };
        let f = FindingsEngine::eval_dns(&dns, false);
        let got: Vec<_> = f.iter().map(|x| (x.severity, x.category)).collect();
        assert_eq!(
            got,
            vec![
                ("HIGH", "DNS"),   // SPF absent
                ("LOW", "DNS"),    // DMARC p=none
                ("LOW", "DNS"),    // DNSSEC absent
                ("INFO", "EMAIL"), // MX présents
                ("LOW", "DNS"),    // CAA absents
            ]
        );
    }

    #[test]
    fn test_eval_http_cookies_and_hsts_max_age() {
        // Pas de service HTTP : un seul unfinding INFO, cookies ignorés
        let http = HttpAuditResult {
            http_status: 0,
            cookies: vec![crate::modules::http::CookieAuditEntry {
                name: "sid".into(),
                secure: false,
                http_only: false,
                same_site: None,
            }],
            ..Default::default()
        };
        let f = FindingsEngine::eval_http(&http);
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].title, "Aucun serveur HTTP/HTTPS accessible en tête de cible");

        // Service présent : cookie non durci signalé + HSTS max-age trop court
        let http = HttpAuditResult {
            http_status: 200,
            hsts_present: true,
            hsts_value: Some("max-age=86400".into()),
            csp_present: true,
            csp_value: Some("script-src 'unsafe-inline'".into()),
            cookies: vec![crate::modules::http::CookieAuditEntry {
                name: "sid".into(),
                secure: true,
                http_only: false,
                same_site: None,
            }],
            ..Default::default()
        };
        let f = FindingsEngine::eval_http(&http);
        let titles: Vec<&str> = f.iter().map(|x| x.title.as_str()).collect();
        assert_eq!(
            titles,
            vec![
                "Pas de redirection forcée vers HTTPS",
                "CSP présente mais contournable : directive 'unsafe-inline' active",
                "En-tête X-Frame-Options manquant",
                "HSTS max-age trop court (86400 s < 6 mois recommandés)",
                "Cookie 'sid' émis sans attribut(s) de sécurité : HttpOnly, SameSite",
            ],
            "ordre d'émission identique au monolithe"
        );
    }
}
