use regex::Regex;
use std::process::Command;

#[allow(dead_code)]
#[derive(Debug, Clone)]
#[derive(serde::Serialize)]
pub struct VulnFinding {
    pub id: String,
    pub severity: &'static str, // CRITICAL, HIGH, MEDIUM, LOW, INFO
    pub category: &'static str, // CVE, SRI, MIXED_CONTENT, CORS, SECRETS
    pub title: String,
    pub description: String,
    pub fix: String,
    pub owasp: &'static str,
}

#[allow(dead_code)]
#[derive(Debug, Clone, Default)]
#[derive(serde::Serialize)]
pub struct VulnAuditResult {
    pub html_retrieved: bool,
    pub cdn_scripts_count: usize,
    pub missing_sri_count: usize,
    pub mixed_content_count: usize,
    pub cors_misconfigured: bool,
    pub detected_libraries: Vec<String>,
    pub findings: Vec<VulnFinding>,
}

pub struct VulnAuditor;

impl VulnAuditor {
    /// Analyse statique et dynamique du contenu Web rendu et des configurations d'origine
    pub fn audit(domain: &str) -> VulnAuditResult {
        let mut res = VulnAuditResult {
            html_retrieved: false,
            cdn_scripts_count: 0,
            missing_sri_count: 0,
            mixed_content_count: 0,
            cors_misconfigured: false,
            detected_libraries: Vec::new(),
            findings: Vec::new(),
        };

        let target_url = format!("https://{}/", domain);

        // 1. Récupération du HTML source
        let mut html_content = String::new();
        if let Ok(output) = Command::new("curl")
            .args(["-s", "-L", "--max-time", "5", &target_url])
            .output()
        {
            if output.status.success() {
                html_content = String::from_utf8_lossy(&output.stdout).to_string();
                if !html_content.trim().is_empty() {
                    res.html_retrieved = true;
                }
            }
        }

        if res.html_retrieved {
            // A. Détection des bibliothèques JS obsolètes et vulnérables
            Self::check_libraries(&html_content, &mut res);

            // B. Vérification de Subresource Integrity (SRI)
            Self::check_sri(&html_content, &mut res);

            // C. Vérification de Contenu Mixte (Mixed Content)
            Self::check_mixed_content(&html_content, &mut res);

            // D. Fuites de traces de débogage ou commentaires sensibles
            Self::check_sensitive_patterns(&html_content, &mut res);
        }

        // E. Audit CORS (Test avec Origin externe)
        Self::check_cors(domain, &mut res);

        res
    }

    fn check_libraries(html: &str, res: &mut VulnAuditResult) {
        let lower = html.to_lowercase();

        // Détection jQuery : ancrée aux attributs src/href d'une URL (évite les faux
        // positifs sur du texte/commentaires) + version complète majeur.mineur[.patch]
        let jq_re = Regex::new(
            r#"(?:src|href)\s*=\s*["'][^"']*jquery[/-]?(\d+)\.(\d+)(?:\.(\d+))?["']"#,
        )
        .unwrap();
        if let Some(caps) = jq_re.captures(&lower) {
            let major: u32 = caps[1].parse().unwrap_or(u32::MAX);
            let minor: u32 = caps[2].parse().unwrap_or(u32::MAX);
            if (major, minor) < (3, 5) {
                res.detected_libraries.push(format!("jQuery {}.{} < 3.5.0", major, minor));
                res.findings.push(VulnFinding {
                    id: "cve-jquery-xss".into(),
                    severity: "HIGH",
                    category: "CVE",
                    title: format!("Bibliothèque jQuery vulnérable aux failles XSS (CVE-2020-11022 / CVE-2020-11023) — détectée {}.{}", major, minor),
                    description: "Une version de jQuery inférieure à 3.5.0 a été détectée. Ces versions transforment le HTML de manière non sécurisée dans jQuery.htmlPrefilter.".into(),
                    fix: "Mettre à jour jQuery vers la version 3.5.0 ou supérieure, ou vers la branche moderne 3.7+.".into(),
                    owasp: "A06:2021 - Vulnerable and Outdated Components",
                });
            } else {
                res.detected_libraries.push(format!("jQuery {}.{}", major, minor));
            }
        }

        // Détection Bootstrap 3.x (version numérique requise dans un contexte de ressource)
        let bootstrap3_re = Regex::new(r"bootstrap[/-]3\.\d").unwrap();
        if bootstrap3_re.is_match(&lower) {
            res.detected_libraries.push("Bootstrap v3".into());
            res.findings.push(VulnFinding {
                id: "cve-bootstrap-xss".into(),
                severity: "MEDIUM",
                category: "CVE",
                title: "Bootstrap 3.x obsolète et non maintenu (Failles XSS CVE-2019-8331)".into(),
                description: "Bootstrap 3 contient des failles Cross-Site Scripting dans les plugins data-target/tooltip.".into(),
                fix: "Migrer vers Bootstrap 5 ou une alternative moderne sans dépendance jQuery.".into(),
                owasp: "A06:2021 - Vulnerable and Outdated Components",
            });
        }
    }

    fn check_sri(html: &str, res: &mut VulnAuditResult) {
        let cdns = [
            "cdnjs.cloudflare.com",
            "cdn.jsdelivr.net",
            "unpkg.com",
            "stackpath.bootstrapcdn.com",
            "code.jquery.com",
        ];

        // Regex stricte : <script src="https://cdn..."> ou <link href="https://cdn...">
        // Capture le tag complet pour vérifier la présence d'integrity= dans le même tag.
        let tag_re = Regex::new(
            r#"<(?:script|link)\b[^>]*?\s(?:src|href)\s*=\s*["'](https?://[^"']+)["'][^>]*>"#
        ).unwrap();

        for cap in tag_re.captures_iter(html) {
            let url = cap[1].to_lowercase();
            let tag = &cap[0];
            for cdn in &cdns {
                if url.contains(cdn) {
                    res.cdn_scripts_count += 1;
                    if !tag.contains("integrity=") {
                        res.missing_sri_count += 1;
                    }
                    break;
                }
            }
        }

        if res.missing_sri_count > 0 {
            res.findings.push(VulnFinding {
                id: "vuln-sri-missing".into(),
                severity: "MEDIUM",
                category: "SRI",
                title: format!("{} script(s) externe(s) CDN sans attribut Subresource Integrity (SRI)", res.missing_sri_count),
                description: "Les ressources chargées depuis un CDN tiers ne possèdent pas l'attribut d'intégrité cryptographique. Si le CDN est compromis, un attaquant pourrait injecter du code malveillant.".into(),
                fix: "Ajouter l'attribut integrity=\"sha384-...\" et crossorigin=\"anonymous\" sur toutes les balises <script> et <link> externes.".into(),
                owasp: "A08:2021 - Software and Data Integrity Failures",
            });
        }
    }

    fn check_mixed_content(html: &str, res: &mut VulnAuditResult) {
        // Mixed content : occurrences réelles (pas des lignes), guillemets simples inclus
        let src_http_re = Regex::new(r#"src\s*=\s*["']http://[^"']+"#).unwrap();
        let css_http_re = Regex::new(r#"href\s*=\s*["']http://[^"']*\.(?:css|js|mjs)["']"#).unwrap();
        res.mixed_content_count = src_http_re.find_iter(html).count() + css_http_re.find_iter(html).count();

        if res.mixed_content_count > 0 {
            res.findings.push(VulnFinding {
                id: "vuln-mixed-content".into(),
                severity: "HIGH",
                category: "MIXED_CONTENT",
                title: format!("{} ressource(s) chargée(s) en HTTP non sécurisé (Mixed Content)", res.mixed_content_count),
                description: "La page HTTPS charge des ressources en clair HTTP. Ces requêtes peuvent être interceptées ou bloquées par les navigateurs récents.".into(),
                fix: "Migrer toutes les URLs de ressources vers 'https://' ou des chemins relatifs.".into(),
                owasp: "A05:2021 - Security Misconfiguration",
            });
        }
    }

    fn check_sensitive_patterns(html: &str, res: &mut VulnAuditResult) {
        let lower = html.to_lowercase();

        // Stack trace
        if lower.contains("traceback (most recent call last):")
            || lower.contains("exception in thread")
            || lower.contains("stack trace:")
            || lower.contains("fatal error: uncaught exception")
        {
            res.findings.push(VulnFinding {
                id: "vuln-stack-trace".into(),
                severity: "HIGH",
                category: "SECRETS",
                title: "Fuite de Stack Trace ou d'erreur système dans le HTML".into(),
                description: "Le code HTML rendu affiche une trace de débogage révélant des chemins internes, modules ou versions de serveur.".into(),
                fix: "Désactiver le mode DEBUG sur le serveur d'application et configurer des pages d'erreur génériques.".into(),
                owasp: "A05:2021 - Security Misconfiguration",
            });
        }

        // Divulgation de secrets / clés API dans le code source public (touche pro)
        let secret_patterns: &[(&str, &str, &str)] = &[
            (r"AIza[0-9A-Za-z_\-]{35}", "Clé API Google exposée dans la page", "HIGH"),
            (r"sk_live_[0-9a-zA-Z]{20,}", "Clé secrète Stripe (mode LIVE) exposée", "CRITICAL"),
            (r"gh[pousr]_[0-9A-Za-z]{20,}", "Token GitHub (PAT) exposé", "HIGH"),
            (r"AKIA[0-9A-Z]{16}", "Access Key ID AWS exposée", "HIGH"),
            (r"xox[baprs]-[0-9A-Za-z\-]{10,}", "Token Slack exposé", "HIGH"),
            (r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----", "Clé privée embarquée dans la page", "CRITICAL"),
        ];
        for (pat, title, sev) in secret_patterns {
            if let Ok(re) = Regex::new(pat) {
                if re.is_match(html) {
                    res.findings.push(VulnFinding {
                        id: "vuln-secret-exposure".into(),
                        severity: match *sev {
                            "CRITICAL" => "CRITICAL",
                            "HIGH" => "HIGH",
                            _ => "MEDIUM",
                        },
                        category: "SECRETS",
                        title: (*title).to_string(),
                        description: "Un motif de secret ou de clé d'API a été détecté dans le contenu HTML public.".into(),
                        fix: "Retirer immédiatement le secret du code livré, le révoquer, et le gérer via un gestionnaire de secrets.".into(),
                        owasp: "A02:2021 - Cryptographic Failures",
                    });
                }
            }
        }
    }

    fn check_cors(domain: &str, res: &mut VulnAuditResult) {
        let target_url = format!("https://{}/", domain);
        if let Ok(out) = Command::new("curl")
            .args([
                "-s",
                "-I",
                "-H",
                "Origin: https://evil.veridy-test.com",
                "--max-time",
                "4",
                &target_url,
            ])
            .output()
        {
            let s = String::from_utf8_lossy(&out.stdout);
            let mut allow_origin = None;
            let mut allow_credentials = false;

            for line in s.lines() {
                let lower = line.to_lowercase();
                if lower.starts_with("access-control-allow-origin:") {
                    allow_origin =
                        Some(
                        line.split_once(':')
                            .map(|x| x.1)
                            .unwrap_or("")
                            .trim()
                            .to_string(),
                    );
                } else if lower.starts_with("access-control-allow-credentials:")
                    && lower.contains("true")
                {
                    allow_credentials = true;
                }
            }

            if let Some(ref origin) = allow_origin {
                if origin == "*" && allow_credentials {
                    res.cors_misconfigured = true;
                    res.findings.push(VulnFinding {
                        id: "vuln-cors-wildcard-creds".into(),
                        severity: "CRITICAL",
                        category: "CORS",
                        title: "Configuration CORS critique (Wildcard avec Credentials autorisés)".into(),
                        description: "Le serveur autorise n'importe quelle origine externe avec transmission des cookies et sessions privées.".into(),
                        fix: "Restreindre Access-Control-Allow-Origin aux domaines légitimes autorisés.".into(),
                        owasp: "A01:2021 - Broken Access Control",
                    });
                } else if origin.contains("evil.veridy-test.com") {
                    res.cors_misconfigured = true;
                    res.findings.push(VulnFinding {
                        id: "vuln-cors-origin-reflection".into(),
                        severity: "HIGH",
                        category: "CORS",
                        title: "Configuration CORS permissive (Reflet dynamique de l'origine non vérifiée)".into(),
                        description: "Le serveur reflète aveuglément l'en-tête Origin envoyé par le client sans validation sur liste blanche.".into(),
                        fix: "Valider rigoureusement l'origine reçue contre une liste blanche explicite.".into(),
                        owasp: "A01:2021 - Broken Access Control",
                    });
                }
            }
        }
    }
}
