//! Réécriture serde_json du parseur WhatWeb : plugin + VERSION par techno.
//!
//! Le parseur historique à la main (find/brace-counting) ne retenait que les
//! noms des plugins whatweb — le champ `"version":["2.4.7"]` de chaque plugin
//! était jeté, donc aucun verdict « version obsolète » n'était possible.
//! Ce module capture désormais nom + version par composant et compare chaque
//! branche (majeur.mineur) à une base de seuils EOL pour émettre un finding
//! dédié quand la branche n'est plus maintenue.

use crate::modules::findings::SecurityFinding;
use std::fs;
use std::time::Instant;

#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct TechStackResult {
    pub success: bool,
    pub elapsed_seconds: f32,
    pub http_status: u16,
    /// En-tête Server complet, ex. "Apache/2.4.7 (Ubuntu)"
    pub server: Option<String>,
    pub emails_exposed: Vec<String>,
    pub detected_technologies: Vec<String>,
    /// Composants versionnés : (nom, version), dédupliqués.
    pub versioned: Vec<TechComponent>,
    /// Technos tierces détectées par marqueurs HTML/JS (GTM, OneTrust, ...).
    pub js_third_party: Vec<String>,
    pub raw_output: String,
    pub summary: String,
}

/// Un composant technologique identifié avec sa version.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct TechComponent {
    pub name: String,
    pub version: String,
}

/// Verdict EOL pour un composant dont la branche n'est plus maintenue.
#[derive(Debug, Clone, PartialEq)]
pub struct VersionVerdict {
    pub name: String,
    pub detected: String,
    /// Branche minimale maintenue, ex. "2.4"
    pub branch_min: String,
    pub recommendation: String,
}

pub struct TechStackAuditor;

impl TechStackAuditor {
    pub fn audit(target: &str, custom_ports: &[u16]) -> TechStackResult {
        let start = Instant::now();
        // Schéma détecté : les box HTB servent souvent du HTTP pur sur un port
        // exotique — l ancien https:// forcé rendait l outil aveugle (0 findings).
        let hostport = crate::utils::host_with_port(target, custom_ports);
        let scheme_order = crate::modules::scheme_detect::detect_scheme(&hostport).order;
        let target_url = format!("{}://{}", scheme_order[0], hostport);
        let pid = std::process::id();
        let tmp_output = format!(
            "/tmp/whatweb_{}_{}.json",
            crate::utils::sanitize_target(target),
            pid
        );
        let log_arg = format!("--log-json={tmp_output}");

        let output = match crate::utils::run_tool("whatweb", &[&log_arg, &target_url], 60) {
            Some(o) => o,
            None => {
                return TechStackResult {
                    success: false,
                    elapsed_seconds: start.elapsed().as_secs_f32(),
                    http_status: 0,
                    server: None,
                    emails_exposed: Vec::new(),
                    detected_technologies: Vec::new(),
                    versioned: Vec::new(),
                    js_third_party: Vec::new(),
                    raw_output: "whatweb : timeout (60s) ou binaire introuvable".into(),
                    summary: "WhatWeb interrompu : deadline dépassée".into(),
                };
            }
        };

        let elapsed = start.elapsed().as_secs_f32();
        let raw_json = fs::read_to_string(&tmp_output)
            .unwrap_or_else(|_| String::from_utf8_lossy(&output.stdout).to_string());
        let _ = fs::remove_file(&tmp_output);

        let (http_status, server, emails, techs, versioned) = Self::parse_json(&raw_json);
        let js_third_party = {
            let hostport2 = crate::utils::host_with_port(target, custom_ports);
            let mut found = Vec::new();
            for scheme in ["https", "http"] {
                let url = format!("{}://{}/", scheme, hostport2);
                if let Some(o) =
                    crate::utils::run_tool("curl", &["-s", "-L", "--max-time", "5", &url], 30)
                {
                    let html = String::from_utf8_lossy(&o.stdout).to_string();
                    if html.trim().is_empty() {
                        continue;
                    }
                    found = Self::sweep_js_markers(&html);
                    break;
                }
            }
            found
        };
        let techs = merge_unique(techs, js_third_party.to_vec());
        let summary = format!(
            "WhatWeb a identifié {} composant(s)/technologie(s) dont {} versionné(s), {} techno(s) JS tierce(s), et {} adresse(s) email en {:.2}s",
            techs.len(),
            versioned.len(),
            js_third_party.len(),
            emails.len(),
            elapsed
        );

        TechStackResult {
            success: output.status.success(),
            elapsed_seconds: elapsed,
            http_status,
            server,
            emails_exposed: emails,
            detected_technologies: techs,
            versioned,
            js_third_party,
            raw_output: raw_json,
            summary,
        }
    }

    /// Signatures technos tierces : (nom affiché, marqueurs HTML/JS).
    /// Marqueur = sous-chaîne case-insensitive présente dans la source ;
    /// un seul marqueur suffit (OR). Les scripts chargés au runtime laissent
    /// leur marqueur de chargement dans la source (gtm.js?id=, otSDKStub.js).
    pub(crate) const JS_THIRD_PARTY_MARKERS: &[(&str, &[&str])] = &[
        ("Google Tag Manager", &["googletagmanager.com/gtm.js", "googletagmanager.com/ns.html"]),
        ("Google Analytics (gtag)", &["gtag/js?id=G-", "googletagmanager.com/gtag/js"]),
        ("reCAPTCHA", &["google.com/recaptcha/api.js", "grecaptcha.execute"]),
        ("OneTrust CMP", &["cookielaw.org/scripttemplates/otSDKStub.js", "data-domain-script"]),
        ("Criteo", &["criteo.com", "criteo.net", "criteo-ads.js", "CRITEO_RETAILER_VISITOR_COOKIE"]),
        ("DialogInsight", &["cdn.dialoginsight.com"]),
        ("DoubleClick / Google Ad Manager", &["doubleclick.net", "googlesyndication.com", "securepubads.g.doubleclick.net"]),
        // Les URLs échappées \/\/ (blocs JS/JSON) doivent matcher aussi :
        // le lowercasing ne retire pas les backslashes, on teste les deux formes.
        ("Google Maps", &["maps.googleapis.com/maps", "maps.googleapis.com\\/maps", "maps.google.com/maps"]),
        ("Plausible Analytics", &["plausible.io/js", "plausible.io/api/event"]),
        ("Google Fonts", &["fonts.googleapis.com/css", "fonts.googleapis.com\\/css", "fonts.gstatic.com"]),
        ("Cloudflare Turnstile", &["challenges.cloudflare.com/turnstile"]),
        ("hCaptcha", &["hcaptcha.com/1/api.js"]),
        ("Stripe", &["js.stripe.com"]),
        ("PayPal", &["paypal.com/sdk/js", "paypalobjects.com"]),
        ("Facebook Pixel", &["connect.facebook.net", "fbevents.js"]),
        ("Hotjar", &["static.hotjar.com"]),
        ("Sentry", &["browser.sentry-cdn.com", "js.sentry-cdn.com"]),
        ("Segment", &["cdn.segment.com"]),
        ("TikTok Pixel", &["analytics.tiktok.com"]),
        ("Microsoft Clarity", &["clarity.ms"]),
        ("jQuery", &["jquery.min.js", "jquery.js", "jquery-"]),
        ("React", &["react.production.min.js", "react-dom", "_reactRoot"]),
        ("Vue.js", &["vue.runtime", "vue.min.js", "vue.global"]),
        ("Angular", &["ng-version", "angular.min.js"]),
        ("Bootstrap", &["bootstrap.min.css", "bootstrap.bundle.min.js"]),
    ];

    /// Cherche les marqueurs dans le HTML ; retourne les noms détectés.
    pub(crate) fn sweep_js_markers(html: &str) -> Vec<String> {
        let lower = html.to_lowercase();
        let mut out = Vec::new();
        for (name, markers) in Self::JS_THIRD_PARTY_MARKERS {
            if markers
                .iter()
                .any(|m| lower.contains(&m.to_lowercase()))
            {
                out.push(name.to_string());
            }
        }
        out
    }

    /// Parse la sortie JSON de whatweb (`--log-json`) avec serde_json.
    ///
    /// whatweb émet un document JSON par cible ; plusieurs cibles (ou un
    /// repli stdout) concatènent des tableaux adjacents `[{...}]\n[{...}]` —
    /// on fusionne ces tableaux avant décodage (comportement observé en live
    /// sur whatweb 0.6.4, 2026-09-29).
    ///
    /// Retour : (http_status, Server, emails, technos, composants versionnés)
    pub(crate) fn parse_json(
        json: &str,
    ) -> (
        u16,
        Option<String>,
        Vec<String>,
        Vec<String>,
        Vec<TechComponent>,
    ) {
        let mut server = None;
        let mut emails = Vec::new();
        let mut techs = Vec::new();
        let mut versioned = Vec::new();
        let mut http_status = 0u16;
        let mut seen = std::collections::BTreeSet::new();

        // Normalisation des tableaux concaténés → un seul document.
        let normalized = json.trim().replace("]\n[", ",").replace("][", ",");
        let root: serde_json::Value = match serde_json::from_str(&normalized) {
            Ok(v) => v,
            // Dégradation gracieuse : JSON invalide → zéro invention.
            Err(_) => return (http_status, server, emails, techs, versioned),
        };

        // Racine tableau (whatweb standard) ou objet unique (repli).
        let targets: Vec<&serde_json::Value> = match &root {
            serde_json::Value::Array(arr) => arr.iter().collect(),
            serde_json::Value::Object(_) => vec![&root],
            _ => Vec::new(),
        };

        for target in targets {
            if http_status == 0 {
                if let Some(s) = target.get("http_status").and_then(|v| v.as_u64()) {
                    http_status = s as u16;
                }
            }
            let Some(plugins) = target.get("plugins").and_then(|p| p.as_object()) else {
                continue;
            };
            for (name, fields) in plugins {
                // Nom nettoyé : whatweb rapporte parfois "Plugin [target]".
                let clean_name = name.split('[').next().unwrap_or(name).trim().to_string();
                if clean_name.is_empty() {
                    continue;
                }
                if seen.insert(clean_name.clone()) {
                    techs.push(clean_name.clone());
                }

                // Server complet depuis HTTPServer.string
                if clean_name == "HTTPServer" {
                    if let Some(s) = fields.get("string").and_then(|v| v.as_array()) {
                        if let Some(first) = s
                            .iter()
                            .filter_map(|x| x.as_str())
                            .find(|x| !x.trim().is_empty())
                        {
                            server = Some(first.to_string());
                        }
                    }
                }

                // Emails depuis Email.string
                if clean_name == "Email" {
                    if let Some(arr) = fields.get("string").and_then(|v| v.as_array()) {
                        for e in arr.iter().filter_map(|x| x.as_str()) {
                            if e.contains('@') && !emails.iter().any(|x| x == e) {
                                emails.push(e.to_string());
                            }
                        }
                    }
                }

                // Bannière Server -> composants produit/version dérivés.
                // "Apache/2.2.15 (Unix)" -> ("Apache", "2.2.15") : le plugin
                // whatweb s appelle "HTTPServer" (aucune clé de seuil) mais le
                // produit réel doit être comparé aux seuils EOL.
                if clean_name == "HTTPServer" {
                    if let Some(s) = server.as_deref() {
                        for (product, version) in products_from_server_banner(s) {
                            if !versioned
                                .iter()
                                .any(|c| c.name == product && c.version == version)
                            {
                                versioned.push(TechComponent {
                                    name: product,
                                    version,
                                });
                            }
                        }
                    }
                }

                // VERSION : champ version[] prioritaire, sinon string[]
                // qui ressemble à une version ("nginx/1.22.1", "2.4.7").
                if let Some(v) = extract_version(fields) {
                    if !versioned
                        .iter()
                        .any(|c| c.name == clean_name && c.version == v)
                    {
                        versioned.push(TechComponent {
                            name: clean_name.clone(),
                            version: v,
                        });
                    }
                }
            }
        }

        (http_status, server, emails, techs, versioned)
    }

    /// Verdicts « version obsolète » : la branche (majeur.mineur) de chaque
    /// composant versionné est comparée au seuil minimal maintenu de la base
    /// THRESHOLDS. Branche inférieure au seuil → finding EOL. Composant sans
    /// seuil connu ou version non numérique → silence (zéro invention).
    pub(crate) fn version_verdicts(versioned: &[TechComponent]) -> Vec<VersionVerdict> {
        versioned
            .iter()
            .filter_map(|c| {
                let pv = parse_version(&c.version)?;
                let branch = [pv[0], pv[1]];
                let lower = c.name.to_lowercase();
                let (_, threshold) = THRESHOLDS
                    .iter()
                    .find(|(k, _)| lower.contains(k))?;
                if branch >= *threshold {
                    return None; // branche maintenue (patch-lag ≠ EOL)
                }
                let branch_min = format!("{}.{}", threshold[0], threshold[1]);
                let branch_cur = format!("{}.{}", branch[0], branch[1]);
                let recommendation = format!(
                    "Mettre à jour {} vers la branche maintenue {}.x ou supérieure (branche {} détectée).",
                    c.name, branch_min, branch_cur
                );
                Some(VersionVerdict {
                    name: c.name.clone(),
                    detected: c.version.clone(),
                    branch_min,
                    recommendation,
                })
            })
            .collect()
    }

    pub fn to_findings(&self, res: &TechStackResult) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();

        if !res.emails_exposed.is_empty() {
            findings.push(SecurityFinding {
                severity: "LOW",
                category: "WEB",
                title: format!("WhatWeb - {} adresse(s) de courriel publique(s) exposée(s) dans le code source : {}", res.emails_exposed.len(), res.emails_exposed.join(", ")),
                recommendation: "Protéger les adresses courriel contre le scraping automatisé (obfuscation HTML, formulaires de contact) pour prévenir le spam et le spear-phishing.".to_string(),
            });
        }

        if !res.detected_technologies.is_empty() {
            findings.push(SecurityFinding {
                severity: "INFO",
                category: "WEB",
                title: format!("WhatWeb - Inventaire d'empreinte technologique : {}", res.detected_technologies.join(", ")),
                recommendation: "Maintenir à jour l'inventaire des composants logiciels et des dépendances externes.".to_string(),
            });
        }

        if res.http_status >= 400 {
            findings.push(SecurityFinding {
                severity: "MEDIUM",
                category: "WEB",
                title: format!("WhatWeb - Réponse d'erreur HTTP inattendue : Code {}", res.http_status),
                recommendation: "Vérifier la configuration du serveur web et la disponibilité du site pour les requêtes publiques.".to_string(),
            });
        }

        // Verdicts « version obsolète » — un finding par composant EOL.
        for v in Self::version_verdicts(&res.versioned) {
            findings.push(SecurityFinding {
                severity: "MEDIUM",
                category: "WEB",
                title: format!(
                    "Composant obsolète - {} {} (branche < {}.x n'est plus maintenue)",
                    v.name, v.detected, v.branch_min
                ),
                recommendation: v.recommendation.clone(),
            });
        }

        findings
    }
}

/// Extrait la version d'un plugin whatweb.
///
/// 1. Champ canonique `version[]` : valeur nue ("2.4.7", "Universal" rejeté).
/// 2. Champ `string[]` : uniquement le motif produit/version ("nginx/1.22.1",
///    "Apache/2.4.7 (Ubuntu)") — un nombre isolé comme "max-age=31536000"
///    n'est PAS une version et ne doit jamais finir dans audit_tech.
fn extract_version(fields: &serde_json::Value) -> Option<String> {
    if let Some(arr) = fields.get("version").and_then(|v| v.as_array()) {
        for v in arr.iter().filter_map(|x| x.as_str()) {
            let norm = normalize_version_token(v);
            if looks_like_version(&norm) {
                return Some(norm);
            }
        }
    }
    if let Some(arr) = fields.get("string").and_then(|v| v.as_array()) {
        for v in arr.iter().filter_map(|x| x.as_str()) {
            if !v.contains('/') {
                continue; // nombre isolé (max-age, UA-…) ≠ version produit
            }
            let norm = normalize_version_token(v);
            if looks_like_version(&norm) {
                return Some(norm);
            }
        }
    }
    None
}

/// "nginx/1.22.1" → "1.22.1" ; "Apache/2.4.7 (Ubuntu)" → "2.4.7".
fn normalize_version_token(s: &str) -> String {
    let s = s.trim();
    // Dernier token numérique du segment après '/' (ou du entier si pas de '/').
    let base = s.rsplit('/').next().unwrap_or(s);
    let mut best: Option<&str> = None;
    for token in base.split(|c: char| !c.is_ascii_digit() && c != '.') {
        if looks_like_version(token) {
            best = Some(token); // dernier token numérique gagne
        }
    }
    best.unwrap_or(s).trim_matches('.').to_string()
}


/// Fusionne deux listes sans doublons (order-preserving).
fn merge_unique(mut base: Vec<String>, extra: Vec<String>) -> Vec<String> {
    for e in extra {
        if !base.contains(&e) {
            base.push(e);
        }
    }
    base
}

/// Décompose une bannière Server en composants produit/version.
/// "Apache/2.2.15 (Unix)" -> [("Apache", "2.2.15")]
/// "BaseHTTP/0.6 Python/3.14.7" -> [("BaseHTTP", "0.6"), ("Python", "3.14.7")]
fn products_from_server_banner(banner: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for token in banner.split_whitespace() {
        let Some((left, right)) = token.split_once(char::from(0x2F)) else {
            continue;
        };
        let product = left.trim();
        if product.is_empty()
            || !product.chars().next().is_some_and(|c| c.is_ascii_alphabetic())
        {
            continue;
        }
        let version = normalize_version_token(right);
        if looks_like_version(&version) {
            let product = product.to_string();
            if !out.iter().any(|(p, _): &(String, String)| *p == product) {
                out.push((product, version));
            }
        }
    }
    out
}

/// Un token ressemble à une version s'il commence par un chiffre et contient
/// au moins un point OU au moins deux chiffres ("3", "2.4.7", "1.22").
/// "Universal", "RESERVED" etc. sont exclus d'office.
fn looks_like_version(s: &str) -> bool {
    let t = s.trim().trim_start_matches(['v', 'V']);
    let mut chars = t.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    if !first.is_ascii_digit() {
        return false;
    }
    let rest: String = chars.collect();
    rest.contains('.') || rest.chars().filter(|c| c.is_ascii_digit()).count() >= 1
}

/// "1.22.1" → [1, 22, 1] ; suffixes ignorés ("7.4.33-1" → 7.4.33).
/// Exige au moins un composant numérique ; "3" → [3, 0, 0].
fn parse_version(v: &str) -> Option<[u32; 3]> {
    let t = v.trim().trim_start_matches(['v', 'V']);
    let mut parts = [0u32; 3];
    let mut filled = false;
    for (i, part) in t.split('.').enumerate() {
        if i > 2 {
            break;
        }
        let digits: String = part.chars().take_while(|c| c.is_ascii_digit()).take(4).collect();
        if digits.is_empty() {
            // Segment non numérique ("2.4.x-beta") → on arrête net.
            break;
        }
        parts[i] = digits.parse().ok()?;
        filled = true;
    }
    if filled {
        Some(parts)
    } else {
        None
    }
}

// -----------------------------------------------------------------------------
// Base de seuils EOL — branche minimale maintenue par composant (majeur,mineur).
// La correspondance est « contains » insensible à la casse sur le nom du plugin
// whatweb ("Nginx" ↔ "nginx"). Un composant sans entrée → aucun verdict.
// -----------------------------------------------------------------------------

pub(crate) const THRESHOLDS: &[(&str, [u32; 2])] = &[
    // Serveurs web
    ("apache", [2, 4]),
    ("nginx", [1, 24]),
    ("litespeed", [6, 0]),
    ("iis", [10, 0]),
    ("lighttpd", [1, 4]),
    ("varnish", [6, 0]),
    ("squid", [5, 0]),
    ("caddy", [2, 0]),
    // Langages & runtimes
    ("php", [8, 2]),
    ("python", [3, 9]),
    ("ruby", [3, 2]),
    ("perl", [5, 32]),
    ("java", [11, 0]),
    ("openssl", [1, 1]),
    ("asp.net", [4, 8]),
    ("asp", [4, 8]),
    ("node", [18, 0]),
    // CMS
    ("wordpress", [6, 0]),
    ("drupal", [10, 0]),
    ("joomla", [4, 0]),
    ("spip", [4, 0]),
    ("magento", [2, 4]),
    ("shopify", [99, 0]),   // SaaS : jamais de verdict version
    ("wix", [99, 0]),
    ("squarespace", [99, 0]),
    // Bases de données
    ("mysql", [8, 0]),
    ("mariadb", [10, 11]),
    ("postgresql", [13, 0]),
    ("redis", [6, 0]),
    ("mongodb", [6, 0]),
    // Frameworks JS/CSS
    ("jquery", [3, 5]),
    ("bootstrap", [4, 0]),
    ("react", [17, 0]),
    ("angular", [12, 0]),
    ("vue", [2, 7]),
    ("next.js", [13, 0]),
    ("webpack", [5, 0]),
    ("font-awesome", [6, 0]),
    ("font awesome", [6, 0]),
    // Frameworks backend
    ("laravel", [10, 0]),
    ("rails", [6, 1]),
    ("django", [3, 2]),
    ("express", [4, 0]),
    ("tomcat", [9, 0]),
    ("jetty", [9, 0]),
    // Services exposés
    ("openssh", [9, 0]),
    ("proftpd", [1, 3]),
    ("vsftpd", [3, 0]),
    ("cpanel", [11, 0]),
    ("plesk", [18, 0]),
    ("sentry", [21, 0]),
];

#[cfg(test)]
mod tests {
    use super::*;

    /// Sortie RÉELLE de whatweb 0.6.4 captée en live sur scanme.nmap.org
    /// (2026-09-29) — non-regression : le parseur doit survivre à la vraie
    /// forme, pas à un JSON synthétique.
    const LIVE_OUTPUT: &str = r#"[
{
  "target": "http://scanme.nmap.org",
  "http_status": 200,
  "plugins": {
    "Apache": {"version": ["2.4.7"]},
    "Country": {"string": ["RESERVED"], "module": ["ZZ"]},
    "Google-Analytics": {"version": ["Universal"], "account": ["UA-11009417-1"]},
    "HTML5": {},
    "HTTPServer": {"os": ["Ubuntu Linux"], "string": ["Apache/2.4.7 (Ubuntu)"]},
    "IP": {"string": ["45.33.38.153"]},
    "Script": {},
    "Title": {"string": ["Go ahead and ScanMe!"]}
  }
}
]"#;

    #[test]
    fn test_parse_versioned_components_live_shape() {
        let (status, server, _emails, techs, versioned) = TechStackAuditor::parse_json(LIVE_OUTPUT);
        assert_eq!(status, 200);
        assert_eq!(server.as_deref(), Some("Apache/2.4.7 (Ubuntu)"));
        assert!(techs.contains(&"Apache".to_string()));
        let apache = versioned
            .iter()
            .find(|c| c.name == "Apache")
            .expect("Apache doit être versionné");
        assert_eq!(apache.version, "2.4.7");
        // "Universal" n'est pas numérique → jamais versionné, jamais comparé
        assert!(!versioned.iter().any(|c| c.name == "Google-Analytics"));
        // "RESERVED" (Country) et "Ubuntu Linux" (os) → non versionnés
        assert!(!versioned.iter().any(|c| c.name == "Country"));
    }

    #[test]
    fn test_parse_multiple_concatenated_documents() {
        let two = format!(
            "{LIVE_OUTPUT}\n{}",
            LIVE_OUTPUT.replace("scanme.nmap.org", "other.target")
        );
        let (_s, _sv, _e, techs, versioned) = TechStackAuditor::parse_json(&two);
        assert!(versioned.iter().any(|c| c.name == "Apache" && c.version == "2.4.7"));
        assert!(techs.contains(&"Apache".to_string()));
        // Pas de doublon Apache malgré deux documents
        assert_eq!(versioned.iter().filter(|c| c.name == "Apache").count(), 1);
    }

    #[test]
    fn test_parse_invalid_json_degrades_gracefully() {
        let (status, server, emails, techs, versioned) =
            TechStackAuditor::parse_json("ceci n'est pas du json");
        assert_eq!(status, 0);
        assert!(server.is_none());
        assert!(emails.is_empty());
        assert!(techs.is_empty());
        assert!(versioned.is_empty());
    }

    #[test]
    fn test_eol_verdict_old_branch() {
        let comps = vec![
            TechComponent { name: "Apache".into(), version: "2.2.15".into() },
            TechComponent { name: "PHP".into(), version: "7.4.33".into() },
            TechComponent { name: "jQuery".into(), version: "1.12.4".into() },
        ];
        let verdicts = TechStackAuditor::version_verdicts(&comps);
        assert_eq!(verdicts.len(), 3, "2.2 / 7.4 / 1.12 sont toutes EOL");
        let apache = verdicts.iter().find(|v| v.name == "Apache").unwrap();
        assert_eq!(apache.branch_min, "2.4");
        assert_eq!(apache.detected, "2.2.15");
        let php = verdicts.iter().find(|v| v.name == "PHP").unwrap();
        assert_eq!(php.branch_min, "8.2");
    }

    #[test]
    fn test_no_verdict_on_maintained_branch() {
        // 2.4.7 : branche 2.4 maintenue → patch-lag, PAS un EOL de branche
        let comps = vec![
            TechComponent { name: "Apache".into(), version: "2.4.7".into() },
            TechComponent { name: "Nginx".into(), version: "1.24.0".into() },
            TechComponent { name: "PHP".into(), version: "8.3.1".into() },
        ];
        assert!(TechStackAuditor::version_verdicts(&comps).is_empty());
    }

    #[test]
    fn test_no_verdict_unknown_component() {
        let comps = vec![TechComponent { name: "X-Custom-Thing".into(), version: "0.1".into() }];
        assert!(TechStackAuditor::version_verdicts(&comps).is_empty());
    }

    #[test]
    fn test_products_from_server_banner() {
        let ps = products_from_server_banner("Apache/2.2.15 (Unix)");
        assert_eq!(ps, vec![("Apache".to_string(), "2.2.15".to_string())]);
        let ps = products_from_server_banner("BaseHTTP/0.6 Python/3.14.7");
        assert!(ps.contains(&("Python".to_string(), "3.14.7".to_string())));
        assert!(products_from_server_banner("nginx").is_empty());
        assert!(products_from_server_banner("cow/abc").is_empty());
    }

    #[test]
    fn test_version_extraction_from_string_field() {
        // Nginx whatweb : {"string": ["nginx/1.22.1"]} sans champ version
        let json = r#"[{"target":"http://t","http_status":200,"plugins":{"Nginx":{"string":["nginx/1.22.1"]},"HTTPServer":{"string":["nginx/1.22.1"]}}}]"#;
        let (_s, server, _e, _t, versioned) = TechStackAuditor::parse_json(json);
        assert_eq!(server.as_deref(), Some("nginx/1.22.1"));
        let nginx = versioned.iter().find(|c| c.name == "Nginx").unwrap();
        assert_eq!(nginx.version, "1.22.1");
        // Branche 1.22 < 1.24 → verdict EOL
        assert!(!TechStackAuditor::version_verdicts(&versioned).is_empty());
    }

    #[test]
    fn test_version_helpers() {
        assert_eq!(normalize_version_token("nginx/1.22.1"), "1.22.1");
        assert_eq!(normalize_version_token("Apache/2.4.7 (Ubuntu)"), "2.4.7");
        assert_eq!(normalize_version_token("3"), "3");
        assert!(looks_like_version("2.4.7"));
        assert!(looks_like_version("18"));
        assert!(!looks_like_version("Universal"));
        assert!(!looks_like_version("RESERVED"));
        assert!(!looks_like_version(""));
        assert_eq!(parse_version("7.4.33-1"), Some([7, 4, 33]));
        assert_eq!(parse_version("3"), Some([3, 0, 0]));
        assert_eq!(parse_version("abc"), None);
    }
}
