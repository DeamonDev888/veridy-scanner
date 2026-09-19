use std::collections::HashMap;
use std::process::Command;

#[allow(dead_code)]
#[derive(Debug, Clone, serde::Serialize)]
pub struct HttpHeaderEntry {
    pub name: String,
    pub value: String,
    pub evaluation: String, // PASS, MISSING, WARNING, INFO
}

#[allow(dead_code)]
#[derive(Debug, Clone, serde::Serialize)]
pub struct CookieAuditEntry {
    pub name: String,
    pub secure: bool,
    pub http_only: bool,
    pub same_site: Option<String>,
}

#[allow(dead_code)]
#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct HttpAuditResult {
    pub target_url: String,
    pub http_status: u16,
    pub redirects_to_https: bool,
    pub server_header: Option<String>,
    pub powered_by: Option<String>,
    pub hsts_present: bool,
    pub hsts_value: Option<String>,
    pub csp_present: bool,
    pub csp_value: Option<String>,
    pub x_frame_options: Option<String>,
    pub x_content_type_options: Option<String>,
    pub referrer_policy: Option<String>,
    pub permissions_policy: Option<String>,
    pub coop: Option<String>,
    pub corp: Option<String>,
    pub cookies: Vec<CookieAuditEntry>,
    pub all_headers: Vec<HttpHeaderEntry>,
    pub missing_security_headers: Vec<&'static str>,
    pub score_percentage: u8,
}

pub struct HttpAuditor;

/// Les 6 en-têtes de sécurité obligatoires, vérifiés en boucle data-driven :
/// (libellé complet pour `missing`, clé minuscule de la HashMap `headers`).
/// Le nom affiché dans `all_headers` est le libellé sans suffixe " (...)".
const SECURITY_HEADERS: [(&str, &str); 6] = [
    (
        "Strict-Transport-Security (HSTS)",
        "strict-transport-security",
    ),
    ("Content-Security-Policy (CSP)", "content-security-policy"),
    ("X-Frame-Options", "x-frame-options"),
    ("X-Content-Type-Options", "x-content-type-options"),
    ("Referrer-Policy", "referrer-policy"),
    ("Permissions-Policy", "permissions-policy"),
];

impl HttpAuditor {
    pub fn audit(domain: &str) -> HttpAuditResult {
        let mut missing = Vec::new();
        let mut headers = HashMap::new();
        let mut raw_headers_list = Vec::new();
        let mut cookies_list = Vec::new();
        let mut status_code = 0;
        let mut redirects_to_https = false;

        // 1. Test de redirection HTTP -> HTTPS sur le port 80
        let http_url = format!("http://{}/", domain);
        if let Ok(output) = Command::new("curl")
            .args(["-s", "-I", "--max-time", "4", &http_url])
            .output()
        {
            let out = String::from_utf8_lossy(&output.stdout);
            for line in out.lines() {
                let lower = line.to_lowercase();
                if lower.starts_with("location:") {
                    if let Some((_, val)) = line.split_once(':') {
                        if val.trim().to_lowercase().starts_with("https://") {
                            redirects_to_https = true;
                        }
                    }
                }
            }
        }

        // 2. Récupération des en-têtes et cookies HTTPS sur le port 443
        let https_url = format!("https://{}/", domain);
        if let Ok(output) = Command::new("curl")
            .args(["-s", "-I", "--max-time", "5", &https_url])
            .output()
        {
            let out = String::from_utf8_lossy(&output.stdout);
            for line in out.lines() {
                let trimmed = line.trim();
                if trimmed.starts_with("HTTP/") {
                    let parts: Vec<&str> = trimmed.split_whitespace().collect();
                    if parts.len() >= 2 {
                        if let Ok(code) = parts[1].parse::<u16>() {
                            status_code = code;
                        }
                    }
                } else if let Some((key, val)) = trimmed.split_once(':') {
                    let k = key.trim().to_lowercase();
                    let v = val.trim().to_string();

                    // Détection cookies : nom/valeur séparés des attributs (split ';'),
                    // attributs matchés exactement — le nom "secure_session=1" n'est PAS
                    // un attribut Secure (faux positif historique).
                    if k == "set-cookie" {
                        let (pair, attrs) = match v.split_once(';') {
                            Some((a, b)) => (a, b),
                            None => (v.as_str(), ""),
                        };
                        let cookie_name = pair
                            .split('=')
                            .next()
                            .unwrap_or("cookie")
                            .trim()
                            .to_string();
                        let mut has_secure = false;
                        let mut has_http_only = false;
                        let mut same_site = None;
                        for attr in attrs.split(';') {
                            let a = attr.trim().to_lowercase();
                            if a == "secure" {
                                has_secure = true;
                            } else if a == "httponly" {
                                has_http_only = true;
                            } else if let Some(mode) = a.strip_prefix("samesite=") {
                                same_site = Some(match mode {
                                    "strict" => "Strict".to_string(),
                                    "lax" => "Lax".to_string(),
                                    "none" => "None".to_string(),
                                    other => other.to_string(),
                                });
                            }
                        }
                        cookies_list.push(CookieAuditEntry {
                            name: cookie_name,
                            secure: has_secure,
                            http_only: has_http_only,
                            same_site,
                        });
                    }

                    headers.insert(k, v);
                }
            }
        }

        let server_header = headers.get("server").cloned();
        let powered_by = headers.get("x-powered-by").cloned();

        let hsts_value = headers.get("strict-transport-security").cloned();
        let csp_value = headers.get("content-security-policy").cloned();
        let x_frame_options = headers.get("x-frame-options").cloned();
        let x_content_type_options = headers.get("x-content-type-options").cloned();
        let referrer_policy = headers.get("referrer-policy").cloned();
        let permissions_policy = headers.get("permissions-policy").cloned();
        let hsts_present = hsts_value.is_some();
        let csp_present = csp_value.is_some();

        // Boucle data-driven sur SECURITY_HEADERS : libellé complet ->
        // `missing`, nom sans suffixe " (...)" -> `all_headers`. Ordre
        // inchangé (HSTS, CSP, XFO, XCTO, Referrer, Permissions), puis
        // COOP / CORP / Server ci-dessous.
        for (label, key) in SECURITY_HEADERS {
            let display_name = label.split(" (").next().unwrap_or(label);
            match headers.get(key) {
                Some(val) => raw_headers_list.push(HttpHeaderEntry {
                    name: display_name.into(),
                    value: val.clone(),
                    evaluation: "PASS".into(),
                }),
                None => {
                    missing.push(label);
                    raw_headers_list.push(HttpHeaderEntry {
                        name: display_name.into(),
                        value: "-".into(),
                        evaluation: "MISSING".into(),
                    });
                }
            }
        }

        let coop = headers.get("cross-origin-opener-policy").cloned();
        if let Some(ref val) = coop {
            raw_headers_list.push(HttpHeaderEntry {
                name: "Cross-Origin-Opener-Policy".into(),
                value: val.clone(),
                evaluation: "PASS".into(),
            });
        }

        let corp = headers.get("cross-origin-resource-policy").cloned();
        if let Some(ref val) = corp {
            raw_headers_list.push(HttpHeaderEntry {
                name: "Cross-Origin-Resource-Policy".into(),
                value: val.clone(),
                evaluation: "PASS".into(),
            });
        }

        if let Some(ref s) = server_header {
            raw_headers_list.push(HttpHeaderEntry {
                name: "Server".into(),
                value: s.clone(),
                evaluation: "INFO".into(),
            });
        }

        // Calcul du score (base 100)
        let total_checks = 6;
        let passed = total_checks - missing.len();
        let mut score = ((passed as f32 / total_checks as f32) * 100.0) as u8;
        if redirects_to_https {
            score = (score + 5).min(100);
        }

        HttpAuditResult {
            target_url: https_url,
            http_status: status_code,
            redirects_to_https,
            server_header,
            powered_by,
            hsts_present,
            hsts_value,
            csp_present,
            csp_value,
            x_frame_options,
            x_content_type_options,
            referrer_policy,
            permissions_policy,
            coop,
            corp,
            cookies: cookies_list,
            all_headers: raw_headers_list,
            missing_security_headers: missing,
            score_percentage: score.min(100),
        }
    }
}
