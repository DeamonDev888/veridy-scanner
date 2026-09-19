
#[allow(dead_code)]
#[derive(Debug, Clone, Default)]
#[derive(serde::Serialize, serde::Deserialize)]
pub struct WebEndpointsResult {
    pub domain: String,
    pub security_txt_present: bool,
    pub security_txt_url: Option<String>,
    pub robots_txt_present: bool,
    pub robots_disallowed_paths: Vec<String>,
    pub allowed_http_methods: Vec<String>,
    pub dangerous_methods_found: bool,
    pub http2_supported: bool,
    pub alpn_negotiated: Option<String>,
}

/// Wrapper curl HEAD standardisé : `-s -I --max-time {timeout_s}`.
/// Deadline run_tool conservée à 8 s (valeur historique avant extraction).
fn run_curl_head(url: &str, timeout_s: u64) -> Option<std::process::Output> {
    let max_time = timeout_s.to_string();
    crate::utils::run_tool("curl", &["-s", "-I", "--max-time", &max_time, url], 8)
}

/// Wrapper curl GET standardisé : `-s --max-time {timeout_s}` (corps de réponse).
fn run_curl_get(url: &str, timeout_s: u64) -> Option<std::process::Output> {
    let max_time = timeout_s.to_string();
    crate::utils::run_tool("curl", &["-s", "--max-time", &max_time, url], 8)
}

/// Variante HEAD + `-X OPTIONS` pour énumérer les méthodes (en-tête Allow:).
fn run_curl_options(url: &str, timeout_s: u64) -> Option<std::process::Output> {
    let max_time = timeout_s.to_string();
    crate::utils::run_tool("curl", &["-s", "-I", "-X", "OPTIONS", "--max-time", &max_time, url], 8)
}

pub struct WebEndpointsAuditor;


impl WebEndpointsAuditor {
    pub fn audit(domain: &str, ip: &str) -> WebEndpointsResult {
        let mut res = WebEndpointsResult {
            domain: domain.to_string(),
            security_txt_present: false,
            security_txt_url: None,
            robots_txt_present: false,
            robots_disallowed_paths: Vec::new(),
            allowed_http_methods: Vec::new(),
            dangerous_methods_found: false,
            http2_supported: false,
            alpn_negotiated: None,
        };

        // 1. security.txt (RFC 9116)
        let sec_url = format!("https://{}/.well-known/security.txt", domain);
        if let Some(out) = run_curl_head(&sec_url, 3) {
            let s = String::from_utf8_lossy(&out.stdout);
            // Code de statut = ligne de statut UNIQUEMENT ("Content-Length: 200" ne compte pas)
            let code = s
                .lines()
                .next()
                .and_then(|l| l.split_whitespace().nth(1))
                .and_then(|c| c.parse::<u16>().ok());
            if code == Some(200) {
                res.security_txt_present = true;
                res.security_txt_url = Some(sec_url);
            }
        }

        // 2. robots.txt
        let robots_url = format!("https://{}/robots.txt", domain);
        if let Some(out) = run_curl_get(&robots_url, 3) {
            let s = String::from_utf8_lossy(&out.stdout);
            if s.contains("User-agent:") || s.contains("Disallow:") || s.contains("Allow:") {
                res.robots_txt_present = true;
                for line in s.lines() {
                    let trimmed = line.trim();
                    if trimmed.to_lowercase().starts_with("disallow:") {
                        let path = trimmed
                            .split_once(':')
                            .map(|x| x.1)
                            .unwrap_or("")
                            .trim()
                            .to_string();
                        if !path.is_empty() && !res.robots_disallowed_paths.contains(&path) {
                            res.robots_disallowed_paths.push(path);
                        }
                    }
                }
            }
        }

        // 3. Méthodes HTTP autorisées (OPTIONS)
        let root_url = format!("https://{}/", domain);
        if let Some(out) = run_curl_options(&root_url, 3) {
            let s = String::from_utf8_lossy(&out.stdout);
            for line in s.lines() {
                if line.to_lowercase().starts_with("allow:") {
                    let methods_str = line.split_once(':').map(|x| x.1).unwrap_or("").trim();
                    for m in methods_str.split(',') {
                        let method = m.trim().to_uppercase();
                        if !method.is_empty() {
                            if method == "TRACE"
                                || method == "TRACK"
                                || method == "PUT"
                                || method == "DELETE"
                            {
                                res.dangerous_methods_found = true;
                            }
                            res.allowed_http_methods.push(method);
                        }
                    }
                }
            }
        }

        // 4. ALPN HTTP/2 support (sans shell, via grep sur stdout)
        // Connexion sur l'IP résolue + SNI (évite IPv6-first + vhost par défaut des CDN)
        let host_ip = if ip.contains(':') {
            format!("[{}]", ip)
        } else {
            ip.to_string()
        };
        let connect_target = format!("{}:443", host_ip);
        if let Some(out) = crate::utils::run_tool(
            "openssl",
            &[
                "s_client",
                "-connect",
                &connect_target,
                "-servername",
                domain,
                "-alpn",
                "h2,http/1.1",
            ],
            8,
        ) {
            let s = String::from_utf8_lossy(&out.stdout);
            if s.contains("ALPN protocol: h2") {
                res.http2_supported = true;
                res.alpn_negotiated = Some("h2".into());
            } else if s.contains("ALPN protocol: http/1.1") {
                res.alpn_negotiated = Some("http/1.1".into());
            }
        }

        res
    }
}
