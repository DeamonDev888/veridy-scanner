//! Sélecteur de schéma réutilisable : détecte si un host:port répond en
//! HTTPS ou HTTP et dans quel ordre tenter les deux. Élimine le bug racine
//! des outils nuclei/nikto/wafw00f/whatweb qui forçaient https:// sur des
//! box HTTP-only (échec silencieux → 0 findings).

/// Résultat de la détection de schéma pour un host:port.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SchemePlan {
    /// Ordre des schémas à tenter, ex. ["http", "https"].
    pub order: Vec<&'static str>,
    /// Vrai si au moins un schéma répond.
    pub reachable: bool,
}

/// Détecte le schéma réel d'un host:port : TLS d'abord (handshake explicite),
/// puis HTTP. Timeout court — appelé avant chaque outil web.
pub fn detect_scheme(hostport: &str) -> SchemePlan {
    let tls = tls_handshake_answers(hostport);
    let http = !tls && http_answers(hostport);

    if tls {
        SchemePlan { order: vec!["https", "http"], reachable: true }
    } else if http {
        SchemePlan { order: vec!["http", "https"], reachable: true }
    } else {
        SchemePlan { order: vec!["https", "http"], reachable: false }
    }
}

/// Handshake TLS explicite (openssl s_client -brief) : plus fiable que curl -k
/// car il distingue "pas de TLS" de "HTTP répond".
fn tls_handshake_answers(hostport: &str) -> bool {
    crate::utils::run_tool(
        "openssl",
        &["s_client", "-connect", hostport, "-brief"],
        6,
    )
    .is_some_and(|o| {
        let s = format!(
            "{}{}",
            String::from_utf8_lossy(&o.stdout),
            String::from_utf8_lossy(&o.stderr)
        );
        s.contains("CONNECTION ESTABLISHED") || s.contains("Protocol version:")
    })
}

/// Le port répond-il en HTTP clair ? (HEAD / → n'importe quel statut HTTP)
fn http_answers(hostport: &str) -> bool {
    crate::utils::run_tool(
        "curl",
        &[
            "-s", "-o", "/dev/null",
            "--max-time", "4",
            "-w", "%{http_code}",
            &format!("http://{}/", hostport),
        ],
        6,
    )
    .is_some_and(|o| {
        let code = String::from_utf8_lossy(&o.stdout).trim().to_string();
        !code.is_empty() && code != "000"
    })
}

/// Construit la liste d'URLs racine pour un outil, dans le bon ordre.
#[allow(dead_code)]
pub fn root_urls(hostport: &str) -> Vec<String> {
    detect_scheme(hostport)
        .order
        .iter()
        .map(|s| format!("{}://{}/", s, hostport))
        .collect()
}
