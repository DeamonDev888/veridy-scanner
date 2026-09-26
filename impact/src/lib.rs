//! veridy-impact — modules de preuve d'impact pour veridy_scanner.
//!
//! Principes NON NEGOCIABLES :
//! - lecture seule : HTTP GET et DNS exclusivement, jamais de POST/PUT/DELETE,
//!   jamais d'écriture sur la cible ;
//! - requête unique par objet (pas de brute-force : les chemins viennent du
//!   scanner) ;
//! - timeout dur sur chaque requête (curl --max-time) ;
//! - subprocess via args() uniquement, jamais `sh -c` ;
//! - secrets jamais affichés en clair : masqués avant affichage.

use std::process::{Command, Stdio};

/// Réponse HTTP minimale (via curl, zéro dépendance).
#[derive(Debug, Clone)]
pub struct HttpResponse {
    pub status: u16,
    pub content_type: String,
    pub body: String,
}

/// GET HTTP avec timeout dur. Retourne None si curl échoue (DNS, réseau, TLS).
pub fn http_get(url: &str, timeout_secs: u64) -> Option<HttpResponse> {
    http_get_headers(url, timeout_secs, &[])
}

/// GET HTTP avec en-têtes supplémentaires (ex. Referer pour tester les
/// restrictions de clé), timeout dur. Retourne None si curl échoue.
pub fn http_get_headers(
    url: &str,
    timeout_secs: u64,
    headers: &[(&str, &str)],
) -> Option<HttpResponse> {
    let mut args: Vec<String> = [
        "-s",
        "-L",
        "--max-time",
        &timeout_secs.to_string(),
        "-w",
        "\n%{http_code}|%{content_type}",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect();
    for (h, v) in headers {
        args.push("-H".to_string());
        args.push(format!("{h}: {v}"));
    }
    args.push(url.to_string());
    let out = Command::new("curl")
        .args(&args)
        .stdin(Stdio::null())
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let raw = String::from_utf8_lossy(&out.stdout).to_string();
    let idx = raw.rfind('\n')?;
    let (body, meta) = (raw[..idx].to_string(), raw[idx + 1..].to_string());
    let mut parts = meta.split('|');
    let status: u16 = parts.next()?.trim().parse().ok()?;
    let content_type = parts.next().unwrap_or("").trim().to_string();
    Some(HttpResponse {
        status,
        content_type,
        body,
    })
}

/// Masque un secret : 3 premiers caractères + longueur, jamais la valeur.
pub fn mask_secret(v: &str) -> String {
    let t = v.trim();
    let n = t.chars().count();
    if n == 0 {
        return String::from("(vide)");
    }
    if n <= 6 {
        return format!("{} ({n} chars)", "*".repeat(n));
    }
    let head: String = t.chars().take(3).collect();
    format!("{head}**** ({n} chars)")
}

/// Parse un contenu .env en paires clé/valeur (ignore commentaires et vides).
pub fn parse_env(body: &str) -> Vec<(String, String)> {
    body.lines()
        .filter_map(|l| {
            let l = l.trim();
            if l.is_empty() || l.starts_with('#') {
                return None;
            }
            l.split_once('=').map(|(k, v)| {
                (
                    k.trim().to_string(),
                    v.trim().trim_matches('"').trim_matches('\'').to_string(),
                )
            })
        })
        .collect()
}

/// Une réponse ressemble-t-elle à un vrai .env (anti soft-404) ?
pub fn looks_like_env(body: &str) -> bool {
    let pairs = parse_env(body);
    let low = body.to_lowercase();
    pairs.len() >= 2 && !low.contains("<html") && !low.contains("<!doctype")
}

/// Clé d'environnement à forte valeur (identifiants, secrets, DSN).
pub fn is_high_signal(key: &str) -> bool {
    const PATTERNS: [&str; 13] = [
        "PASSWORD",
        "PASSWD",
        "PWD",
        "SECRET",
        "TOKEN",
        "API_KEY",
        "APIKEY",
        "PRIVATE",
        "DSN",
        "AWS_",
        "SMTP",
        "DATABASE_URL",
        "CREDENTIAL",
    ];
    let u = key.to_uppercase();
    PATTERNS.iter().any(|p| u.contains(p))
}

/// Type de clé API deviné depuis son format (classification seule).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyKind {
    Google,
    StripeLive,
    StripeTest,
    SendGrid,
    Slack,
    GitHub,
    OpenAI,
    Unknown,
}

impl KeyKind {
    pub fn label(self) -> &'static str {
        match self {
            KeyKind::Google => "Google API",
            KeyKind::StripeLive => "Stripe LIVE",
            KeyKind::StripeTest => "Stripe test",
            KeyKind::SendGrid => "SendGrid",
            KeyKind::Slack => "Slack token",
            KeyKind::GitHub => "GitHub token",
            KeyKind::OpenAI => "OpenAI",
            KeyKind::Unknown => "inconnu",
        }
    }

    /// Seules certaines clés peuvent être vérifiées sans effet de bord.
    pub fn safely_checkable(self) -> bool {
        matches!(self, KeyKind::Google)
    }
}

pub fn classify_key(k: &str) -> KeyKind {
    let k = k.trim();
    if k.starts_with("AIza") && k.len() == 39 {
        KeyKind::Google
    } else if k.starts_with("sk_live") {
        KeyKind::StripeLive
    } else if k.starts_with("sk_test") {
        KeyKind::StripeTest
    } else if k.starts_with("SG.") && k.matches('.').count() == 2 {
        KeyKind::SendGrid
    } else if k.starts_with("xox") {
        KeyKind::Slack
    } else if k.starts_with("ghp_") || k.starts_with("github_pat_") {
        KeyKind::GitHub
    } else if k.starts_with("sk-") {
        KeyKind::OpenAI
    } else {
        KeyKind::Unknown
    }
}

/// Résultat de la vérification non destructive d'une clé Google Maps.
#[derive(Debug, Clone)]
pub struct GoogleKeyVerdict {
    pub valid: bool,
    pub detail: String,
}

/// Vérifie une clé Google via une requête staticmap minimale (1 requête GET,
/// gratuite, sans effet de bord). Détecte aussi les restrictions referrer/IP.
pub fn check_google_key(key: &str, timeout_secs: u64) -> Option<GoogleKeyVerdict> {
    let url =
        format!("https://maps.googleapis.com/maps/api/staticmap?center=0,0&size=16x16&key={key}");
    let r = http_get(&url, timeout_secs)?;
    let low = r.body.to_lowercase();
    if r.status == 200 {
        return Some(GoogleKeyVerdict {
            valid: true,
            detail: "clé ACCEPTÉE (200) — utilisable telle quelle".to_string(),
        });
    }
    if low.contains("request_denied") || low.contains("requestdenied") {
        if low.contains("referrer") || low.contains("http_referrer") {
            return Some(GoogleKeyVerdict {
                valid: true,
                detail: "clé VALIDE mais restreinte par referrer HTTP (contournable via spoofing Referer)".to_string(),
            });
        }
        if low.contains("ip") || low.contains("address") {
            return Some(GoogleKeyVerdict {
                valid: true,
                detail: "clé VALIDE mais restreinte par IP (utilisable depuis les IP autorisées)"
                    .to_string(),
            });
        }
        if low.contains("billing") || low.contains("quota") {
            return Some(GoogleKeyVerdict {
                valid: true,
                detail: "clé VALIDE mais quota/billing épuisé".to_string(),
            });
        }
        if low.contains("invalid") || low.contains("keyinvalid") {
            return Some(GoogleKeyVerdict {
                valid: false,
                detail: "clé INVALIDE (révoquée ou mal copiée)".to_string(),
            });
        }
        return Some(GoogleKeyVerdict {
            valid: false,
            detail: format!("REQUEST_DENIED ({}): {}", r.status, one_line(&r.body, 120)),
        });
    }
    Some(GoogleKeyVerdict {
        valid: false,
        detail: format!("HTTP {} inattendu: {}", r.status, one_line(&r.body, 120)),
    })
}

fn one_line(s: &str, max: usize) -> String {
    let flat: String = s.split_whitespace().collect::<Vec<_>>().join(" ");
    flat.chars().take(max).collect()
}

/// Dig +short sur un enregistrement TXT.
pub fn dig_txt(domain: &str) -> Vec<String> {
    let out = Command::new("dig")
        .args(["+short", "TXT", domain, "+time=5", "+tries=1"])
        .stdin(Stdio::null())
        .output();
    match out {
        Ok(o) if o.status.success() => String::from_utf8_lossy(&o.stdout)
            .lines()
            .map(|l| l.trim().trim_matches('"').to_string())
            .filter(|l| !l.is_empty())
            .collect(),
        _ => Vec::new(),
    }
}

/// Qualificateur du mécanisme `all` d'un SPF (`-all`, `~all`, `?all`, `+all`).
pub fn spf_all_qualifier(spf: &str) -> Option<char> {
    let low = spf.to_lowercase();
    for mech in low.split([' ', '\t']) {
        let m = mech.trim();
        if m == "all" {
            return Some('+');
        }
        if let Some(rest) = m.strip_suffix("all") {
            let last = rest.chars().last()?;
            if matches!(last, '-' | '~' | '?' | '+') {
                return Some(last);
            }
        }
    }
    None
}

/// Politique DMARC (tag p=) depuis un TXT _dmarc.
pub fn dmarc_policy(txt: &str) -> Option<String> {
    for tag in txt.split(';') {
        let tag = tag.trim();
        if let Some(v) = tag.strip_prefix("p=").or_else(|| tag.strip_prefix("P=")) {
            return Some(v.trim().to_lowercase());
        }
    }
    None
}

/// Verdict d'usurpabilité d'un domaine (analyse seule, aucun envoi réel).
pub fn spoof_verdict(spf: Option<&str>, dmarc_p: Option<&str>) -> (&'static str, String) {
    let qualif = spf.and_then(spf_all_qualifier);
    match dmarc_p {
        None => match (spf, qualif) {
            (None, _) => (
                "USURPABLE",
                "aucun SPF ni DMARC : n'importe qui peut envoyer des mails au nom du domaine".to_string(),
            ),
            (Some(_), Some('-')) | (Some(_), Some('~')) => (
                "PARTIEL",
                "SPF restrictif mais DMARC absent : usurpation filtree uniquement par les destinataires SPF-strict".to_string(),
            ),
            (Some(_), _) => (
                "USURPABLE",
                "SPF permissif (qualificateur soft/pass) et DMARC absent".to_string(),
            ),
        },
        Some(p) => match (spf, p) {
            (_, "reject") => (
                "PROTEGE",
                "DMARC p=reject : usurpation bloquee par les boites conformes".to_string(),
            ),
            (None, "quarantine") | (None, "none") | (None, _) => (
                "PARTIEL",
                format!("DMARC p={p} sans SPF explicite (politique partielle)"),
            ),
            (_, "quarantine") => (
                "PARTIEL",
                "DMARC p=quarantine : usurpation mise en quarantaine (spam), pas bloquee".to_string(),
            ),
            (_, _) => (
                "PARTIEL",
                "DMARC p=none : monitorage seul, aucune action anti-usurpation".to_string(),
            ),
        },
    }
}

/// Emails de développeurs extraits d'un git log exposé (preuve d'impact OSINT).
pub fn extract_emails(log: &str) -> Vec<String> {
    let mut out = Vec::new();
    for line in log.lines() {
        if let (Some(a), Some(b)) = (line.find('<'), line.find('>')) {
            if b > a {
                let mail = line[a + 1..b].to_string();
                if mail.contains('@') && !mail.contains(' ') && !out.contains(&mail) {
                    out.push(mail);
                }
            }
        }
    }
    out
}

/// URLs de remotes extraites d'un .git/config exposé.
pub fn extract_remotes(config: &str) -> Vec<String> {
    config
        .lines()
        .filter_map(|l| {
            let l = l.trim();
            l.strip_prefix("url =").map(|u| u.trim().to_string())
        })
        .collect()
}

// ============================================================
// gkeyx — enumeration des privileges d'une cle Google (AIza...)
// Sondes GET lecture-seule, une par service : ce que la cle ouvre.
// ============================================================

/// Statut d'une sonde gkeyx.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GProbeStatus {
    /// 200 avec donnees : acces PROUVE.
    Granted,
    /// Cle reconnue mais contrainte (API non activee, restriction referrer/IP, quota).
    Constrained,
    /// Cle refusee (invalide ou revokee).
    Denied,
    /// Sonde non concluante (reseau, reponse inattendue).
    Inconclusive,
}

impl GProbeStatus {
    pub fn label(self) -> &'static str {
        match self {
            Self::Granted => "ACCEPTE",
            Self::Constrained => "CONTRAINT",
            Self::Denied => "REFUSE",
            Self::Inconclusive => "NON_CONCLUANT",
        }
    }
}

/// Resultat d'une sonde GET vers un service Google.
#[derive(Debug, Clone)]
pub struct GProbe {
    pub family: &'static str,
    pub service: &'static str,
    pub status: GProbeStatus,
    pub detail: String,
}

/// Numero de projet Google fuite par un message d'erreur
/// ("... has not been used in project 123456789 before ...").
pub fn extract_google_project(body: &str) -> Option<String> {
    for pat in ["project ", "projects/"] {
        let mut from = 0usize;
        while let Some(pos) = body[from..].find(pat) {
            let rest = &body[from + pos + pat.len()..];
            let digits: String = rest.chars().take_while(|c| c.is_ascii_digit()).collect();
            if digits.len() >= 6 {
                return Some(digits);
            }
            from += pos + pat.len();
        }
    }
    None
}

/// Classifie la reponse d'une sonde Google (pure, testable sans reseau).
/// Signatures issue de reponses REELLES capturees le 2026-09-26.
pub fn google_probe_classify(status: u16, body: &str) -> (GProbeStatus, String) {
    let low = body.to_lowercase();
    // 1. cle invalide (googleapis HTTP 400, ou Maps HTTP 200 + REQUEST_DENIED)
    if low.contains("api key not valid")
        || low.contains("api_key_invalid")
        || low.contains("api key is invalid")
        || low.contains("keyinvalid")
    {
        return (GProbeStatus::Denied, "cle invalide".into());
    }
    // 2. Maps renvoie HTTP 200 avec REQUEST_DENIED dans le corps JSON
    if low.contains("request_denied") {
        if low.contains("referer") || low.contains("referrer") || low.contains("from this site") {
            return (
                GProbeStatus::Constrained,
                "cle VALIDE, restriction referrer".into(),
            );
        }
        if low.contains("ip address")
            || low.contains("this ip")
            || low.contains("site or ip")
            || low.contains("from this site")
            || low.contains("mobile application")
        {
            return (
                GProbeStatus::Constrained,
                "cle VALIDE, restriction site/IP".into(),
            );
        }
        if low.contains("billing") || low.contains("quota") {
            return (
                GProbeStatus::Constrained,
                "cle VALIDE, billing/quota non actif".into(),
            );
        }
        return (
            GProbeStatus::Constrained,
            "cle VALIDE, non autorisee sur ce service (restriction API)".into(),
        );
    }
    // 3. acces prouve
    if status == 200 {
        return (GProbeStatus::Granted, "acces PROUVE (200)".into());
    }
    // 4. rate limite
    if status == 429 || low.contains("quota exceeded") || low.contains("resource_exhausted") {
        return (
            GProbeStatus::Constrained,
            "rate-limitee (429) — cle vive, quota epuise".into(),
        );
    }
    // 5. API non activee dans le projet -> fuite du numero de projet
    if let Some(p) = extract_google_project(body) {
        return (
            GProbeStatus::Constrained,
            format!("cle VALIDE, API non activee (projet {p})"),
        );
    }
    if status == 403 {
        return (GProbeStatus::Constrained, "403 (restriction)".into());
    }
    (
        GProbeStatus::Inconclusive,
        format!("http {status} non concluant"),
    )
}

/// Noms de modeles extraits d'une reponse 200 de Generative Language
/// (cosmetique et tolerant : extrait au format, rien de critique dessus).
pub fn gemini_models(body: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut rest = body;
    while let Some(pos) = rest.find("\"name\"") {
        rest = &rest[pos + 6..];
        let Some(q1) = rest.find('"') else { break };
        let after = &rest[q1 + 1..];
        let Some(q2) = after.find('"') else { break };
        let val = &after[..q2];
        if val.starts_with("models/") {
            out.push(val.to_string());
            if out.len() >= 5 {
                break;
            }
        }
        rest = &after[q2..];
    }
    out
}

/// Enumere les privileges d'une cle Google : une sonde GET par service,
/// timeout dur sur chacune, jamais de POST.
pub fn gkeyx_report(key: &str, timeout_secs: u64) -> Vec<GProbe> {
    let probes: Vec<(&'static str, &'static str, String)> = vec![
        (
            "LLM",
            "gemini",
            format!(
                "https://generativelanguage.googleapis.com/v1beta/models?pageSize=50&key={key}"
            ),
        ),
        (
            "MAPS",
            "staticmap",
            format!("https://maps.googleapis.com/maps/api/staticmap?center=0,0&size=16x16&key={key}"),
        ),
        (
            "MAPS",
            "geocode",
            format!("https://maps.googleapis.com/maps/api/geocode/json?address=Montreal&key={key}"),
        ),
        (
            "MAPS",
            "streetview",
            format!("https://maps.googleapis.com/maps/api/streetview/metadata?location=45.5,-73.6&key={key}"),
        ),
        (
            "MAPS",
            "directions",
            format!("https://maps.googleapis.com/maps/api/directions/json?origin=Montreal&destination=Quebec&key={key}"),
        ),
        (
            "MAPS",
            "elevation",
            format!("https://maps.googleapis.com/maps/api/elevation/json?locations=45.5,-73.6&key={key}"),
        ),
        (
            "DATA",
            "youtube",
            format!("https://www.googleapis.com/youtube/v3/videos?part=id&chart=mostPopular&maxResults=1&key={key}"),
        ),
        (
            "DATA",
            "translate",
            format!("https://translation.googleapis.com/language/translate/v2?q=cat&target=fr&key={key}"),
        ),
        (
            "DATA",
            "customsearch",
            format!("https://www.googleapis.com/customsearch/v1?q=test&key={key}"),
        ),
    ];
    let mut out = Vec::new();
    for (family, service, url) in probes {
        let g = match http_get(&url, timeout_secs) {
            None => GProbe {
                family,
                service,
                status: GProbeStatus::Inconclusive,
                detail: "erreur reseau".into(),
            },
            Some(r) => {
                let (status, mut detail) = google_probe_classify(r.status, &r.body);
                if service == "gemini" && status == GProbeStatus::Granted {
                    let models = gemini_models(&r.body);
                    if !models.is_empty() {
                        detail = format!(
                            "{detail} — {} modele(s) : {}",
                            models.len(),
                            models
                                .iter()
                                .map(|m| m.trim_start_matches("models/").to_string())
                                .collect::<Vec<_>>()
                                .join(", ")
                        );
                    }
                }
                GProbe {
                    family,
                    service,
                    status,
                    detail,
                }
            }
        };
        out.push(g);
    }
    out
}

/// Verdict global : VALIDE (services accessibles), VALIDE_RESTREINTE,
/// INVALIDE (refusee partout) ou NON_VERIFIABLE.
pub fn gkeyx_verdict(probes: &[GProbe]) -> (&'static str, String) {
    let granted: Vec<&GProbe> = probes
        .iter()
        .filter(|p| p.status == GProbeStatus::Granted)
        .collect();
    let constrained = probes.iter().any(|p| p.status == GProbeStatus::Constrained);
    let denied = probes
        .iter()
        .filter(|p| p.status == GProbeStatus::Denied)
        .count();
    if !granted.is_empty() {
        let svcs: Vec<&str> = granted.iter().map(|p| p.service).collect();
        let mut fams: Vec<&str> = Vec::new();
        for p in &granted {
            if !fams.contains(&p.family) {
                fams.push(p.family);
            }
        }
        (
            "VALIDE",
            format!(
                "{} service(s) utilisable(s) [{}] : {}",
                granted.len(),
                fams.join("+"),
                svcs.join(", ")
            ),
        )
    } else if constrained {
        (
            "VALIDE_RESTREINTE",
            "cle vive mais aucun service pleinement ouvert (restrictions / API non activees)"
                .into(),
        )
    } else if denied == probes.len() {
        ("INVALIDE", "refusee sur tous les services sondes".into())
    } else {
        ("NON_VERIFIABLE", "sondes non concluantes (reseau?)".into())
    }
}

/// Phase d'exploitation post-verdict (toujours lecture seule) :
/// 1. fuites de numero de projet dans les details des sondes ;
/// 2. test de bypass de la restriction referrer (differential sans/avec
///    Referer) sur un service deja ouvert — prouve si la cle est consommable
///    en server-side pur (contournement de restriction).
pub fn gkeyx_exploit(key: &str, probes: &[GProbe], timeout_secs: u64) -> Vec<String> {
    let mut notes = Vec::new();
    // 1. fuite du numero de projet
    let mut projects: Vec<String> = Vec::new();
    for p in probes {
        if let Some(num) = extract_google_project(&p.detail) {
            if !projects.contains(&num) {
                projects.push(num);
            }
        }
    }
    if projects.is_empty() {
        if let Some(r) = http_get(
            &format!("https://www.googleapis.com/customsearch/v1?q=x&key={key}"),
            timeout_secs,
        ) {
            if let Some(num) = extract_google_project(&r.body) {
                projects.push(num);
            }
        }
    }
    if !projects.is_empty() {
        notes.push(format!(
            "RECON  : numero(s) de projet Google fuite(s) : {} (les 403 \"has not been used in project NNN\" identifient le projet proprietaire)",
            projects.join(", ")
        ));
    }
    // 2. bypass referrer : un service ouvert sans Referer + refuse avec Referer
    //    etranger = restriction non appliquee server-side.
    let open_probe = probes
        .iter()
        .find(|p| p.status == GProbeStatus::Granted && p.family == "MAPS");
    if let Some(op) = open_probe {
        let url = match op.service {
            "staticmap" => format!("https://maps.googleapis.com/maps/api/staticmap?center=45.5,-73.6&size=32x32&key={key}"),
            "geocode" => format!("https://maps.googleapis.com/maps/api/geocode/json?address=Montreal&key={key}"),
            "streetview" => format!("https://maps.googleapis.com/maps/api/streetview/metadata?location=45.5,-73.6&key={key}"),
            "directions" => format!("https://maps.googleapis.com/maps/api/directions/json?origin=Montreal&destination=Quebec&key={key}"),
            "elevation" => format!("https://maps.googleapis.com/maps/api/elevation/json?locations=45.5,-73.6&key={key}"),
            _ => return notes,
        };
        let with_ref = http_get_headers(
            &url,
            timeout_secs,
            &[("Referer", "https://attacker.example")],
        );
        match with_ref {
            Some(r) if r.status == 200 => notes.push(
                "BYPASS  : restriction referrer NON appliquee — la cle marche avec un Referer etranger (consommable depuis n'importe quel site/client)".to_string(),
            ),
            Some(_) => notes.push(
                "BYPASS  : restriction referrer appliquee sur les navigateurs (Referer etranger = 403) MAIS la cle repond 200 sans Referer -> consommable en server-side pur (curl/scripts) : vol de quota Maps possible".to_string(),
            ),
            None => notes.push("BYPASS  : test non concluant (reseau)".to_string()),
        }
    }
    notes
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mask_secret_never_leaks_full_value() {
        let m = mask_secret("SUPERSECRET123456");
        assert!(!m.contains("SUPERSECRET123456"));
        assert!(m.contains("SUP"));
        assert!(m.contains("chars"));
        assert_eq!(mask_secret("abc"), "*** (3 chars)");
        assert_eq!(mask_secret(""), "(vide)");
    }

    #[test]
    fn parse_env_handles_comments_quotes() {
        let env = "# comment\nDB_HOST=localhost\nDB_PASSWORD=p@ss_w0rd!\nEMPTY=\n";
        let pairs = parse_env(env);
        assert_eq!(pairs.len(), 3);
        assert_eq!(pairs[0], ("DB_HOST".to_string(), "localhost".to_string()));
        assert_eq!(pairs[1].1, "p@ss_w0rd!");
    }

    #[test]
    fn looks_like_env_rejects_html_soft404() {
        assert!(looks_like_env("A=1\nB=2\n"));
        assert!(!looks_like_env("<html><body>404</body></html>"));
    }

    #[test]
    fn high_signal_keys() {
        assert!(is_high_signal("DATABASE_PASSWORD"));
        assert!(is_high_signal("aws_secret_access_key"));
        assert!(is_high_signal("SMTP_TOKEN"));
        assert!(!is_high_signal("APP_NAME"));
        assert!(!is_high_signal("DEBUG"));
    }

    #[test]
    fn classify_key_formats() {
        let g = "AIzaSy123456789012345678901234567890123"; // 39 chars
        assert_eq!(classify_key(g), KeyKind::Google);
        assert_eq!(classify_key("sk_live_abc123"), KeyKind::StripeLive);
        assert_eq!(classify_key("sk_test_abc123"), KeyKind::StripeTest);
        assert_eq!(classify_key("SG.abc.def"), KeyKind::SendGrid);
        assert_eq!(classify_key("xoxb-123"), KeyKind::Slack);
        assert_eq!(classify_key("ghp_abc"), KeyKind::GitHub);
        assert_eq!(classify_key("sk-proj-xyz"), KeyKind::OpenAI);
        assert_eq!(classify_key("nimporte"), KeyKind::Unknown);
        assert!(!classify_key("sk_live_x").safely_checkable());
        assert!(classify_key(g).safely_checkable());
    }

    #[test]
    fn spf_qualifier_parsing() {
        assert_eq!(spf_all_qualifier("v=spf1 ip4:1.2.3.4 -all"), Some('-'));
        assert_eq!(spf_all_qualifier("v=spf1 ~all"), Some('~'));
        assert_eq!(spf_all_qualifier("v=spf1 all"), Some('+'));
        assert_eq!(spf_all_qualifier("v=spf1 ip4:1.2.3.4"), None);
    }

    #[test]
    fn dmarc_policy_parsing() {
        assert_eq!(
            dmarc_policy("v=DMARC1; p=reject; rua=mailto:x@y.z"),
            Some("reject".to_string())
        );
        assert_eq!(dmarc_policy("v=DMARC1; p=none"), Some("none".to_string()));
        assert_eq!(dmarc_policy("v=spf1 -all"), None);
    }

    #[test]
    fn spoof_verdict_matrix() {
        let (v, _) = spoof_verdict(None, None);
        assert_eq!(v, "USURPABLE");
        let (v, _) = spoof_verdict(Some("v=spf1 -all"), Some("reject"));
        assert_eq!(v, "PROTEGE");
        let (v, _) = spoof_verdict(Some("v=spf1 -all"), Some("none"));
        assert!(v.contains("PARTIEL"));
        let (v, _) = spoof_verdict(Some("v=spf1 -all"), None);
        assert_eq!(v, "PARTIEL");
    }

    #[test]
    fn extract_emails_and_remotes() {
        let log = "0000 1111 Alice <alice@corp.internal> 1700000000 +0000\tinit\n2222 3333 Bob <bob@corp.internal> 1700000001 +0000\tfix";
        assert_eq!(
            extract_emails(log),
            vec!["alice@corp.internal", "bob@corp.internal"]
        );
        let cfg = r#"[core]
	repositoryformatversion = 0
[remote "origin"]
	url = git@internal.git.corp:proj/web.git
"#;
        assert_eq!(
            extract_remotes(cfg),
            vec!["git@internal.git.corp:proj/web.git"]
        );
    }

    #[test]
    fn gkeyx_classify_real_signatures() {
        // Fixtures = reponses REELLES capturees des APIs Google (2026-09-26).
        // googleapis.com (gemini/youtube/translate) : HTTP 400 + message.
        let g400 = r#"{"error":{"code":400,"message":"API key not valid. Please pass a valid API key.","status":"INVALID_ARGUMENT","details":[{"reason":"API_KEY_INVALID"}]}}"#;
        assert_eq!(google_probe_classify(400, g400).0, GProbeStatus::Denied);
        // maps.googleapis.com : HTTP 200 + REQUEST_DENIED dans le corps.
        let maps_invalid = r#"{"candidates":[],"error_message":"The provided API key is invalid.","status":"REQUEST_DENIED"}"#;
        assert_eq!(
            google_probe_classify(200, maps_invalid).0,
            GProbeStatus::Denied
        );
        // Maps restreinte referrer : cle vive.
        let maps_ref = r#"{"error_message":"This API key is not authorized to be used from this site.","status":"REQUEST_DENIED"}"#;
        let (st, d) = google_probe_classify(200, maps_ref);
        assert_eq!(st, GProbeStatus::Constrained);
        assert!(d.contains("referrer"), "{d}");
        // API non activee : fuite du numero de projet.
        let not_used = r#"{"error":{"code":403,"message":"Google Maps JavaScript API error: RefererNotAllowedMapError ... has not been used in project 123456789012 before or it is disabled"}}"#;
        let (st, d) = google_probe_classify(403, not_used);
        assert_eq!(st, GProbeStatus::Constrained);
        assert!(d.contains("123456789012"), "{d}");
        // 200 net = acces prouve.
        assert_eq!(
            google_probe_classify(200, r#"{"models":[]}"#).0,
            GProbeStatus::Granted
        );
        // 429 = cle vive, rate-limitee.
        assert_eq!(
            google_probe_classify(429, r#"{"error":{"code":429}}"#).0,
            GProbeStatus::Constrained
        );
    }

    #[test]
    fn gkeyx_project_extraction() {
        assert_eq!(
            extract_google_project("has not been used in project 987654321234 before"),
            Some("987654321234".to_string())
        );
        // projects/ extrait aussi
        assert_eq!(
            extract_google_project("projects/555666777888/locations/global"),
            Some("555666777888".to_string())
        );
        assert_eq!(extract_google_project("rien ici"), None);
        // numero trop court = pas un projet
        assert_eq!(extract_google_project("project 123"), None);
    }

    #[test]
    fn gkeyx_gemini_models_parse() {
        let body =
            r#"{"models":[{"name":"models/gemini-2.0-flash"},{"name":"models/gemini-1.5-pro"}]}"#;
        assert_eq!(
            gemini_models(body),
            vec!["models/gemini-2.0-flash", "models/gemini-1.5-pro"]
        );
        assert!(gemini_models("{}").is_empty());
    }

    #[test]
    fn gkeyx_verdict_matrix() {
        let mk = |family: &'static str, service: &'static str, status: GProbeStatus| GProbe {
            family,
            service,
            status,
            detail: String::new(),
        };
        let probes = vec![
            mk("LLM", "gemini", GProbeStatus::Granted),
            mk("MAPS", "staticmap", GProbeStatus::Granted),
            mk("DATA", "youtube", GProbeStatus::Denied),
        ];
        let (v, d) = gkeyx_verdict(&probes);
        assert_eq!(v, "VALIDE");
        assert!(d.contains("gemini"), "{d}");
        assert!(d.contains("LLM"), "{d}");

        let constrained = vec![
            mk("MAPS", "staticmap", GProbeStatus::Constrained),
            mk("DATA", "youtube", GProbeStatus::Constrained),
        ];
        assert_eq!(gkeyx_verdict(&constrained).0, "VALIDE_RESTREINTE");

        let denied = vec![
            mk("LLM", "gemini", GProbeStatus::Denied),
            mk("MAPS", "staticmap", GProbeStatus::Denied),
        ];
        assert_eq!(gkeyx_verdict(&denied).0, "INVALIDE");

        let inc = vec![mk("LLM", "gemini", GProbeStatus::Inconclusive)];
        assert_eq!(gkeyx_verdict(&inc).0, "NON_VERIFIABLE");
    }
}
