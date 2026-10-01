//! redisx — preuve d'exposition publique d'un service Redis (port 6379).
//!
//! Non destructif : UNE seule connexion TCP, envoi de la commande inline
//! `PING` (lecture seule, aucune écriture), lecture de la réponse RESP,
//! AUCUNE credential. Verdicts :
//!   - REDIS_EXPOSE_PUBLIC   : +PONG reçu (service utilisable anonymement)
//!   - REDIS_AUTH_REQUISE    : -NOAUTH / -ERR operation not permitted
//!   - REDIS_PROTEGE_ACL     : -ERR ACL (user par défaut désactivé)
//!   - REDIS_EDGE_FANTOME    : réponse HTTP ou silence = pas un redis
//!   - REDIS_INJOIGNABLE
//!
//! Règles du crate impact : lecture seule, secrets masqués, timeout dur,
//! persistance audit_impact (module=redisx). args() only, jamais de sh -c.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::net::ToSocketAddrs;
use std::time::Duration;

fn esc(s: &str) -> String {
    s.replace('\'', "''")
}

fn psql_rows(sql: &str) -> Vec<String> {
    let out = std::process::Command::new("sudo")
        .args([
            "-n",
            "-u",
            "postgres",
            "psql",
            "-d",
            "veridy_audit",
            "-tAc",
            sql,
        ])
        .output();
    match out {
        Ok(o) if o.status.success() => String::from_utf8_lossy(&o.stdout)
            .lines()
            .map(|l| l.to_string())
            .collect(),
        _ => Vec::new(),
    }
}

fn save_verdict(module: &str, target: &str, verdict: &str, detail: &str, evidence: &str) {
    psql_rows(&format!(
        "INSERT INTO audit_impact (module, target, verdict, detail, evidence) \
         VALUES ('{m}', '{t}', '{v}', '{d}', '{e}')",
        m = esc(module),
        t = esc(target),
        v = esc(verdict),
        d = esc(detail),
        e = esc(evidence),
    ));
}

/// Masque toute IPv4 dans un message (notre IP d'audit ne doit pas fuiter).
fn redact_ips(s: &str) -> String {
    let pat = regex::Regex::new(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b").unwrap();
    pat.replace_all(s, "x.x.x.x").into_owned()
}

/// Masque la version Redis : garde majeur.mineur seulement.
#[allow(dead_code)] // reserve a un futur verdict INFO (version complete non requise par PING)
fn mask_version(v: &str) -> String {
    let parts: Vec<&str> = v.split('.').collect();
    if parts.len() >= 2 {
        format!("{}.{}.x", parts[0], parts[1])
    } else {
        "x.x".into()
    }
}

/// Parse une réponse RESP simple : `-ERR message\r\n`, `+PONG\r\n`,
/// ou `-NOAUTH ...`. Retourne (type, message).
fn parse_resp(data: &[u8]) -> Option<(char, String)> {
    if data.is_empty() {
        return None;
    }
    let t = data[0] as char;
    if !matches!(t, '+' | '-' | '$' | ':' | '*') {
        return None;
    }
    let end = data.iter().position(|&b| b == b'\n')?;
    let line = String::from_utf8_lossy(&data[1..end]).trim().to_string();
    Some((t, line))
}

fn probe(host: &str, port: u16) -> (String, String, String) {
    let addr = format!("{host}:{port}");
    let sock = match addr.to_socket_addrs().ok().and_then(|mut i| i.next()) {
        Some(a) => a,
        None => {
            return (
                "REDIS_INJOIGNABLE".into(),
                "résolution DNS échouée".into(),
                String::new(),
            )
        }
    };
    let mut stream = match TcpStream::connect_timeout(&sock, Duration::from_secs(6)) {
        Ok(s) => s,
        Err(e) => {
            return (
                "REDIS_INJOIGNABLE".into(),
                format!("TCP {port} refusé/timeout: {e}"),
                String::new(),
            )
        }
    };
    let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
    let _ = stream.set_write_timeout(Some(Duration::from_secs(5)));

    // PING inline : lecture seule, aucune clé touchée.
    if let Err(e) = stream.write_all(b"PING\r\n") {
        return (
            "REDIS_EDGE_FANTOME".into(),
            format!("connexion perdue avant réponse: {e}"),
            String::new(),
        );
    }
    let mut buf = [0u8; 512];
    let n = match stream.read(&mut buf) {
        Ok(n) if n > 0 => n,
        _ => {
            return (
                "REDIS_EDGE_FANTOME".into(),
                "port accepté mais silence total après PING — pas un redis prouvé".into(),
                String::new(),
            )
        }
    };
    let data = &buf[..n];

    let head = String::from_utf8_lossy(&data[..data.len().min(60)]).to_string();
    if head.starts_with("HTTP/") {
        return (
            "REDIS_EDGE_FANTOME".into(),
            "réponse HTTP — artefact edge/WAF, pas un redis".into(),
            format!("first-line: {}", head.lines().next().unwrap_or("")),
        );
    }

    let Some((t, line)) = parse_resp(data) else {
        return (
            "REDIS_EDGE_FANTOME".into(),
            "réponse non-RESP".into(),
            format!(
                "hex head: {}",
                data[..data.len().min(24)]
                    .iter()
                    .map(|b| format!("{b:02x}"))
                    .collect::<String>()
            ),
        );
    };

    match (t, line.as_str()) {
        ('+', "PONG") => (
            "REDIS_EXPOSE_PUBLIC".into(),
            "Redis répond +PONG sans authentification : service utilisable anonymement en lecture ET écriture".into(),
            "PING -> +PONG (aucune auth exigée)".into(),
        ),
        ('-', l) if l.starts_with("NOAUTH") => (
            "REDIS_AUTH_REQUISE".into(),
            "Redis réel exposé — authentification exigée (requirepass/ACL)".into(),
            format!("PING -> -{}", redact_ips(l)),
        ),
        ('-', l) if l.contains("operation not permitted") => (
            "REDIS_AUTH_REQUISE".into(),
            "Redis réel exposé — commandes refusées sans auth (mode protégé ou ACL)".into(),
            format!("PING -> -{}", redact_ips(l)),
        ),
        ('-', l) if l.to_lowercase().contains("acl") || l.contains("WRONGPASS") || l.contains("authenticated") => (
            "REDIS_PROTEGE_ACL".into(),
            "Redis réel exposé — ACL active (user par défaut restreint)".into(),
            format!("PING -> -{}", redact_ips(l)),
        ),
        _ => (
            "REDIS_EXPOSE_PUBLIC".into(),
            "Redis réel exposé — réponse RESP inattendue au PING".into(),
            format!("type {t}: {}", redact_ips(&line)),
        ),
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        eprintln!(
            "usage: redisx <hote> [port]  (preuve exposition Redis, defaut 6379, lecture seule)"
        );
        std::process::exit(2);
    }
    let host = &args[1];
    let port: u16 = args.get(2).and_then(|p| p.parse().ok()).unwrap_or(6379);
    let (verdict, detail, evidence) = probe(host, port);
    println!("hôte     : {host}");
    println!("verdict  : {verdict}");
    println!("détail   : {detail}");
    if !evidence.is_empty() {
        println!("preuve   : {evidence}");
    }
    save_verdict("redisx", host, &verdict, &detail, &evidence);
    let code = match verdict.as_str() {
        "REDIS_EXPOSE_PUBLIC" => 0,
        "REDIS_AUTH_REQUISE" | "REDIS_PROTEGE_ACL" => 0,
        _ => 1,
    };
    std::process::exit(code);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_redisx_parse_resp_pong() {
        let (t, line) = parse_resp(b"+PONG\r\n").expect("parse");
        assert_eq!(t, '+');
        assert_eq!(line, "PONG");
    }

    #[test]
    fn test_redisx_parse_resp_noauth() {
        let (t, line) = parse_resp(b"-NOAUTH Authentication required.\r\n").expect("parse");
        assert_eq!(t, '-');
        assert!(line.starts_with("NOAUTH"));
    }

    #[test]
    fn test_redisx_parse_resp_rejects_http() {
        assert!(parse_resp(b"HTTP/1.1 400 Bad Request\r\n").is_none());
    }

    #[test]
    fn test_redisx_mask_version() {
        assert_eq!(mask_version("7.2.4"), "7.2.x");
        assert_eq!(mask_version("v=6.0.16"), "v=6.0.x");
        assert_eq!(mask_version("single"), "x.x");
    }

    #[test]
    fn test_redisx_redact_ips() {
        let masked = redact_ips("client from 192.168.40.5 denied");
        assert!(!masked.contains("192.168"), "IP fuit: {masked}");
        assert!(masked.contains("x.x.x.x"));
    }
}
