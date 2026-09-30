//! mysqlx — preuve d'exposition publique d'un service MySQL (port 3306).
//!
//! Non destructif : UNE seule connexion TCP, lecture du greeting serveur
//! (paquet d'accueil que mysqld envoie spontanément), AUCUNE credential
//! envoyée, AUCUNE requête protocole. Verdicts :
//!   - MYSQL_EXPOSE_PUBLIC   : greeting mysqld reçu (version divulgée)
//!   - MYSQL_ACL_REFUS       : greeting + ERR 1130 « Host not allowed »
//!     (service réel, accès filtré par ACL IP)
//!   - MYSQL_EDGE_FANTOME    : réponse HTTP ou silence = pas un mysqld
//!   - MYSQL_INJOIGNABLE
//!
//! Règles du crate impact : lecture seule, secrets masqués, timeout dur,
//! persistance audit_impact (module=mysqlx). args() only, jamais de sh -c.

use std::io::Read;
use std::net::TcpStream;
use std::time::Duration;

fn esc(s: &str) -> String {
    s.replace('\'', "''")
}

fn psql_rows(sql: &str) -> Vec<String> {
    let out = std::process::Command::new("sudo")
        .args(["-n", "-u", "postgres", "psql", "-d", "veridy_audit", "-tAc", sql])
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

/// Parse un paquet greeting MySQL : [len(3)][seq(1)][proto(1)][version\0]...
/// Retourne (proto, version) si le format tient.
fn parse_mysql_greeting(data: &[u8]) -> Option<(u8, String)> {
    if data.len() < 5 {
        return None;
    }
    let proto = data[4];
    // proto 8 (MySQL 3.23-4.0), 9 (4.1+), 10 (5.x/8.x) — hors plage = pas mysqld
    // On exige juste que le buffer puisse contenir au moins la version.
    if !(8..=10).contains(&proto) {
        return None;
    }
    let end = data[5..].iter().position(|&b| b == 0)? + 5;
    let version = String::from_utf8_lossy(&data[5..end]).to_string();
    if version.is_empty() || !version.bytes().next().is_some_and(|b| b.is_ascii_digit()) {
        return None;
    }
    Some((proto, version))
}

/// Masque la version complète (indice de version = divulgation : on garde
/// majeur.mineur seulement, le reste en astérisques).
fn mask_version(v: &str) -> String {
    let parts: Vec<&str> = v.split('.').collect();
    if parts.len() >= 2 {
        format!("{}.{}.x", parts[0], parts[1])
    } else {
        "x.x".into()
    }
}

fn probe(host: &str) -> (String, String, String) {
    let addr = format!("{host}:3306");
    let sock = match addr.to_socket_addrs().ok().and_then(|mut i| i.next()) {
        Some(a) => a,
        None => return ("MYSQL_INJOIGNABLE".into(), "résolution DNS échouée".into(), String::new()),
    };
    let mut stream = match TcpStream::connect_timeout(&sock, Duration::from_secs(6)) {
        Ok(s) => s,
        Err(e) => {
            return ("MYSQL_INJOIGNABLE".into(), format!("TCP 3306 refusé/timeout: {e}"), String::new())
        }
    };
    let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
    let _ = stream.set_write_timeout(Some(Duration::from_secs(5)));
    let mut buf = [0u8; 512];
    let n = match stream.read(&mut buf) {
        Ok(n) if n > 0 => n,
        _ => return ("MYSQL_EDGE_FANTOME".into(), "3306 accepté mais silence total (aucun greeting) — pas un mysqld prouvé".into(), String::new()),
    };
    let data = &buf[..n];
    // ERR packet immédiat (refus ACL avant tout échange) : header 4 + 0xff
    if data.len() > 5 && data[4] == 0xff {
        let code = u16::from(data[5]) | (u16::from(data[6]) << 8);
        let msg = String::from_utf8_lossy(&data[9..]).trim().to_string();
        if code == 1130 {
            // ER_HOST_NOT_PRIVILEGED — masking de notre IP dans l'evidence
            let msg_masked = redact_ips(&msg);
            return (
                "MYSQL_ACL_REFUS".into(),
                "mysqld réel exposé publiquement — accès refusé par ACL IP (host not allowed), aucune tentative d'auth tentée".into(),
                format!("ERR 1130: {msg_masked}"),
            );
        }
        return (
            "MYSQL_EXPOSE_PUBLIC".into(),
            "mysqld réel exposé publiquement (paquet ERR avant auth)".into(),
            format!("ERR {code} (première ligne: {})", redact_ips(&msg[..msg.len().min(60)])),
        );
    }
    match parse_mysql_greeting(data) {
        Some((proto, version)) => (
            "MYSQL_EXPOSE_PUBLIC".into(),
            "greeting mysqld reçu : service MySQL authentifiable exposé publiquement".into(),
            format!("proto {proto}, version {}", mask_version(&version)),
        ),
        None => {
            // réponse HTTP = edge qui parle HTTP partout (cf. detect_uniform_edge)
            let head = String::from_utf8_lossy(&data[..data.len().min(60)]);
            if head.starts_with("HTTP/") {
                ("MYSQL_EDGE_FANTOME".into(), "réponse HTTP sur :3306 — artefact edge/WAF, pas un mysqld".into(), format!("first-line: {}", head.lines().next().unwrap_or("")),)
            } else {
                ("MYSQL_EDGE_FANTOME".into(), "réponse non-MySQL sur :3306".into(), format!("hex head: {}", data[..data.len().min(24)].iter().map(|b| format!("{b:02x}")).collect::<String>()))
            }
        }
    }
}

/// Masque toute IPv4 dans un message (notre IP d'audit ne doit pas finir en evidence).
fn redact_ips(s: &str) -> String {
    // On cherche exactement 4 groupes pxs entre [ ] en bord de mot;
    // sinon on laisse intact (numero de telephone, timestamp, etc.).
    let pat = regex::Regex::new(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b").unwrap();
    pat.replace_all(s, "x.x.x.x").into_owned()
}

use std::net::ToSocketAddrs;



fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        eprintln!("usage: mysqlx <hote>  (preuve d'exposition MySQL :3306, lecture seule)");
        std::process::exit(2);
    }
    let host = &args[1];
    let (verdict, detail, evidence) = probe(host);
    println!("hôte     : {host}");
    println!("verdict  : {verdict}");
    println!("détail   : {detail}");
    if !evidence.is_empty() {
        println!("preuve   : {evidence}");
    }
    save_verdict("mysqlx", host, &verdict, &detail, &evidence);
    let code = match verdict.as_str() {
        "MYSQL_EXPOSE_PUBLIC" => 0,
        "MYSQL_ACL_REFUS" => 0,
        _ => 1,
    };
    std::process::exit(code);
}


#[cfg(test)]
mod tests {
    use super::*;

    // Greeting mysqld 5.x : len=0x32, seq=0, proto=10, version\0, ...
    #[allow(dead_code)]
    const _ERR_PACKET_1130: &[u8] = &[
        0x56, 0x00, 0x00, 0x00, 0xff, 0x6a, 0x04, 0x23,
        0x48, 0x59, 0x30, 0x30, 0x30, b' ', 0, 0,
    ];
    const GREETING_FIXTURE: &[u8] = &[
        0x32, 0x00, 0x00, 0x00, 0x0a, b'5', b'.', b'7', b'.', b'2', b'2', 0x00, 0, 0,
    ];

    #[test]
    fn test_mysqlx_parse_greeting_5x() {
        let (proto, version) = parse_mysql_greeting(GREETING_FIXTURE).expect("parse");
        assert_eq!(proto, 10);
        assert!(version.starts_with("5.7"), "got {}", version);
    }

    #[test]
    fn test_mysqlx_redact_ips_masks_ipv4_only() {
        let masked = redact_ips("Host '157-208-25-18.mc.derytele.com' is not allowed");
        // Pas une IPv4 : hostname intact
        assert!(masked.contains("derytele.com"), "hostname manque: {masked}");
        let masked = redact_ips("connected from 192.168.40.5 port");
        assert!(masked.contains("x.x.x.x"), "IP non masquee: {masked}");
        assert!(!masked.contains("192.168"), "IP fuit: {masked}");
    }

    #[test]
    fn test_mysqlx_mask_version_keeps_major_minor() {
        assert_eq!(mask_version("5.7.22-log"), "5.7.x");
        assert_eq!(mask_version("10.11.4-MariaDB-1:10.11.4"), "10.11.x");
        assert_eq!(mask_version("single"), "x.x");
    }
}