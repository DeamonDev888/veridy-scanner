//! mongodx — preuve d'exposition publique d'un service MongoDB (port 27017).
//!
//! Non destructif : UNE seule connexion, commande `hello` (ex isMaster)
//! via OP_MSG wire protocol, lecture de la réponse BSON, AUCUNE credential.
//! La réponse hello divulgue isWritablePrimary + maxWireVersion + helloOk.
//! Verdicts :
//!   - MONGO_EXPOSE_PUBLIC   : réponse BSON valide (service joignable)
//!   - MONGO_AUTH_REQUISE    : errmsg "auth required" / code 13 Unauthorized
//!   - MONGO_EDGE_FANTOME    : réponse HTTP ou silence = pas un mongod
//!   - MONGO_INJOIGNABLE
//!
//! Règles du crate impact : lecture seule, timeout dur, persistance
//! audit_impact (module=mongodx). args() only, jamais de sh -c.

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

fn redact_ips(s: &str) -> String {
    let pat = regex::Regex::new(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b").unwrap();
    pat.replace_all(s, "x.x.x.x").into_owned()
}

/// Construit une requête OP_MSG `hello` minimale (BSON {hello:1}).
/// OP_MSG : struct{i32 msgLength, i32 requestID, i32 responseTo, i32 opCode=2013,
/// u32 flagBits=0, section kind=0, body BSON}.
fn build_hello_opmsg() -> Vec<u8> {
    // BSON body: int32 len + (string "hello" + int32 1) + 0x00
    // Élément type 0x10 (int32), clé "hello", valeur 1.
    let mut body: Vec<u8> = Vec::new();
    body.push(0x10); // int32
    body.extend_from_slice(b"hello\x00");
    body.extend_from_slice(&1i32.to_le_bytes());
    body.push(0x00); // fin document
    let body_len = (body.len() + 4) as i32;
    let mut bson = body_len.to_le_bytes().to_vec();
    bson.extend_from_slice(&body);

    let total_len = (16 + 4 + 1 + bson.len()) as i32;
    let mut msg: Vec<u8> = Vec::new();
    msg.extend_from_slice(&total_len.to_le_bytes());
    msg.extend_from_slice(&1i32.to_le_bytes()); // requestID
    msg.extend_from_slice(&0i32.to_le_bytes()); // responseTo
    msg.extend_from_slice(&2013i32.to_le_bytes()); // OP_MSG
    msg.extend_from_slice(&0u32.to_le_bytes()); // flagBits
    msg.push(0x00); // section kind 0
    msg.extend_from_slice(&bson);
    msg
}

/// Extrait une chaîne lisible d'une réponse BSON pour l'evidence
/// (cherche les clés/marqueurs connus : isWritablePrimary, maxWireVersion...).
fn bson_markers(data: &[u8]) -> Vec<&'static str> {
    let mut found = Vec::new();
    let text = String::from_utf8_lossy(data);
    if text.contains("isWritablePrimary") {
        found.push("isWritablePrimary");
    }
    if text.contains("maxWireVersion") {
        found.push("maxWireVersion");
    }
    if text.contains("helloOk") {
        found.push("helloOk");
    }
    if text.contains("ismaster") || text.contains("isMaster") {
        found.push("isMaster");
    }
    if text.contains("logicalSessionTimeoutMinutes") {
        found.push("logicalSessionTimeoutMinutes");
    }
    found
}

/// Détecte un refus d'auth dans la réponse BSON (code 13 = Unauthorized,
/// errmsg contient "auth" ou "requires authentication").
fn bson_auth_refused(data: &[u8]) -> bool {
    let text = String::from_utf8_lossy(data).to_lowercase();
    text.contains("unauthorized")
        || text.contains("requires authentication")
        || text.contains("authentication required")
        || text.contains("auth failed")
}

fn probe(host: &str, port: u16) -> (String, String, String) {
    let addr = format!("{host}:{port}");
    let sock = match addr.to_socket_addrs().ok().and_then(|mut i| i.next()) {
        Some(a) => a,
        None => {
            return (
                "MONGO_INJOIGNABLE".into(),
                "résolution DNS échouée".into(),
                String::new(),
            )
        }
    };
    let mut stream = match TcpStream::connect_timeout(&sock, Duration::from_secs(6)) {
        Ok(s) => s,
        Err(e) => {
            return (
                "MONGO_INJOIGNABLE".into(),
                format!("TCP {port} refusé/timeout: {e}"),
                String::new(),
            )
        }
    };
    let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
    let _ = stream.set_write_timeout(Some(Duration::from_secs(5)));

    let hello = build_hello_opmsg();
    if let Err(e) = stream.write_all(&hello) {
        return (
            "MONGO_EDGE_FANTOME".into(),
            format!("connexion perdue avant réponse: {e}"),
            String::new(),
        );
    }
    let mut buf = [0u8; 1024];
    let n = match stream.read(&mut buf) {
        Ok(n) if n > 0 => n,
        _ => {
            return (
                "MONGO_EDGE_FANTOME".into(),
                "port accepté mais silence total après hello — pas un mongod prouvé".into(),
                String::new(),
            )
        }
    };
    let data = &buf[..n];

    let head = String::from_utf8_lossy(&data[..data.len().min(60)]).to_string();
    if head.starts_with("HTTP/") {
        return (
            "MONGO_EDGE_FANTOME".into(),
            "réponse HTTP — artefact edge/WAF, pas un mongod".into(),
            format!(
                "first-line: {}",
                redact_ips(head.lines().next().unwrap_or(""))
            ),
        );
    }

    // Réponse OP_MSG : opCode attendu 2013 en position 12..16.
    let op_ok = data.len() >= 16 && {
        let op = i32::from_le_bytes([data[12], data[13], data[14], data[15]]);
        op == 2013 // OP_MSG
            || op == 2004 // OP_REPLY (ancien protocole, isMaster legacy)
    };
    let markers = bson_markers(data);
    if op_ok || !markers.is_empty() {
        if bson_auth_refused(data) {
            return (
                "MONGO_AUTH_REQUISE".into(),
                "mongod réel exposé — authentification exigée (Unauthorized)".into(),
                format!("markers: {}", markers.join(", ")),
            );
        }
        return (
            "MONGO_EXPOSE_PUBLIC".into(),
            "mongod répond au hello sans authentification préalable : service interrogeable anonymement".into(),
            format!("markers BSON: {}", markers.join(", ")),
        );
    }

    (
        "MONGO_EDGE_FANTOME".into(),
        "réponse non-BSON sur le port".into(),
        format!(
            "hex head: {}",
            redact_ips(
                &data[..data.len().min(24)]
                    .iter()
                    .map(|b| format!("{b:02x}"))
                    .collect::<String>()
            )
        ),
    )
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        eprintln!("usage: mongodx <hote> [port]  (preuve exposition MongoDB, defaut 27017, lecture seule)");
        std::process::exit(2);
    }
    let host = &args[1];
    let port: u16 = args.get(2).and_then(|p| p.parse().ok()).unwrap_or(27017);
    let (verdict, detail, evidence) = probe(host, port);
    println!("hôte     : {host}");
    println!("verdict  : {verdict}");
    println!("détail   : {detail}");
    if !evidence.is_empty() {
        println!("preuve   : {evidence}");
    }
    save_verdict("mongodx", host, &verdict, &detail, &evidence);
    let code = match verdict.as_str() {
        "MONGO_EXPOSE_PUBLIC" | "MONGO_AUTH_REQUISE" => 0,
        _ => 1,
    };
    std::process::exit(code);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mongodx_hello_opmsg_shape() {
        let msg = build_hello_opmsg();
        // longueur totale cohérente
        let len = i32::from_le_bytes([msg[0], msg[1], msg[2], msg[3]]) as usize;
        assert_eq!(len, msg.len(), "longueur OP_MSG incoherente");
        // opCode = 2013 en position 12
        let op = i32::from_le_bytes([msg[12], msg[13], msg[14], msg[15]]);
        assert_eq!(op, 2013);
        // le body contient "hello"
        assert!(String::from_utf8_lossy(&msg).contains("hello"));
    }

    #[test]
    fn test_mongodx_bson_markers_detection() {
        let fake = b"...isWritablePrimary...maxWireVersion...";
        let m = bson_markers(fake);
        assert!(m.contains(&"isWritablePrimary"));
        assert!(m.contains(&"maxWireVersion"));
        assert_eq!(m.len(), 2);
    }

    #[test]
    fn test_mongodx_auth_refused_detection() {
        assert!(bson_auth_refused(b"errmsg requires authentication"));
        assert!(bson_auth_refused(b"code 13 Unauthorized"));
        assert!(!bson_auth_refused(b"isWritablePrimary true"));
    }

    #[test]
    fn test_mongodx_redact_ips() {
        let masked = redact_ips("connect from 10.0.0.5 denied");
        assert!(!masked.contains("10.0.0.5"));
        assert!(masked.contains("x.x.x.x"));
    }
}
