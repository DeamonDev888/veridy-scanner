//! elasticx — preuve d'exposition publique d'un service Elasticsearch
//! (port 9200, API REST HTTP).
//!
//! Non destructif : UNE seule requête HTTP GET "/" (la racine renvoie
//! spontanément cluster_name / version / lucene_version — jamais de
//! recherche, jamais d'écriture, AUCUNE credential). Verdicts :
//!   - ELASTIC_EXPOSE_PUBLIC : JSON racine avec "cluster_name" et
//!     "version" (pas d'auth exigée, version divulgée)
//!   - ELASTIC_AUTH_REQUISE  : 401/403 avec body JSON (security activée)
//!   - ELASTIC_EDGE_FANTOME  : autre réponse HTTP / silence : pas un ES
//!   - ELASTIC_INJOIGNABLE
//!
//! Règles du crate impact : lecture seule, secrets masqués, timeout dur,
//! persistance audit_impact (module=elasticx). args() only, jamais de sh -c.

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

/// Masque toute IPv4 dans un message (notre IP d'audit ne doit pas finir en evidence).
fn redact_ips(s: &str) -> String {
    let pat = regex::Regex::new(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b").unwrap();
    pat.replace_all(s, "x.x.x.x").into_owned()
}

/// Masque la version complète (majeur.mineur seulement).
fn mask_version(v: &str) -> String {
    let parts: Vec<&str> = v.split('.').collect();
    if parts.len() >= 2 {
        format!("{}.{}.x", parts[0], parts[1])
    } else {
        "x.x".into()
    }
}

/// Extrait "number" (version) d'un body JSON racine Elasticsearch.
/// Parse volontairement minimal (une clé, guillemets doubles) : pas de
/// serde pour rester zéro-dépassement du pattern mysqlx (socket pure).
fn extract_es_version(body: &str) -> Option<String> {
    // "version" : { ... "number" : "8.11.1" ... }
    let idx = body.find("\"number\"")?;
    let after = &body[idx + "\"number\"".len()..];
    let q1 = after.find('"')?;
    let rest = &after[q1 + 1..];
    let q2 = rest.find('"')?;
    let v = &rest[..q2];
    if v.is_empty() || !v.bytes().next().is_some_and(|b| b.is_ascii_digit()) {
        return None;
    }
    Some(v.to_string())
}

/// Extrait "cluster_name" d'un body JSON racine Elasticsearch.
fn extract_es_cluster(body: &str) -> Option<String> {
    let idx = body.find("\"cluster_name\"")?;
    let after = &body[idx + "\"cluster_name\"".len()..];
    let q1 = after.find('"')?;
    let rest = &after[q1 + 1..];
    let q2 = rest.find('"')?;
    let c = &rest[..q2];
    if c.is_empty() {
        return None;
    }
    Some(c.to_string())
}

/// GET HTTP "/" sur host:port, une seule tentative, timeout dur.
/// Retourne (status, content_type, body tronqué).
fn http_get_root(host: &str, port: u16) -> Result<(u16, String, String), String> {
    let addr = format!("{host}:{port}");
    let sock = addr
        .to_socket_addrs()
        .ok()
        .and_then(|mut i| i.next())
        .ok_or_else(|| "résolution DNS échouée".to_string())?;
    let mut stream =
        TcpStream::connect_timeout(&sock, Duration::from_secs(6)).map_err(|e| e.to_string())?;
    let _ = stream.set_read_timeout(Some(Duration::from_secs(6)));
    let _ = stream.set_write_timeout(Some(Duration::from_secs(6)));
    let req = format!(
        "GET / HTTP/1.1\r\nHost: {host}\r\nUser-Agent: elasticx-probe\r\nAccept: application/json\r\nConnection: close\r\n\r\n"
    );
    stream
        .write_all(req.as_bytes())
        .map_err(|e| e.to_string())?;
    let mut raw = Vec::new();
    let mut buf = [0u8; 4096];
    loop {
        match stream.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                raw.extend_from_slice(&buf[..n]);
                if raw.len() > 64 * 1024 {
                    break; // borne dure : on ne lit jamais plus de 64 Ko
                }
            }
            Err(_) => break,
        }
    }
    if raw.is_empty() {
        return Err("silence total (connexion fermée sans réponse)".into());
    }
    let text = String::from_utf8_lossy(&raw).to_string();
    let status_line = text.lines().next().unwrap_or("");
    let status: u16 = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| format!("ligne de statut non parsable: {status_line}"))?;
    let content_type = text
        .lines()
        .find(|l| l.to_ascii_lowercase().starts_with("content-type:"))
        .map(|l| l.split(':').nth(1).unwrap_or("").trim().to_string())
        .unwrap_or_default();
    let body = match text.find("\r\n\r\n") {
        Some(i) => text[i + 4..].to_string(),
        None => String::new(),
    };
    Ok((status, content_type, body))
}

fn probe(host: &str, port: u16) -> (String, String, String) {
    let (status, ctype, body) = match http_get_root(host, port) {
        Ok(v) => v,
        Err(e) => {
            // DNS KO, TCP refusé ou timeout = rien n'écoute : INJOIGNABLE.
            // Seul le silence APRÈS connexion acceptée = edge fantôme.
            let verdict = if e.contains("résolution")
                || e.contains("refused")
                || e.contains("timed out")
                || e.contains("Timeout")
                || e.contains("unreachable")
            {
                "ELASTIC_INJOIGNABLE"
            } else {
                "ELASTIC_EDGE_FANTOME"
            };
            return (verdict.into(), e, String::new());
        }
    };
    let head = body.chars().take(400).collect::<String>();
    // 1. Racine JSON avec cluster_name + version = Elasticsearch sans auth
    if (status == 200 || status == 401 || status == 403)
        && body.contains("\"cluster_name\"")
        && body.contains("\"number\"")
    {
        let cluster = extract_es_cluster(&body).unwrap_or_else(|| "?".into());
        let version = extract_es_version(&body).unwrap_or_else(|| "?".into());
        if status == 200 {
            return (
                "ELASTIC_EXPOSE_PUBLIC".into(),
                "racine Elasticsearch accessible sans auth : cluster et version divulgés (aucune requête de recherche émise)".into(),
                format!("cluster_name={}, version={}", redact_ips(&cluster), mask_version(&version)),
            );
        }
        return (
            "ELASTIC_AUTH_REQUISE".into(),
            "service Elasticsearch réel derrière auth (401/403 JSON avec cluster_name)".into(),
            format!("HTTP {status}, cluster_name={}", redact_ips(&cluster)),
        );
    }
    // 2. 401/403 JSON générique (basic auth security sans cluster_name)
    if (status == 401 || status == 403)
        && (ctype.contains("json") || head.trim_start().starts_with('{'))
    {
        return (
            "ELASTIC_AUTH_REQUISE".into(),
            "auth exigée (401/403 JSON) — service réel, accès contrôlé".into(),
            format!("HTTP {status}, content-type: {ctype}"),
        );
    }
    // 3. Autre chose : edge fantôme ou service non-ES
    let first_line = body.lines().next().unwrap_or("").to_string();
    let snippet: String = if first_line.is_empty() {
        head.chars().take(80).collect()
    } else {
        first_line.chars().take(80).collect()
    };
    (
        "ELASTIC_EDGE_FANTOME".into(),
        format!("réponse HTTP {status} sans signature Elasticsearch sur :{port}"),
        format!("first-line: {}", redact_ips(&snippet)),
    )
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        eprintln!("usage: elasticx <hote> [port]  (preuve exposition Elasticsearch, defaut 9200, lecture seule)");
        std::process::exit(2);
    }
    let host = &args[1];
    let port: u16 = args.get(2).and_then(|p| p.parse().ok()).unwrap_or(9200);
    let (verdict, detail, evidence) = probe(host, port);
    println!("hôte     : {host}");
    println!("verdict  : {verdict}");
    println!("détail   : {detail}");
    if !evidence.is_empty() {
        println!("preuve   : {evidence}");
    }
    save_verdict("elasticx", host, &verdict, &detail, &evidence);
    let code = match verdict.as_str() {
        "ELASTIC_EXPOSE_PUBLIC" | "ELASTIC_AUTH_REQUISE" => 0,
        _ => 1,
    };
    std::process::exit(code);
}

#[cfg(test)]
mod tests {
    use super::*;

    const ES_ROOT_200: &str = "{\n  \"name\" : \"node-1\",\n  \"cluster_name\" : \"prod-cluster\",\n  \"cluster_uuid\" : \"abc123\",\n  \"version\" : {\n    \"number\" : \"8.11.1\",\n    \"build_flavor\" : \"default\"\n  },\n  \"tagline\" : \"You Know, for Search\"\n}";

    const ES_ROOT_401: &str = "{\n  \"error\" : \"Incorrect HTTP method for uri [/] and method [GET], allowed: [GET]\",\n  \"status\" : 401\n}";

    #[test]
    fn test_elasticx_extract_version() {
        assert_eq!(extract_es_version(ES_ROOT_200).as_deref(), Some("8.11.1"));
        assert_eq!(extract_es_version("no version here"), None);
    }

    #[test]
    fn test_elasticx_extract_cluster() {
        assert_eq!(
            extract_es_cluster(ES_ROOT_200).as_deref(),
            Some("prod-cluster")
        );
        assert_eq!(extract_es_cluster(ES_ROOT_401), None);
    }

    #[test]
    fn test_elasticx_mask_version() {
        assert_eq!(mask_version("8.11.1"), "8.11.x");
        assert_eq!(mask_version("7.17.16"), "7.17.x");
        assert_eq!(mask_version("single"), "x.x");
    }

    #[test]
    fn test_elasticx_redact_ips() {
        let m = redact_ips("connect from 10.10.10.10 ok");
        assert!(m.contains("x.x.x.x"), "non masque: {m}");
        let m2 = redact_ips("cluster prod-abc-1 ready");
        assert!(m2.contains("prod-abc-1"), "nom cluster altere: {m2}");
    }
}
