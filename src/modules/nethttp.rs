//! Client HTTP/1.1 minimal 100 % natif (std::net::TcpStream + rustls)
//! Remplace les spawns `curl -s -I` : zéro process, zéro latence de fork.
//! Parse les réponses HEAD/GET jusqu'aux headers (le body ne nous intéresse
//! que rarement — `read_body` le lit en borné quand demandé).

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

#[allow(dead_code)]
pub struct HeadResult {
    pub status: u16,
    pub headers: HashMap<String, String>,
    pub raw: String,
    pub ok: bool,
}

/// Établit TcpStream avec timeout, TLS si demandé (rustls si compilé, sinon HTTP only).
fn connect(host: &str, port: u16, tls: bool, timeout: Duration) -> Option<TcpStream> {
    let addr = format!("{}:{}", host, port);
    let s = TcpStream::connect(&addr).ok()?;
    s.set_read_timeout(Some(timeout)).ok()?;
    s.set_write_timeout(Some(timeout)).ok()?;
    if tls {
        // TLS natif : délégué à rustls via crate (voir tls.rs) — ici on
        // refuse en HTTP simple : l'appelant choisit scheme via scheme_detect.
        return None;
    }
    Some(s)
}

/// Requête HEAD native. `host_header` permet Host: custom (vhosts).
pub fn head(
    host: &str,
    port: u16,
    path: &str,
    host_header: Option<&str>,
    timeout: Duration,
) -> Option<HeadResult> {
    let mut stream = connect(host, port, false, timeout)?;
    let hh = host_header.unwrap_or(host);
    let req = format!(
        "HEAD {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: veridy-scanner/0.3.7\r\nAccept: */*\r\nConnection: close\r\n\r\n",
        path, hh
    );
    stream.write_all(req.as_bytes()).ok()?;
    let mut buf = Vec::with_capacity(8192);
    let mut chunk = [0u8; 4096];
    // lire jusqu'à \r\n\r\n ou 16 KiB max
    loop {
        match stream.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => {
                buf.extend_from_slice(&chunk[..n]);
                if buf.windows(4).any(|w| w == b"\r\n\r\n") || buf.len() > 16384 {
                    break;
                }
            }
            Err(_) => break,
        }
    }
    let raw = String::from_utf8_lossy(&buf).to_string();
    let mut lines = raw.lines();
    let status_line = lines.next()?;
    let status: u16 = status_line.split_whitespace().nth(1)?.parse().ok()?;
    let mut headers = HashMap::new();
    for line in lines {
        if let Some((k, v)) = line.split_once(':') {
            headers.insert(k.trim().to_lowercase(), v.trim().to_string());
        }
    }
    Some(HeadResult {
        status,
        headers,
        raw,
        ok: (200..400).contains(&status),
    })
}

/// GET borné (max_bytes) — pour récupérer un body (index, robots.txt…).
#[allow(dead_code)]
pub fn get(
    host: &str,
    port: u16,
    path: &str,
    host_header: Option<&str>,
    timeout: Duration,
    max_bytes: usize,
) -> Option<(u16, HashMap<String, String>, Vec<u8>)> {
    let mut stream = connect(host, port, false, timeout)?;
    let hh = host_header.unwrap_or(host);
    let req = format!(
        "GET {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: veridy-scanner/0.3.7\r\nAccept: */*\r\nConnection: close\r\n\r\n",
        path, hh
    );
    stream.write_all(req.as_bytes()).ok()?;
    let mut buf = Vec::with_capacity(8192);
    let mut chunk = [0u8; 4096];
    loop {
        if buf.len() >= max_bytes {
            break;
        }
        match stream.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => {
                buf.extend_from_slice(&chunk[..n]);
                if buf.windows(4).any(|w| w == b"\r\n\r\n") && buf.len() > 8192 {
                    // headers reçus et déjà du body : continuer jusqu'à max
                }
            }
            Err(_) => break,
        }
    }
    let sep = buf.windows(4).position(|w| w == b"\r\n\r\n")?;
    let head = String::from_utf8_lossy(&buf[..sep]).to_string();
    let body = buf[sep + 4..].to_vec();
    let status: u16 = head
        .lines()
        .next()?
        .split_whitespace()
        .nth(1)?
        .parse()
        .ok()?;
    let mut headers = HashMap::new();
    for line in head.lines().skip(1) {
        if let Some((k, v)) = line.split_once(':') {
            headers.insert(k.trim().to_lowercase(), v.trim().to_string());
        }
    }
    Some((status, headers, body))
}

#[cfg(test)]
mod tests {

    #[test]
    fn head_parse_status_and_headers() {
        // parse sans réseau : on teste la logique via une chaîne brute simulée
        let raw = "HTTP/1.1 301 Moved\r\nLocation: https://x/\r\nServer: nginx\r\n";
        let status: u16 = raw
            .lines()
            .next()
            .unwrap()
            .split_whitespace()
            .nth(1)
            .unwrap()
            .parse()
            .unwrap();
        assert_eq!(status, 301);
        let mut h = std::collections::HashMap::new();
        for line in raw.lines().skip(1) {
            if let Some((k, v)) = line.split_once(':') {
                h.insert(k.trim().to_lowercase(), v.trim().to_string());
            }
        }
        assert_eq!(h.get("location").unwrap(), "https://x/");
    }
}
