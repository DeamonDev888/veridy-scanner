#![allow(dead_code)]
//! Balayage TCP asynchrone des 65535 ports — mémoire O(1) par port (bitfield),
//! pings lents relancés en seconde passe, sortie identique à PortScanner.
//! Conçu pour les box HTB : un service sur port exotique ne doit JAMAIS
//! passer inaperçu parce qu'il n'est pas dans une liste de 75 ports.

use std::io;
use std::net::{TcpStream, ToSocketAddrs};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

/// État d'un port pendant le balayage : fermé / ouvert / timeout (à retenter).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PortState {
    Closed,
    Open,
    Timeout,
}

/// Résultat public aligné sur PortScanResult (migration transparente).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct FullPortScanResult {
    pub port: u16,
    pub is_open: bool,
    pub service_hint: &'static str,
    pub banner: Option<String>,
}

pub struct FullPortScanner;

impl FullPortScanner {
    /// Balaye les 65535 ports en TCP connect avec pool borné.
    /// `open_callback` est invoqué (depuis un thread de travail) à chaque
    /// port ouvert confirmé — permet l'affichage live type rustscan.
    pub fn scan_all<F: Fn(u16) + Send + Sync + 'static>(
        target: &str,
        per_connect_timeout: Duration,
        open_callback: Option<F>,
    ) -> Vec<FullPortScanResult> {
        Self::scan_range(target, 1, 65535, per_connect_timeout, open_callback)
    }

    /// Balayage d'une plage arbitraire [start, end] incluse.
    pub fn scan_range<F: Fn(u16) + Send + Sync + 'static>(
        target: &str,
        start: u16,
        end: u16,
        per_connect_timeout: Duration,
        open_callback: Option<F>,
    ) -> Vec<FullPortScanResult> {
        // Résolution UNE fois (65535 to_socket_addrs = interdit).
        let addr = format!("{}:443", target)
            .to_socket_addrs()
            .ok()
            .and_then(|mut i| i.next())
            .map(|a| a.ip());
        let addr = match addr {
            Some(ip) => ip,
            None => return Vec::new(),
        };

        // Bitfield des états : 2 bits par port (closed=0, open=1, timeout=2)
        const STATES: usize = 3; // 0=Closed 1=Open 2=Timeout
        let total = (end as usize) - (start as usize) + 1;
        let slots = (total * 2).div_ceil(8); // 2 bits par port
        let states: Arc<Vec<AtomicU64>> =
            Arc::new((0..slots.max(1)).map(|_| AtomicU64::new(0)).collect());
        let cb = open_callback.map(Arc::new);

        let worker_count = 128usize;
        let next_port = Arc::new(AtomicU64::new(start as u64));
        let end_atomic = end as u64;

        let mut handles = Vec::with_capacity(worker_count);
        for _ in 0..worker_count {
            let states = Arc::clone(&states);
            let next = Arc::clone(&next_port);
            let cb = cb.clone();
            let timeout = per_connect_timeout;
            handles.push(thread::spawn(move || loop {
                let p = next.fetch_add(1, Ordering::Relaxed);
                if p > end_atomic {
                    break;
                }
                let port = p as u16;
                let state = probe(addr, port, timeout);
                set_state(&states, (port as usize) - (start as usize), state);
                if state == PortState::Open {
                    if let Some(ref cb) = cb {
                        cb(port);
                    }
                }
            }));
        }
        for h in handles {
            let _ = h.join();
        }

        // Seconde passe : les timeouts (ports filtrés/lents) retentés une fois.
        let next_port = Arc::new(AtomicU64::new(start as u64));
        let mut handles = Vec::with_capacity(worker_count);
        for _ in 0..worker_count {
            let states = Arc::clone(&states);
            let next = Arc::clone(&next_port);
            let cb = cb.clone();
            let timeout = per_connect_timeout * 2;
            handles.push(thread::spawn(move || loop {
                let p = next.fetch_add(1, Ordering::Relaxed);
                if p > end_atomic {
                    break;
                }
                let port = p as u16;
                if get_state(&states, (port as usize) - (start as usize)) == PortState::Timeout {
                    let state = probe(addr, port, timeout);
                    set_state(&states, (port as usize) - (start as usize), state);
                    if state == PortState::Open {
                        if let Some(ref cb) = cb {
                            cb(port);
                        }
                    }
                }
            }));
        }
        for h in handles {
            let _ = h.join();
        }

        // Collecte des ouverts + bannières (réutilise le grab de ports.rs).
        let mut results = Vec::new();
        for p in start..=end {
            if get_state(&states, (p as usize) - (start as usize)) == PortState::Open {
                let banner = grab_banner(addr, p);
                results.push(FullPortScanResult {
                    port: p,
                    is_open: true,
                    service_hint: crate::modules::ports::PortScanner::guess_service(p),
                    banner,
                });
            }
        }
        results
    }
}

/// Connexion TCP avec discrimination refus-immédiat vs timeout.
fn probe(ip: std::net::IpAddr, port: u16, timeout: Duration) -> PortState {
    let sockaddr = std::net::SocketAddr::new(ip, port);
    match TcpStream::connect_timeout(&sockaddr, timeout) {
        Ok(_) => PortState::Open,
        Err(e) => match e.kind() {
            io::ErrorKind::ConnectionRefused => PortState::Closed,
            io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock | io::ErrorKind::UnexpectedEof => {
                PortState::Timeout
            }
            _ => PortState::Closed,
        },
    }
}

/// Bannière : lecture spontanée (SSH/FTP/SMTP) puis HEAD HTTP sinon.
fn grab_banner(ip: std::net::IpAddr, port: u16) -> Option<String> {
    use std::io::{Read, Write};
    let sockaddr = std::net::SocketAddr::new(ip, port);
    let mut stream = TcpStream::connect_timeout(&sockaddr, Duration::from_millis(1500)).ok()?;
    let _ = stream.set_read_timeout(Some(Duration::from_millis(700)));
    let _ = stream.set_write_timeout(Some(Duration::from_millis(700)));

    let mut buf = [0u8; 512];
    if let Ok(n) = stream.read(&mut buf) {
        if n > 0 {
            let s = String::from_utf8_lossy(&buf[..n]).trim().to_string();
            if !s.is_empty() {
                return Some(s);
            }
        }
    }

    // HEAD sur tout port muet : beaucoup de services HTTP sur ports exotiques.
    let probe = format!("HEAD / HTTP/1.0\r\nHost: {}\r\n\r\n", ip);
    if stream.write_all(probe.as_bytes()).is_ok() {
        use std::io::Write as _;
        let _ = stream.flush();
        if let Ok(n) = stream.read(&mut buf) {
            if n > 0 {
                let s = String::from_utf8_lossy(&buf[..n])
                    .lines()
                    .next()
                    .unwrap_or("")
                    .trim()
                    .to_string();
                if !s.is_empty() {
                    return Some(s);
                }
            }
        }
    }
    None
}

#[inline]
fn set_state(states: &[AtomicU64], index: usize, state: PortState) {
    let word = index / 32;
    let shift = (index % 32) * 2;
    let val = match state {
        PortState::Closed => 0u64,
        PortState::Open => 1u64,
        PortState::Timeout => 2u64,
    };
    states[word].fetch_or(val << shift, Ordering::Relaxed);
}

#[inline]
fn get_state(states: &[AtomicU64], index: usize) -> PortState {
    let word = index / 32;
    let shift = (index % 32) * 2;
    let v = (states[word].load(Ordering::Relaxed) >> shift) & 0b11;
    match v {
        1 => PortState::Open,
        2 => PortState::Timeout,
        _ => PortState::Closed,
    }
}
