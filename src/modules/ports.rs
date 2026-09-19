use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::sync::{mpsc, Arc, Mutex};
use std::thread;
use std::time::Duration;

/// Catalogue étendu des 75 ports d'infrastructure, web, bases de données et services distants les plus critiques
pub const EXTENDED_TARGET_PORTS: &[u16] = &[
    // Web & Proxies
    80, 443, 8000, 8008, 8080, 8443, 8888, 9000, 9090, 9443, 10000,
    // Accès distant & Administration
    21, 22, 23, 2222, 3389, 5900, 5901, // Messagerie
    25, 110, 143, 465, 587, 993, 995, 2525, // Infrastructure & Réseau
    53, 67, 68, 69, 123, 161, 162, 389, 636, 873, // Bases de données & Cache
    1433, 1521, 2049, 3306, 5432, 5984, 6379, 7474, 9200, 9300, 11211, 27017, 28017,
    // Conteneurs & Orchestration
    2375, 2376, 2379, 2380, 6443, 10250, // Queues & Bus de messages
    5672, 15672, 9092, // Outils Dev & CI/CD
    3000, 5000, 8081, 8161, 8880, 9001,
];

#[allow(dead_code)]
#[derive(Debug, Clone)]
#[derive(serde::Serialize, serde::Deserialize)]
pub struct PortScanResult {
    pub port: u16,
    pub is_open: bool,
    pub service_hint: &'static str,
    pub banner: Option<String>,
}

pub struct PortScanner;

impl PortScanner {
    /// Identifie le nom de service usuel associé au port.
    pub fn guess_service(port: u16) -> &'static str {
        match port {
            21 => "FTP",
            22 | 2222 => "SSH",
            23 => "Telnet (Insécurisé)",
            25 => "SMTP",
            53 => "DNS",
            80 | 8000 | 8008 | 8080 | 8888 => "HTTP",
            110 => "POP3",
            123 => "NTP",
            143 => "IMAP",
            161 | 162 => "SNMP",
            389 => "LDAP",
            443 | 8443 | 9443 => "HTTPS",
            465 => "SMTPS",
            587 => "Submission (SMTP)",
            636 => "LDAPS",
            873 => "Rsync",
            993 => "IMAPS",
            995 => "POP3S",
            1433 => "MSSQL",
            1521 => "Oracle DB",
            2049 => "NFS",
            2375 | 2376 => "Docker API",
            2379 | 2380 => "etcd",
            2525 => "SMTP Alt",
            3000 => "Node/React/Grafana",
            3306 => "MySQL",
            3389 => "RDP (Bureau à distance)",
            5000 => "Flask/Docker Registry",
            5432 => "PostgreSQL",
            5672 | 15672 => "RabbitMQ",
            5900 | 5901 => "VNC",
            5984 => "CouchDB",
            6379 => "Redis",
            6443 => "Kubernetes API",
            7474 => "Neo4j",
            8081 => "Nexus/Proxy",
            8161 => "ActiveMQ",
            9000 => "FastCGI / SonarQube",
            9090 => "Prometheus / Cockpit",
            9092 => "Kafka",
            9200 | 9300 => "Elasticsearch",
            10000 => "Webmin",
            10250 => "Kubelet",
            11211 => "Memcached",
            27017 | 28017 => "MongoDB",
            _ => "Service spécifique",
        }
    }

    /// Scan TCP Connect avec POOL DE THREADS BORNÉ (24 workers max, file de
    /// travail partagée) — remplace l'ancien 1-thread-OS-par-port (75 threads
    /// simultanés en plus des modules parallèles de l'orchestrateur).
    pub fn scan(target: &str, ports: &[u16], timeout: Duration) -> Vec<PortScanResult> {
        const MAX_WORKERS: usize = 24;
        let target_arc = Arc::new(target.to_string());

        let (work_tx, work_rx) = mpsc::channel::<u16>();
        let work_rx = Arc::new(Mutex::new(work_rx));
        let (res_tx, res_rx) = mpsc::channel::<PortScanResult>();

        let mut handles = Vec::new();
        let worker_count = MAX_WORKERS.min(ports.len().max(1));
        for _ in 0..worker_count {
            let rx = Arc::clone(&work_rx);
            let t = Arc::clone(&target_arc);
            let tx = res_tx.clone();
            handles.push(thread::spawn(move || loop {
                let port = {
                    let guard = rx.lock().unwrap_or_else(|e| e.into_inner());
                    guard.recv().ok()
                };
                match port {
                    Some(p) => {
                        if let Some(r) = probe_port(&t, p, timeout) {
                            let _ = tx.send(r);
                        }
                    }
                    None => break,
                }
            }));
        }

        for &port in ports {
            let _ = work_tx.send(port);
        }
        drop(work_tx);
        for handle in handles {
            let _ = handle.join();
        }
        drop(res_tx);

        let mut open_results: Vec<PortScanResult> = res_rx.into_iter().collect();
        open_results.sort_by_key(|r| r.port);
        open_results.dedup_by_key(|r| r.port);
        open_results
    }
}

/// Sonde un unique port : TCP connect + bannière spontanée + probe HEAD web.
fn probe_port(target: &str, port: u16, timeout: Duration) -> Option<PortScanResult> {
    let addr_str = format!("{}:{}", target, port);
    if let Ok(mut addrs) = addr_str.to_socket_addrs() {
        if let Some(sock_addr) = addrs.next() {
            if let Ok(mut stream) = TcpStream::connect_timeout(&sock_addr, timeout) {
                let _ = stream.set_read_timeout(Some(Duration::from_millis(600)));
                let _ = stream.set_write_timeout(Some(Duration::from_millis(600)));

                let mut banner = None;

                // Tentative de lecture spontanée (SSH, FTP, SMTP)
                let mut buf = [0u8; 256];
                if let Ok(n) = stream.read(&mut buf) {
                    if n > 0 {
                        let s = String::from_utf8_lossy(&buf[..n]).trim().to_string();
                        if !s.is_empty() {
                            banner = Some(s);
                        }
                    }
                }

                // Si rien reçu et port Web, probe HEAD
                if banner.is_none()
                    && (port == 80 || port == 8080 || port == 8000 || port == 8888)
                {
                    let probe = format!("HEAD / HTTP/1.0\r\nHost: {}\r\n\r\n", target);
                    if stream.write_all(probe.as_bytes()).is_ok() {
                        if let Ok(n) = stream.read(&mut buf) {
                            if n > 0 {
                                let s = String::from_utf8_lossy(&buf[..n])
                                    .lines()
                                    .next()
                                    .unwrap_or("")
                                    .trim()
                                    .to_string();
                                if !s.is_empty() {
                                    banner = Some(s);
                                }
                            }
                        }
                    }
                }

                return Some(PortScanResult {
                    port,
                    is_open: true,
                    service_hint: PortScanner::guess_service(port),
                    banner,
                });
            }
        }
    }
    None
}
