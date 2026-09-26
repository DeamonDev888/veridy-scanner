use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use crate::config::Config;
use crate::modules::brand_sec::BrandSecAuditor;
use crate::modules::dns::DnsAuditor;
use crate::modules::dns_hardening::DnsHardeningAuditor;
use crate::modules::dnsrecon_audit::DnsreconAuditor;
use crate::modules::email_sec::EmailSecAuditor;
use crate::modules::ffuf_audit::FfufAuditor;
use crate::modules::findings::{FindingsEngine, SecurityFinding};
use crate::modules::geo::GeoAuditor;
use crate::modules::http::HttpAuditor;
use crate::modules::http_probe::probe_parallel;
use crate::modules::loot::LootCollector;
use crate::modules::nikto_deep::NiktoAuditor;
use crate::modules::nmap_deep::NmapAuditor;
use crate::modules::nuclei_deep::NucleiAuditor;
use crate::modules::obscura_audit::ObscuraAuditor;
use crate::modules::ports::{PortScanner, EXTENDED_TARGET_PORTS};
use crate::modules::portscan_rustscan::RustScanWrapper;
use crate::modules::progress::ProgressTracker;
use crate::modules::sqli_audit::scan_urls_parallel;
use crate::modules::sslscan_audit::SslscanAuditor;
use crate::modules::subdomains::SubdomainScanner;
use crate::modules::tech_stack::TechStackAuditor;
use crate::modules::theharvester_audit::TheHarvesterAuditor;
use crate::modules::tls::TlsAuditor;
use crate::modules::vuln_audit::VulnAuditor;
use crate::modules::waf::WafAuditor;
use crate::modules::web_endpoints::WebEndpointsAuditor;
use crate::modules::whois_audit::WhoisAuditor;
use crate::report::FullAuditReport;
use crate::utils::iso_timestamp;

#[derive(serde::Serialize, serde::Deserialize)]
pub struct AuditOrchestrator;

impl AuditOrchestrator {
    pub fn run(config: &Config, first_ip: &str) -> FullAuditReport {
        let start_time = Instant::now();
        let target = &config.target;

        // 1. Définition des tâches pour le moniteur de progression interactif
        let mut task_names: Vec<&str> = vec![
            "Ports & Réseau (Core)",
            "GéoIP & Localisation",
            "Certificats TLS & Ciphers",
            "DNS & Messagerie (SPF)",
            "Sous-domaines (DNS/Recon)",
            "Endpoints & Fichiers Web",
            "En-têtes HTTP & Sécurité",
            "Vulnérabilités & Injections",
            "DNS Hardening & Durcissement",
        ];

        let mut idx_waf = None;
        let mut idx_whatweb = None;
        let mut idx_sslscan = None;
        let mut idx_dnstwist = None;
        let mut idx_ffuf = None;
        let mut idx_nmap = None;
        let mut idx_nuclei = None;
        let mut idx_nikto = None;
        let mut idx_whois = None;
        let mut idx_dnsrecon = None;
        let mut idx_theharvester = None;
        let mut idx_obscura = None;

        if config.tools.waf {
            idx_waf = Some(task_names.len());
            task_names.push("Wafw00f (Pare-feu Web)");
        }
        if config.tools.whatweb {
            idx_whatweb = Some(task_names.len());
            task_names.push("WhatWeb (Stack & Emails)");
        }
        if config.tools.sslscan {
            idx_sslscan = Some(task_names.len());
            task_names.push("SSLScan (Diagnostic TLS)");
        }
        if config.tools.dnstwist {
            idx_dnstwist = Some(task_names.len());
            task_names.push("Dnstwist (Typosquatting)");
        }
        if config.tools.ffuf {
            idx_ffuf = Some(task_names.len());
            task_names.push("Ffuf (Fuzzing SecLists)");
        }
        if config.tools.nmap {
            idx_nmap = Some(task_names.len());
            task_names.push("Nmap (Services & NSE)");
        }
        if config.tools.nuclei {
            idx_nuclei = Some(task_names.len());
            task_names.push("Nuclei (CVEs Deep Engine)");
        }
        if config.tools.nikto {
            idx_nikto = Some(task_names.len());
            task_names.push("Nikto (Audit HTTP)");
        }
        if config.tools.whois {
            idx_whois = Some(task_names.len());
            task_names.push("Whois (Registre Domaine)");
        }
        if config.tools.dnsrecon {
            idx_dnsrecon = Some(task_names.len());
            task_names.push("Dnsrecon (Audit DNS SRV)");
        }
        if config.tools.theharvester {
            idx_theharvester = Some(task_names.len());
            task_names.push("theHarvester (OSINT)");
        }
        if config.tools.obscura {
            idx_obscura = Some(task_names.len());
            task_names.push("Obscura (DOM V8 & PNG)");
        }
        let mut idx_httpx = None;
        let mut idx_rustscan = None;
        let mut idx_sqlmap = None;
        if config.tools.httpx {
            idx_httpx = Some(task_names.len());
            task_names.push("Httpx (Probe HTTP + Tech)");
        }
        if config.tools.rustscan {
            idx_rustscan = Some(task_names.len());
            task_names.push("RustScan (Balayage 65535)");
        }
        if config.tools.sqlmap {
            idx_sqlmap = Some(task_names.len());
            task_names.push("SQLMap (Injections SQL)");
        }

        let progress_enabled = !config.json_mode;
        let tracker = ProgressTracker::new(target, &task_names, progress_enabled);
        let ticker_handle = tracker.start();

        // 2. Spawning des modules natifs Core en parallèle
        let tracker_ports = Arc::clone(&tracker);
        let t_ports = target.clone();
        let custom_ports = config.custom_ports.clone();
        let timeout_ms = config.timeout_ms;
        let handle_ports = thread::spawn(move || {
            let t0 = Instant::now();
            tracker_ports.set_running(0, "Balayage SYN/Connect des 75+ ports critiques...");
            let ports = custom_ports.as_deref().unwrap_or(EXTENDED_TARGET_PORTS);
            run_guarded(t0, &tracker_ports, 0, "Ports", move || {
                PortScanner::scan(&t_ports, ports, Duration::from_millis(timeout_ms))
            })
        });

        let tracker_geo = Arc::clone(&tracker);
        let ip_geo = first_ip.to_string();
        let handle_geo = thread::spawn(move || {
            let t0 = Instant::now();
            tracker_geo.set_running(1, "Géolocalisation IP & résolution whois...");
            run_guarded(t0, &tracker_geo, 1, "GéoIP", || GeoAuditor::audit(&ip_geo))
        });

        let tracker_tls = Arc::clone(&tracker);
        let t_tls = target.clone();
        let ip_tls = first_ip.to_string();
        let handle_tls = {
            let ip_tls = ip_tls.clone();
            thread::spawn(move || {
                let t0 = Instant::now();
                tracker_tls.set_running(2, "Inspection chaîne X.509, expiration & SAN...");
                run_guarded(t0, &tracker_tls, 2, "TLS", move || {
                    TlsAuditor::audit(&t_tls, &ip_tls)
                })
            })
        };

        let tracker_dns = Arc::clone(&tracker);
        let t_dns = target.clone();
        let handle_dns = thread::spawn(move || {
            let t0 = Instant::now();
            tracker_dns.set_running(3, "Résolution A/AAAA/MX/TXT, vérification SPF & DMARC...");
            run_guarded(t0, &tracker_dns, 3, "DNS", || DnsAuditor::audit(&t_dns))
        });

        let tracker_subs = Arc::clone(&tracker);
        let t_subs = target.clone();
        let handle_subs = thread::spawn(move || {
            let t0 = Instant::now();
            tracker_subs.set_running(4, "Découverte des sous-domaines & adresses IP...");
            // IP nue : pas de zone DNS, aucune énumération de sous-domaines
            let is_ip_target = t_subs.parse::<std::net::IpAddr>().is_ok();
            run_guarded(t0, &tracker_subs, 4, "Sous-domaines", move || {
                if is_ip_target {
                    Vec::new()
                } else {
                    SubdomainScanner::scan_with_mode(
                        &t_subs,
                        crate::modules::subdomains::ScanMode::Auto,
                    )
                }
            })
        });

        let tracker_web = Arc::clone(&tracker);
        let t_web = target.clone();
        let ip_web = first_ip.to_string();
        let handle_web = {
            let ip_web = ip_web.clone();
            thread::spawn(move || {
                let t0 = Instant::now();
                tracker_web
                    .set_running(5, "Détection des fichiers sensibles (.env, /admin, git)...");
                run_guarded(t0, &tracker_web, 5, "Endpoints", move || {
                    WebEndpointsAuditor::audit(&t_web, &ip_web)
                })
            })
        };

        let tracker_http = Arc::clone(&tracker);
        let t_http = target.clone();
        let http_ports = config.custom_ports.clone().unwrap_or_default();
        let handle_http = thread::spawn(move || {
            let t0 = Instant::now();
            tracker_http.set_running(6, "Analyse des en-têtes HTTP, HSTS, CSP & cookies...");
            run_guarded(t0, &tracker_http, 6, "HTTP", move || {
                HttpAuditor::audit(&t_http, &http_ports)
            })
        });

        let tracker_vuln = Arc::clone(&tracker);
        let t_vuln = target.clone();
        let vuln_ports = config.custom_ports.clone().unwrap_or_default();
        let handle_vuln = thread::spawn(move || {
            let t0 = Instant::now();
            tracker_vuln.set_running(7, "Recherche de vulnérabilités web génériques...");
            run_guarded(t0, &tracker_vuln, 7, "Vulnérabilités", move || {
                VulnAuditor::audit(&t_vuln, &vuln_ports)
            })
        });

        let tracker_dnsh = Arc::clone(&tracker);
        let ip_dns_h = first_ip.to_string();
        let t_dns_h = target.clone();
        let handle_dns_h = thread::spawn(move || {
            let t0 = Instant::now();
            tracker_dnsh.set_running(8, "Audit DNSSEC, récursion & durcissement serveurs...");
            run_guarded(t0, &tracker_dnsh, 8, "DNS Hardening", || {
                DnsHardeningAuditor::audit(&ip_dns_h, &t_dns_h)
            })
        });

        // 3. Spawning des modules Kali en arrière-plan
        let handle_waf = if let Some(idx) = idx_waf {
            let tracker_c = Arc::clone(&tracker);
            let t = target.clone();
            Some(thread::spawn(move || {
                let t0 = Instant::now();
                tracker_c.set_running(idx, "Envoi requêtes forgées & empreinte WAF...");
                run_guarded(t0, &tracker_c, idx, "Wafw00f", || WafAuditor::audit(&t))
            }))
        } else {
            None
        };

        let handle_whatweb = if let Some(idx) = idx_whatweb {
            let tracker_c = Arc::clone(&tracker);
            let t = target.clone();
            Some(thread::spawn(move || {
                let t0 = Instant::now();
                tracker_c.set_running(idx, "Empreinte CMS, librairies JS & adresses emails...");
                run_guarded(t0, &tracker_c, idx, "WhatWeb", || {
                    TechStackAuditor::audit(&t)
                })
            }))
        } else {
            None
        };

        let handle_sslscan = if let Some(idx) = idx_sslscan {
            let tracker_c = Arc::clone(&tracker);
            let t = target.clone();
            Some(thread::spawn(move || {
                let t0 = Instant::now();
                tracker_c.set_running(idx, "Test des ciphers TLS 1.0-1.3 & Heartbleed...");
                run_guarded(t0, &tracker_c, idx, "SSLScan", || SslscanAuditor::audit(&t))
            }))
        } else {
            None
        };

        let handle_dnstwist = if let Some(idx) = idx_dnstwist {
            let tracker_c = Arc::clone(&tracker);
            let t = target.clone();
            Some(thread::spawn(move || {
                let t0 = Instant::now();
                tracker_c.set_running(idx, "Génération variantes typosquatting & phishing...");
                run_guarded(t0, &tracker_c, idx, "Dnstwist", || {
                    BrandSecAuditor::audit(&t)
                })
            }))
        } else {
            None
        };

        let handle_ffuf = if let Some(idx) = idx_ffuf {
            let tracker_c = Arc::clone(&tracker);
            let t = target.clone();
            let ffuf_ports = config.custom_ports.clone().unwrap_or_default();
            Some(thread::spawn(move || {
                let t0 = Instant::now();
                tracker_c.set_running(idx, "Fuzzing routes sensibles via SecLists quickhits...");
                run_guarded(t0, &tracker_c, idx, "Ffuf", move || {
                    FfufAuditor::audit(&t, &ffuf_ports)
                })
            }))
        } else {
            None
        };

        let handle_nuclei = if let Some(idx) = idx_nuclei {
            let tracker_c = Arc::clone(&tracker);
            let t = target.clone();
            Some(thread::spawn(move || {
                let t0 = Instant::now();
                tracker_c.set_running(idx, "Exécution templates CVEs & failles critiques...");
                run_guarded(t0, &tracker_c, idx, "Nuclei", || NucleiAuditor::audit(&t))
            }))
        } else {
            None
        };

        let handle_nikto = if let Some(idx) = idx_nikto {
            let tracker_c = Arc::clone(&tracker);
            let t = target.clone();
            Some(thread::spawn(move || {
                let t0 = Instant::now();
                tracker_c.set_running(idx, "Scan des 6700+ fichiers dangereux & config HTTP...");
                run_guarded(t0, &tracker_c, idx, "Nikto", || NiktoAuditor::audit(&t))
            }))
        } else {
            None
        };

        let handle_whois = if let Some(idx) = idx_whois {
            let tracker_c = Arc::clone(&tracker);
            let t = target.clone();
            Some(thread::spawn(move || {
                let t0 = Instant::now();
                tracker_c.set_running(idx, "Interrogation registre de domaine & expiration...");
                run_guarded(t0, &tracker_c, idx, "Whois", || WhoisAuditor::audit(&t))
            }))
        } else {
            None
        };

        let handle_dnsrecon = if let Some(idx) = idx_dnsrecon {
            let tracker_c = Arc::clone(&tracker);
            let t = target.clone();
            Some(thread::spawn(move || {
                let t0 = Instant::now();
                tracker_c.set_running(idx, "Énumération DNS SRV, zone AXFR & Bind version...");
                run_guarded(t0, &tracker_c, idx, "Dnsrecon", || {
                    DnsreconAuditor::audit(&t)
                })
            }))
        } else {
            None
        };

        let handle_theharvester = if let Some(idx) = idx_theharvester {
            let tracker_c = Arc::clone(&tracker);
            let t = target.clone();
            Some(thread::spawn(move || {
                let t0 = Instant::now();
                tracker_c.set_running(idx, "Recherche OSINT emails d'employés & hôtes...");
                run_guarded(t0, &tracker_c, idx, "theHarvester", || {
                    TheHarvesterAuditor::audit(&t)
                })
            }))
        } else {
            None
        };

        let handle_obscura = if let Some(idx) = idx_obscura {
            let tracker_c = Arc::clone(&tracker);
            let t = target.clone();
            Some(thread::spawn(move || {
                let t0 = Instant::now();
                tracker_c.set_running(idx, "Moteur V8 : Rendu DOM & capture PNG...");
                run_guarded(t0, &tracker_c, idx, "Obscura", || ObscuraAuditor::audit(&t))
            }))
        } else {
            None
        };

        // RustScan : balayage de TOUS les ports (65535). Si le binaire rustscan
        // est absent, FALLBACK natif FullPortScanner (TCP connect async, pool
        // de 128 workers) : --rustscan garantit désormais la couverture
        // complète même sans l'outil externe.
        let handle_rustscan = if let Some(idx) = idx_rustscan {
            let tracker_c = Arc::clone(&tracker);
            let t = target.clone();
            Some(thread::spawn(move || {
                let t0 = Instant::now();
                tracker_c.set_running(idx, "Balayage des 65535 ports...");
                run_guarded(t0, &tracker_c, idx, "RustScan", || {
                    // NATIF en priorité : TCP connect 128 workers, déterministe
                    // (rustscan externe s est montré non-déterministe : ports
                    // sautés selon les runs). Le natif couvre les 65535 en ~5 s.
                    let start = Instant::now();
                    let results = crate::modules::full_portscan::FullPortScanner::scan_all(
                        &t,
                        Duration::from_millis(1200),
                        None::<fn(u16)>,
                    );
                    let mut open_ports: Vec<u16> = results.iter().map(|r| r.port).collect();
                    let elapsed = start.elapsed().as_millis() as u64;
                    // Secours rustscan si le natif n a rien vu mais que l hôte
                    // répond ailleurs (parano double-check, aucun coût si vide)
                    if open_ports.is_empty() && RustScanWrapper::is_available() {
                        if let Ok(rs) = RustScanWrapper::scan_ports(&t, 3) {
                            open_ports = rs.open_ports;
                        }
                    }
                    crate::modules::portscan_rustscan::RustScanResult {
                        host: t.clone(),
                        open_ports,
                        scan_duration_ms: elapsed,
                        success: true,
                    }
                })
            }))
        } else {
            None
        };

        let rustscan_result = handle_rustscan.map(|h| h.join().unwrap_or_default());
        // 4. Récupération des résultats Core
        let port_results = handle_ports.join().unwrap_or_default();
        let geo_result = handle_geo.join().unwrap_or_default();
        let tls_result = handle_tls.join().unwrap_or_default();
        let dns_result = handle_dns.join().unwrap_or_default();
        let subdomains_result = handle_subs.join().unwrap_or_default();
        let web_endpoints_result = handle_web.join().unwrap_or_default();
        let http_result = handle_http.join().unwrap_or_default();
        let vuln_result = handle_vuln.join().unwrap_or_default();
        let dns_hardening_result = handle_dns_h.join().unwrap_or_default();

        // Module Messagerie (protégé contre les panics, jamais re-exécuté).
        // IP nue = pas de zone DNS : on saute les ~18 requêtes dig (SPF/DKIM/MTA-STS/BIMI).
        let email_sec_result = if target.parse::<std::net::IpAddr>().is_ok() {
            EmailSecAuditor::audit_skipped_for_ip(target)
        } else {
            run_guarded(Instant::now(), &tracker, usize::MAX, "Messagerie", || {
                EmailSecAuditor::audit(
                    target,
                    dns_result.spf_record.as_deref(),
                    dns_result.dmarc_record.as_deref(),
                )
            })
        };

        // 5. Exécution conditionnelle de Nmap sur les ports découverts
        let nmap_result = if let Some(idx) = idx_nmap {
            let mut open_ports: Vec<u16> = port_results.iter().map(|p| p.port).collect();
            // Fusion avec RustScan 65535 : les ports vus par le balayage
            // complet alimentent aussi nmap (services sur ports exotiques).
            if let Some(ref rs) = rustscan_result {
                for p in &rs.open_ports {
                    if !open_ports.contains(p) {
                        open_ports.push(*p);
                    }
                }
            }
            open_ports.sort_unstable();
            open_ports.dedup();
            let t0 = Instant::now();
            tracker.set_running(
                idx,
                &format!(
                    "Scan -sV -sC approfondi sur {} port(s)...",
                    open_ports.len()
                ),
            );
            let res = run_guarded(t0, &tracker, idx, "Nmap", || {
                NmapAuditor::audit(target, &open_ports)
            });
            Some(res)
        } else {
            None
        };

        // 6. Récupération des outils Kali en arrière-plan
        let waf_result = handle_waf.map(|h| h.join().unwrap_or_default());
        let whatweb_result = handle_whatweb.map(|h| h.join().unwrap_or_default());
        let sslscan_result = handle_sslscan.map(|h| h.join().unwrap_or_default());
        let dnstwist_result = handle_dnstwist.map(|h| h.join().unwrap_or_default());
        let ffuf_result = handle_ffuf.map(|h| h.join().unwrap_or_default());

        // v0.3+ : Loot des fichiers sensibles trouves par ffuf (opt-in)
        let loot_result: Option<crate::modules::loot::LootResult> = if config.tools.loot {
            // Construit la liste des URLs a looter depuis ffuf (filtrees par extension et status 200)
            let urls_to_loot: Vec<(String, String, String)> = ffuf_result
                .as_ref()
                .map(|r| {
                    r.endpoints
                        .iter()
                        .filter(|e| {
                            e.status == 200 && !LootCollector::should_skip_extension(&e.url)
                        })
                        .map(|e| (e.url.clone(), "CRITICAL".to_string(), "WEB".to_string()))
                        .collect()
                })
                .unwrap_or_default();
            if !urls_to_loot.is_empty() {
                let loot_dir = "/var/lib/veridy/loot";
                Some(LootCollector::loot_urls(
                    0,
                    urls_to_loot,
                    &iso_timestamp(),
                    loot_dir,
                ))
            } else {
                None
            }
        } else {
            None
        };

        let nuclei_result = handle_nuclei.map(|h| h.join().unwrap_or_default());
        let nikto_result = handle_nikto.map(|h| h.join().unwrap_or_default());
        let whois_result = handle_whois.map(|h| h.join().unwrap_or_default());
        let dnsrecon_result = handle_dnsrecon.map(|h| h.join().unwrap_or_default());
        let theharvester_result = handle_theharvester.map(|h| h.join().unwrap_or_default());
        let obscura_result = handle_obscura.map(|h| h.join().unwrap_or_default());

        // Httpx : probe séquentiel APRÈS subdomains — prober racine + tous les
        // sous-domaines découverts par subfinder (c'est là toute la valeur)
        let httpx_result = if config.tools.httpx {
            if let Some(idx) = idx_httpx {
                let t0 = Instant::now();
                let mut targets: Vec<String> =
                    vec![format!("https://{}", target), format!("http://{}", target)];
                for sub in &subdomains_result {
                    targets.push(format!("https://{}", sub.subdomain));
                    targets.push(format!("http://{}", sub.subdomain));
                }
                tracker.set_running(
                    idx,
                    &format!("Probe httpx sur {} cible(s)...", targets.len()),
                );
                let res = run_guarded(t0, &tracker, idx, "Httpx", || probe_parallel(targets, 40));
                Some(res)
            } else {
                None
            }
        } else {
            None
        };

        // SQLMap : dépend des endpoints découverts — tourne en fin de chaîne
        let sqli_result = if config.tools.sqlmap {
            if let Some(idx) = idx_sqlmap {
                let t0 = Instant::now();
                tracker.set_running(idx, "Injection SQL : analyse des endpoints paramétrés...");
                let urls: Vec<String> =
                    vec![format!("https://{}", target), format!("http://{}", target)];
                let res = run_guarded(t0, &tracker, idx, "SQLMap", || scan_urls_parallel(urls, 60));
                Some(res)
            } else {
                None
            }
        } else {
            None
        };

        let mut open_ports_early: Vec<u16> = port_results.iter().map(|p| p.port).collect();
        if let Some(ref rs) = rustscan_result {
            for p in &rs.open_ports {
                if !open_ports_early.contains(p) {
                    open_ports_early.push(*p);
                }
            }
        }
        let open_smb = open_ports_early.contains(&445) || open_ports_early.contains(&139);

        // Module BoxProber : probes actifs spécifiques lab/box (FTP anonymous,
        // Redis PING, SNMP public, titres HTTP sur ports exotiques). Tourne
        // uniquement sur cible IP, après le scan de ports.
        let box_probe_result = if target.parse::<std::net::IpAddr>().is_ok() {
            let open_ports: Vec<u16> = {
                let mut v: Vec<u16> = port_results.iter().map(|p| p.port).collect();
                if let Some(ref rs) = rustscan_result {
                    for p in &rs.open_ports {
                        if !v.contains(p) {
                            v.push(*p);
                        }
                    }
                }
                v.sort_unstable();
                v.dedup();
                v
            };
            if open_ports.is_empty() {
                None
            } else {
                Some(crate::modules::box_prober::BoxProber::audit(
                    target,
                    &open_ports,
                ))
            }
        } else {
            None
        };

        // Module SmbAuditor : énumération SAMR null-session (utilisateurs,
        // hostname, domaine) dès que 445 est ouvert — polyvalent, pas HTB-only.
        let smb_audit_result = if open_smb {
            Some(crate::modules::smb_audit::SmbAuditor::audit(target))
        } else {
            None
        };

        // 7. Fin du moniteur interactif et affichage final 100%
        tracker.finish(ticker_handle);

        // 8. Évaluation experte des risques (Findings Engine)
        let mut findings = FindingsEngine::evaluate(
            &dns_result,
            &port_results,
            &http_result,
            &tls_result,
            &subdomains_result,
            &geo_result,
            &email_sec_result,
            &web_endpoints_result,
            &dns_hardening_result,
            &vuln_result,
        );

        // Enrichissement avec les constats d'outils externes
        if let Some(ref nm) = nmap_result {
            findings.extend(NmapAuditor.to_findings(nm));
        }
        if let Some(ref nu) = nuclei_result {
            findings.extend(NucleiAuditor.to_findings(nu));
        }
        if let Some(ref nk) = nikto_result {
            findings.extend(NiktoAuditor.to_findings(nk));
        }
        if let Some(ref w) = waf_result {
            findings.extend(WafAuditor.to_findings(w));
        }
        if let Some(ref tw) = whatweb_result {
            findings.extend(TechStackAuditor.to_findings(tw));
        }
        if let Some(ref ss) = sslscan_result {
            findings.extend(SslscanAuditor.to_findings(ss));
        }
        if let Some(ref bs) = dnstwist_result {
            findings.extend(BrandSecAuditor.to_findings(bs));
        }
        if let Some(ref ff) = ffuf_result {
            findings.extend(FfufAuditor.to_findings(ff));
        }
        if let Some(ref wh) = whois_result {
            findings.extend(WhoisAuditor.to_findings(wh));
        }
        if let Some(ref dr) = dnsrecon_result {
            findings.extend(DnsreconAuditor.to_findings(dr));
        }
        if let Some(ref th) = theharvester_result {
            findings.extend(TheHarvesterAuditor.to_findings(th));
        }
        if let Some(ref obs) = obscura_result {
            findings.extend(ObscuraAuditor.to_findings(obs));
        }
        if let Some(ref hp) = httpx_result {
            let live = hp.iter().filter(|r| r.status_code.is_some()).count();
            if live > 0 {
                let techs: std::collections::HashSet<String> = hp
                    .iter()
                    .flat_map(|r| r.technologies.iter().cloned())
                    .collect();
                if !techs.is_empty() {
                    let t_list: Vec<String> = techs.into_iter().collect();
                    findings.push(SecurityFinding {
                        severity: "INFO",
                        category: "HTTP",
                        title: "Technologies détectées (httpx)".to_string(),
                        recommendation: format!(
                            "Stack identifiée par httpx sur les {} hôte(s) vivants : {}",
                            live,
                            t_list.join(", ")
                        ),
                    });
                }
            }
        }
        if let Some(ref rs) = rustscan_result {
            if rs.success && !rs.open_ports.is_empty() {
                let diff_core: Vec<u16> = rs
                    .open_ports
                    .iter()
                    .filter(|p| !port_results.iter().any(|cp| cp.port == **p))
                    .cloned()
                    .collect();
                if !diff_core.is_empty() {
                    findings.push(SecurityFinding {
                        severity: "MEDIUM",
                        category: "PORT",
                        title: "Ports vus par RustScan uniquement".to_string(),
                        recommendation: format!(
                            "Ports ouverts détectés par RustScan mais absents du scan Core (75 ports ciblés) : {}. Le scan Core passe à côté de services non standards — utiliser --rustscan pour un balayage exhaustif.",
                            diff_core.iter().map(|p| p.to_string()).collect::<Vec<_>>().join(", ")
                        ),
                    });
                }
            }
        }
        if let Some(ref sq) = sqli_result {
            for f in sq.iter() {
                findings.push(SecurityFinding {
                    severity: "CRITICAL",
                    category: "SQLI",
                    title: "Injection SQL confirmée".to_string(),
                    recommendation: format!(
                        "[SQLMap] {} paramètre '{}' ({}) — types: {} — DBMS: {}",
                        f.url,
                        f.parameter,
                        f.method,
                        f.injection_type.join(", "),
                        f.dbms.as_deref().unwrap_or("inconnu")
                    ),
                });
            }
        }
        if let Some(ref bp) = box_probe_result {
            findings.extend(bp.findings.iter().cloned());
        }
        if let Some(ref sm) = smb_audit_result {
            for f in &sm.findings {
                findings.push(SecurityFinding {
                    severity: "INFO",
                    category: "SMB",
                    title: f.clone(),
                    recommendation:
                        "Voir le module SMB pour le detail utilisateur / SAMR / partage."
                            .to_string(),
                });
            }
        }

        let duration = start_time.elapsed();
        let timestamp = iso_timestamp();

        FullAuditReport::new(
            target.clone(),
            timestamp,
            duration.as_secs_f32(),
            dns_result,
            port_results,
            http_result,
            tls_result,
            subdomains_result,
            geo_result,
            email_sec_result,
            web_endpoints_result,
            dns_hardening_result,
            vuln_result,
            nmap_result,
            nuclei_result,
            nikto_result,
            waf_result,
            whatweb_result,
            sslscan_result,
            dnstwist_result,
            ffuf_result,
            whois_result,
            dnsrecon_result,
            theharvester_result,
            obscura_result,
            httpx_result,
            rustscan_result,
            sqli_result,
            loot_result,
            box_probe_result,
            smb_audit_result,
            findings,
        )
    }
}

/// Exécute un module en capturant toute panic : set_done si OK, set_failed sinon.
/// Retourne T::default() en cas de panic — JAMAIS de re-exécution synchrone
/// (l'ancien pattern join().unwrap_or_else(|_| re-audit) relançait l'outil une
/// deuxième fois sur la cible et pouvait re-paniquer dans le thread principal).
pub(crate) fn run_guarded<T: Default, F: FnOnce() -> T>(
    t0: std::time::Instant,
    tracker: &crate::modules::progress::ProgressTracker,
    idx: usize,
    name: &str,
    f: F,
) -> T {
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(f)) {
        Ok(v) => {
            tracker.set_done(idx, t0.elapsed());

            // v0.3+ : Loot des fichiers sensibles (--loot opt-in). Sera peuple par ffuf ci-dessous.
            v
        }
        Err(e) => {
            tracker.set_failed(idx, t0.elapsed());
            eprintln!("[PANIC MODULE {}] tâche marquée ÉCHEC : {:?}", name, e);
            T::default()
        }
    }
}
