//! gitdump — preuve d'impact d'un depot .git expose : remotes + identites, sans dump complet.
use std::io::Write;
use veridy_scanner::{extract_emails, extract_remotes, http_get, mask_secret};

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 2 {
        eprintln!("usage: gitdump <base-url>   (ex: https://cible/.git/)");
        std::process::exit(2);
    }
    let base = args[1].trim_end_matches('/');
    let config_url = format!("{base}/config");

    let cfg = match http_get(&config_url, 25) {
        Some(r) if r.status == 200 && !r.body.to_lowercase().contains("<html") => r.body,
        _ => {
            eprintln!("[NON EXPOSE] {config_url} injoignable ou soft-404");
            std::process::exit(1);
        }
    };

    let remotes = extract_remotes(&cfg);
    println!("[.git/config EXPOSE]");
    for u in &remotes {
        // masque un eventuel user:token@ dans l URL du remote
        let masked = match u.find("://").and_then(|i| u[i + 3..].find('@')) {
            Some(at) => {
                let i = u.find("://").unwrap() + 3;
                format!("{}****@{}", &u[..i], &u[i + at + 1..])
            }
            None => u.clone(),
        };
        println!("  remote : {masked}");
    }
    if remotes.is_empty() {
        println!("  (aucun remote — depot local)");
    }

    // log pour identites (si servi)
    if let Some(log) = http_get(&format!("{base}/logs/HEAD"), 25) {
        if log.status == 200 && !log.body.to_lowercase().contains("<html") {
            let mails = extract_emails(&log.body);
            println!("  identites ({}) :", mails.len());
            for m in mails.iter().take(10) {
                println!("    - {m}");
            }
            if let Ok(mut f) = std::fs::File::create("/tmp/gitdump_logs.txt") {
                let _ = write!(f, "{}", log.body);
            }
        }
    }
    // indice de completude : HEAD present => dump complet possible
    if let Some(h) = http_get(&format!("{base}/HEAD"), 25) {
        if h.status == 200 && h.body.starts_with("ref:") {
            println!("  [DUMP COMPLET POSSIBLE] HEAD valide — reconstruction zoner out-of-scope (lecture seule ici)");
        }
    }
    let _ = mask_secret("noop"); // garde le helper lie en cas de build --gc-sections
    std::process::exit(0);
}
