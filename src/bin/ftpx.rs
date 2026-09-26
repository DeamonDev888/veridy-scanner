//! ftpx — preuve d'impact d'un FTP anonyme ouvert (port 21).
//! Lecture seule : tentative de login anonymous + LIST du root. Jamais
//! d'upload (STOR interdit par design).
//! Usage: ftpx <hote>
use std::process::{Command, Stdio};

fn ftp_probe(host: &str) -> (u16, String, Vec<String>) {
    let out = Command::new("curl")
        .args([
            "-s",
            "-v",
            "--ftp-pasv",
            "--max-time",
            "20",
            "--user",
            "anonymous:probe@veridy.ca",
            &format!("ftp://{host}/"),
        ])
        .stdin(Stdio::null())
        .output();
    let mut code = 0u16;
    let mut banner = String::new();
    let mut listing_lines: Vec<String> = Vec::new();
    if let Ok(o) = out {
        let verb = String::from_utf8_lossy(&o.stderr).to_string();
        for l in verb.lines() {
            let t = l.trim_start_matches("* ").trim();
            if let Some(b) = t.strip_prefix("< 220 ") {
                banner = b.to_string();
            }
            if t.starts_with("< 230 ") {
                code = 230;
            } else if t.starts_with("< 530 ") {
                code = 530;
            }
        }
        let listing = String::from_utf8_lossy(&o.stdout).to_string();
        for l in listing.lines().filter(|l| !l.trim().is_empty()) {
            // ligne de listing FTP : drwxr-xr-x ... ou -rw-r--r-- ...
            if l.starts_with('d') || l.starts_with('-') || l.contains(" ") {
                listing_lines.push(l.trim().to_string());
            }
        }
    }
    (code, banner, listing_lines)
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 2 {
        eprintln!("usage: ftpx <hote>");
        std::process::exit(2);
    }
    let host = &args[1];
    let (code, banner, listing) = ftp_probe(host);
    println!("hôte     : {host}");
    println!(
        "banner   : {}",
        if banner.is_empty() {
            "(aucun)"
        } else {
            &banner
        }
    );
    match code {
        230 => {
            println!("LOGIN    : anonymous ACCEPTÉ (230)");
            println!("fichiers lisibles en racine ({} entrées) :", listing.len());
            for l in listing.iter().take(15) {
                println!("   {l}");
            }
            if listing.len() > 15 {
                println!("   ... +{} autres", listing.len() - 15);
            }
            println!("impact   : données exposées sans authentification (lecture seule prouvée, aucun upload tenté)");
            std::process::exit(0);
        }
        530 => {
            println!("LOGIN    : anonymous REFUSÉ (530) — pas d'exposition");
            std::process::exit(1);
        }
        _ => {
            println!("LOGIN    : indéterminé (pas de réponse FTP exploitable)");
            std::process::exit(1);
        }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn aucun_stor_dans_le_binaire() {
        // garde-fou anti-régression : le module ne doit JAMAIS tenter d'upload
        let src = include_str!("ftpx.rs");
        assert!(!src.to_lowercase().contains("-t "), "STOR interdit");
        assert!(src.contains("--ftp-pasv"));
    }
}
