//! subalive — re-sonde les sous-domaines "morts" du catalogue et corrige la DB.
//! Motivation réelle : bug httpx stderr → subs jamais probés → marqués morts
//! à tort (api.metro.ca servait un site complet en 200).
//! Usage: subalive <cible> [--fix]   (--fix = UPDATE is_alive/http_status en DB)
use std::process::{Command, Stdio};

fn psql_rows(sql: &str) -> Vec<String> {
    let out = Command::new("psql")
        .args([
            "-h",
            "/var/run/postgresql",
            "-U",
            "demon",
            "-d",
            "veridy_audit",
            "-tA",
            "-c",
            sql,
        ])
        .stdin(Stdio::null())
        .output();
    match out {
        Ok(o) if o.status.success() => String::from_utf8_lossy(&o.stdout)
            .lines()
            .map(|l| l.trim().to_string())
            .filter(|l| !l.is_empty())
            .collect(),
        _ => Vec::new(),
    }
}

/// Sonde de vivacité honnête : GET minimal avec UA navigateur, follow redirects,
/// 2 schémas essayés. Retourne (scheme, status) si réponse HTTP obtenue.
fn probe(sub: &str) -> Option<(String, u16)> {
    for scheme in ["https", "http"] {
        let url = format!("{scheme}://{sub}/");
        let out = Command::new("curl")
            .args([
                "-s", "-o", "/dev/null", "-L", "--max-time", "8",
                "-A", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120 Safari/537.36",
                "-w", "%{http_code}", &url,
            ])
            .stdin(Stdio::null())
            .output();
        if let Ok(o) = out {
            let code = String::from_utf8_lossy(&o.stdout).trim().to_string();
            if let Ok(st) = code.parse::<u16>() {
                if st > 0 {
                    return Some((scheme.to_string(), st));
                }
            }
        }
    }
    None
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        eprintln!("usage: subalive <cible> [--fix]");
        std::process::exit(2);
    }
    let target = &args[1];
    let fix = args.iter().any(|a| a == "--fix");

    // Dernier scan de la cible + ses subs déclarés morts
    let target_esc = target.replace('\'', "''");
    let rows = psql_rows(&format!(
        "SELECT a.subdomain FROM audit_subdomains a \
         JOIN audit_scans s ON s.id = a.scan_id \
         WHERE s.id = (SELECT MAX(id) FROM audit_scans WHERE target = '{target_esc}') \
         AND a.is_alive = false"
    ));
    if rows.is_empty() {
        println!("[{target}] aucun sous-domaine mort en catalogue");
        std::process::exit(0);
    }
    let mut revived: Vec<(String, String, u16)> = Vec::new();
    println!(
        "[{target}] re-sondage de {} sous-domaine(s) déclaré(s) mort(s)...",
        rows.len()
    );
    for sub in &rows {
        match probe(sub) {
            Some((scheme, st)) => {
                println!("  VIVANT  {sub} ({scheme} {st}) — faux négatif du scan initial");
                revived.push((sub.clone(), scheme, st));
            }
            None => println!("  mort    {sub} (confirmé)"),
        }
    }
    println!(
        "\n{} subs en réalité vivants sur {} déclarés morts",
        revived.len(),
        rows.len()
    );
    if !revived.is_empty() && !fix {
        println!("(--fix pour mettre à jour audit_subdomains)");
    }
    if fix {
        for (sub, scheme, st) in &revived {
            let sql = format!(
                "UPDATE audit_subdomains a SET is_alive = true, http_status = {st} \
                 FROM audit_scans s WHERE s.id = a.scan_id \
                 AND s.id = (SELECT MAX(id) FROM audit_scans WHERE target = '{target_esc}') \
                 AND a.subdomain = '{sub_esc}'",
                sub_esc = sub.replace('\'', "''")
            );
            let n = psql_rows(&sql);
            let _ = scheme;
            println!("  DB corrigée: {sub} -> vivant ({st}) [{} lignes]", n.len());
        }
    }
}
