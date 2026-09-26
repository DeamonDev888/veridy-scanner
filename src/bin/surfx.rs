//! surfx — cartographie offensive de la surface des sous-domaines vivants.
//! Compagnon de subalive : une fois les faux morts ressuscités, il fingerprint
//! chaque sous-domaine (titre, serveur, techno, redirection) et FLAG les
//! portals intéressants (login, admin, dev, staging, vpn, webmail...) pour
//! prioriser l'exploitation. Persiste dans audit_surface.
//! Usage: surfx <cible> [--max N]
use std::process::{Command, Stdio};

const UA: &str =
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120 Safari/537.36";
const DEFAULT_MAX: usize = 64;
const WORKERS: usize = 8;

/// Mots-clés qui font d'un sous-domaine une cible prioritaire d'exploitation.
const INTERESTING: &[&str] = &[
    "login",
    "admin",
    "signin",
    "auth",
    "vpn",
    "webmail",
    "owa",
    "jenkins",
    "grafana",
    "kibana",
    "jira",
    "gitlab",
    "staging",
    "dev.",
    ".dev",
    "test.",
    "uat",
    "qa.",
    "phpmyadmin",
    "dashboard",
    "portal",
    "portail",
    "paystub",
    "intranet",
    "extranet",
    "conf",
    "backup",
    "api",
];

fn psql(sql: &str) -> Vec<String> {
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

#[derive(Debug, Clone, Default)]
struct SurfRow {
    sub: String,
    status: u16,
    title: String,
    server: String,
    tech: Vec<String>,
    flags: Vec<String>,
}

fn techs(body: &str, headers: &str) -> Vec<String> {
    let b = body.to_lowercase();
    let h = headers.to_lowercase();
    let mut v = Vec::new();
    if h.contains("x-powered-by: asp.net") || h.contains("iis") {
        v.push("ASP.NET/IIS".into());
    }
    if b.contains("wp-content") || b.contains("wp-json") {
        v.push("WordPress".into());
    }
    if b.contains("drupal") {
        v.push("Drupal".into());
    }
    if b.contains("__next") {
        v.push("Next.js".into());
    }
    if b.contains("ng-version") {
        v.push("Angular".into());
    }
    if b.contains("shopify") {
        v.push("Shopify".into());
    }
    if b.contains("laravel_session") {
        v.push("Laravel".into());
    }
    if b.contains("phpsessid") {
        v.push("PHP".into());
    }
    if b.contains("sharepoint") || b.contains("_layouts") {
        v.push("SharePoint".into());
    }
    v
}

fn flags_for(sub: &str, body: &str) -> Vec<String> {
    let hay = format!("{} {}", sub.to_lowercase(), body.to_lowercase());
    INTERESTING
        .iter()
        .filter(|k| hay.contains(*k))
        .map(|k| (*k).to_string())
        .collect()
}

fn extract_title(body: &str) -> String {
    let low = body.to_lowercase();
    if let Some(s) = low.find("<title") {
        if let Some(gt) = low[s..].find('>') {
            let rest = &body[s + gt + 1..];
            if let Some(end) = rest.to_lowercase().find("</title>") {
                return rest[..end]
                    .split_whitespace()
                    .collect::<Vec<_>>()
                    .join(" ")
                    .chars()
                    .take(60)
                    .collect();
            }
        }
    }
    String::new()
}

fn probe(sub: &str) -> SurfRow {
    let mut row = SurfRow {
        sub: sub.to_string(),
        ..Default::default()
    };
    for scheme in ["https", "http"] {
        let out = Command::new("curl")
            .args([
                "-s",
                "-L",
                "-i",
                "--max-time",
                "6",
                "-A",
                UA,
                &format!("{scheme}://{sub}/"),
            ])
            .stdin(Stdio::null())
            .output();
        let Ok(o) = out else { continue };
        let raw = String::from_utf8_lossy(&o.stdout).to_string();
        // dernière réponse (suivant les redirects) : dernier bloc headers + corps
        let mut status = 0u16;
        let mut server = String::new();
        let mut headers = String::new();
        for part in raw.split("\r\n\r\n") {
            let lower = part.to_lowercase();
            if lower.starts_with("http/") {
                headers = part.to_string();
                if let Some(code) = part.split_whitespace().nth(1) {
                    status = code.parse().unwrap_or(0);
                }
                for hl in part.lines() {
                    if hl.to_lowercase().starts_with("server:") {
                        server = hl[7..].trim().chars().take(30).collect();
                    }
                }
            }
        }
        if status == 0 {
            continue;
        }
        let body = raw
            .rsplit_once("\r\n\r\n")
            .map(|(_, b)| b.to_string())
            .unwrap_or_default();
        row.status = status;
        row.title = extract_title(&body);
        row.server = server;
        row.tech = techs(&body, &headers);
        row.flags = flags_for(sub, &body);
        return row;
    }
    row
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        eprintln!("usage: surfx <cible> [--max N]");
        std::process::exit(2);
    }
    let target = &args[1];
    let max = args
        .iter()
        .position(|a| a == "--max")
        .and_then(|i| args.get(i + 1))
        .and_then(|v| v.parse().ok())
        .unwrap_or(DEFAULT_MAX);

    // table de persistance
    let _ = psql(
        "CREATE TABLE IF NOT EXISTS audit_surface (\
         id SERIAL PRIMARY KEY, created_at TIMESTAMPTZ NOT NULL DEFAULT now(),\
         cible TEXT NOT NULL, subdomain TEXT NOT NULL, status INT,\
         title TEXT, server TEXT, tech TEXT, flags TEXT)",
    );

    let mut subs = psql(&format!(
        "SELECT DISTINCT a.subdomain FROM audit_subdomains a \
         JOIN audit_scans s ON s.id = a.scan_id \
         WHERE s.id = (SELECT MAX(id) FROM audit_scans WHERE target = '{target}') \
         AND a.is_alive = true ORDER BY 1 LIMIT {max}"
    ));
    if subs.is_empty() {
        println!(
            "[{target}] aucun sous-domaine vivant en catalogue (lancer subalive --fix d'abord)"
        );
        std::process::exit(1);
    }
    println!(
        "[{target}] fingerprint de {} sous-domaine(s) vivant(s), {} workers...",
        subs.len(),
        WORKERS
    );

    let mut results: Vec<SurfRow> = Vec::with_capacity(subs.len());
    let chunk = subs.len().div_ceil(WORKERS);
    std::thread::scope(|scope| {
        let handles: Vec<_> = subs
            .chunks_mut(chunk.max(1))
            .map(|group| {
                let g: Vec<String> = group.to_vec();
                scope.spawn(move || g.iter().map(|s| probe(s)).collect::<Vec<_>>())
            })
            .collect();
        for h in handles {
            if let Ok(rows) = h.join() {
                results.extend(rows);
            }
        }
    });

    // tri : flaggés d'abord, puis par statut
    results.sort_by(|a, b| b.flags.len().cmp(&a.flags.len()).then(a.sub.cmp(&b.sub)));

    let flagged = results.iter().filter(|r| !r.flags.is_empty()).count();
    println!(
        "\n== SURFACE PRIORITAIRE ({flagged} flaggé(s) sur {}) ==",
        results.len()
    );
    for r in &results {
        if r.flags.is_empty() {
            continue;
        }
        println!(
            "  [{:>3}] {:<44} {} {}",
            r.status,
            r.sub,
            if r.title.is_empty() {
                String::new()
            } else {
                format!("\"{}\"", r.title)
            },
            if r.flags.is_empty() {
                String::new()
            } else {
                format!("[{}]", r.flags.join(","))
            }
        );
        let _ = psql(&format!(
            "INSERT INTO audit_surface (cible, subdomain, status, title, server, tech, flags) \
             VALUES ('{t}', '{s}', {st}, '{ti}', '{sv}', '{te}', '{fl}')",
            t = target.replace('\'', "''"),
            s = r.sub.replace('\'', "''"),
            st = r.status as i32,
            ti = r.title.replace('\'', "''"),
            sv = r.server.replace('\'', "''"),
            te = r.tech.join(",").replace('\'', "''"),
            fl = r.flags.join(",").replace('\'', "''"),
        ));
    }
    // persistance du reste (sans affichage)
    for r in &results {
        if r.flags.is_empty() {
            let _ = psql(&format!(
                "INSERT INTO audit_surface (cible, subdomain, status, title, server, tech, flags) \
                 VALUES ('{t}', '{s}', {st}, '{ti}', '{sv}', '{te}', '')",
                t = target.replace('\'', "''"),
                s = r.sub.replace('\'', "''"),
                st = r.status as i32,
                ti = r.title.replace('\'', "''"),
                sv = r.server.replace('\'', "''"),
                te = r.tech.join(",").replace('\'', "''"),
            ));
        }
    }
    println!("\n(surface complète persistée dans audit_surface)");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flags_detectent_les_portals() {
        assert!(flags_for("paystub.metro.ca", "").contains(&"paystub".to_string()));
        assert!(flags_for("x.dev.metro.ca", "").contains(&"dev.".to_string()));
        assert!(
            flags_for("portailfournisseurdev.metro.ca", "<html>Portail</html>")
                .iter()
                .any(|f| f == "portail" || f == "dev")
        );
        assert!(flags_for("banal.example.com", "rien d interessant ici").is_empty());
    }

    #[test]
    fn techs_via_signatures() {
        assert!(
            techs("<script src=/wp-content/themes/x.js>", "").contains(&"WordPress".to_string())
        );
        assert!(techs("", "X-Powered-By: ASP.NET\r\n").contains(&"ASP.NET/IIS".to_string()));
    }

    #[test]
    fn titre_extrait_et_borne() {
        assert_eq!(
            extract_title("<html><title>Mon Portail Employé</title>"),
            "Mon Portail Employé"
        );
        let long = format!("<title>{}</title>", "x".repeat(200));
        assert!(extract_title(&long).chars().count() <= 60);
    }
}
