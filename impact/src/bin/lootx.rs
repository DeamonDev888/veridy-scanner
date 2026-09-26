//! lootx — qualifie les fichiers lootés par le scanner (audit_loot + disque).
//! Détecte secrets (env, clés, PK), dépôts git, fichiers sans valeur (licences,
//! quotas), déduplique par SHA-256, MASQUE tout secret à l'affichage.
//! Persiste le verdict dans audit_impact (module='lootx').
//! Usage: lootx [scan_id]   (sans argument = tous les scans)
use std::process::{Command, Stdio};

fn psql_rows(sql: &str) -> Vec<Vec<String>> {
    let out = Command::new("psql")
        .args([
            "-h",
            "/var/run/postgresql",
            "-U",
            "demon",
            "-d",
            "veridy_audit",
            "-tA",
            "-F",
            "\u{1f}",
            "-c",
            sql,
        ])
        .stdin(Stdio::null())
        .output();
    match out {
        Ok(o) if o.status.success() => String::from_utf8_lossy(&o.stdout)
            .lines()
            .filter(|l| !l.trim().is_empty())
            .map(|l| l.split('\u{1f}').map(|c| c.trim().to_string()).collect())
            .collect(),
        _ => Vec::new(),
    }
}

fn esc(s: &str) -> String {
    s.replace('\'', "''")
}

fn mask(v: &str) -> String {
    let n = v.chars().count();
    if n == 0 {
        return "(vide)".into();
    }
    let head: String = v.chars().take(3).collect();
    format!("{head}**** ({n} chars)")
}

/// Signatures de secrets génériques dans un contenu texte.
fn find_secrets(body: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for line in body.lines().take(500) {
        let l = line.trim();
        if let Some((k, v)) = l.split_once('=') {
            let ku = k.to_uppercase();
            if !v.is_empty()
                && (ku.contains("PASSWORD")
                    || ku.contains("SECRET")
                    || ku.contains("TOKEN")
                    || ku.contains("API_KEY")
                    || ku.contains("PRIVATE")
                    || ku.contains("DSN")
                    || ku.contains("AWS_"))
            {
                out.push((format!("env:{k}"), v.to_string()));
            }
        }
        for (pat, label) in [
            ("AIza", "cle Google"),
            ("sk_live_", "cle Stripe LIVE"),
            ("sk-proj-", "cle OpenAI"),
            ("ghp_", "token GitHub"),
            ("AKIA", "cle AWS"),
            ("BEGIN RSA PRIVATE KEY", "cle privee RSA"),
            ("BEGIN PRIVATE KEY", "cle privee"),
        ] {
            if let Some(pos) = l.find(pat) {
                let end = (pos + 48).min(l.len());
                out.push((label.to_string(), l[pos..end].to_string()));
            }
        }
    }
    out
}

fn qualifies(path: &str, body: &str) -> (String, String) {
    // (verdict, detail)
    let low = body.to_lowercase();
    if low.starts_with("ref: refs/") || low.contains("[core]") || low.contains("[user]") {
        return (
            "SENSIBLE".into(),
            format!(
                "artefact git exposé ({})",
                path.rsplit('/').next().unwrap_or(path)
            ),
        );
    }
    if low.contains("wordpress - web publishing") || path.ends_with("license.txt") {
        return (
            "SANS_VALEUR".into(),
            "licence/logiciel public, pas un secret".into(),
        );
    }
    if path.ends_with(".ftpquota") {
        return ("SANS_VALEUR".into(), "quota FTP hébergeur".into());
    }
    let secrets = find_secrets(body);
    if !secrets.is_empty() {
        return (
            "SENSIBLE".into(),
            format!("{} secret(s) détecté(s)", secrets.len()),
        );
    }
    ("NEUTRE".into(), "aucune signature de secret".into())
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let filter = if args.len() == 2 {
        format!("AND l.scan_id = {}", args[1].parse::<i64>().unwrap_or(0))
    } else {
        String::new()
    };

    let rows = psql_rows(&format!(
        "SELECT s.target, l.url, COALESCE(l.local_path,''), l.sha256, l.size_bytes, \
         COALESCE(l.first_64_bytes_hex,'') FROM audit_loot l \
         JOIN audit_scans s ON s.id = l.scan_id WHERE true {filter} ORDER BY l.id"
    ));
    if rows.is_empty() {
        println!("aucun loot en catalogue");
        std::process::exit(0);
    }

    println!("Qualification de {} fichier(s) looté(s)...", rows.len());
    let mut seen_sha: Vec<String> = Vec::new();
    let mut sensible = 0usize;
    for r in &rows {
        if r.len() < 6 {
            continue;
        }
        let (target, url, local, sha, size, hex) = (&r[0], &r[1], &r[2], &r[3], &r[4], &r[5]);
        if seen_sha.contains(sha) {
            println!("  [DOUBLON] {url} (sha déjà vu)");
            continue;
        }
        seen_sha.push(sha.clone());

        // contenu : fichier disque si présent, sinon hex des 64 premiers octets
        let body = std::fs::read_to_string(local).unwrap_or_else(|_| {
            hex.chars()
                .collect::<Vec<char>>()
                .chunks(2)
                .map(|c| {
                    u8::from_str_radix(&c.iter().collect::<String>(), 16)
                        .map(|b| b as char)
                        .unwrap_or('.')
                })
                .collect()
        });

        let (verdict, detail) = qualifies(url, &body);
        let secrets = find_secrets(&body);
        println!("  [{verdict:<12}] {target} {url} ({size} o)");
        println!("                {detail}");
        for (label, secret) in secrets.iter().take(5) {
            println!("                  !! {label} = {}", mask(secret));
        }
        if verdict == "SENSIBLE" {
            sensible += 1;
        }
        let evidence = secrets
            .first()
            .map(|(l, s)| format!("{l}={}", mask(s)))
            .unwrap_or_default();
        let _ = psql_rows(&format!(
            "INSERT INTO audit_impact (module, target, verdict, detail, evidence) \
             VALUES ('lootx', '{t}', '{v}', '{d}', '{e}')",
            t = esc(target),
            v = esc(&verdict),
            d = esc(&format!("{detail} — {url}")),
            e = esc(&evidence),
        ));
    }
    println!("\n{sensible} fichier(s) SENSIBLE(S) sur {} unique(s). Verdicts persistés dans audit_impact.", seen_sha.len());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secrets_env_detectes_masques() {
        let s = find_secrets("DB_PASSWORD=SuperSecret123\nAPP_NAME=x\nAPI_KEY=AIzaSyABCDEF");
        assert!(s.iter().any(|(l, _)| l == "env:DB_PASSWORD"));
        assert!(s.iter().any(|(l, _)| l.contains("Google")));
        assert!(!s.iter().any(|(l, _)| l == "env:APP_NAME"));
        let m = mask("SuperSecret123");
        assert!(!m.contains("SuperSecret123"));
    }

    #[test]
    fn qualification_licences_et_git() {
        assert_eq!(
            qualifies("/license.txt", "WordPress - Web publishing software").0,
            "SANS_VALEUR"
        );
        assert_eq!(
            qualifies("/.git/HEAD", "ref: refs/heads/main").0,
            "SENSIBLE"
        );
        assert_eq!(qualifies("/.ftpquota", "777 6306191").0, "SANS_VALEUR");
        assert_eq!(qualifies("/index.html", "<html>hello</html>").0, "NEUTRE");
    }
}
