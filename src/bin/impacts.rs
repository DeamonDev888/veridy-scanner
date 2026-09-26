//! impacts — dashboard de visualisation des resultats des modules d'impact.
//! Lit veridy_audit (socket peer) : verdicts audit_impact, secrets detectes,
//! loot, faux positifs confirmes. Option --live: re-verifie les cles Google.
use std::process::{Command, Stdio};

fn psql(sql: &str) -> Vec<Vec<String>> {
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

fn hdr(t: &str) {
    println!("\n{}\n{}", t, "=".repeat(t.chars().count()));
}

fn main() {
    let live = std::env::args().any(|a| a == "--live");

    hdr("MODULES D'IMPACT — veridy_audit");

    // 1. Verdicts resume
    hdr("RESUME DES VERDICTS");
    for r in
        psql("SELECT module, verdict, COUNT(*) FROM audit_impact GROUP BY 1,2 ORDER BY 1,3 DESC")
    {
        if r.len() == 3 {
            println!("  {:<12} {:<14} x{}", r[0], r[1], r[2]);
        }
    }

    // 2. Cles/secrets: verdicts keyprobe + evidence masquee
    hdr("CLES API (evidence masquee — JAMAIS la valeur complete)");
    for r in psql("SELECT target, verdict, COALESCE(evidence,'-'), LEFT(detail,70) FROM audit_impact WHERE module='keyprobe' ORDER BY verdict, target") {
        if r.len() == 4 {
            println!("  {:<22} {:<14} {:<18} {}", r[0], r[1], r[2], r[3]);
        }
    }
    println!("  (cle complete = keyprobe la re-verify, ou payload nuclei du scan)");

    // 3. Domaines usurpables
    hdr("USURPABILITE EMAIL");
    for r in psql("SELECT verdict, string_agg(target, ', ' ORDER BY target) FROM audit_impact WHERE module='spoofcheck' GROUP BY verdict ORDER BY verdict") {
        if r.len() == 2 {
            println!("  {:<10} {}", r[0], r[1]);
        }
    }

    // 4. Faux positifs confirmes (envx/gitdump)
    hdr("GATE DE CONFIRMATION (envx/gitdump)");
    for r in psql("SELECT target, module, verdict, LEFT(detail,60) FROM audit_impact WHERE module IN ('envx','gitdump') ORDER BY target") {
        if r.len() == 4 {
            println!("  {:<12} {:<9} {:<12} {}", r[0], r[1], r[2], r[3]);
        }
    }

    // 5. Secrets detectes par le scanner (findings SECRETS par cible, dernier scan)
    hdr("SECRETS DETECTES PAR LE SCANNER (findings)");
    for r in psql("SELECT DISTINCT ON (s.target) s.target, f.severity, s.created_at::date FROM audit_findings f JOIN audit_scans s ON s.id=f.scan_id WHERE f.category='SECRETS' ORDER BY s.target, s.created_at DESC") {
        if r.len() == 3 {
            println!("  {:<22} {:<8} scan du {}", r[0], r[1], r[2]);
        }
    }

    // 6. Loot
    hdr("LOOT (fichiers exfiltres en lecture seule)");
    for r in psql("SELECT s.target, COUNT(*), COALESCE(SUM(l.size_bytes),0) FROM audit_loot l JOIN audit_scans s ON s.id=l.scan_id GROUP BY s.target ORDER BY 2 DESC") {
        if r.len() == 3 {
            let octets: u64 = r[2].parse().unwrap_or(0);
            println!("  {:<22} {:>3} fichiers  {:>7} octets", r[0], r[1], octets);
        }
    }

    // 7. Re-verification live des cles
    if live {
        hdr("RE-VERIFICATION LIVE DES CLES GOOGLE");
        // extrait les cles AIza des payloads nuclei (dernier scan par cible)
        let rows = psql(
            "SELECT DISTINCT ON (s.target) s.target, \
             (SELECT string_agg(m[1], ',') FROM regexp_matches((s.payload->'nuclei')::text, 'AIza[A-Za-z0-9_-]{35}', 'g') m) \
             FROM audit_scans s WHERE (s.payload->'nuclei')::text LIKE '%AIza%' \
             ORDER BY s.target, s.created_at DESC",
        );
        if rows.is_empty() {
            println!("  (aucune cle en base)");
        }
        for r in rows {
            if r.len() == 2 && !r[1].is_empty() {
                println!("  === {} ===", r[0]);
                for key in r[1].split(',') {
                    let out = Command::new("keyprobe")
                        .stdin(Stdio::piped())
                        .stdout(Stdio::piped())
                        .stderr(Stdio::null())
                        .spawn()
                        .and_then(|mut c| {
                            use std::io::Write;
                            if let Some(ref mut si) = c.stdin {
                                let _ = si.write_all(format!("{key}\n").as_bytes());
                            }
                            c.wait_with_output()
                        });
                    match out {
                        Ok(o) => {
                            for l in String::from_utf8_lossy(&o.stdout).lines() {
                                println!("    {l}");
                            }
                        }
                        Err(_) => println!("    (keyprobe indisponible)"),
                    }
                }
            }
        }
    } else {
        println!("\nAstuce: `impacts --live` re-verifie les cles Google en temps reel (1 GET staticmap par cle).");
    }
}
