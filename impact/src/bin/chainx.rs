//! chainx — dispatcher automatique détection → exploitation.
//! Lit le catalogue (dernier scan par cible) et route chaque finding vers son
//! bin d'exploitation en chaîne SÛRE (GET/DNS uniquement) :
//!   DNS DMARC-less → spoofcheck · port 21 → ftpx · WEB .env/.git confirmé →
//!   envx/gitdump (gate) · clés AIza (payload nuclei) → keyprobe ·
//!   subdomains → subalive + cnametake + surfx.
//! Persiste les verdicts dans audit_impact (evidence masquée).
//! Cibles lab/IP/LAN exclues par défaut.
//! Usage: chainx [cible] [--force]   (--force = re-pipe même si verdict récent)
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

fn run_bin(bin: &str, args: &[&str], stdin_data: Option<&str>) -> (u16, String) {
    let mut cmd = Command::new(bin);
    cmd.args(args).stdin(if stdin_data.is_some() {
        Stdio::piped()
    } else {
        Stdio::null()
    });
    let Ok(mut child) = cmd.spawn() else {
        return (127, String::new());
    };
    if let Some(data) = stdin_data {
        if let Some(ref mut si) = child.stdin {
            use std::io::Write;
            let _ = si.write_all(data.as_bytes());
        }
    }
    match child.wait_with_output() {
        Ok(o) => (
            o.status.code().unwrap_or(1) as u16,
            String::from_utf8_lossy(&o.stdout).to_string(),
        ),
        Err(_) => (126, String::new()),
    }
}

fn save_verdict(module: &str, target: &str, verdict: &str, detail: &str, evidence: &str) {
    let _ = psql_rows(&format!(
        "INSERT INTO audit_impact (module, target, verdict, detail, evidence) \
         VALUES ('{m}', '{t}', '{v}', '{d}', '{e}')",
        m = esc(module),
        t = esc(target),
        v = esc(verdict),
        d = esc(detail),
        e = esc(evidence),
    ));
}

fn has_recent_verdict(module: &str, target: &str) -> bool {
    !psql_rows(&format!(
        "SELECT 1 FROM audit_impact WHERE module = '{m}' AND target = '{t}' \
         AND created_at > now() - interval '24 hours' LIMIT 1",
        m = esc(module),
        t = esc(target),
    ))
    .is_empty()
}

/// Cible exclue du chaînage auto : lab, IP pure, LAN, cibles de test.
fn excluded(t: &str) -> bool {
    t.parse::<std::net::IpAddr>().is_ok()
        || t.starts_with("127.")
        || t.starts_with("192.168.")
        || t.starts_with("10.")
        || t.ends_with(".nmap.org")
        || t == "example.com"
        || t == "localhost"
}

fn dispatch_target(target: &str, force: bool) {
    println!("\n══ {target} ══");

    // findings du dernier scan
    let findings = psql_rows(&format!(
        "SELECT f.category, f.severity, f.title FROM audit_findings f \
         WHERE f.scan_id = (SELECT MAX(id) FROM audit_scans WHERE target = '{t}')",
        t = esc(target),
    ));
    if findings.is_empty() {
        println!("  (aucun finding — skip)");
        return;
    }
    let has = |cat: &str, needle: &str| {
        findings
            .iter()
            .any(|f| f.len() >= 3 && f[0] == cat && f[2].to_lowercase().contains(needle))
    };

    // 1. spoofcheck sur absence DMARC/SPF
    if has("DNS", "dmarc") || has("DNS", "spf") {
        if force || !has_recent_verdict("spoofcheck", target) {
            let (code, out) = run_bin("spoofcheck", &[target], None);
            let verdict = out
                .lines()
                .find_map(|l| {
                    l.strip_prefix("VERDICT")
                        .map(|v| v.trim_start_matches(':').trim().to_string())
                })
                .unwrap_or_else(|| format!("EXIT{code}"));
            println!("  spoofcheck → {verdict}");
            save_verdict(
                "spoofcheck",
                target,
                &verdict,
                out.lines().last().unwrap_or("").trim(),
                "",
            );
        } else {
            println!("  spoofcheck → déjà verdict <24h (skip, --force pour re-pipe)");
        }
    }

    // 2. ftpx sur port 21 ouvert
    let has_ftp = findings
        .iter()
        .any(|f| f.len() >= 3 && f[0] == "PORT" && f[2].contains("21/tcp"));
    if has_ftp && (force || !has_recent_verdict("ftpx", target)) {
        let (code, out) = run_bin("ftpx", &[target], None);
        let verdict = if code == 0 {
            "ANONYME_OUVERT"
        } else {
            "ANONYME_REFUSE"
        };
        println!("  ftpx → {verdict}");
        save_verdict(
            "ftpx",
            target,
            verdict,
            &out.lines().take(3).collect::<Vec<_>>().join(" | "),
            "",
        );
    }

    // 3. gates envx/gitdump sur WEB CRITICAL confirmés
    for f in &findings {
        if f.len() < 3 || f[0] != "WEB" || f[1] != "CRITICAL" {
            continue;
        }
        let t = f[2].to_lowercase();
        if t.contains(".env") && (force || !has_recent_verdict("envx", target)) {
            for base in ["https", "http"] {
                let (code, out) = run_bin("envx", &[&format!("{base}://{target}/.env")], None);
                if code == 2 {
                    continue;
                }
                let verdict = if code == 0 { "EXPOSE" } else { "NON_EXPOSE" };
                println!("  envx → {verdict}");
                save_verdict(
                    "envx",
                    target,
                    verdict,
                    out.lines().next().unwrap_or(""),
                    "",
                );
                break;
            }
        }
        if t.contains(".git") && (force || !has_recent_verdict("gitdump", target)) {
            for base in ["https", "http"] {
                let (code, out) = run_bin("gitdump", &[&format!("{base}://{target}/.git")], None);
                if code == 2 {
                    continue;
                }
                let verdict = if code == 0 { "EXPOSE" } else { "NON_EXPOSE" };
                println!("  gitdump → {verdict}");
                save_verdict(
                    "gitdump",
                    target,
                    verdict,
                    out.lines().next().unwrap_or(""),
                    "",
                );
                break;
            }
        }
    }

    // 4. clés AIza du payload nuclei → keyprobe (stdin)
    let keys = psql_rows(&format!(
        "SELECT DISTINCT (regexp_matches((s.payload->'nuclei')::text, 'AIza[A-Za-z0-9_-]{{35}}'))[1] \
         FROM audit_scans s WHERE s.target = '{t}' \
         AND s.id = (SELECT MAX(id) FROM audit_scans WHERE target = '{t}')",
        t = esc(target),
    ));
    if !keys.is_empty() && (force || !has_recent_verdict("keyprobe", target)) {
        let key = &keys[0][0];
        let (code, out) = run_bin("keyprobe", &[], Some(&format!("{key}\n")));
        let verdict = if code == 0 { "VALIDE" } else { "INVALIDE" };
        println!("  keyprobe → {verdict} ({} clé(s))", keys.len());
        save_verdict(
            "keyprobe",
            target,
            verdict,
            out.lines().next().unwrap_or(""),
            &format!(
                "{}**** ({} chars)",
                &key[..4.min(key.len())],
                key.chars().count()
            ),
        );
    }

    // 5. sous-domaines → subalive + cnametake + surfx
    let subcount: String = psql_rows(&format!(
        "SELECT COUNT(*) FROM audit_subdomains a \
         WHERE a.scan_id = (SELECT MAX(id) FROM audit_scans WHERE target = '{t}')",
        t = esc(target),
    ))
    .first()
    .and_then(|r| r.first().cloned())
    .unwrap_or_else(|| "0".into());
    if subcount.parse::<usize>().unwrap_or(0) > 0 && (force || !has_recent_verdict("surfx", target))
    {
        let (_, _) = run_bin("subalive", &[target, "--fix"], None); // corrige is_alive (donnee factuelle)
        let (_, _) = run_bin("cnametake", &["--db", target], None);
        let (_, out) = run_bin("surfx", &[target, "--max", "30"], None);
        let flagged = out
            .lines()
            .filter(|l| l.contains('[') && l.contains("200") || l.contains("flaggé"))
            .count();
        println!("  surfx → surface persistée (~{flagged} lignes affichées)");
        save_verdict(
            "surfx",
            target,
            "SURFACE_MAPPEE",
            &format!("{subcount} sous-domaines en catalogue"),
            "",
        );
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let force = args.iter().any(|a| a == "--force");
    // cible positionnelle = premier arg apres le nom du binaire qui n est pas --force
    let one = args
        .iter()
        .skip(1)
        .position(|a| a != "--force")
        .map(|i| i + 1);

    let targets: Vec<String> = if let Some(i) = one {
        vec![args[i].clone()]
    } else {
        psql_rows(
            "SELECT DISTINCT ON (target) target FROM audit_scans \
             WHERE created_at > now() - interval '30 days' ORDER BY target, created_at DESC",
        )
        .into_iter()
        .flatten()
        .filter(|t| !excluded(t))
        .collect()
    };

    println!(
        "chainx — dispatcher détection → exploitation ({} cible(s))",
        targets.len()
    );
    println!(
        "Chaîne sûre : spoofcheck · ftpx · envx/gitdump · keyprobe · subalive/cnametake/surfx"
    );
    for t in &targets {
        dispatch_target(t, force);
    }
    println!("\nVerdicts persistés — `impacts` pour le tableau de bord complet.");
}

#[cfg(test)]
mod tests {
    #[test]
    fn exclusions_lab_et_ip() {
        assert!(super::excluded("127.0.0.1"));
        assert!(super::excluded("192.168.40.15"));
        assert!(super::excluded("scanme.nmap.org"));
        assert!(super::excluded("example.com"));
        assert!(!super::excluded("metro.ca"));
        assert!(!super::excluded("savardplouffe.com"));
    }
}
