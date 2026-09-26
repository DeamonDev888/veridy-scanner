//! cnamewatch — chien de garde de takeover CNAME cloud.
//! Compagnon de cnametake : il re-vérifie périodiquement les CNAME cloud
//! d'une cible, compare avec le verdict précédent (historique audit_impact)
//! et ALERTe quand une ressource devient orpheline = fenêtre de takeover
//! ouverte. 100% lecture seule. Cron-able.
//! Usage: cnamewatch <cible>
use std::process::{Command, Stdio};

const CLOUD_DOMAINS: &[&str] = &[
    "herokuapp.com",
    "herokussl.com",
    "cloudfront.net",
    "azurewebsites.net",
    "azureedge.net",
    "cloudapp.net",
    "trafficmanager.net",
    "github.io",
    "shopify.com",
    "fastly.net",
    "pantheon.io",
    "zendesk.com",
    "surge.sh",
    "readme.io",
    "cargo.site",
    "blob.core.windows.net",
    "cloudflare.io",
];

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

fn dig_short(sub: &str, rtype: &str) -> Vec<String> {
    let out = Command::new("dig")
        .args(["+short", rtype, sub, "+time=5", "+tries=1"])
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

/// (sous-domaine, cname_cloud, orphelin?)
fn assess(sub: &str) -> Option<(String, String, bool)> {
    let cname = dig_short(sub, "CNAME").first()?.clone();
    if !CLOUD_DOMAINS.iter().any(|d| cname.contains(d)) {
        return None;
    }
    let a = dig_short(sub, "A");
    let orphan = a.is_empty() || a.iter().all(|r| r.contains("0.0.0.0"));
    Some((sub.to_string(), cname, orphan))
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 2 {
        eprintln!("usage: cnamewatch <cible>");
        std::process::exit(2);
    }
    let target = &args[1];

    let subs: Vec<String> = psql(&format!(
        "SELECT DISTINCT a.subdomain FROM audit_subdomains a \
         JOIN audit_scans s ON s.id = a.scan_id WHERE s.target = '{t}'",
        t = target.replace('\'', "''")
    ))
    .into_iter()
    .flatten()
    .collect();

    if subs.is_empty() {
        println!("[{target}] aucun sous-domaine en catalogue");
        std::process::exit(1);
    }
    println!(
        "[{target}] surveillance takeover de {} sous-domaine(s)...",
        subs.len()
    );

    let mut windows_open = 0;
    for sub in &subs {
        let Some((s, cname, orphan)) = assess(sub) else {
            continue;
        };

        // verdict précédent (dernier known pour ce sous-domaine)
        let prev = psql(&format!(
            "SELECT verdict FROM audit_impact WHERE module = 'cnamewatch' \
             AND target = '{s}' ORDER BY id DESC LIMIT 1",
            s = s.replace('\'', "''")
        ));
        let prev_v = prev.first().and_then(|r| r.first()).cloned();

        let (verdict, detail) = if orphan {
            (
                "TAKEOVER_WINDOW_OPEN",
                format!("CNAME {cname} ORPHELIN (aucun A) — recréer la ressource = contrôle du sous-domaine"),
            )
        } else {
            ("STABLE", format!("CNAME {cname} avec ressource active"))
        };

        // Alerte si bascule vers orphelin
        if orphan && prev_v.as_deref() != Some("TAKEOVER_WINDOW_OPEN") {
            println!("  🚨 [ALERTE] {s} : fenêtre de takeover OUVERTE ({cname} orphelin)");
            windows_open += 1;
        } else {
            println!("  [{verdict}] {s} → {detail}");
        }

        let _ = psql(&format!(
            "INSERT INTO audit_impact (module, target, verdict, detail) \
             VALUES ('cnamewatch', '{s}', '{v}', '{d}')",
            s = s.replace('\'', "''"),
            v = verdict,
            d = format!("{detail} (cible={target})").replace('\'', "''"),
        ));
    }
    if windows_open == 0 {
        println!(
            "\nAucune fenêtre de takeover ouverte. Verdicts persistés (historique consultable)."
        );
    } else {
        println!(
            "\n{windows_open} fenêtre(s) de takeover OUVERTE(S) — décision opérateur requise."
        );
        std::process::exit(3);
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn cloud_domains_uniques() {
        let mut v = super::CLOUD_DOMAINS.to_vec();
        v.sort();
        v.dedup();
        assert_eq!(v.len(), super::CLOUD_DOMAINS.len());
    }

    #[test]
    fn assess_none_sur_sans_cname() {
        // 127.0.0.1 n a pas de CNAME — doit retourner None sans panic
        assert!(super::assess("127.0.0.1").is_none());
    }
}
