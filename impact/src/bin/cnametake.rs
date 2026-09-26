//! cnametake — preuve de takeover de sous-domaine par CNAME pendant.
//! Un CNAME vers un service cloud dont la ressource est supprimée (NXDOMAIN
//! ou fingerprint d'erreur cloud) = le sous-domaine est récupérable par
//! n'importe qui en recréant la ressource. LECTURE SEULE : on prouve,
//! on n'usurpe jamais.
//! Usage: cnametake <domaine> | cnametake --db <cible> (subs depuis catalogue)
use std::process::{Command, Stdio};

/// Fingerprints de services cloud dont l'absence de ressource est
/// publiquement revendiquable (takeover possible en recréant la ressource).
const TAKEOVER_FINGERPRINTS: &[(&str, &str)] = &[
    ("herokuapp.com", "no such app"),
    ("herokussl.com", "no such app"),
    ("cloudfront.net", "bad request"),
    ("azurewebsites.net", "404 web site not found"),
    ("azureedge.net", "the requested content does not exist"),
    ("cloudapp.net", "not found"),
    ("trafficmanager.net", "not found"),
    ("github.io", "there isn't a github pages site here"),
    ("shopify.com", "sorry, this shop is currently unavailable"),
    ("fastly.net", "fastly error: unknown domain"),
    ("pantheon.io", "the gods are wise"),
    ("zendesk.com", "help center closed"),
    ("surge.sh", "project not found"),
    ("readme.io", "project doesnt exist"),
    ("cargo.site", "if you're the owner"),
];

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

fn http_body(sub: &str) -> Option<(u16, String)> {
    let out = Command::new("curl")
        .args([
            "-s",
            "-L",
            "--max-time",
            "10",
            "-A",
            "Mozilla/5.0 (X11; Linux x86_64)",
            "-w",
            "\n%{http_code}",
            &format!("http://{sub}/"),
        ])
        .stdin(Stdio::null())
        .output()
        .ok()?;
    let raw = String::from_utf8_lossy(&out.stdout).to_string();
    let idx = raw.rfind('\n')?;
    let st: u16 = raw[idx + 1..].trim().parse().ok()?;
    Some((st, raw[..idx].to_lowercase()))
}

/// Verdict de takeover pour un sous-domaine.
pub fn check_subdomain(sub: &str) -> Option<(&'static str, String)> {
    let cnames = dig_short(sub, "CNAME");
    let cname = cnames.first()?;
    let cloud = TAKEOVER_FINGERPRINTS
        .iter()
        .find(|(dom, _)| cname.contains(dom))?;

    // Le CNAME pointe vers un cloud : la ressource existe-t-elle encore ?
    let a_records = dig_short(sub, "A");
    let resolves = !a_records.is_empty() && !a_records.iter().all(|r| r.contains("0.0.0.0"));

    if resolves {
        // ressource vivante : vérifier le fingerprint d'erreur quand même
        if let Some((_st, body)) = http_body(sub) {
            if body.contains(cloud.1) {
                return Some((
                    "TAKEOVER PROBABLE",
                    format!("{sub} → CNAME {cname} vivant mais corps d'erreur cloud (« {} ») — service non configuré", cloud.1),
                ));
            }
        }
        return Some((
            "NON PRENABLE",
            format!("{sub} → CNAME {cname} avec ressource active"),
        ));
    }
    // CNAME cloud + aucune résolution A = ressource supprimée
    Some((
        "TAKEOVER CONFIRMÉ",
        format!("{sub} → CNAME {cname} orphelin (aucun A) : recréer la ressource chez {} suffit à prendre le contrôle", cloud.0),
    ))
}

fn subs_from_db(target: &str) -> Vec<String> {
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
            &format!(
                "SELECT DISTINCT a.subdomain FROM audit_subdomains a \
                 JOIN audit_scans s ON s.id = a.scan_id WHERE s.target = '{}'",
                target.replace('\'', "''")
            ),
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

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let subs: Vec<String> = if args.len() >= 3 && args[1] == "--db" {
        subs_from_db(&args[2])
    } else if args.len() == 2 {
        // énumération passive légère : www + préfixes courants via CNAME uniquement
        [
            "www", "mail", "ftp", "vpn", "api", "dev", "staging", "portal", "shop", "blog",
        ]
        .iter()
        .map(|p| format!("{}.{}", p, args[1]))
        .collect()
    } else {
        eprintln!("usage: cnametake <domaine> | cnametake --db <cible>");
        std::process::exit(2);
    };

    println!(
        "Analyse takeover de {} sous-domaine(s) (lecture seule)...",
        subs.len()
    );
    let mut found = 0;
    for sub in &subs {
        if let Some((verdict, detail)) = check_subdomain(sub) {
            println!("  [{verdict}] {detail}");
            found += 1;
        }
    }
    if found == 0 {
        println!("Aucun CNAME cloud takeover-candidate détecté.");
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn fingerprints_non_vides_et_uniques() {
        let doms: Vec<&str> = super::TAKEOVER_FINGERPRINTS
            .iter()
            .map(|(d, _)| *d)
            .collect();
        assert!(doms.len() >= 10);
        let mut sorted = doms.clone();
        sorted.sort();
        sorted.dedup();
        assert_eq!(sorted.len(), doms.len(), "doublons de domaines cloud");
    }
}
