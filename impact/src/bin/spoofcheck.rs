//! spoofcheck — preuve d'usurpabilite email d'un domaine (analyse SPF/DMARC, zero envoi).
use std::process::Command;
use std::process::Stdio;
use veridy_impact::{dig_txt, dmarc_policy, spoof_verdict};

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 2 {
        eprintln!("usage: spoofcheck <domaine>");
        std::process::exit(2);
    }
    let domain = args[1].trim_matches('.');

    let spf: Option<String> = dig_txt(domain)
        .into_iter()
        .find(|t| t.to_lowercase().starts_with("v=spf1"));
    let dmarc: Option<String> = dig_txt(&format!("_dmarc.{domain}"))
        .into_iter()
        .find(|t| t.to_lowercase().starts_with("v=dmarc1"));

    // MX presents ? (usurpation interessante seulement si le domaine recoit du mail)
    let mx = Command::new("dig")
        .args(["+short", "MX", domain, "+time=5", "+tries=1"])
        .stdin(Stdio::null())
        .output();
    let has_mx = match mx {
        Ok(o) => !String::from_utf8_lossy(&o.stdout).trim().is_empty(),
        Err(_) => false,
    };

    println!("domaine   : {domain}");
    println!("SPF       : {}", spf.as_deref().unwrap_or("(absent)"));
    println!(
        "DMARC     : {}",
        dmarc
            .as_deref()
            .map(|d| format!("p={}", dmarc_policy(d).unwrap_or_else(|| "?".into())))
            .unwrap_or_else(|| "(absent)".into())
    );
    println!(
        "MX        : {}",
        if has_mx {
            "oui (domaine de reception)"
        } else {
            "non"
        }
    );

    let (verdict, detail) = spoof_verdict(
        spf.as_deref(),
        dmarc_policy(dmarc.as_deref().unwrap_or("")).as_deref(),
    );
    println!("\nVERDICT   : {verdict}");
    println!("  {detail}");
    if has_mx && verdict != "PROTEGE" {
        println!("  impact : phishing direct sur les clients/partners du domaine possible");
    }
}
