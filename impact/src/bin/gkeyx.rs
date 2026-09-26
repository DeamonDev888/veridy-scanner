//! gkeyx — enumeration des privileges d'une cle Google (AIza...).
//! Lit la cle depuis stdin (jamais en argument) et sonde une fois par service :
//! LLM (Gemini), MAPS (staticmap/geocode/streetview/directions/elevation),
//! DATA (youtube/translate/customsearch). Lecture seule : GET uniquement,
//! timeout dur, aucun effet de bord. Phase exploit : fuite du n° de projet
//! + test differentiel de bypass de la restriction referrer.
use std::io::BufRead;
use veridy_impact::{gkeyx_exploit, gkeyx_report, gkeyx_verdict, mask_secret, GProbeStatus};

fn main() {
    let stdin = std::io::stdin();
    let mut had_any = false;
    let mut had_granted = false;
    for line in stdin.lock().lines().map_while(Result::ok) {
        let k = line.trim();
        if k.is_empty() || k.starts_with('#') {
            continue;
        }
        if !k.starts_with("AIza") {
            eprintln!(
                "[gkeyx] ignore (pas une cle Google AIza...) : {}",
                mask_secret(k)
            );
            continue;
        }
        had_any = true;
        println!("cle       : {}", mask_secret(k));
        println!("sondes    : 1 GET par service (9), lecture seule\n");
        let probes = gkeyx_report(k, 20);
        let mut cur_family = "";
        for p in &probes {
            if p.family != cur_family {
                cur_family = p.family;
                println!("[{}]", cur_family);
            }
            let mark = match p.status {
                GProbeStatus::Granted => "[+]",
                GProbeStatus::Constrained => "[~]",
                GProbeStatus::Denied => "[-]",
                GProbeStatus::Inconclusive => "[?]",
            };
            println!(
                "  {mark} {:<13} {:<14} {}",
                p.service,
                p.status.label(),
                p.detail
            );
        }
        let (verdict, detail) = gkeyx_verdict(&probes);
        println!("\nVERDICT   : {verdict}");
        println!("  {detail}");
        if verdict == "VALIDE" {
            had_granted = true;
            if probes
                .iter()
                .any(|p| p.family == "LLM" && p.status == GProbeStatus::Granted)
            {
                println!("  impact : cle LLM utilisable — generation de contenu aux frais du proprietaire");
            }
        }
        // phase exploit (lecture seule) : recon projet + bypass referrer
        let notes = gkeyx_exploit(k, &probes, 20);
        if !notes.is_empty() {
            println!("\nEXPLOIT");
            for n in &notes {
                println!("  {n}");
            }
        }
        println!();
    }
    if !had_any {
        eprintln!("usage: echo <cle AIza...> | gkeyx   (ou gkeyx < cles.txt, une par ligne)");
        std::process::exit(2);
    }
    // exit 0 = au moins un service accessible, 1 = aucune cle pleinement ouverte
    std::process::exit(if had_granted { 0 } else { 1 });
}
