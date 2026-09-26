//! envx — preuve d'impact d'un .env expose : parse, signaux forts, masque tout.
use std::io::Write;
use veridy_scanner::{http_get, is_high_signal, looks_like_env, mask_secret, parse_env};

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 2 {
        eprintln!("usage: envx <url-du-.env>");
        std::process::exit(2);
    }
    let url = &args[1];
    match http_get(url, 25) {
        None => {
            eprintln!("[IMPOSSIBLE] requete echouee (DNS/reseau/timeout)");
            std::process::exit(1);
        }
        Some(r) if r.status != 200 => {
            eprintln!("[NON EXPOSE] HTTP {} (pas un .env servi)", r.status);
            std::process::exit(1);
        }
        Some(r) => {
            if !looks_like_env(&r.body) {
                eprintln!("[SOFT-404] reponse 200 mais pas un .env (HTML/catch-all)");
                std::process::exit(1);
            }
            let pairs = parse_env(&r.body);
            let high: Vec<_> = pairs.iter().filter(|(k, _)| is_high_signal(k)).collect();
            println!(
                "[.env EXPOSE] {} variables, {} a haute valeur",
                pairs.len(),
                high.len()
            );
            for (k, v) in &high {
                println!("  !! {:<28} = {}", k, mask_secret(v));
            }
            for (k, v) in pairs.iter().filter(|(k, _)| !is_high_signal(k)) {
                println!("    {:<28} = {}", k, mask_secret(v));
            }
            if high.is_empty() {
                println!("  (aucune credential directe — verifier les vars d'app nonetheless)");
            }
            // preuve conservee cote operateur seulement, jamais affichee en clair
            if let Ok(mut f) = std::fs::File::create("/tmp/envx_proof.env") {
                let _ = writeln!(f, "{}", r.body);
            }
            std::process::exit(0);
        }
    }
}
