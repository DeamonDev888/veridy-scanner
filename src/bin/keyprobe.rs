//! keyprobe — classification et verification NON DESTRUCTIVE des cles API trouvees.
//! Lit les cles depuis stdin (une par ligne) : jamais en argument (history/ps).
use std::io::BufRead;
use veridy_scanner::{check_google_key, classify_key, mask_secret, KeyKind};

fn main() {
    let stdin = std::io::stdin();
    let mut any_valid = false;
    for line in stdin.lock().lines().map_while(Result::ok) {
        let k = line.trim();
        if k.is_empty() || k.starts_with('#') {
            continue;
        }
        let kind = classify_key(k);
        print!("[{}] {}", kind.label(), mask_secret(k));
        if kind.safely_checkable() {
            match check_google_key(k, 15) {
                Some(v) => {
                    println!(" -> {}", v.detail);
                    if v.valid {
                        any_valid = true;
                    }
                }
                None => println!(" -> verification impossible (reseau)"),
            }
        } else {
            println!(
                " -> {} (verification active volontairement absente : effet de bord possible)",
                if matches!(kind, KeyKind::Unknown) {
                    "format inconnu"
                } else {
                    "NON verifiee"
                }
            );
        }
    }
    std::process::exit(if any_valid { 0 } else { 1 });
}
