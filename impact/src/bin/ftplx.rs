//! ftplx — loot FTP borné : quand ftpx prouve un anonymous accepté, ftplx
//! dresse le manifeste (LIST récursif borné) et, avec --dl, télécharge un
//! ÉCHANTILLON borné (≤5 fichiers, ≤64 Ko, extensions texte) avec SHA-256.
//! Preuve de divulgation de données sans exfiltration massive.
//! JAMAIS d'upload (aucune option curl d'écriture — test verrouillé).
//! Usage: ftplx <hote> [--dl]
use std::process::{Command, Stdio};

const MAX_FILES_DL: usize = 5;
const MAX_BYTES: usize = 65536;
const MAX_DIRS: usize = 20;
const OK_EXT: &[&str] = &[
    "txt", "csv", "json", "xml", "conf", "cfg", "ini", "log", "md", "sql", "env", "bak", "yml",
    "yaml", "htm", "html", "php", "asp", "aspx",
];

fn curl_ftp(args: &[&str], host: &str, path: &str) -> Option<String> {
    let out = Command::new("curl")
        .args([
            "-s",
            "--ftp-pasv",
            "--max-time",
            "20",
            "--user",
            "anonymous:probe@veridy.ca",
        ])
        .args(args)
        .arg(format!("ftp://{host}/{path}"))
        .stdin(Stdio::null())
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    Some(String::from_utf8_lossy(&out.stdout).to_string())
}

/// Login anonymous accepté ? (via verbataire du refus 530)
fn anonymous_ok(host: &str) -> bool {
    let out = Command::new("curl")
        .args([
            "-s",
            "-v",
            "--ftp-pasv",
            "--max-time",
            "15",
            "--user",
            "anonymous:probe@veridy.ca",
            "-l",
            &format!("ftp://{host}/"),
        ])
        .stdin(Stdio::null())
        .output();
    match out {
        Ok(o) => {
            let verb = String::from_utf8_lossy(&o.stderr);
            !(verb.contains("530") || verb.contains("Access denied"))
        }
        Err(_) => false,
    }
}

#[derive(Debug, Clone)]
struct FtpEntry {
    path: String,
    is_dir: bool,
    size: u64,
}

/// Parse une ligne de listing UNIX (drwxr-xr-x 2 owner group 4096 Jan 1 10:00 name)
fn parse_list_line(line: &str) -> Option<FtpEntry> {
    let t = line.trim_end();
    if t.is_empty() {
        return None;
    }
    let first = t.chars().next()?;
    if first != 'd' && first != '-' && first != 'l' {
        return None; // en-tête ou ligne étrangère
    }
    let mut it = t.split_whitespace();
    let _perms = it.next()?;
    let _links = it.next()?;
    let _owner = it.next()?;
    let _group = it.next()?;
    let size: u64 = it.next()?.parse().ok()?;
    let _month = it.next()?;
    let _day = it.next()?;
    let _time = it.next()?;
    let rest: String = it.collect::<Vec<_>>().join(" ");
    if rest.is_empty() || rest == "." || rest == ".." {
        return None;
    }
    Some(FtpEntry {
        path: rest,
        is_dir: first == 'd',
        size,
    })
}

fn ext_ok(name: &str) -> bool {
    name.rsplit('.')
        .next()
        .map(|e| OK_EXT.contains(&e.to_lowercase().as_str()))
        .unwrap_or(false)
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        eprintln!("usage: ftplx <hote> [--dl]");
        std::process::exit(2);
    }
    let host = &args[1];
    let dl = args.iter().any(|a| a == "--dl");

    if !anonymous_ok(host) {
        println!("[{host}] anonymous REFUSÉ — rien à looter (lancer ftpx pour la preuve)");
        std::process::exit(1);
    }

    // LIST racine
    let root = curl_ftp(&[], host, "").unwrap_or_default();
    let mut entries: Vec<FtpEntry> = root.lines().filter_map(parse_list_line).collect();
    let root_count = entries.len();

    // récursivité bornée sur les répertoires
    let mut dirs_seen = 0;
    let mut i = 0;
    while i < entries.len() && dirs_seen < MAX_DIRS {
        if entries[i].is_dir {
            dirs_seen += 1;
            let dirpath = entries[i].path.clone();
            let sub = curl_ftp(&[], host, &format!("{dirpath}/")).unwrap_or_default();
            for e in sub.lines().filter_map(parse_list_line) {
                let mut child = e.clone();
                child.path = format!("{dirpath}/{}", e.path);
                entries.push(child);
            }
        }
        i += 1;
    }

    let files: Vec<&FtpEntry> = entries.iter().filter(|e| !e.is_dir).collect();
    println!("[{host}] anonymous OK — manifeste : {root_count} entrées racine, {} fichiers (récursivité ≤{MAX_DIRS} dirs)", files.len());
    for e in files.iter().take(25) {
        println!("   {:>9} o  {}", e.size, e.path);
    }
    if files.len() > 25 {
        println!("   ... +{} autres", files.len() - 25);
    }

    if !dl {
        println!("\n(--dl pour télécharger un échantillon borné : ≤{MAX_FILES_DL} fichiers, ≤{MAX_BYTES} o, extensions texte)");
        std::process::exit(0);
    }

    // échantillon : fichiers texte, petits d'abord (minimisation)
    let mut candidates: Vec<&FtpEntry> = files
        .iter()
        .filter(|e| ext_ok(&e.path) && e.size > 0 && e.size as usize <= MAX_BYTES)
        .copied()
        .collect();
    candidates.sort_by_key(|e| e.size);
    candidates.truncate(MAX_FILES_DL);

    let safe_host: String = host
        .chars()
        .map(|c| if c == '.' || c == ':' { '_' } else { c })
        .collect();
    let dir = format!("/tmp/ftplx_{safe_host}");
    let _ = std::fs::create_dir_all(&dir);
    println!("\nÉchantillon téléchargé dans {dir} :");
    for e in &candidates {
        let local = format!("{}/{}", dir, e.path.replace('/', "_"));
        let ok = Command::new("curl")
            .args([
                "-s",
                "--ftp-pasv",
                "--max-time",
                "20",
                "--user",
                "anonymous:probe@veridy.ca",
                "--max-filesize",
                &MAX_BYTES.to_string(),
                "-o",
                &local,
                &format!("ftp://{host}/{}", e.path),
            ])
            .stdin(Stdio::null())
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false);
        if ok {
            let sha = Command::new("sha256sum")
                .arg(&local)
                .stdin(Stdio::null())
                .output()
                .ok()
                .map(|o| {
                    String::from_utf8_lossy(&o.stdout)
                        .split_whitespace()
                        .next()
                        .unwrap_or("?")
                        .to_string()
                })
                .unwrap_or_else(|| "?".to_string());
            println!(
                "   {}  {:>9} o  {}",
                &sha[..16.min(sha.len())],
                e.size,
                e.path
            );
        } else {
            println!("   ÉCHEC téléchargement {}", e.path);
        }
    }
    println!("\nManifeste + échantillon hashé = preuve de divulgation bornée (aucune exfiltration massive).");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_listing_unix() {
        let l = "drwxr-xr-x   2 owner    group        4096 Jan  1 10:00 data";
        let e = parse_list_line(l).unwrap();
        assert!(e.is_dir);
        assert_eq!(e.path, "data");
        let f = "-rw-r--r--   1 owner    group         512 Feb  3 09:00 secrets.txt";
        let e = parse_list_line(f).unwrap();
        assert!(!e.is_dir);
        assert_eq!(e.size, 512);
        assert_eq!(e.path, "secrets.txt");
        assert!(parse_list_line("total 3").is_none());
        assert!(parse_list_line("").is_none());
        assert!(parse_list_line("drwxr-xr-x 2 o g 4096 Jan 1 10:00 ..").is_none());
    }

    #[test]
    fn extensions_filtrees() {
        assert!(ext_ok("config.ini"));
        assert!(ext_ok("db.SQL"));
        assert!(!ext_ok("video.mp4"));
        assert!(!ext_ok("archive.zip"));
    }

    #[test]
    fn binaire_sans_ecriture_ftp() {
        // Les tokens interdits sont construits dynamiquement pour que le test
        // ne se matche pas lui-même (leçon des tests d'invariants).
        let src = include_str!("ftplx.rs");
        let up_short = format!("-{u} ", u = "T");
        let up_long = format!("--{u}", u = "upload-file");
        let met = format!("-{m} ", m = "X");
        let corps = &src[..src.find("#[cfg(test)]").unwrap_or(src.len())];
        assert!(!corps.contains(&up_short), "upload interdit");
        assert!(!corps.contains(&up_long), "upload interdit");
        assert!(!corps.contains(&met), "méthode forcée interdite");
        assert!(corps.contains("--max-filesize"), "taille bornée requise");
    }
}
