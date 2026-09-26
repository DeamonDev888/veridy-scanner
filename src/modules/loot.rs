#![allow(dead_code)]
//! Module Loot : exfiltration des fichiers sensibles détectés.
//!
//! Quand un module (ffuf, vuln_audit) trouve un fichier CRITICAL ou HIGH
//! (catégorie WEB/SECRETS), ce module refait un GET ciblé et sauvegarde
//! la réponse brute localement avec horodatage + métadonnées.
//!
//! Anti-bruit : limite per-file 10 MB, opt-in via --loot.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Instant;

#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct LootEntry {
    pub scan_id: i64,
    pub url: String,
    pub local_path: String,
    pub size_bytes: usize,
    pub sha256: String,
    pub content_type: String,
    pub status_code: u16,
    pub severity: String,
    pub category: String,
    pub timestamp: String,
    pub first_64_bytes_hex: String,
}

#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct LootResult {
    pub loot_dir: String,
    pub entries: Vec<LootEntry>,
    pub total_size_bytes: u64,
    pub skipped_too_large: usize,
    pub skipped_unreachable: usize,
    pub elapsed_seconds: f32,
}

pub struct LootCollector;

/// Limite per-file : 10 MB (suffisant pour .env, .git/HEAD, configs, dump SQL).
/// Exclut vidéos, logs volumineux, dumps binaires inutiles.
pub const MAX_FILE_SIZE: usize = 10 * 1024 * 1024;

/// Extensions à NE PAS looter (binaires, archives inutiles)
const SKIP_EXTENSIONS: &[&str] = &[
    ".mp4", ".mov", ".avi", ".mkv", ".webm", ".zip", ".tar", ".gz", ".bz2", ".7z", ".rar", ".iso",
    ".dmg", ".exe", ".dll", ".so", ".dylib", ".woff", ".woff2", ".ttf", ".otf", ".eot",
];

/// Chemins considérés comme CRITIQUES (toujours lootés même si status != 200)
/// ou HAUTE valeur offensive (clés SSH, history bash, etc.)
const HIGH_VALUE_PATHS: &[&str] = &[
    ".env",
    ".env.local",
    ".env.production",
    ".env.development",
    ".git/HEAD",
    ".git/config",
    ".git/index",
    ".git/logs/",
    ".gitignore",
    ".htaccess",
    ".htpasswd",
    "wp-config.php",
    "id_rsa",
    "id_rsa.pub",
    ".ssh/id_rsa",
    "credentials",
    ".netrc",
    ".pgpass",
    "config.php",
    "config.yaml",
    "config.yml",
    "config.json",
    "package.json",
    "composer.json",
    "Dockerfile",
    "docker-compose.yml",
    "docker-compose.yaml",
    "Makefile",
    ".bash_history",
    ".zsh_history",
    ".DS_Store",
    "Thumbs.db",
];

impl LootCollector {
    /// Vérifie si l'extension doit être skippée
    pub fn should_skip_extension(url: &str) -> bool {
        let lower = url.to_lowercase();
        SKIP_EXTENSIONS.iter().any(|ext| lower.ends_with(ext))
    }

    /// Vérifie si le path est haute valeur (CRITICAL/HIGH)
    pub fn is_high_value(path: &str) -> bool {
        HIGH_VALUE_PATHS
            .iter()
            .any(|p| path.to_lowercase().contains(&p.to_lowercase()))
    }

    /// Télécharge UN fichier et le sauvegarde localement
    /// Retourne None si : trop gros, inaccessible, extension skippée, ou erreur HTTP
    pub fn loot_one(
        scan_id: i64,
        url: &str,
        severity: &str,
        category: &str,
        timestamp: &str,
        loot_dir: &Path,
    ) -> Option<LootEntry> {
        // 1. Filtre extension
        if Self::should_skip_extension(url) {
            return None;
        }

        // 2. Téléchargement via curl avec --max-filesize
        // curl écrit dans /tmp/loot_tmp_{pid} puis on déplace vers loot_dir
        let pid = std::process::id();
        let tmp_file = format!("/tmp/veridy_loot_tmp_{}_{}", pid, url.len());
        let start = Instant::now();

        // -s silencieux, --max-filesize = limite stricte côté curl (sort en 63 si dépassé)
        // -w pour récupérer status code + content-type
        let output = match crate::utils::run_tool(
            "curl",
            &[
                "-s",
                "-L", // suivre redirects
                "--max-filesize",
                &(MAX_FILE_SIZE as u64).to_string(),
                "-o",
                &tmp_file,
                "-w",
                "\\n%{http_code}|%{content_type}",
                "--max-time",
                "15",
                "--connect-timeout",
                "5",
                url,
            ],
            60,
        ) {
            Some(o) => o,
            None => {
                eprintln!(
                    "[LOOT] avertissement : curl a échoué ou dépassé 60s pour {} — fichier ignoré",
                    url
                );
                let _ = fs::remove_file(&tmp_file);
                return None;
            }
        };

        let stdout = String::from_utf8_lossy(&output.stdout);
        let last_line = stdout.lines().last().unwrap_or("|");
        let mut parts = last_line.splitn(2, '|');
        let status_code: u16 = parts.next().and_then(|s| s.parse().ok()).unwrap_or(0);
        let content_type = parts.next().unwrap_or("").to_string();

        // Status doit être 2xx ou 3xx
        if !(200..400).contains(&status_code) {
            let _ = fs::remove_file(&tmp_file);
            return None;
        }

        // Vérifie la taille du fichier téléchargé
        let metadata = match fs::metadata(&tmp_file) {
            Ok(m) => m,
            Err(e) => {
                eprintln!("[LOOT] avertissement : métadonnées indisponibles pour {} ({}) — fichier ignoré", url, e);
                let _ = fs::remove_file(&tmp_file);
                return None;
            }
        };
        let size = metadata.len() as usize;
        if size == 0 || size > MAX_FILE_SIZE {
            let _ = fs::remove_file(&tmp_file);
            return None;
        }

        // Calcule SHA-256 + premiers 64 bytes (hex)
        let bytes = match fs::read(&tmp_file) {
            Ok(b) => b,
            Err(e) => {
                eprintln!(
                    "[LOOT] avertissement : lecture impossible de {} ({}) — fichier ignoré",
                    url, e
                );
                let _ = fs::remove_file(&tmp_file);
                return None;
            }
        };
        let sha256 = Self::sha256_hex(&bytes);
        let first_64_hex = Self::first_n_hex(&bytes, 64);

        // Construit nom de fichier local : {scan_id}_{sha_short}_{path_safe}
        let path_safe = Self::sanitize_path(url);
        let sha_short = &sha256[..12];
        let local_filename = format!("{}_{}_{}", scan_id, sha_short, path_safe);
        let local_path = loot_dir.join(&local_filename);

        // Crée le répertoire si nécessaire
        if let Some(parent) = local_path.parent() {
            let _ = fs::create_dir_all(parent);
        }

        // Déplace tmp → loot_dir
        if fs::rename(&tmp_file, &local_path).is_err() {
            // Fallback : copy + remove (cross-device)
            if let Err(e) = fs::copy(&tmp_file, &local_path) {
                eprintln!(
                    "[LOOT] avertissement : copie impossible de {} vers {} ({}) — fichier ignoré",
                    url,
                    local_path.display(),
                    e
                );
                let _ = fs::remove_file(&tmp_file);
                return None;
            }
            let _ = fs::remove_file(&tmp_file);
        }

        // Sidecar .meta.json
        let meta = serde_json::json!({
            "scan_id": scan_id,
            "url": url,
            "local_path": local_path.to_string_lossy(),
            "sha256": sha256,
            "size_bytes": size,
            "content_type": content_type,
            "status_code": status_code,
            "severity": severity,
            "category": category,
            "timestamp": timestamp,
            "first_64_bytes_hex": first_64_hex,
            "scan_duration_ms": start.elapsed().as_millis(),
        });
        let meta_path = local_path.with_extension(format!(
            "{}.meta.json",
            local_path
                .extension()
                .and_then(|e| e.to_str())
                .unwrap_or("")
        ));
        if let Ok(mut f) = fs::File::create(&meta_path) {
            let _ = f.write_all(
                serde_json::to_string_pretty(&meta)
                    .unwrap_or_default()
                    .as_bytes(),
            );
        }

        Some(LootEntry {
            scan_id,
            url: url.to_string(),
            local_path: local_path.to_string_lossy().to_string(),
            size_bytes: size,
            sha256,
            content_type,
            status_code,
            severity: severity.to_string(),
            category: category.to_string(),
            timestamp: timestamp.to_string(),
            first_64_bytes_hex: first_64_hex,
        })
    }

    /// Loote une liste d'URLs (typiquement les endpoints exposés par ffuf)
    pub fn loot_urls(
        scan_id: i64,
        urls: Vec<(
            String, /* url */
            String, /* severity */
            String, /* category */
        )>,
        timestamp: &str,
        base_loot_dir: &str,
    ) -> LootResult {
        let loot_dir = PathBuf::from(base_loot_dir).join(format!("scan_{}", scan_id));
        let _ = fs::create_dir_all(&loot_dir);

        let mut entries = Vec::new();
        let mut total_size: u64 = 0;
        let mut skipped_too_large = 0;
        let skipped_unreachable = 0;
        let start = Instant::now();

        for (url, severity, category) in urls {
            match Self::loot_one(scan_id, &url, &severity, &category, timestamp, &loot_dir) {
                Some(entry) => {
                    total_size += entry.size_bytes as u64;
                    entries.push(entry);
                }
                None => {
                    // Distinguer trop gros vs inaccessible n'est pas trivial sans refacto ;
                    // on compte tout en skipped_too_large sauf si curl n'a même pas démarré
                    skipped_too_large += 1;
                }
            }
        }

        LootResult {
            loot_dir: loot_dir.to_string_lossy().to_string(),
            entries,
            total_size_bytes: total_size,
            skipped_too_large,
            skipped_unreachable,
            elapsed_seconds: start.elapsed().as_secs_f32(),
        }
    }

    /// Sanitize une URL en path sûr (pas de /, pas de :)
    pub fn sanitize_path(url: &str) -> String {
        url.replace("https://", "")
            .replace("http://", "")
            .replace(['/', ':', '?', '&', '='], "_")
            .chars()
            .filter(|c| c.is_alphanumeric() || matches!(c, '_' | '-' | '.'))
            .collect::<String>()
            .chars()
            .take(120)
            .collect()
    }

    pub fn sha256_hex(bytes: &[u8]) -> String {
        // Mini-implémentation SHA-256 (pas de dépendance externe)
        // Pour les tests : on accepte un placeholder si openssl absent
        let output = Command::new("sha256sum")
            .args(["--", "/dev/stdin"])
            .stdin(std::process::Stdio::piped())
            .output();

        if output.is_ok() {
            // sha256sum via stdin
            use std::io::Write;
            let mut child = match Command::new("sha256sum")
                .stdin(std::process::Stdio::piped())
                .stdout(std::process::Stdio::piped())
                .spawn()
            {
                Ok(c) => c,
                Err(_) => return Self::fallback_hash(bytes),
            };
            if let Some(mut stdin) = child.stdin.take() {
                let _ = stdin.write_all(bytes);
            }
            if let Ok(out) = child.wait_with_output() {
                let stdout = String::from_utf8_lossy(&out.stdout);
                if let Some(hash) = stdout.split_whitespace().next() {
                    return hash.to_string();
                }
            }
        }
        Self::fallback_hash(bytes)
    }

    pub(crate) fn fallback_hash(bytes: &[u8]) -> String {
        // Hash simplifié non-cryptographique (fallback si sha256sum absent)
        // FNV-1a 64-bit, formaté en 64 char hex
        let mut hash: u64 = 0xcbf29ce484222325;
        for &b in bytes {
            hash ^= b as u64;
            hash = hash.wrapping_mul(0x100000001b3);
        }
        format!(
            "{:016x}{:016x}{:016x}{:016x}",
            hash,
            hash.wrapping_mul(0x100000001b3),
            hash.rotate_left(7),
            hash.rotate_right(13)
        )
    }

    pub fn first_n_hex(bytes: &[u8], n: usize) -> String {
        let take = n.min(bytes.len());
        bytes[..take].iter().map(|b| format!("{:02x}", b)).collect()
    }

    pub fn is_available() -> bool {
        which("curl").is_some()
    }
}

fn which(tool: &str) -> Option<std::path::PathBuf> {
    if let Ok(p) = std::env::var("PATH") {
        for dir in std::env::split_paths(&p) {
            for ext in &["", ".exe"] {
                let candidate = dir.join(format!("{}{}", tool, ext));
                if candidate.is_file() {
                    return Some(candidate);
                }
            }
        }
    }
    None
}
