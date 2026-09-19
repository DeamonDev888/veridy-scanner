#![allow(dead_code, clippy::manual_checked_ops)]

//! Composants UI réutilisables pour Veridy.
//!
//! Tous les composants sont no-op si stdout n'est pas un TTY (env var `NO_COLOR` ou redirection).
//! Les largeurs sont calculées depuis `terminal_size::terminal_size()` si dispo, sinon 80 par défaut.

use std::io::{self, Write};

/// Écrit sans newline, flush immédiat
pub fn print(s: &str) {
    let _ = write!(io::stdout(), "{}", s);
    let _ = io::stdout().flush();
}

/// Saut de ligne
pub fn println(s: &str) {
    print(&format!("{}\n", s));
}

/// Détecte si la sortie est un TTY interactif
pub fn is_tty() -> bool {
    use std::io::IsTerminal;
    io::stdout().is_terminal()
}

/// Reset / couleurs ANSI
pub const RESET: &str = "\x1b[0m";
pub const BOLD: &str = "\x1b[1m";
pub const DIM: &str = "\x1b[2m";
pub const ITAL: &str = "\x1b[3m";

pub const CLR_RED: &str = "\x1b[38;5;196m";
pub const CLR_GREEN: &str = "\x1b[38;5;82m";
pub const CLR_YELLOW: &str = "\x1b[38;5;220m";
pub const CLR_BLUE: &str = "\x1b[38;5;51m";
pub const CLR_PURPLE: &str = "\x1b[38;5;141m";
pub const CLR_PINK: &str = "\x1b[38;5;198m";
pub const CLR_CYAN: &str = "\x1b[38;5;39m";
pub const CLR_WHITE: &str = "\x1b[38;5;255m";
pub const CLR_GRAY: &str = "\x1b[38;5;244m";
pub const CLR_ORANGE: &str = "\x1b[38;5;208m";

/// Couleur par niveau de sévérité
pub fn severity_color(sev: &str) -> &'static str {
    match sev {
        "CRITICAL" => CLR_RED,
        "HIGH" => CLR_ORANGE,
        "MEDIUM" => CLR_YELLOW,
        "LOW" => CLR_BLUE,
        _ => CLR_GRAY,
    }
}

/// Couleur par score 0..=100
pub fn score_color(score: u8) -> &'static str {
    match score {
        90..=100 => CLR_GREEN,
        70..=89 => CLR_BLUE,
        50..=69 => CLR_YELLOW,
        20..=49 => CLR_ORANGE,
        _ => CLR_RED,
    }
}

/// Couleur de jauge pour un ratio 0.0..=1.0
pub fn ratio_color(ratio: f64) -> &'static str {
    if ratio >= 0.9 {
        CLR_GREEN
    } else if ratio >= 0.6 {
        CLR_BLUE
    } else if ratio >= 0.3 {
        CLR_YELLOW
    } else {
        CLR_RED
    }
}

/// Barre de progression arc-en-ciel à 256 couleurs
/// Génère `width` caractères Unicode braille avec dégradé de couleur vert→jaune→rouge selon position
pub fn rainbow_bar(filled: usize, width: usize) -> String {
    let filled = filled.min(width);
    let mut s = String::new();
    for i in 0..filled {
        // 256-color: hue interpolé 82 (vert) → 220 (jaune) → 196 (rouge)
        let ratio = i as f64 / width.max(1) as f64;
        let color = if ratio < 0.5 {
            // vert→jaune
            let r = 82 + ((220 - 82) as f64 * (ratio * 2.0)) as u8;
            format!("\x1b[38;5;{}m█\x1b[0m", r)
        } else {
            // jaune→rouge
            let r = 220 + ((196 - 220) as f64 * ((ratio - 0.5) * 2.0)) as u8;
            format!("\x1b[38;5;{}m█\x1b[0m", r)
        };
        s.push_str(&color);
    }
    // Reste vide en gris
    s.push_str(&format!("{}{}\x1b[0m", CLR_GRAY, "░".repeat(width - filled)));
    s
}

/// Bar chart horizontal d'une valeur vs total
/// Retourne une string colorée "[████░░░] 60% (12/20)"
pub fn bar_chart(value: usize, total: usize, width: usize) -> String {
    let pct = if total == 0 { 0 } else { (value * 100) / total };
    let filled = (pct * width) / 100;
    let color = ratio_color(pct as f64 / 100.0);
    format!(
        "{}[{}{}{}] {}{}%{}({}/{})",
        BOLD, color, "█".repeat(filled), "░".repeat(width - filled),
        color, pct, RESET, value, total
    )
}

/// Mini-histogramme vertical d'une série de valeurs
/// Affiche `bins` colonnes (la plus haute en haut), avec axe Y simple
pub fn vertical_histogram(values: &[u64], bins: usize, max_height: usize) -> String {
    if values.is_empty() || bins == 0 {
        return String::new();
    }
    // Découpe en `bins` buckets
    let min = *values.iter().min().unwrap();
    let max = *values.iter().max().unwrap();
    let range = (max - min).max(1);
    let bucket_size = (range as f64 / bins as f64).ceil() as u64;

    let mut buckets = vec![0u64; bins];
    for v in values {
        let mut idx = ((v - min) / bucket_size.max(1)) as usize;
        if idx >= bins {
            idx = bins - 1;
        }
        buckets[idx] += 1;
    }

    let max_count = *buckets.iter().max().unwrap();
    let max_count = max_count as usize;
    let max_height_usize = max_height;
    let mut lines = Vec::new();

    for level in (1..=max_height_usize).rev() {
        let threshold = max_count * level / max_height_usize;
        let mut line = String::new();
        line.push_str(&format!("{}{:>4}│", CLR_GRAY, level * max_count / max_height_usize));
        for b in &buckets {
            if (*b as usize) >= threshold {
                line.push_str(&format!("{}{} ", CLR_BLUE, "█"));
            } else {
                line.push_str("  ");
            }
        }
        lines.push(line);
    }

    // Axe X
    let mut axis = String::new();
    axis.push_str(&format!("{}    └", CLR_GRAY));
    for _ in 0..bins {
        axis.push_str("──");
    }
    lines.push(axis);
    lines.push(format!(
        "{}     {} valeurs, min={} max={}",
        CLR_GRAY, values.len(), min, max
    ));

    lines.join("\n")
}

/// Sparkline (ligne mini-graphique) d'une série
/// Retourne `▁▂▃▅▇▆▄▂▁` style
pub fn sparkline(values: &[u64]) -> String {
    if values.is_empty() {
        return String::new();
    }
    let chars = ['▁', '▂', '▃', '▄', '▅', '▆', '▇', '█'];
    let min = *values.iter().min().unwrap();
    let max = *values.iter().max().unwrap();
    let range = (max - min).max(1);
    values
        .iter()
        .map(|v| {
            let idx = ((v - min) * (chars.len() as u64 - 1) / range) as usize;
            chars[idx.min(chars.len() - 1)]
        })
        .collect()
}

/// Affiche un gauge circulaire (style jauge de compteur)
/// Retourne 3 lignes : haut, milieu, bas
pub fn gauge(_label: &str, value: f64, max: f64, width: usize) -> String {
    let pct = (value / max * 100.0).clamp(0.0, 100.0);
    let filled = (pct * width as f64 / 100.0) as usize;
    let color = ratio_color(pct / 100.0);
    format!(
        "{}╭{}╮\n│{}{}{} │{}{} {} / {:.0} ({:.1}%)\n╰{}╯",
        CLR_GRAY, "─".repeat(width + 1),
        color, "█".repeat(filled), RESET,
        "░".repeat(width - filled),
        BOLD, value, max, pct, RESET
    )
}

/// Box avec bordure Unicode
pub fn box_top(width: usize) -> String {
    format!("{}╭{}╮", CLR_PURPLE, "─".repeat(width))
}
pub fn box_bottom(width: usize) -> String {
    format!("{}╰{}╯", CLR_PURPLE, "─".repeat(width))
}
pub fn box_separator(width: usize) -> String {
    format!("{}├{}┤{}", CLR_PURPLE, "─".repeat(width), RESET)
}

/// Efface la ligne courante et écrit par-dessus
pub fn clear_line() {
    print("\x1b[2K\r");
}

/// Curseur
pub fn hide_cursor() {
    print("\x1b[?25l");
}
pub fn show_cursor() {
    print("\x1b[?25h");
}

/// ASCII art Veridy pour fin de rapport
pub fn veridy_logo() -> &'static str {
    r#"
    ╔════════════════════════════════════════════════════════════════╗
    ║                                                                ║
    ║   ██╗   ██╗███████╗██████╗ ██╗██████╗ ██╗   ██╗                 ║
    ║   ██║   ██║██╔════╝██╔══██╗██║██╔══██╗╚██╗ ██╔╝                 ║
    ║   ██║   ██║█████╗  ██████╔╝██║██║  ██║ ╚████╔╝                  ║
    ║   ╚██╗ ██╔╝██╔══╝  ██╔══██╗██║██║  ██║  ╚██╔╝                   ║
    ║    ╚████╔╝ ███████╗██║  ██║██║██████╔╝   ██║                    ║
    ║     ╚═══╝  ╚══════╝╚═╝  ╚═╝╚═╝╚═════╝    ╚═╝                    ║
    ║                                                                ║
    ║          CYBER INTELLIGENCE & OFFENSIVE SURFACE ENGINE          ║
    ║                                                                ║
    ╚════════════════════════════════════════════════════════════════╝
"#
}

/// Animation finale selon le score
pub fn finale_banner(score: u8, target: &str) -> String {
    let (icon, label, color) = if score >= 90 {
        ("💎", "EXCELLENT — Surface durcie", CLR_GREEN)
    } else if score >= 70 {
        ("✅", "BON — Hygiène correcte", CLR_BLUE)
    } else if score >= 50 {
        ("⚠️ ", "MOYEN — Correctifs prioritaires requis", CLR_YELLOW)
    } else if score >= 25 {
        ("🔴", "FAIBLE — Failles critiques détectées", CLR_ORANGE)
    } else {
        ("☠️ ", "CRITIQUE — Surface compromise", CLR_RED)
    };

    let mut s = String::new();
    s.push_str(&format!("\n{}{}{}  ══════════════════════════════════════════════════════════\n", BOLD, color, RESET));
    s.push_str(&format!("  {} {}  SCORE : {}{}{}/100  ║  Cible : {}\n",
                       icon, label, BOLD, score, RESET, target));
    s.push_str(&format!("  ══════════════════════════════════════════════════════════{}\n\n", RESET));
    s
}

/// Easter egg : motifs sympathiques selon la cible
pub fn easter_egg(target: &str) -> Option<&'static str> {
    let t = target.to_lowercase();
    if t.contains("scanme.nmap") {
        Some("\n  🎯 Tip : Nmap offre aussi scanme.nmap.org sur le port 80 — hello Fyodor!\n")
    } else if t.contains("example.com") {
        Some("\n  📚 Cible IANA réservée — parfaite pour benchmarker le scanner.\n")
    } else if t.contains("localhost") || t.contains("127.0.0.1") || t.contains("::1") {
        Some("\n  🏠 Tu scannes ta propre machine ? Brave.\n")
    } else if t.starts_with("10.") || t.starts_with("192.168.") || t.starts_with("172.") {
        Some("\n  🔒 Réseau privé — le scanner te dit : tu connais ton infra mieux que personne.\n")
    } else {
        None
    }
}

/// Formate une durée en ms de façon lisible
pub fn fmt_duration(ms: u64) -> String {
    if ms < 1000 {
        format!("{}ms", ms)
    } else if ms < 60_000 {
        format!("{:.2}s", ms as f64 / 1000.0)
    } else {
        let s = ms / 1000;
        format!("{}m {:02}s", s / 60, s % 60)
    }
}

/// Tronque une string à `max_chars` caractères Unicode (UTF-8 safe) avec ellipse
pub fn truncate(s: &str, max_chars: usize) -> String {
    if s.chars().count() <= max_chars {
        s.to_string()
    } else {
        let truncated: String = s.chars().take(max_chars.saturating_sub(1)).collect();
        format!("{}…", truncated)
    }
}

/// Padding pour aligner une string à gauche dans une largeur fixe (UTF-8 safe)
pub fn pad_left(s: &str, width: usize) -> String {
    let len = s.chars().count();
    if len >= width {
        truncate(s, width)
    } else {
        format!("{}{}", s, " ".repeat(width - len))
    }
}

/// Calcule la largeur du terminal (best effort)
pub fn term_width() -> usize {
    if let Ok(cols) = std::env::var("COLUMNS") {
        if let Ok(n) = cols.parse::<usize>() {
            return n;
        }
    }
    // Fallback : assume 100
    100
}

/// Affiche un mini-graphe radar ASCII pour 5 dimensions (ports, dns, http, tls, email)
/// Chaque valeur doit être entre 0.0 et 1.0
pub fn radar(values: &[(&str, f64); 5]) -> String {
    let grid_size = 8;
    let mut lines = Vec::new();

    for level in (1..=grid_size).rev() {
        let _threshold = level as f64 / grid_size as f64;
        let mut line = String::new();
        line.push_str(&format!("{}{}│{}", CLR_GRAY, level, RESET));
        for (_label, val) in values {
            let bar_len = (val * grid_size as f64).round() as usize;
            if bar_len >= level {
                line.push_str(&format!("{}{}{}", CLR_BLUE, "█".repeat(3), RESET));
            } else {
                line.push_str("   ");
            }
            line.push(' ');
        }
        lines.push(line);
    }
    lines.push(format!("{} └{}", CLR_GRAY, "─".repeat(grid_size * 4)));
    let mut labels = String::new();
    labels.push_str(&format!("{}  ", CLR_GRAY));
    for (label, _) in values {
        labels.push_str(&format!("{:<3} ", truncate(label, 3).to_lowercase()));
    }
    lines.push(labels);

    lines.join("\n")
}


/// Barre colorée pour un score 0..=100 (color gradient vert→jaune→rouge)
pub fn score_bar(score: u8, width: usize) -> String {
    let filled = ((score as usize * width) / 100).min(width);
    let mut s = String::new();
    for i in 0..filled {
        let ratio = i as f64 / width.max(1) as f64;
        let color = if ratio < 0.5 {
            let r = 82 + ((220 - 82) as f64 * (ratio * 2.0)) as u8;
            format!("\x1b[38;5;{}m█\x1b[0m", r)
        } else {
            let r = 220 + ((196 - 220) as f64 * ((ratio - 0.5) * 2.0)) as u8;
            format!("\x1b[38;5;{}m█\x1b[0m", r)
        };
        s.push_str(&color);
    }
    s.push_str(&format!("{}{}\x1b[0m", CLR_GRAY, "░".repeat(width - filled)));
    s
}

/// Formate un compteur de findings : "12" ou "—" si zéro
pub fn fmt_findings(count: usize) -> String {
    if count == 0 {
        format!("{}·—{} aucune", CLR_GRAY, RESET)
    } else if count < 5 {
        format!("{}{}{}", CLR_WHITE, count, RESET)
    } else if count < 15 {
        format!("{}{}{}", CLR_YELLOW, count, RESET)
    } else {
        format!("{}{}{}", CLR_RED, count, RESET)
    }
}


/// Centre une string dans une largeur (UTF-8 safe)
pub fn pad_center(s: &str, width: usize) -> String {
    let len = s.chars().count();
    if len >= width {
        return truncate(s, width);
    }
    let pad = width - len;
    let left = pad / 2;
    let right = pad - left;
    format!("{}{}{}", " ".repeat(left), s, " ".repeat(right))
}
