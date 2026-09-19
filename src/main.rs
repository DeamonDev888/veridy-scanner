mod config;
mod modules;
mod orchestrator;
mod report;
mod target_parser;
mod ui;
mod utils;

#[cfg(test)]
mod tests;

use config::Config;
use modules::db::{DatabaseManager, ScanHistoryEntry};
use orchestrator::AuditOrchestrator;
use target_parser::{TargetParser, TargetVerdict};

fn main() {
    // Panic hook global : restaure le curseur terminal avant tout message de panic
    // (sinon le curseur reste caché par \x1b[?25l après un crash du HUD)
    let default_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let _ = std::io::Write::write_all(&mut std::io::stdout(), b"\x1b[?25h");
        default_hook(info);
    }));

    let config = match Config::parse() {
        Ok(Some(cfg)) => cfg,
        Ok(None) => return,
        Err(e) => {
            eprintln!("[ERREUR ARGUMENTS] {}", e);
            std::process::exit(1);
        }
    };

    // Commande Historique
    if config.show_history {
        match DatabaseManager::get_history(&config.target, config.history_limit, &config.db_name) {
            Ok(entries) => print_history(&config.target, &entries),
            Err(e) => {
                eprintln!("[ERREUR DB] Impossible de lire l'historique : {}", e);
                std::process::exit(1);
            }
        }
        return;
    }

    // 1. Résolution et validation de la cible
    let ips = match TargetParser::resolve(&config.target) {
        TargetVerdict::Resolved(ips) => ips,
        TargetVerdict::InvalidFormat(reason) | TargetVerdict::Unresolvable(reason) => {
            eprintln!("[CIBLE INVALIDE] {}", reason);
            std::process::exit(1);
        }
    };

    let first_ip = match ips.first() {
        Some(ip) => ip.to_string(),
        None => {
            eprintln!("[ERREUR] Aucune adresse IP valide résolue");
            std::process::exit(1);
        }
    };

    if !config.json_mode {
        println!(
            ">>> Lancement de l'audit approfondi Veridy pour la cible : {}",
            config.target
        );
        println!(">>> IPs résolues : {:?}", ips);
        println!(">>> Exécution parallèle des modules (GéoIP, DNS, 75+ Ports, HTTP, TLS, Sous-domaines, Endpoints)...");
        if config.tools.has_any() {
            println!(
                ">>> [KALI 360° ORCHESTRATION] Outils activés en arrière-plan : {}",
                config.tools.active_names().join(", ")
            );
        }
    }

    // 2. Exécution coordonnée via l'Orchestrateur
    let report = AuditOrchestrator::run(&config, &first_ip);

    // 3. Persistance et Catalogage dans PostgreSQL (12 tables relationnelles)
    let mut db_id = None;
    if config.save_to_db {
        match DatabaseManager::save_scan(&report, &config.db_name) {
            Ok(id) => db_id = Some(id),
            Err(e) => {
                if !config.json_mode {
                    eprintln!("[ATTENTION DB] Échec du catalogage relationnel : {}", e);
                }
            }
        }
    }

    // 4. Affichage console ou JSON
    if config.json_mode {
        println!("{}", report.to_json());
    } else {
        report.print_console();
        if let Some(id) = db_id {
            println!(
                ">>> [POSTGRESQL] Audit approfondi 360° catalogué avec succès dans '{}' (Scan ID #{})",
                config.db_name, id
            );
            println!(">>> [POSTGRESQL] Tables enrichies (audit_scans, audit_findings, audit_tool_outputs, geo_compliance, etc.).");
        }
        println!();
    }
}

fn print_history(target: &str, entries: &[ScanHistoryEntry]) {
    println!("================================================================================");
    let scope = if target.trim().is_empty() {
        "TOUTES CIBLES".to_string()
    } else {
        target.to_string()
    };
    println!(
        "           HISTORIQUE POSTGRESQL DES AUDITS CATALOGUÉS : {}",
        scope
    );
    println!("================================================================================");
    if entries.is_empty() {
        println!("Aucun audit catalogué pour cette cible.");
    } else {
        println!(
            "{:<6} | {:<25} | {:<7} | {:<8} | {:<10} | Findings",
            "ID", "Date & Heure", "Score", "Durée", "Ports O."
        );
        println!(
            "{:-<6}-+-{:-<25}-+-{:-<7}-+-{:-<8}-+-{:-<10}-+-------------------",
            "", "", "", "", ""
        );
        for e in entries {
            println!(
                "{:<6} | {:<25} | {:<5}/100 | {:<6.2}s | {:<10} | {} constatations",
                e.id,
                e.created_at,
                e.overall_score,
                e.duration_seconds,
                e.open_ports_count,
                e.findings_count
            );
        }
    }
    println!("--------------------------------------------------------------------------------\n");
}
