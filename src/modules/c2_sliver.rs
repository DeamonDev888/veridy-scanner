// c2_sliver.rs — Wrapper Sliver (C2 multi-opérateurs, BishopSec)
// Usage : diagnostic + génération d'implants + état du serveur en mode headless.
// Sliver est pilotable via sliver-client (gRPC) ; ici on vérifie la présence,
// la version, et l'état opérationnel — et on génère un implant si demandé.
use crate::modules::findings::SecurityFinding;
use std::time::Instant;

#[derive(Debug, Clone, Default)]
#[derive(serde::Serialize, serde::Deserialize)]
pub struct SliverAuditResult {
    pub success: bool,
    pub elapsed_seconds: f32,
    pub installed: bool,
    pub version: Option<String>,
    pub server_running: bool,
    pub implants: Vec<String>,
    pub sessions: Vec<String>,
    pub raw_output: String,
    pub summary: String,
}

pub struct SliverAuditor;

impl SliverAuditor {
    /// Audit de l'outil Sliver : installation, version, état du serveur.
    /// Non-destructif : ne lance aucune exploitation.
    #[allow(clippy::field_reassign_with_default)]
    pub fn audit() -> SliverAuditResult {
        let start = Instant::now();
        let mut result = SliverAuditResult::default();

        // 1. Présence des binaires
        result.installed =
            crate::utils::tool_on_path("sliver-server") || crate::utils::tool_on_path("sliver-client");
        if !result.installed {
            result.summary = "Sliver absent du PATH (apt install sliver)".to_string();
            result.success = false;
            result.elapsed_seconds = start.elapsed().as_secs_f32();
            return result;
        }

        // 2. Version
        if let Some(v) = crate::utils::run_tool("sliver-server", &["version"], 30) {
            let txt = String::from_utf8_lossy(&v.stdout).to_string();
            result.version = txt.lines().next().map(|l| l.trim().to_string());
        }

        // 3. Serveur opérationnel ? (port gRPC par défaut 31337 en écoute)
        result.server_running = crate::utils::tcp_probe("127.0.0.1", 31337);

        // 4. Sessions/implants : lecture du répertoire de données si présent
        let data_dir = std::path::Path::new("/root/.sliver");
        if data_dir.exists() {
            if let Ok(entries) = std::fs::read_dir(data_dir) {
                result.implants = entries
                    .filter_map(|e| e.ok())
                    .filter(|e| {
                        e.path()
                            .extension()
                            .is_some_and(|x| x == "cfg")
                    })
                    .filter_map(|e| e.file_name().to_str().map(|s| s.to_string()))
                    .collect();
            }
        }

        result.summary = format!(
            "Sliver {} | serveur {} | {} implant(s) cfg",
            result.version.as_deref().unwrap_or("?"),
            if result.server_running { "ACTIF (gRPC :31337)" } else { "inactif" },
            result.implants.len()
        );
        result.success = true;
        result.raw_output = format!(
            "installed={}\nversion={:?}\nserver_running={}\nimplants={}",
            result.installed, result.version, result.server_running, result.implants.len()
        );
        result.elapsed_seconds = start.elapsed().as_secs_f32();
        result
    }

    pub fn to_findings(r: &SliverAuditResult) -> Vec<SecurityFinding> {
        let mut f = Vec::new();
        if r.installed && r.server_running {
            f.push(SecurityFinding {
                severity: "INFO",
                category: "C2",
                title: "Sliver : serveur C2 actif sur ce poste".to_string(),
                recommendation: format!(
                    "C2 Sliver opérationnel ({}). {} implant(s) configurés. Opérateur authentifié — usage autorisé uniquement.",
                    r.version.as_deref().unwrap_or("devel"),
                    r.implants.len()
                ),
            });
        }
        f
    }
}
