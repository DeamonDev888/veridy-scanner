// c2_havoc.rs — Wrapper Havoc (C2 red team, demon)
use crate::modules::findings::SecurityFinding;
use std::time::Instant;

#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct HavocAuditResult {
    pub success: bool,
    pub elapsed_seconds: f32,
    pub installed: bool,
    pub version: Option<String>,
    pub teamserver_running: bool,
    pub raw_output: String,
    pub summary: String,
}

pub struct HavocAuditor;

impl HavocAuditor {
    #[allow(clippy::field_reassign_with_default)]
    pub fn audit() -> HavocAuditResult {
        let start = Instant::now();
        let mut result = HavocAuditResult::default();

        result.installed = crate::utils::tool_on_path("havoc");
        if !result.installed {
            result.summary = "Havoc absent du PATH (apt install havoc)".to_string();
            result.success = false;
            result.elapsed_seconds = start.elapsed().as_secs_f32();
            return result;
        }

        // Havoc --help contient la version en tête
        if let Some(o) = crate::utils::run_tool("havoc", &["--help"], 30) {
            let txt = String::from_utf8_lossy(&o.stdout).to_string()
                + &String::from_utf8_lossy(&o.stderr);
            for line in txt.lines().take(3) {
                if line.contains("Version") {
                    result.version = Some(line.trim().to_string());
                    break;
                }
            }
            result.raw_output = txt.lines().take(5).collect::<Vec<_>>().join("\n");
        }

        // Teamserver : port 40056 par défaut
        result.teamserver_running = crate::utils::tcp_probe("127.0.0.1", 40056);

        result.summary = format!(
            "Havoc {} | teamserver {}",
            result.version.as_deref().unwrap_or("?"),
            if result.teamserver_running {
                "ACTIF (:40056)"
            } else {
                "inactif"
            }
        );
        result.success = result.installed;
        result.elapsed_seconds = start.elapsed().as_secs_f32();
        result
    }

    pub fn to_findings(r: &HavocAuditResult) -> Vec<SecurityFinding> {
        let mut f = Vec::new();
        if r.installed && r.teamserver_running {
            f.push(SecurityFinding {
                severity: "INFO",
                category: "C2",
                title: "Havoc : teamserver actif sur ce poste".to_string(),
                recommendation: format!(
                    "Teamserver Havoc opérationnel ({}). Implants demon disponibles — usage autorisé uniquement.",
                    r.version.as_deref().unwrap_or("?")
                ),
            });
        }
        f
    }
}
