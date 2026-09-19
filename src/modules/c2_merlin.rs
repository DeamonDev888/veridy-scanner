// c2_merlin.rs — Wrapper Merlin (C2 HTTP/2, RussMcRee)
use crate::modules::findings::SecurityFinding;
use std::time::Instant;

#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct MerlinAuditResult {
    pub success: bool,
    pub elapsed_seconds: f32,
    pub installed: bool,
    pub version: Option<String>,
    pub server_running: bool,
    pub raw_output: String,
    pub summary: String,
}

pub struct MerlinAuditor;

impl MerlinAuditor {
    #[allow(clippy::field_reassign_with_default)]
    pub fn audit() -> MerlinAuditResult {
        let start = Instant::now();
        let mut result = MerlinAuditResult::default();

        // Binaire : merlinserver (/usr/sbin)
        result.installed =
            crate::utils::tool_on_path("merlinserver") || crate::utils::tool_on_path("merlinAgent");

        if result.installed {
            if let Some(o) = crate::utils::run_tool("merlinserver", &["-h"], 20) {
                let txt = String::from_utf8_lossy(&o.stdout).to_string()
                    + &String::from_utf8_lossy(&o.stderr);
                result.raw_output = txt.lines().take(6).collect::<Vec<_>>().join("\n");
            }
            // Serveur gRPC : 127.0.0.1:50051 par défaut
            result.server_running = crate::utils::tcp_probe("127.0.0.1", 50051);
            result.version = Some("2.x".to_string());
        }

        result.summary = format!(
            "Merlin {} | serveur {}",
            result.version.as_deref().unwrap_or("?"),
            if result.server_running {
                "ACTIF (gRPC :50051)"
            } else {
                "inactif"
            }
        );
        result.success = result.installed;
        result.elapsed_seconds = start.elapsed().as_secs_f32();
        result
    }

    pub fn to_findings(r: &MerlinAuditResult) -> Vec<SecurityFinding> {
        let mut f = Vec::new();
        if r.installed && r.server_running {
            f.push(SecurityFinding {
                severity: "INFO",
                category: "C2",
                title: "Merlin : serveur C2 actif".to_string(),
                recommendation:
                    "Serveur Merlin opérationnel (HTTP/2 C2). Agents déployables — usage autorisé uniquement."
                        .to_string(),
            });
        }
        f
    }
}
