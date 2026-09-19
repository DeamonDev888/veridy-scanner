// c2_poshc2.rs — Wrapper PoshC2 (C2 proxy-aware, Nettitude)
use crate::modules::findings::SecurityFinding;
use std::time::Instant;

#[derive(Debug, Clone, Default)]
#[derive(serde::Serialize, serde::Deserialize)]
pub struct PoshC2AuditResult {
    pub success: bool,
    pub elapsed_seconds: f32,
    pub installed: bool,
    pub framework_dir: Option<String>,
    pub service_running: bool,
    pub raw_output: String,
    pub summary: String,
}

pub struct PoshC2Auditor;

impl PoshC2Auditor {
    #[allow(clippy::field_reassign_with_default)]
    pub fn audit() -> PoshC2AuditResult {
        let start = Instant::now();
        let mut result = PoshC2AuditResult::default();

        // PoshC2 s'installe en framework Python + wrappers /usr/bin/posh*
        let dir = "/usr/share/poshc2";
        result.installed = std::path::Path::new(dir).exists()
            || crate::utils::tool_on_path("posh-server");

        if result.installed {
            result.framework_dir = Some(dir.to_string());
            // posh-service (systemd) actif ?
            if let Some(o) = crate::utils::run_tool("systemctl", &["is-active", "poshc2"], 15) {
                let txt = String::from_utf8_lossy(&o.stdout).to_string();
                result.service_running = txt.trim() == "active";
                result.raw_output = txt;
            }
        }

        result.summary = format!(
            "PoshC2 {} | service {}",
            if result.installed { "installé" } else { "absent" },
            if result.service_running { "ACTIF" } else { "inactif" }
        );
        result.success = result.installed;
        result.elapsed_seconds = start.elapsed().as_secs_f32();
        result
    }

    pub fn to_findings(r: &PoshC2AuditResult) -> Vec<SecurityFinding> {
        let mut f = Vec::new();
        if r.installed && r.service_running {
            f.push(SecurityFinding {
                severity: "INFO",
                category: "C2",
                title: "PoshC2 : serveur actif".to_string(),
                recommendation:
                    "Framework PoshC2 opérationnel (implants PowerShell/.NET). Usage autorisé uniquement."
                        .to_string(),
            });
        }
        f
    }
}
