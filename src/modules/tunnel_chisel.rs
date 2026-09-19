// tunnel_chisel.rs — Wrapper Chisel (tunnelling TCP HTTP, jpillora)
// Mode non-destructif : vérifie la présence + démontre la capacité serveur
// locale (bind 127.0.0.1 éphémère, auto-fermé) — jamais de tunnel sortant.
use crate::modules::findings::SecurityFinding;
use std::time::Instant;

#[derive(Debug, Clone, Default)]
#[derive(serde::Serialize, serde::Deserialize)]
pub struct ChiselAuditResult {
    pub success: bool,
    pub elapsed_seconds: f32,
    pub installed: bool,
    pub server_demo_ok: bool,
    pub version: Option<String>,
    pub raw_output: String,
    pub summary: String,
}

pub struct ChiselAuditor;

impl ChiselAuditor {
    #[allow(clippy::field_reassign_with_default)]
    pub fn audit() -> ChiselAuditResult {
        let start = Instant::now();
        let mut result = ChiselAuditResult::default();

        result.installed = crate::utils::tool_on_path("chisel");
        if !result.installed {
            result.summary = "Chisel absent du PATH (apt install chisel)".to_string();
            result.success = false;
            result.elapsed_seconds = start.elapsed().as_secs_f32();
            return result;
        }

        // help contient la version
        if let Some(o) = crate::utils::run_tool("chisel", &["--help"], 15) {
            let txt = String::from_utf8_lossy(&o.stdout).to_string()
                + &String::from_utf8_lossy(&o.stderr);
            for line in txt.lines().take(3) {
                if line.contains("version") {
                    result.version = Some(line.trim().to_string());
                    break;
                }
            }
            result.raw_output = txt.lines().take(3).collect::<Vec<_>>().join("\n");
        }

        // Démo locale : serveur chisel sur port éphémère 127.0.0.1:18124, 4 s max
        let demo = std::process::Command::new("chisel")
            .args(["server", "-p", "18124", "--reverse"])
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn();
        if let Ok(mut child) = demo {
            std::thread::sleep(std::time::Duration::from_millis(1500));
            result.server_demo_ok = crate::utils::tcp_probe("127.0.0.1", 18124);
            let _ = child.kill();
            let _ = child.wait();
        }

        result.summary = format!(
            "Chisel {} | serveur local {}",
            result.version.as_deref().unwrap_or("?"),
            if result.server_demo_ok { "démontrable (bind OK)" } else { "non démontré" }
        );
        result.success = result.installed;
        result.elapsed_seconds = start.elapsed().as_secs_f32();
        result
    }

    pub fn to_findings(_r: &ChiselAuditResult) -> Vec<SecurityFinding> {
        Vec::new() // outil de tunnelling : pas de finding d'audit de cible
    }
}
