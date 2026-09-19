// c2_empire.rs — Wrapper Empire 6.x (BC-SECURITY, agents PowerShell/Python)
use crate::modules::findings::SecurityFinding;
use std::time::Instant;

#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct EmpireAuditResult {
    pub success: bool,
    pub elapsed_seconds: f32,
    pub installed: bool,
    pub database_ready: bool,
    pub server_running: bool,
    pub raw_output: String,
    pub summary: String,
}

pub struct EmpireAuditor;

impl EmpireAuditor {
    #[allow(clippy::field_reassign_with_default)]
    pub fn audit() -> EmpireAuditResult {
        let start = Instant::now();
        let mut result = EmpireAuditResult::default();

        result.installed = crate::utils::tool_on_path("powershell-empire");
        if !result.installed {
            result.summary = "Empire absent du PATH (apt install powershell-empire)".to_string();
            result.success = false;
            result.elapsed_seconds = start.elapsed().as_secs_f32();
            return result;
        }

        // DB prête ? (mariadb/mysql + base empire créée par `powershell-empire setup`)
        result.database_ready =
            crate::utils::run_tool("mysql", &["-u", "root", "-e", "USE empire;"], 10).is_some();

        // Serveur REST actif ? (port 1337 par défaut)
        result.server_running = crate::utils::tcp_probe("127.0.0.1", 1337);

        if let Some(o) = crate::utils::run_tool("powershell-empire", &["--help"], 20) {
            let txt = String::from_utf8_lossy(&o.stdout).to_string()
                + &String::from_utf8_lossy(&o.stderr);
            result.raw_output = txt.lines().take(4).collect::<Vec<_>>().join("\n");
        }

        result.summary = format!(
            "Empire installé | DB {} | serveur {}",
            if result.database_ready {
                "prête"
            } else {
                "non initialisée (setup requis)"
            },
            if result.server_running {
                "ACTIF (:1337)"
            } else {
                "inactif"
            }
        );
        result.success = result.installed;
        result.elapsed_seconds = start.elapsed().as_secs_f32();
        result
    }

    pub fn to_findings(r: &EmpireAuditResult) -> Vec<SecurityFinding> {
        let mut f = Vec::new();
        if r.installed {
            if r.server_running {
                f.push(SecurityFinding {
                    severity: "INFO",
                    category: "C2",
                    title: "Empire : serveur actif".to_string(),
                    recommendation:
                        "Empire opérationnel (agents PowerShell/Python, modules persistants). Usage autorisé uniquement."
                            .to_string(),
                });
            } else if !r.database_ready {
                f.push(SecurityFinding {
                    severity: "LOW",
                    category: "C2",
                    title: "Empire : base de données non initialisée".to_string(),
                    recommendation:
                        "Lancer `powershell-empire setup` pour créer la base (mariadb) avant usage."
                            .to_string(),
                });
            }
        }
        f
    }
}
