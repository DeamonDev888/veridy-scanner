// lateral_netexec.rs — Wrapper NetExec (crackmapexec v2, mouvement latéral)
// Audit NON-destructif : null-session probing SMB/WinRM/LDAP — jamais de
// spray, jamais de --sam/--lsa. Preuve = bannière + signing + OS.
use crate::modules::findings::SecurityFinding;
use std::time::Instant;

#[derive(Debug, Clone, Default)]
#[derive(serde::Serialize, serde::Deserialize)]
pub struct NetexecAuditResult {
    pub success: bool,
    pub elapsed_seconds: f32,
    pub installed: bool,
    pub version: Option<String>,
    pub target_reachable: bool,
    pub smb_signing_enforced: Option<bool>,
    pub os_info: Option<String>,
    pub raw_output: String,
    pub summary: String,
}

pub struct NetexecAuditor;

impl NetexecAuditor {
    /// Probe SMB null-session sur la cible (lecture seule, non-destructif).
    #[allow(clippy::field_reassign_with_default)]
    pub fn audit(target: &str) -> NetexecAuditResult {
        let start = Instant::now();
        let mut result = NetexecAuditResult::default();

        result.installed = crate::utils::tool_on_path("nxc");
        if !result.installed {
            result.summary = "NetExec absent du PATH (apt install netexec)".to_string();
            result.success = false;
            result.elapsed_seconds = start.elapsed().as_secs_f32();
            return result;
        }

        if let Some(o) = crate::utils::run_tool("nxc", &["--version"], 15) {
            let txt = String::from_utf8_lossy(&o.stdout).to_string();
            result.version = txt.lines().next().map(|l| l.trim().to_string());
        }

        // SMB probe null-session (signing inclus dans la sortie standard)
        if let Some(o) = crate::utils::run_tool("nxc", &["smb", target, "--gen-json", "/dev/stdout"], 90) {
            let o = String::from_utf8_lossy(&o.stdout).to_string()
                + &String::from_utf8_lossy(&o.stderr);
            result.raw_output = o.chars().take(2000).collect();
            result.target_reachable = o.contains("\"status\"");
            // signing : "(signing:True)" / "(signing:False)" ou json "signing"
            if o.contains("signing:True") || o.contains("\"signing\": true") {
                result.smb_signing_enforced = Some(true);
            } else if o.contains("signing:False") || o.contains("\"signing\": false") {
                result.smb_signing_enforced = Some(false);
            }
            // OS
            if let Some(pos) = o.find("OS:") {
                result.os_info = Some(o[pos..].chars().take(60).collect());
            }
        }

        result.summary = format!(
            "NetExec {} | cible {} | SMB signing: {}",
            result.version.as_deref().unwrap_or("?"),
            if result.target_reachable { "joignable" } else { "non joignable / SMB fermé" },
            match result.smb_signing_enforced {
                Some(true) => "forcé ✓",
                Some(false) => "NON forcé ⚠",
                None => "indéterminé",
            }
        );
        result.success = result.installed;
        result.elapsed_seconds = start.elapsed().as_secs_f32();
        result
    }

    pub fn to_findings(r: &NetexecAuditResult) -> Vec<SecurityFinding> {
        let mut f = Vec::new();
        if r.smb_signing_enforced == Some(false) {
            f.push(SecurityFinding {
                severity: "MEDIUM",
                category: "SMB",
                title: "SMB : signature non forcée (relais possible)".to_string(),
                recommendation: format!(
                    "NetExec : signing désactivé sur {} — attaques relais (ntlmrelayx) possibles. Forcer le signing par GPO.",
                    r.raw_output.lines().next().unwrap_or("cible")
                ),
            });
        }
        if r.target_reachable && r.smb_signing_enforced.is_none() && r.success {
            f.push(SecurityFinding {
                severity: "INFO",
                category: "SMB",
                title: "NetExec : probe SMB effectué".to_string(),
                recommendation: r.summary.clone(),
            });
        }
        f
    }
}
