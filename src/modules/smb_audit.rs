#![allow(dead_code)]
//! Module SMB cible IP : enum users via SAMR null session, listing des partages,
//! détection d'authentification anonyme / guest, version Samba, identification
//! de comptes de service cachés via SAMR RID cycling ciblé.
//!
//! Conçu pour les boxes de type Appointment / Driver / Active / Forest : SMBv2 only,
//! sans Kerberos ni WinRM, mais SAMR ouvert en null.

use std::time::Instant;

#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct SmbAuditResult {
    pub success: bool,
    pub brute_force_feasible: bool,
    pub elapsed_seconds: f32,
    pub target: String,
    pub smb_version: Option<String>,
    pub shares: Vec<String>,
    pub anonymous_access: Vec<String>, // shares accessibles sans auth
    pub users: Vec<SmbUserRecord>,
    pub groups: Vec<String>,
    pub signature_required: bool,
    pub os: Option<String>,
    pub findings: Vec<String>,
    pub raw_evidence: String,
}

#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct SmbUserRecord {
    pub username: String,
    pub full_name: String,
    pub description: String,
    pub rid: u32,
}

pub struct SmbAuditor;

impl SmbAuditor {
    /// Lance enum4linux + rpcclient + smbclient sur une IP
    pub fn audit(target: &str) -> SmbAuditResult {
        let start = Instant::now();
        let mut res = SmbAuditResult {
            success: true,
            brute_force_feasible: false,
            elapsed_seconds: 0.0,
            target: target.to_string(),
            smb_version: None,
            shares: Vec::new(),
            anonymous_access: Vec::new(),
            users: Vec::new(),
            groups: Vec::new(),
            signature_required: false,
            os: None,
            findings: Vec::new(),
            raw_evidence: String::new(),
        };

        // 1. Version Samba + OS via nmap
        if let Some(o) = crate::utils::run_tool(
            "nmap",
            &["-Pn", "-p", "445", "--script=smb-os-discovery,smb2-security-mode",
              "-sV", "--max-retries", "1", "-T4", target],
            30,
        ) {
            let s = String::from_utf8_lossy(&o.stdout).to_string();
            // Extraction basique : "OS: Windows ..." et "|   Samba ..."
            for line in s.lines() {
                if line.contains("Samba") {
                    res.smb_version = Some(line.trim().to_string());
                }
                if line.contains("OS:") && res.os.is_none() {
                    res.os = Some(line.trim().to_string());
                }
                if line.contains("Message signing enabled but not required") {
                    res.signature_required = false;
                    res.findings.push(
                        "SMB signing DISABLED: vulnérable à NTLM relay (mitm6, responder)"
                            .to_string(),
                    );
                }
                if line.contains("Message signing enabled and required") {
                    res.signature_required = true;
                }
            }
        }

        // 2. Enum shares anonymes
        if let Some(o) = crate::utils::run_tool(
            "smbclient",
            &["-N", "-L", &format!("//{}/", target)],
            15,
        ) {
            let s = String::from_utf8_lossy(&o.stdout).to_string();
            res.raw_evidence.push_str(&s);
            let mut in_share_block = false;
            for line in s.lines() {
                if line.trim().starts_with("---------") {
                    in_share_block = !in_share_block;
                    continue;
                }
                if in_share_block && !line.trim().is_empty() && !line.contains("Sharename") {
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    if !parts.is_empty() {
                        let name = parts[0].to_string();
                        let junk = ["Reconnecting", "Protocol", "Unable", "Server",
                                    "ntlm_password", "session_setup", "tree",
                                    "Domain=", "SMB1", "password"];
                        let is_junk = junk.contains(&name.as_str())
                            || name.starts_with("NT_STATUS")
                            || name.starts_with("smb")
                            || name.contains(':');
                        if !name.is_empty() && !is_junk && !res.shares.contains(&name) {
                            res.shares.push(name);
                        }
                    }
                }
            }
        }

        // 3. Test accès anonyme sur chaque partage (cherche des fichiers/dossiers)
        for share in &res.shares.clone() {
            if share == "IPC$" {
                continue;
            }
            if let Some(o) = crate::utils::run_tool(
                "smbclient",
                &["-N", "-c", "ls; exit", &format!("//{}/{}", target, share)],
                15,
            ) {
                let s = String::from_utf8_lossy(&o.stdout).to_string();
                let denied = s.contains("NT_STATUS_ACCESS_DENIED")
                    || s.contains("NT_STATUS_NO_SUCH_FILE")
                    || s.contains("NT_STATUS_ACCESS_MASK")
                    || s.trim().is_empty();
                if !denied {
                    res.anonymous_access.push(share.to_string());
                    res.findings.push(format!(
                        "Partage SMB '{}' accessible ANONYMOUSMENT (données lues via SMB null session)",
                        share
                    ));
                }
            }
        }

        // 4. Enum users via SAMR (via rpcclient)
        if let Some(o) = crate::utils::run_tool(
            "rpcclient",
            &["-N", "-U", "", "-c", "querydispinfo;enumdomusers;enumdomgroups", target],
            30,
        ) {
            let s = String::from_utf8_lossy(&o.stdout).to_string();
            res.raw_evidence.push_str("\n--- RPC ---\n");
            res.raw_evidence.push_str(&s);
            parse_samr_users(&s, &mut res.users);
            parse_samr_groups(&s, &mut res.groups);
        }

        // 5. SAMR RID cycling 500-550, 1000-1200 (comptes de service cachés)
        for rid in [500u32, 501, 502, 503, 504, 505, 506, 512, 513, 514, 515,
                    1000, 1001, 1002, 1003, 1004, 1005, 1006, 1007, 1008, 1009, 1010,
                    1011, 1012, 1013, 1014, 1015, 1016, 1017, 1018, 1019, 1020, 1100, 1101,
                    1200, 1300, 1400, 1500, 2000, 2001] {
            if let Some(o) = crate::utils::run_tool(
                "rpcclient",
                &["-N", "-U", "", "-c", &format!("queryuser {}", rid), target],
                6,
            ) {
                let s = String::from_utf8_lossy(&o.stdout).to_string();
                if s.contains("Account:") && !s.contains("NT_STATUS_NONE_MAPPED") {
                    // Extraire le username
                    if let Some(name) = s.lines()
                        .find(|l| l.contains("Account:"))
                        .and_then(|l| l.split(':').nth(1))
                        .map(|s| s.trim().to_string())
                    {
                        if !res.users.iter().any(|u| u.username == name) {
                            res.users.push(SmbUserRecord {
                                username: name,
                                full_name: String::new(),
                                description: String::new(),
                                rid,
                            });
                        }
                    }
                }
            }
        }

        // 6. Politique de mots de passe via rpcclient getdompwinfo (feu vert brute force ?)
        if let Some(o) = crate::utils::run_tool(
            "rpcclient",
            &["-N", "-U", "", "-c", "getdompwinfo", target],
            10,
        ) {
            let s = String::from_utf8_lossy(&o.stdout).to_string();
            if s.contains("Account Lockout Threshold") {
                let no_lockout = s.lines().any(|l| {
                    l.contains("Account Lockout Threshold")
                        && (l.contains("None") || l.trim().ends_with("0"))
                });
                if no_lockout && !res.users.is_empty() {
                    res.findings.push(
                        "AUCUN verrouillage de compte (threshold=None): le brute force SMB \
                         par dictionnaire est SANS RISQUE de lockout sur les comptes découverts"
                            .to_string(),
                    );
                    res.brute_force_feasible = true;
                }
                res.raw_evidence.push_str(&format!("\n--- PW-POL ---\n{}", s));
            }
        }

        if !res.anonymous_access.is_empty() {
            res.findings.push(format!(
                "{} partage(s) accessible(s) sans authentification — vecteur de données exfiltrables",
                res.anonymous_access.len()
            ));
        }
        if !res.signature_required {
            res.findings.push(
                "SMB signing NOT required: vulnérable à NTLM relay (responder/ntlmrelayx)"
                    .to_string(),
            );
        }
        if res.users.len() > 5 {
            res.findings.push(format!(
                "{} comptes découverts — tester wordlist ciblée sur chaque username \
                 et chercher les descriptions / login scripts visibles",
                res.users.len()
            ));
        }

        res.elapsed_seconds = start.elapsed().as_secs_f32();
        res
    }
}

fn parse_samr_users(s: &str, out: &mut Vec<SmbUserRecord>) {
    let mut idx: u32 = 0;
    for line in s.lines() {
        if line.starts_with("index:") {
            // Format: "index: 0x1 RID: 0x3e8 acb: 0x00000010 Account: scott\tName: Scott Mercer\tDesc: "
            let parts: Vec<&str> = line.split('\t').collect();
            if parts.len() >= 2 {
                let account_part = parts.iter().find(|p| p.contains("Account:"));
                let name_part = parts.iter().find(|p| p.contains("Name:"));
                if let Some(acct) = account_part {
                    let username = acct.rsplit("Account:").next().unwrap_or("").trim().to_string();
                    let full = name_part
                        .and_then(|n| n.split(':').nth(1))
                        .unwrap_or("")
                        .trim()
                        .to_string();
                    let rid_str = parts[0].split("RID:").nth(1).unwrap_or("0").trim();
                    let rid = u32::from_str_radix(rid_str.trim_start_matches("0x"), 16).unwrap_or(idx);
                    if !username.is_empty() && !out.iter().any(|u| u.username == username) {
                        out.push(SmbUserRecord {
                            username,
                            full_name: full,
                            description: String::new(),
                            rid,
                        });
                    }
                }
                idx += 1;
            }
        }
    }
}

fn parse_samr_groups(s: &str, out: &mut Vec<String>) {
    for line in s.lines() {
        if line.contains("Group:") && line.contains("rid:") {
            if let Some(name) = line.split("Group:").nth(1) {
                let n = name.split_whitespace().next().unwrap_or("").to_string();
                if !n.is_empty() && !out.contains(&n) {
                    out.push(n);
                }
            }
        }
    }
}