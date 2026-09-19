use std::net::{IpAddr, ToSocketAddrs};

/// Validation et résolution de la cible. Aucune restriction normative :
/// l'opérateur est maître de ce qu'il scanne. On valide uniquement :
///   - Format du host (regex stricte : lettres, chiffres, . - _, longueur 1..=253)
///   - Résolution DNS effective
///   - Déduplication des IPs
pub struct TargetParser;

#[derive(Debug, PartialEq, Eq)]
pub enum TargetVerdict {
    Resolved(Vec<IpAddr>),
    InvalidFormat(String),
    Unresolvable(String),
}

impl TargetParser {
    /// Valide le format et résout la cible en adresses IP.
    pub fn resolve(target: &str) -> TargetVerdict {
        let trimmed = target.trim().to_lowercase();

        if trimmed.is_empty() {
            return TargetVerdict::InvalidFormat("Cible vide".into());
        }
        if trimmed.len() > 253 {
            return TargetVerdict::InvalidFormat(format!(
                "Cible trop longue : {} caractères (max 253)",
                trimmed.len()
            ));
        }

        // Hostname : alphanum + . - _, chaque label 1..=63, séparés par .
        // IP brute acceptée en input direct (on parse plus bas).
        let host_re_ok = trimmed
            .split('.')
            .all(|label| {
                !label.is_empty()
                    && label.len() <= 63
                    && label
                        .chars()
                        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
            });

        // Si ça parse comme IP, on accepte directement sans passer par le host regex
        let is_ip = trimmed.parse::<IpAddr>().is_ok();
        if !is_ip && !host_re_ok {
            return TargetVerdict::InvalidFormat(format!(
                "Format de cible invalide : '{}' (attendu : lettres/chiffres/./-/_)",
                trimmed
            ));
        }

        // IP directe → pas de résolution DNS
        if let Ok(ip) = trimmed.parse::<IpAddr>() {
            return TargetVerdict::Resolved(vec![ip]);
        }

        // Hostname → résolution DNS
        let host_port = format!("{}:80", trimmed);
        match host_port.to_socket_addrs() {
            Ok(addrs) => {
                let mut ips: Vec<IpAddr> = Vec::new();
                for sock_addr in addrs {
                    let ip = sock_addr.ip();
                    if !ips.contains(&ip) {
                        ips.push(ip);
                    }
                }
                if ips.is_empty() {
                    TargetVerdict::Unresolvable(format!("Aucune adresse IP résolue pour '{}'", trimmed))
                } else {
                    TargetVerdict::Resolved(ips)
                }
            }
            Err(e) => TargetVerdict::Unresolvable(format!(
                "Échec de résolution DNS pour '{}': {}",
                trimmed, e
            )),
        }
    }
}
