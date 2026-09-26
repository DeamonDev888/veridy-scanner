
#[allow(dead_code)]
#[derive(Debug, Clone, Default)]
#[derive(serde::Serialize, serde::Deserialize)]
pub struct TlsAuditResult {
    pub domain: String,
    pub protocol: Option<String>,
    pub cipher: Option<String>,
    pub issuer: Option<String>,
    pub subject: Option<String>,
    pub sans: Vec<String>,
    pub valid_from: Option<String>,
    pub valid_until: Option<String>,
    pub days_remaining: Option<i32>,
    pub is_valid: bool,
    pub is_self_signed: bool,
    pub supports_tls10: bool,
    pub supports_tls11: bool,
    pub supports_tls12: bool,
    pub supports_tls13: bool,
    pub issues: Vec<String>,
}

pub struct TlsAuditor;

impl TlsAuditor {
    pub fn audit(domain: &str, ip: &str) -> TlsAuditResult {
        let mut result = TlsAuditResult {
            domain: domain.to_string(),
            protocol: None,
            cipher: None,
            issuer: None,
            subject: None,
            sans: Vec::new(),
            valid_from: None,
            valid_until: None,
            days_remaining: None,
            is_valid: false,
            is_self_signed: false,
            supports_tls10: false,
            supports_tls11: false,
            supports_tls12: false,
            supports_tls13: false,
            issues: Vec::new(),
        };

        // Connexion sur l'IP RÉSOLUE (IPv4 en pratique) + SNI = domaine : évite le
        // piège openssl qui tente l'IPv6 en premier (Network is unreachable sur un
        // réseau sans route v6) et garantit qu'on audite l'IP effectivement résolue.
        let host_ip = if ip.contains(':') {
            format!("[{}]", ip) // IPv6 littéral → crochets requis pour -connect
        } else {
            ip.to_string()
        };
        let connect_target = format!("{}:443", host_ip);
        let sni_args = ["-servername", domain];

        // 1. Négociation moderne par défaut — avec RETRY : si la ligne
        // "Verification:" manque de la sortie fusionnée stdout+stderr (race
        // kill/timeout, serveur lent), is_valid resterait false à tort et
        // déclencherait le finding CRITICAL "Chaîne de confiance invalide"
        // sur des cibles parfaitement valides (bug vu sur example.com et
        // veridy.ca). On relance le handshake jusqu'à obtenir le verdict.
        let mut verification_seen = false;
        for _attempt in 0..3 {
            if let Some(output) = crate::utils::run_tool(
                "openssl",
                &[
                    "s_client",
                    "-connect",
                    &connect_target,
                    sni_args[0],
                    sni_args[1],
                    "-brief",
                ],
                10,
            ) {
                // -brief écrit la négociation sur STDERR : fusion des deux flux
                let mut stdout = String::from_utf8_lossy(&output.stdout).to_string();
                stdout.push_str(&String::from_utf8_lossy(&output.stderr));
                let mut found_this_pass = false;
                for line in stdout.lines() {
                    let trimmed = line.trim();
                    if trimmed.starts_with("Protocol version:") {
                        let proto = trimmed.split(':').nth(1).map(|s| s.trim().to_string());
                        if let Some(ref p) = proto {
                            if p.contains("1.3") {
                                result.supports_tls13 = true;
                            } else if p.contains("1.2") {
                                result.supports_tls12 = true;
                            }
                        }
                        result.protocol = proto;
                    } else if trimmed.starts_with("Ciphersuite:") {
                        result.cipher = trimmed.split(':').nth(1).map(|s| s.trim().to_string());
                    } else if trimmed.starts_with("Verification:") {
                        found_this_pass = true;
                        if trimmed.contains("OK") {
                            result.is_valid = true;
                        } else {
                            result
                                .issues
                                .push(format!("Erreur de chaîne de confiance : {}", trimmed));
                        }
                    }
                }
                verification_seen = found_this_pass;
                if found_this_pass {
                    break;
                }
            } else {
                // openssl injoignable/network KO → inutile de boucler
                break;
            }
        }
        let _ = verification_seen;

        // 2. Vérification de la présence de protocoles obsolètes (TLS 1.0, 1.1)
        if let Some(out) = crate::utils::run_tool(
            "openssl",
            &[
                "s_client",
                "-connect",
                &connect_target,
                sni_args[0],
                sni_args[1],
                "-tls1",
            ],
            10,
        ) {
            let s = String::from_utf8_lossy(&out.stdout);
            if s.contains("Cipher is ")
                && !s.contains("Cipher is (NONE)")
                && !s.contains("Cipher is 0000")
                && !s.contains("alert protocol version")
                && !s.contains("handshake failure")
            {
                result.supports_tls10 = true;
                result.issues.push(
                    "Vulnérabilité : Le protocole obsolète et non sécurisé TLSv1.0 est activé !"
                        .into(),
                );
            }
        }

        if let Some(out) = crate::utils::run_tool(
            "openssl",
            &[
                "s_client",
                "-connect",
                &connect_target,
                sni_args[0],
                sni_args[1],
                "-tls1_1",
            ],
            10,
        ) {
            let s = String::from_utf8_lossy(&out.stdout);
            if s.contains("Cipher is ")
                && !s.contains("Cipher is (NONE)")
                && !s.contains("Cipher is 0000")
                && !s.contains("alert protocol version")
                && !s.contains("handshake failure")
            {
                result.supports_tls11 = true;
                result.issues.push(
                    "Vulnérabilité : Le protocole obsolète et non sécurisé TLSv1.1 est activé !"
                        .into(),
                );
            }
        }

        // 3. Inspection détaillée du certificat x509
        // On récupère le cert PEM via openssl s_client, puis on parse avec openssl x509 sur un fichier tmp
        let pid = std::process::id();
        let cert_pem = format!("/tmp/tls_cert_{}_{}.pem", crate::utils::sanitize_target(domain), pid);
        if let Some(out) = crate::utils::run_tool(
            "openssl",
            &[
                "s_client",
                "-connect",
                &connect_target,
                sni_args[0],
                sni_args[1],
                "-showcerts",
            ],
            10,
        ) {
            if !out.stdout.is_empty() {
                let _ = std::fs::write(&cert_pem, &out.stdout);
            }
        }

        if let Some(output) = crate::utils::run_tool(
            "openssl",
            &["x509", "-noout", "-subject", "-issuer", "-dates", "-ext", "subjectAltName", "-checkend", "0", "-in", &cert_pem],
            10,
        ) {
            let _ = std::fs::remove_file(&cert_pem);
            let stdout = String::from_utf8_lossy(&output.stdout);
            for line in stdout.lines() {
                let trimmed = line.trim();
                if trimmed.starts_with("subject=") {
                    result.subject =
                        Some(trimmed.trim_start_matches("subject=").trim().to_string());
                } else if trimmed.starts_with("issuer=") {
                    result.issuer = Some(trimmed.trim_start_matches("issuer=").trim().to_string());
                } else if trimmed.starts_with("notBefore=") {
                    result.valid_from =
                        Some(trimmed.trim_start_matches("notBefore=").trim().to_string());
                } else if trimmed.starts_with("notAfter=") {
                    result.valid_until =
                        Some(trimmed.trim_start_matches("notAfter=").trim().to_string());
                } else if trimmed.contains("DNS:") {
                    for entry in trimmed.split(',') {
                        let e = entry.trim();
                        if let Some(san) = e.strip_prefix("DNS:") {
                            let san_str = san.trim().to_string();
                            if !result.sans.contains(&san_str) {
                                result.sans.push(san_str);
                            }
                        }
                    }
                }
            }
        }

        // 4. Calcul des jours restants avant expiration — depuis valid_until déjà
        //    récupéré à l'étape 3 (UNE seule connexion s_client pour tout le module).
        if let Some(ref vu) = result.valid_until {
            if let Some(end_epoch) = parse_openssl_date(vu) {
                let now_epoch = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs() as i64)
                    .unwrap_or(0);
                let days = ((end_epoch - now_epoch) / 86400) as i32;
                result.days_remaining = Some(days);
                if days <= 0 {
                    result.issues.push("CRITIQUE : Le certificat TLS a expiré !".into());
                } else if days < 15 {
                    result.issues.push(format!(
                        "AVERTISSEMENT : Le certificat expire bientôt (dans {} jours) !",
                        days
                    ));
                }
            }
        }

        // Auto-signé ?
        if let (Some(sub), Some(iss)) = (&result.subject, &result.issuer) {
            if sub == iss {
                result.is_self_signed = true;
                result.issues.push(
                    "Certificat auto-signé non reconnu par les autorités de confiance.".into(),
                );
            }
        }

        result
    }
}

/// Parse une date au format openssl x509 -enddate : "Jan 15 12:00:00 2027 GMT" / "Jan 15 12:00:00 2027"
pub(crate) fn parse_openssl_date(s: &str) -> Option<i64> {
    // Tolérant aux préfixes "notAfter=" / "notBefore=" (bug historique : jamais strippé)
    let s = s
        .trim()
        .trim_start_matches("notAfter=")
        .trim_start_matches("notBefore=")
        .trim();
    let months = ["Jan","Feb","Mar","Apr","May","Jun","Jul","Aug","Sep","Oct","Nov","Dec"];
    let parts: Vec<&str> = s.split_whitespace().collect();
    if parts.len() < 4 { return None; }
    let month = months.iter().position(|m| *m == parts[0])? as i64 + 1;
    let day: i64 = parts[1].parse().ok()?;
    let time: Vec<&str> = parts[2].split(':').collect();
    if time.len() != 3 { return None; }
    let h: i64 = time[0].parse().ok()?;
    let m: i64 = time[1].parse().ok()?;
    let sec: i64 = time[2].parse().ok()?;
    let year: i64 = parts[3].parse().ok()?;
    // Algo Howard Hinnant (days_from_civil) → epoch
    let y = if month <= 2 { year - 1 } else { year };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let _m = if month > 2 { month - 3 } else { month + 9 };
    let doy = (153 * _m + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146097 + doe - 719468;
    Some(days * 86400 + h * 3600 + m * 60 + sec)
}
