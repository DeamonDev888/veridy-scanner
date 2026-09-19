use clap::{Parser, Subcommand};

// ==============================================================================
// TOOL FLAGS — activation des modules Kali
// ==============================================================================

#[derive(Debug, Clone, Default)]
#[derive(serde::Serialize, serde::Deserialize)]
pub struct ToolFlags {
    pub nmap: bool,
    pub nuclei: bool,
    pub nikto: bool,
    pub waf: bool,
    pub whatweb: bool,
    pub sslscan: bool,
    pub dnstwist: bool,
    pub ffuf: bool,
    pub whois: bool,
    pub dnsrecon: bool,
    pub theharvester: bool,
    pub obscura: bool,
    pub httpx: bool,
    pub rustscan: bool,
    pub sqlmap: bool,
    // ----- Modules C2 / post-exploitation (opt-in explicite) -----
    pub sliver: bool,
    pub havoc: bool,
    pub merlin: bool,
    pub poshc2: bool,
    pub empire: bool,
    pub chisel: bool,
    pub netexec: bool,
}

impl ToolFlags {
    pub fn enable_all(&mut self) {
        self.nmap = true;
        self.nuclei = true;
        self.nikto = true;
        self.waf = true;
        self.whatweb = true;
        self.sslscan = true;
        self.dnstwist = true;
        self.ffuf = true;
        self.whois = true;
        self.dnsrecon = true;
        self.theharvester = true;
        self.obscura = true;
        self.httpx = true;
        self.rustscan = true;
        // sqlmap sciemment EXCLU de enable_all : c'est un outil d'exploitation
        // actif (temps + charge réseau). Opt-in explicite --sqli uniquement.
    }

    pub fn has_any(&self) -> bool {
        self.nmap
            || self.nuclei
            || self.nikto
            || self.waf
            || self.whatweb
            || self.sslscan
            || self.dnstwist
            || self.ffuf
            || self.whois
            || self.dnsrecon
            || self.theharvester
            || self.obscura
            || self.httpx
            || self.rustscan
            || self.sqlmap
            || self.sliver
            || self.havoc
            || self.merlin
            || self.poshc2
            || self.empire
            || self.chisel
            || self.netexec
    }

    pub fn active_names(&self) -> Vec<&'static str> {
        let mut names = Vec::new();
        if self.waf {
            names.push("Wafw00f");
        }
        if self.whatweb {
            names.push("WhatWeb");
        }
        if self.sslscan {
            names.push("SSLScan");
        }
        if self.dnstwist {
            names.push("Dnstwist");
        }
        if self.ffuf {
            names.push("Ffuf/SecLists");
        }
        if self.whois {
            names.push("Whois");
        }
        if self.dnsrecon {
            names.push("Dnsrecon");
        }
        if self.theharvester {
            names.push("theHarvester");
        }
        if self.obscura {
            names.push("Obscura");
        }
        if self.nmap {
            names.push("Nmap");
        }
        if self.nuclei {
            names.push("Nuclei");
        }
        if self.nikto {
            names.push("Nikto");
        }
        if self.httpx {
            names.push("Httpx");
        }
        if self.rustscan {
            names.push("RustScan");
        }
        // C2 / post-exploitation : opt-in explicite uniquement
        if self.sliver {
            names.push("Sliver");
        }
        if self.havoc {
            names.push("Havoc");
        }
        if self.merlin {
            names.push("Merlin");
        }
        if self.poshc2 {
            names.push("PoshC2");
        }
        if self.empire {
            names.push("Empire");
        }
        if self.chisel {
            names.push("Chisel");
        }
        if self.netexec {
            names.push("NetExec");
        }
        names
    }
}

// ==============================================================================
// CONFIG — configuration d'exécution dérivée de la CLI
// ==============================================================================

#[derive(Debug, Clone)]
#[derive(serde::Serialize, serde::Deserialize)]
pub struct Config {
    pub target: String,
    pub json_mode: bool,
    pub timeout_ms: u64,
    pub custom_ports: Option<Vec<u16>>,
    pub db_name: String,
    pub save_to_db: bool,
    pub show_history: bool,
    pub history_limit: usize,
    pub tools: ToolFlags,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            target: String::new(),
            json_mode: false,
            timeout_ms: 800,
            custom_ports: None,
            db_name: "veridy_audit".to_string(),
            save_to_db: true,
            show_history: false,
            history_limit: 5,
            tools: ToolFlags::default(),
        }
    }
}

// ==============================================================================
// CLI — définition clap (aide auto-générée, sous-commandes, aliases compat)
// ==============================================================================

#[derive(Subcommand, Debug)]
enum Commands {
    /// Historique des scans catalogués en PostgreSQL
    History {
        /// Nombre max d'entrées à afficher
        limit: Option<usize>,
        /// Filtrer par cible (vide = toutes cibles)
        #[arg(short, long)]
        target: Option<String>,
        /// Nom de la base PostgreSQL
        #[arg(long, default_value = "veridy_audit")]
        db: String,
    },
    /// Diagnostic de l'environnement : outils Kali, wordlists, PostgreSQL
    Tools,
}

#[derive(Parser, Debug)]
#[command(
    name = "veridy",
    version,
    about = "VERIDY CYBERSCAN 360° — Scanner de surface offensif",
    arg_required_else_help = true,
    after_help = "PROFILS PRÊTS À L'EMPLOI:\n  \
        veridy cible.com -1              Audit rapide Core Rust (~1.5s)\n  \
        veridy cible.com -2              Périmètre web (WAF+WhatWeb+SSLScan+Dnstwist)\n  \
        veridy cible.com -3              360° complet — tous les outils Kali\n  \
        veridy cible.com -4              Infrastructure (Nmap+SSLScan)\n  \
        veridy cible.com -5              Vulnérabilités (Nuclei+Nikto+Nmap)\n  \
        veridy cible.com -d              Découverte endpoints (Ffuf+Nikto+WAF)\n\n\
        MODULES À LA CARTE:\n  \
        veridy cible.com --nmap --nuclei\n  \
        veridy cible.com -m ssl,tech,osint\n  \
        veridy cible.com --ports 22,80,443 --json\n\n\
        BASE DE DONNÉES:\n  \
        veridy history 10\n  \
        veridy history --target cible.com\n  \
        veridy tools"
)]
struct Cli {
    /// Cible à auditer (domaine ou IP)
    #[arg(value_name = "TARGET")]
    target: Option<String>,

    /// Cible explicite (priorité sur le positional)
    #[arg(short = 't', long = "target", value_name = "TARGET")]
    target_opt: Option<String>,

    #[command(subcommand)]
    command: Option<Commands>,

    /// Sortie JSON brute (intégration pipeline)
    #[arg(short = 'j', long = "json", visible_alias = "json-mode")]
    json_mode: bool,

    /// Timeout TCP en millisecondes (1..=60000)
    #[arg(
        long,
        default_value_t = 800,
        value_name = "MS",
        value_parser = clap::value_parser!(u64).range(1..=60000)
    )]
    timeout: u64,

    /// Liste de ports spécifiques séparés par virgules
    #[arg(long, value_delimiter = ',', value_name = "P1,P2,..")]
    ports: Option<Vec<u16>>,

    /// Nom de la base PostgreSQL
    #[arg(long, default_value = "veridy_audit", value_name = "NAME")]
    db: String,

    /// Désactiver la persistance en base
    #[arg(long = "no-db")]
    no_db: bool,

    /// Profil rapide : modules Core Rust uniquement
    #[arg(short = '1', long = "fast")]
    fast: bool,

    /// Profil périmètre web : WAF + WhatWeb + SSLScan + Dnstwist
    #[arg(short = '2', long = "web")]
    web: bool,

    /// Profil 360° : TOUS les outils Kali + Obscura
    #[arg(short = '3', long = "full", aliases = ["all-tools", "deep", "360"])]
    full: bool,

    /// Profil infrastructure : Nmap + SSLScan
    #[arg(short = '4', long = "infra")]
    infra: bool,

    /// Profil vulnérabilités : Nuclei + Nikto + Nmap
    #[arg(short = '5', long = "vuln")]
    vuln: bool,

    /// Profil découverte : Ffuf + Nikto + WAF
    #[arg(short = 'd', long = "discovery")]
    discovery: bool,

    /// Modules spécifiques, séparés par virgules
    /// (nmap, nuclei, nikto, waf, whatweb, sslscan, dnstwist, ffuf, whois,
    /// dnsrecon, theharvester, obscura, all)
    #[arg(short = 'm', long = "modules", value_name = "LIST", value_delimiter = ',')]
    modules: Vec<String>,

    /// Nmap : audit profond des services et scripts NSE
    #[arg(long)]
    nmap: bool,

    /// Nuclei : scan de vulnérabilités et templates CVE
    #[arg(long, aliases = ["cve"])]
    nuclei: bool,

    /// Nikto : audit de configuration du serveur web
    #[arg(long)]
    nikto: bool,

    /// Wafw00f : détection de pare-feu applicatif
    #[arg(long, aliases = ["wafw00f"])]
    waf: bool,

    /// WhatWeb : empreinte technologique et emails
    #[arg(long, aliases = ["tech"])]
    whatweb: bool,

    /// SSLScan : diagnostic cryptographique TLS
    #[arg(long, aliases = ["ssl", "tls"])]
    sslscan: bool,

    /// Dnstwist : typosquatting et domaines sosies
    #[arg(long, aliases = ["brand", "phishing"])]
    dnstwist: bool,

    /// Ffuf : fuzzing de routes via SecLists
    #[arg(long, aliases = ["fuzz"])]
    ffuf: bool,

    /// Whois : registre, expiration, verrou de transfert
    #[arg(long)]
    whois: bool,

    /// Dnsrecon : énumération DNS avancée (SRV, Bind)
    #[arg(long)]
    dnsrecon: bool,

    /// theHarvester : OSINT emails et hôtes
    #[arg(long, aliases = ["harvester", "osint"])]
    theharvester: bool,

    /// Obscura : rendu headless V8, DOM et capture PNG
    #[arg(long, aliases = ["render", "headless", "browser", "dom"])]
    obscura: bool,

    /// Httpx : probe HTTP massif + détection techno sur les sous-domaines
    #[arg(long, aliases = ["probe", "httpprobe"])]
    httpx: bool,

    /// RustScan : balayage SYN ultra-rapide de TOUS les 65535 ports (fallback natif si absent)
    #[arg(long, aliases = ["fast-ports", "sy scan"])]
    rustscan: bool,

    /// SQLMap : détection SQL injection sur les endpoints paramétrés découverts (EXCLUSIF)
    #[arg(long, aliases = ["sqli"])]
    sqlmap: bool,

    /// Sliver (C2) : état serveur + implants — opt-in explicite
    #[arg(long)]
    sliver: bool,

    /// Havoc (C2) : état teamserver — opt-in explicite
    #[arg(long)]
    havoc: bool,

    /// Merlin (C2 HTTP/2) : état serveur — opt-in explicite
    #[arg(long)]
    merlin: bool,

    /// PoshC2 (C2) : état service — opt-in explicite
    #[arg(long)]
    poshc2: bool,

    /// Empire (C2) : état serveur + DB — opt-in explicite
    #[arg(long)]
    empire: bool,

    /// Chisel : démo tunnelling local — opt-in explicite
    #[arg(long)]
    chisel: bool,

    /// NetExec : probe SMB null-session (non-destructif) — opt-in explicite
    #[arg(long)]
    netexec: bool,

    /// Afficher l'historique des scans (flag form, cf. sous-commande `history`)
    #[arg(
        short = 'H',
        long,
        num_args = 0..=1,
        default_missing_value = "5",
        value_name = "LIMIT"
    )]
    history: Option<usize>,
}

impl Config {
    pub fn parse() -> Result<Option<Self>, String> {
        let cli = Cli::parse();

        // Sous-commandes
        match &cli.command {
            Some(Commands::History {
                limit,
                target,
                db,
            }) => {
                return Ok(Some(Config {
                    target: target.clone().unwrap_or_default(),
                    show_history: true,
                    history_limit: limit.unwrap_or(5),
                    db_name: db.clone(),
                    ..Config::default()
                }));
            }
            Some(Commands::Tools) => {
                Self::print_tools_status();
                return Ok(None);
            }
            None => {}
        }

        // Résolution de la cible : --target prioritaire, sinon positional
        let target = cli
            .target_opt
            .clone()
            .or_else(|| cli.target.clone())
            .unwrap_or_default();

        if target.is_empty() {
            // Exit code 1 (et non 0) : un pipeline ne doit pas croire au succès
            return Err(
                "Aucune cible fournie. Usage : veridy <TARGET> [OPTIONS] | veridy history | veridy tools"
                    .to_string(),
            );
        }

        // Construction des flags d'outils : profils → flags → modules
        let mut tools = ToolFlags::default();

        if cli.full {
            tools.enable_all();
        }
        if cli.web {
            tools.waf = true;
            tools.whatweb = true;
            tools.sslscan = true;
            tools.dnstwist = true;
            tools.httpx = true;
        }
        if cli.infra {
            tools.nmap = true;
            tools.sslscan = true;
            tools.rustscan = true;
        }
        if cli.vuln {
            tools.nuclei = true;
            tools.nikto = true;
            tools.nmap = true;
            tools.sqlmap = true;
        }
        if cli.sliver {
            tools.sliver = true;
        }
        if cli.havoc {
            tools.havoc = true;
        }
        if cli.merlin {
            tools.merlin = true;
        }
        if cli.poshc2 {
            tools.poshc2 = true;
        }
        if cli.empire {
            tools.empire = true;
        }
        if cli.chisel {
            tools.chisel = true;
        }
        if cli.netexec {
            tools.netexec = true;
        }
        if cli.discovery {
            tools.ffuf = true;
            tools.nikto = true;
            tools.waf = true;
        }
        // `-1/--fast` : modules Core uniquement, aucun outil Kali — no-op voulu
        let _ = cli.fast;

        if cli.nmap {
            tools.nmap = true;
        }
        if cli.nuclei {
            tools.nuclei = true;
        }
        if cli.nikto {
            tools.nikto = true;
        }
        if cli.waf {
            tools.waf = true;
        }
        if cli.whatweb {
            tools.whatweb = true;
        }
        if cli.sslscan {
            tools.sslscan = true;
        }
        if cli.dnstwist {
            tools.dnstwist = true;
        }
        if cli.ffuf {
            tools.ffuf = true;
        }
        if cli.whois {
            tools.whois = true;
        }
        if cli.dnsrecon {
            tools.dnsrecon = true;
        }
        if cli.theharvester {
            tools.theharvester = true;
        }
        if cli.obscura {
            tools.obscura = true;
        }
        if cli.httpx {
            tools.httpx = true;
        }
        if cli.rustscan {
            tools.rustscan = true;
        }
        if cli.sqlmap {
            tools.sqlmap = true;
        }

        for m in &cli.modules {
            match m.trim().to_lowercase().as_str() {
                "nmap" => tools.nmap = true,
                "nuclei" | "cve" => tools.nuclei = true,
                "nikto" => tools.nikto = true,
                "waf" | "wafw00f" => tools.waf = true,
                "whatweb" | "tech" => tools.whatweb = true,
                "sslscan" | "ssl" | "tls" => tools.sslscan = true,
                "dnstwist" | "brand" | "phishing" => tools.dnstwist = true,
                "ffuf" | "fuzz" | "endpoints" => tools.ffuf = true,
                "whois" => tools.whois = true,
                "dnsrecon" => tools.dnsrecon = true,
                "theharvester" | "harvester" | "osint" => tools.theharvester = true,
                "obscura" | "browser" | "render" | "dom" => tools.obscura = true,
                "httpx" | "probe" | "httpprobe" => tools.httpx = true,
                "rustscan" | "fast-ports" => tools.rustscan = true,
                "sqlmap" | "sqli" => tools.sqlmap = true,
                "sliver" => tools.sliver = true,
                "havoc" => tools.havoc = true,
                "merlin" => tools.merlin = true,
                "poshc2" => tools.poshc2 = true,
                "empire" => tools.empire = true,
                "chisel" => tools.chisel = true,
                "netexec" => tools.netexec = true,
                "all" | "360" => tools.enable_all(),
                _ => {
                    return Err(format!("Module inconnu : '{}'", m));
                }
            }
        }

        // Validation des ports : rejet de 0, tri + dédup (l'ancien code acceptait
        // "22,22,80" et le port 0 sans broncher)
        let mut custom_ports = cli.ports;
        if let Some(ref mut p) = custom_ports {
            let before = p.len();
            p.retain(|&x| x != 0);
            p.sort_unstable();
            p.dedup();
            if p.len() != before {
                eprintln!(
                    "[ATTENTION] Ports invalides (0) ou doublons supprimés : {} -> {} ports.",
                    before,
                    p.len()
                );
            }
        }

        // Profils cumulés : avertissement explicite (durée cumulée des outils)
        let profile_count = [cli.full, cli.web, cli.infra, cli.vuln, cli.discovery]
            .iter()
            .filter(|&&b| b)
            .count();
        if profile_count > 1 {
            eprintln!(
                "[ATTENTION] {} profils combinés : l'UNION des outils sera exécutée (durée cumulée).",
                profile_count
            );
        }

        Ok(Some(Config {
            target,
            json_mode: cli.json_mode,
            timeout_ms: cli.timeout,
            custom_ports,
            db_name: cli.db,
            save_to_db: !cli.no_db,
            show_history: cli.history.is_some(),
            history_limit: cli.history.unwrap_or(5),
            tools,
        }))
    }

    /// Diagnostic environnement : outils Kali sur PATH, wordlists, PostgreSQL
    fn print_tools_status() {
        let tools: &[(&str, &str)] = &[
            ("nmap", "Scanner réseau & scripts NSE"),
            ("nuclei", "Templates de vulnérabilités CVE"),
            ("nikto", "Audit serveur web HTTP"),
            ("wafw00f", "Détection de WAF"),
            ("whatweb", "Empreinte technologique"),
            ("sslscan", "Diagnostic cryptographique TLS"),
            ("dnstwist", "Typosquatting & domaines sosies"),
            ("ffuf", "Fuzzing d'endpoints"),
            ("whois", "Registre de domaine"),
            ("dnsrecon", "Énumération DNS avancée"),
            ("theHarvester", "OSINT emails & hôtes"),
            ("obscura", "Headless V8 & rendu DOM"),
            ("dig", "Requêtes DNS"),
            ("curl", "Client HTTP"),
            ("openssl", "Cryptographie & TLS"),
            ("psql", "Client PostgreSQL"),
        ];

        println!("ENVIRONNEMENT KALI — DIAGNOSTIC OUTILS");
        println!("─────────────────────────────────────────────────────────────");
        for (name, desc) in tools {
            let status = if which(name).is_some() { "[✓]" } else { "[✗]" };
            println!("  {} {:<14} {}", status, name, desc);
        }

        let wordlist = "/usr/share/seclists/Discovery/Web-Content/quickhits.txt";
        if std::path::Path::new(wordlist).exists() {
            println!("  [✓] SecLists quickhits : {}", wordlist);
        } else {
            println!("  [✗] SecLists quickhits introuvable : {}", wordlist);
        }

        let db_ok = std::process::Command::new("psql")
            .args(["-d", "veridy_audit", "-t", "-A", "-c", "SELECT 1;"])
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false);
        if db_ok {
            println!("  [✓] PostgreSQL : base 'veridy_audit' joignable");
        } else {
            println!("  [✗] PostgreSQL : base 'veridy_audit' injoignable");
        }
        println!("─────────────────────────────────────────────────────────────");
    }
}

/// Équivalent minimal de `which` : parcours du PATH
fn which(tool: &str) -> Option<std::path::PathBuf> {
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path)
        .map(|dir| dir.join(tool))
        .find(|p| p.is_file() && is_executable(p))
}

#[cfg(unix)]
fn is_executable(p: &std::path::Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(p)
        .map(|m| m.permissions().mode() & 0o111 != 0)
        .unwrap_or(false)
}

#[cfg(not(unix))]
fn is_executable(_p: &std::path::Path) -> bool {
    true
}
