# Changelog

Toutes les modifications notables de `veridy_scanner` sont documentées ici.

Le format suit [Keep a Changelog](https://keepachangelog.com/fr/1.1.0/).

## [0.3.7] — 2026-09-20

### Fixed
- **Timeouts sur 7 appels d'outils externes** : remplacement des `Command::output()` sans deadline par le helper `run_tool` (kill au dépassement, aucune perte de buffer) — `sqlmap` (300 s), `subfinder` (120 s), `curl` loot (60 s), `rustscan` (180 s), `curl` vuln_audit HTML (600 s) et CORS (300 s), plus le loot curl côté `loot.rs`. Arguments et parsing stdout inchangés.
- **Succès nmap réel** : `nmap_deep.rs` ne code plus `success: true` en dur — le champ reflète désormais `output.status.success()`.
- **Logging loot** : les erreurs silencieuses (`.ok()?`) de `fs::copy`/`fs::read`/`fs::metadata`/`curl` dans `loot.rs` émettent désormais un avertissement `[LOOT] avertissement : …` et passent au fichier suivant au lieu d'avorter le module — le loot n'est plus perdu silencieusement.
- **Faux positif loopback** : le finding HIGH « Port de base de données exposé publiquement » est rétrogradé en INFO (« service local (loopback) ») quand la cible scannée est une adresse loopback (127.0.0.0/8 ou ::1), en réutilisant `IpAddr::is_loopback()`.
- **Clippy 0 warning** : `ffuf_audit.rs` utilise `(4500..=7000).contains(&length)` (manual_range_contains).

## [v0.3] — 2026-09-19

### Added
- **45 tests unitaires** (vs 24 en v0.1) — section `src/tests.rs` divisée en 15 catégories :
  - Tests persistance DB (10 tests) : `save_to_db=true` par défaut, helpers SQL (`sql_esc`, `sql_int_array`, `sql_text_array`), score calculation, clamp à 0, échappement dollar-quote PostgreSQL.
  - Tests script d'install (2 tests) : ordre canonique des schemas, `head -1` filter psql.
- **Documentation** :
  - `README.md` réécrit pour refléter v0.3 (16 modules, persistance automatique, ProjectDiscovery tools, profil -4/-5/-2 enrichis).
  - `CHANGELOG.md` créé (ce fichier).
- **Validation DB** dans le script d'install : INSERT ... RETURNING id avec cleanup auto (cleanup_scan), confirmation `DB opérationnelle`.

### Changed
- **`Cargo.toml`** : ajout dépendance `serde_json` (réimplémentation `to_json` maison → serde derive).
- **`FullAuditReport`** : 3 nouveaux champs `http_probe`, `rustscan`, `sqli` (avec derive `Serialize`).
- **`audit_tool_outputs`** : 3 nouvelles `tool_name` (`httpx`, `rustscan`, `sqlmap`) avec `raw_output` JSON sérialisé via `serde_json::to_string_pretty`.
- **Schéma PostgreSQL** : ajout colonnes `audit_tls_certs.valid_from`, `audit_tls_certs.is_self_signed`, `audit_dns_hardening.ip_tested` (migration ALTER TABLE idempotente).
- **Script d'install** : chargement canonique `schema_full.sql` → `schema_deep.sql` → `schema_tools.sql`, init rôle `demon`, validation DB obligatoire (sinon `die`).

### Fixed
- Le binaire de `httpx` système sur Kali (script Python `encode/httpx`) **n'est PAS** ProjectDiscovery. Détection runtime par `httpx -version | grep Current`. Téléchargement `pdhttpx` depuis GitHub releases.
- `sqlmap` correctement opt-in (EXCLU de `enable_all()` mais INCLUS dans profil `-5 --vuln`).
- `rustscan` : parser adapté au vrai format `Open <ip>:<port>` (et non `-> [..]` comme dans la doc).

## [v0.2] — 2026-09-19

### Added
- **3 nouveaux modules offensifs** :
  - `src/modules/http_probe.rs` (HTTPx ProjectDiscovery pdhttpx) — probe HTTP massif + tech detect.
  - `src/modules/portscan_rustscan.rs` (RustScan) — balayage SYN 65535 ports.
  - `src/modules/sqli_audit.rs` (SQLMap) — détection SQL injection (opt-in).
- **Subfinder** (ProjectDiscovery) intégré comme source par défaut pour `subdomains.rs` (avec fallback statique 35 préfixes si absent).
- **Flags CLI** : `--httpx`, `--rustscan`, `--sqlmap`. Shorthands `-m httpx,rustscan,sqlmap`.
- **Profils enrichis** :
  - `-2 --web` ajoute HTTPx.
  - `-4 --infra` ajoute RustScan.
  - `-5 --vuln` ajoute SQLMap.
- **Findings** : catégorie `SQLI`, recommandations adaptées (`[SQLMap] ...`).
- **TUI launch.sh** : `check_tools` affiche désormais pdhttpx et subfinder ; `show_history` avec sparkline ASCII.

### Changed
- **CLI** : refonte majeure avec `clap` v4 derive (vs parser maison 253 lignes).
  - Sous-commandes `history [N] [--target X] [--db N]` et `tools`.
  - `arg_required_else_help`, `after_help` avec exemples.
  - Aliases de compatibilité : `--json-mode`, `--all-tools`, `--deep`, `--360`, `--fast-ports`, `--probe`, etc.
- **Architecture** : 33 → 34 fichiers `.rs`, 8 006 → 9 700 LOC.
- **`subdomains.rs`** : remplacement liste hardcodée 35 par wrapper subfinder (`-d <domain> -silent -nW`).

### Removed
- **`safety.rs`** : garde-fous normatifs (RFC1918, loopback, suffixes gouvernementaux) supprimés. Le scanner accepte désormais toutes les cibles (réservé aux opérateurs de confiance).
- **Catégorie normative métier** supprimée des findings et champ correspondant retiré de la DB (purge d'un contexte non applicable à un scanner offensif pur).

## [v0.1] — 2026-09-19 (initial)

### Added
- Scanner de surface offensif complet en Rust 2021.
- 24 modules initiaux : Core (Ports, DNS, TLS, HTTP, GéoIP, etc.) + Kali (Nmap, Nuclei, Nikto, etc.).
- HUD live avec spinner braille, ETA, sparkline.
- 12 tables PostgreSQL relationnelles.
- TUI launch.sh 5 onglets.
- Module UI custom (rainbow_bar, sparkline, radar, banner adaptatif).

### Fixed (audit v0.1)
- **81 findings corrigés** dans la session d'audit initiale (`AUDIT-RUST-2026-09-19.md`).
- 24/24 tests passent.
- Clippy strict : 0 warning.
- Zéro `sh -c` résiduel, zéro `unwrap()` non gardé.
