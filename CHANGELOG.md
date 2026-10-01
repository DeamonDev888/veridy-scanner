# Changelog

Toutes les modifications notables de `veridy_scanner` sont documentées ici.

Le format suit [Keep a Changelog](https://keepachangelog.com/fr/1.1.0/).

## [0.5.7] — 2026-09-30

### Fixed
- **Pureté scanner offensif** : recommandations à résidu normatif (juridiction/politique interne dans `waf.rs`, politique de transfert dans `findings.rs`) remplacées par du vocabulaire technique (techniques d'évasion, périmètre d'hébergement).
- **Preuves /tmp en permissions 0600** : `envx_proof.env` et `gitdump_logs.txt` étaient posés world-readable — désormais lisibles opérateur seul (`std::os::unix::fs::PermissionsExt`).
- **keyprobe multi-clés** : chainx ne pipe que la première clé en stdin (avant, 9 clés = 1 vérifiée). Concaténation de toutes les clés, une seule exécution, keyprobe boucle sur stdin.
- **Underflow scan_range** : `full_portscan::scan_range` acceptait `end < start` → `usize` panic. Garde ajoutée (plage inversée = `Vec::new()`).
- **sslscan port 443 codé en dur** : `SslscanAuditor::audit` ignorait `--ports` (TLS sur port 8443 = aveugle). Signature étendue à `audit(target, custom_ports)` + appel orchestrateur adapté via capture avant la closure `'static`.
- **Détection TLS 1.0/1.1 ressuscitée** : `openssl.cnf` Kali force `MinProtocol=TLSv1.2`, le client openssl refusait le handshake avant d'interroger le serveur → `supports_tls10/11` quasi toujours false. Override `-min_protocol TLSv1` ajouté aux deux sondes legacy. Vérifié live : `tls-v1-0.badssl.com` → `True | True` ; `scanme.nmap.org` → `False | False`.

## [0.5.6] — 2026-09-30

### Added
- **chainx dispatche désormais les bases de données exposées** : un finding `PORT « Port de base de données N (MySQL/Redis/MongoDB) exposé publiquement »` déclenche automatiquement `mysqlx`/`redisx`/`mongodx` (greeting protocole en lecture seule, zéro credential). Les bins persistant déjà leur verdict dans `audit_impact`, chainx ne fait que les déclencher au bon moment (gate <24h et `--force` identiques aux autres modules). Le mapping est verrouillé par `db_bin_mapping_findings_port` et le parsing de sortie par `parse_kv_verdict_avec_espaces_variables`. PostgreSQL exposé (5432) ne déclenche rien — pas de bin dédié, pas de dispatch inventé.

### Fixed
- **Bug historique chainx : stdout des bins enfants jamais capturé** : `run_bin` appelait `wait_with_output()` sans `stdout(Stdio::piped())` — sans pipe explicite, stdout est hérité du parent et la capture renvoyait TOUJOURS une chaîne vide. Conséquence en DB : verdicts `EXIT0` génériques au lieu des vrais verdicts (19 spoofcheck « EXIT0 » au lieu de PARTIEL/PROTEGE, etc.). Le pipe explicite est maintenant posé + parse robuste `parse_kv_line` (clés `VERDICT`/`verdict`/`détail`, espaces variables) verrouillé par test.
- **Doublon de verdict** : le dispatch DB n'écrivait plus de verdict fantôme `ERREUR_EXECUTION` quand le bin avait déjà persisté le sien (lignes artifacts purgées de la DB).

### Changed
- **Purge du code mort** : `src/modules/orchestrator.rs` et `src/modules/report.rs` (doublons périmés du 2026-09-28, non déclarés dans `mod.rs` donc jamais compilés) supprimés — archivés dans `~/veridy-archive/dead-code-20260930/`. Les versions actives sont `src/orchestrator.rs` et `src/report.rs`.

## [0.5.5] — 2026-09-30

### Fixed
- **SPF/DMARC fallback apex** : un sous-domaine muet (www.) ne déclenche plus le faux positif « SPF/DMARC absents » — TXT et DMARC sont réinterrogés sur le domaine registrable avec marquage `[apex]` (preuve : www.jeancoutu.com SPF strict + DMARC p=reject détectés, 33 → 55).
- **TRACE faux positif** : `Allow: TRACE` dans la réponse OPTIONS ne suffit plus — le module émet un one-shot `curl -X TRACE` et ne classe HIGH que si la réflexion est prouvée (2xx + body écho). Un TRACE annoncé mais non implémenté (501, cas uqac.ca) descend en LOW « annoncé mais non réfléchi ». PUT/DELETE/TRACK restent HIGH quoi qu'il arrive.
- **Schéma hardcodé `https://` dans web_endpoints** : la sonde OPTIONS passe par `scheme_detect` (HTTP pur sur port exotique = box HTB) — même piège que whatweb/nuclei corrigés en 0.5.3.
- **Test blackhole budget 8s → 15s** : aligné sur le seuil 98 % du bail-out (le 90 % historique faisait faux blackhole sur les hôtes filtrés à ~95 % avec ports vivants).

## [0.5.4] — 2026-09-30

### Fixed
- **Ports fantômes d'edge/WAF (faux HIGH en cascade)** : un edge (Imperva/Incapsula constaté sur uniprix.com) accepte TCP sur *tout* port et répond HTTP 400 uniformément — le scanner enregistrait des dizaines de « MySQL/Redis/RDP exposés » sans service réel derrière. Nouvelle sonde litmus dans `probe_port` (trame RDP binaire sur port non web muet : seul un edge répond une ligne de statut HTTP 4xx) + détection d'uniformité `detect_uniform_edge` (signature statut+proto façon baseline soft-404 ffuf, seuil ≥3 ports) : les ports artefacts sont marqués `is_phantom_edge` et les findings correspondants remplacés par un UNIQUE finding INFO agrégé « l'edge répond uniformément ». Même principe que le downgrade loopback : ne pas empoisonner le score avec des artefacts d'edge. Un vrai service (bannière MySQL « Host not allowed », SSH, 220-FTP) n'est jamais marqué ; un HTTP réel isolé sur port exotique (sous le seuil) non plus.
- **Faux CRITICAL « chaîne TLS invalide ou compromise » sur chaîne incomplète** (archambault.ca) : le validateur classait « invalide » une chaîne simplement *incomplète* (serveur ne servant pas l'intermédiaire GoDaddy ; vérifié live `openssl verify -untrusted <intermédiaire AIA>` → OK). Le verdict discrimine désormais : `unable to get local issuer` / `unable to verify the first certificate` → MEDIUM « chaîne incomplète » (config serveur à corriger) ; les autres erreurs de signature restent CRITICAL.
- **Octets NUL refusés par PostgreSQL** : les bannières de services (et certains enregistrements DNS/en-têtes HTTP) peuvent véhiculer des octets NUL bruts ou des échappements `` que PostgreSQL refuse en `jsonb` ET en `text` — l'INSERT du scan échouait alors silencieusement (cible non cataloguée : sunyouth.org, cegepgarneau.ca). Sanitisation au point unique de passage vers la DB : le NUL devient la séquence visible «␀» (`strip_nul_bytes`) pour les colonnes text, et les NUL littéraux + `` sont retirés du payload jsonb (`strip_nul_json`).
- **Compilation E0308** : `strip_nul_bytes(&p.banner)` attendait `&str` alors que la bannière est `Option<String>` — passage par `as_deref().map(strip_nul_bytes)`.

## [0.5.3] — 2026-09-29

### Added
- **Capture des versions WhatWeb** : le parseur whatweb est réécrit en `serde_json` (fin du parseur à la main find/brace-counting) et capture désormais `plugin + version` par composant (`version[]` canonique, sinon `string[]` au motif `produit/version`). Les nombres isolés type `max-age=31536000` ne sont jamais pris pour une version.
- **Table `audit_tech`** : chaque composant versionné est persisté (`scan_id, name, version, source, is_eol, branch_min`) avec `ON DELETE CASCADE`, index dédié, écriture dans `save_scan` et purge dans `cleanup_scan`.
- **Verdicts « version obsolète »** : base de seuils EOL par branche (majeur.mineur) couvrant serveurs web, langages, CMS, bases de données, frameworks JS/backend, services exposés (~50 entrées). Une branche inférieure au seuil minimal maintenu produit un finding MEDIUM « Composant obsolète » + affichage console dédié (section empreinte technologique). Patch-lag sur une branche maintenue ≠ EOL : aucun verdict (zéro invention).

### Fixed
- **Test FTP préexistant en échec** : `test_lock_ftp_no_finding_when_tls_required` échouait sur HEAD (bannière `Pure-FTPd [privsep] [TLS]` signalée « divulgation de version » sans contenir de version). Le finding LOW exige désormais un chiffre dans la bannière (`vsftpd 3.0.5` → LOW ; `Pure-FTPd [TLS]` → rien).

## [0.5.1] — 2026-09-28

### Fixed
- **Doublons de findings Nuclei** : un template multi-correspondances (ex. `http-missing-security-headers`, un match par en-tête manquant) ne produit plus qu'un seul finding agrégé par (template, URL), avec le nombre de correspondances dans le titre — au lieu de 10 lignes identiques en base.
- **Doublons de findings Dnsrecon** : déduplication des divulgations de version DNS par (serveur, version) — plus de triple occurrence du même NS.
- **Test ftpx auto-référent** : le garde-fou anti-upload construisait son verdict sur un littéral présent dans son propre message d'assertion ; le jeton interdit est désormais construit dynamiquement.
- **Table de géolocalisation renommée** : `audit_geo_compliance` devient `audit_geo` (données factuelles IP/ASN/pays uniquement, 160 lignes préservées, index et code mis à jour).

### Changed
- **Purge catalogue** : 120 findings dupliqués historiques supprimés (backup `audit_findings_purges_20260928`), 20 scans re-scorés — cohérence score/count vérifiée à 0 écart.

## [0.5.2] — 2026-09-28

### Fixed
- **Purge des derniers résidus lexicaux** dans les sources et le binaire : renommage de la structure `GeoComplianceResult` en `GeoResult` (le symbole compilé restait visible dans les binaires), correction de la bannière console PostgreSQL (`audit_geo`), reformulation neutre de deux recommandations/commentaires. Vérifié par analyse des chaînes du binaire release : zéro occurrence résiduelle.

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
