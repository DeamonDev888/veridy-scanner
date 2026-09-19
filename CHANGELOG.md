# Changelog — veridy_scanner

Format : [Keep a Changelog](https://keepachangelog.com/fr/1.1.0/)
Versions : [SemVer](https://semver.org/)

## [Unreleased] — en cours

### Publié
- **2026-09-19 : v0.1.0 publié sur crates.io** — https://crates.io/crates/veridy_scanner
- **2026-09-19 : v0.1.1 publié sur crates.io** — README enrichi (section Agents IA, matrice CLI, 15 modules)
- **2026-09-19 : v0.2.0 publié sur crates.io** — full scan par défaut, outils Kali requis

## [0.3.4] — 2026-09-19

### Corrigé
- Restauration des 14 tests unitaires C2 + helper perdus lors du sync 0.3.3 (80 tests au total)

### Outilage qualité (pipeline complet Rust)
- **cargo fmt** : formatage complet du codebase (197 fichiers-diffs résolus, 0 diff résiduel)
- **cargo clippy --all-targets -- -D warnings** : 0 erreur en mode strict (warning = build failure)
- **cargo audit** : 0 vulnérabilité (33 dépendances, base RustSec 1251 advisories)
- **cargo package** : manifeste validé (56 fichiers, 939 Ko compressé)


### Corrigé (prouvé sur scan réel metro.ca — score 0→47, 20 faux CRITICAL→0)
- **Ffuf faux positifs** : les 403/301 (WAF/redirect) ne sont plus comptés comme découvertes ( uniquement) ; les 200 vides du catch-all sont exclus ()
- **Vérification de contenu** : un chemin critique (.env/.git/backup/sql/config) n'est CRITICAL que si la réponse contient la signature attendue (DB_PASSWORD=, [core], INSERT INTO…) — sinon déclassé INFO « soft-404 probable »
- **Parsing ffuf** :  natif — le vrai format imbrique FUZZ dans "input"{} ; l'ancien découpage manuel perdait l'URL (verif de contenu impossible). Rétrocompat format plat conservée
- **Dnsrecon** : déduplication des constats « divulgation version DNS » (5 doublons → 1 par paire serveur/version)

### Modifié
- Test  : fixture au vrai format ffuf + cas rétrocompat ;  : un chemin critique non confirmé ne doit JAMAIS être CRITICAL


### Ajouté
- **14 tests unitaires** pour les modules C2 (sérialisation, findings conditionnels, parsing signing/version, opt-in jamais implicite, helpers tool_on_path/tcp_probe) — total **80 tests**
- README (GitHub + crates.io) : section « Modules C2 / Post-exploitation » avec tableau des 7 flags et exemples

### Modifié
- MSRV relevé à **Rust 1.84** (réel : `is_unicast_link_local` stabilisé en 1.84)

## [0.3.1] — 2026-09-19

### Corrigé
- **Régression 0.3.0** : le gate « outils Kali requis » (REQUIRED_KALI_TOOLS, exit 1 si absent) et le full-scan par défaut avaient été perdus lors de la fusion des modules C2 — restaurés (les flags C2 comptent désormais comme profil explicite)

## [0.3.0] — 2026-09-19

### Ajouté
- **7 modules C2 / post-exploitation** (opt-in explicite, non-destructifs) :
  -  : état serveur gRPC + implants configurés
  -  : état teamserver (port 40056)
  -  : état serveur HTTP/2 (gRPC :50051)
  -  : état service (systemd)
  -  : état serveur + DB MariaDB (setup détecté)
  -  : démo tunnelling locale (bind 127.0.0.1 éphémère, auto-fermé)
  -  : probe SMB null-session avec détection signing (finding MEDIUM si non forcé)
- Helpers  + 
- Findings C2 câblés au moteur, section console « MODULES C2 / POST-EXPLOITATION », sérialisation JSON complète

## [0.2.2] — 2026-09-19

### Modifié
- README : suppression du paragraphe « exceptions hors dépôts » (httpx/subfinder/RustScan) de la section Prérequis
- **PostgreSQL désormais requis** dans la documentation (plus « optionnel ») : install.sh l'installe et initialise la base automatiquement

## [0.2.1] — 2026-09-19

### Modifié
- **Repositionnement Kali Linux natif** : veridy_scanner est une application Kali — les outils d'audit sont pré-installés et maintenus par les dépôts Kali ; le scanner vérifie présence et fraîcheur
-  : refus explicite hors Kali ( avec message), mise à jour ciblée des outils natifs () au lieu d'installation massive, installation automatique des exceptions Go (httpx ProjectDiscovery — avec détection/remplacement du paquet Python homonyme, subfinder, RustScan)
- Hints du gate binaire : « natif Kali — apt install \<outil\> » au lieu des conseils pip/gem multi-distro
- README (GitHub + crates.io) : « Kali Linux uniquement », suppression du tableau pip/gem, ajout de  + diagnostic

## [0.2.0] — 2026-09-19 — BREAKING

### Modifié
- **Full scan par défaut** : sans profil ni flag outil, les 14 outils Kali standards sont activés automatiquement — l'audit est exhaustif d'office.  devient l'opt-out explicite (Core Rust uniquement)
- **Outils Kali REQUIS** :  (14 outils vérifiés sur le PATH). Environnement incomplet → refus de démarrer (exit 1) avec instructions d'installation par outil — plus jamais de scan partiel silencieux
-  installe désormais les outils Kali manquants (apt/dnf/pacman + go install) au lieu de simplement avertir
- README (GitHub + crates.io) et matrice CLI alignés sur le comportement réel

## [0.1.1] — 2026-09-19

### Modifié
- README crates.io enrichi : section « Guide pour Agents IA & Automatisation CLI » (règles non-interactif, commandes recommandées, extraction `jq`, matrice arguments/codes de retour), liste des 15 modules, badges

### Ajouté
- 10 enrichissements findings (attestations positives + signaux offensifs) — bannières ports, DKIM trouvé, DMARC p=reject, CAA actifs, PTR hébergeur, MX, robots.txt recon, CSP unsafe-inline, expiration TLS 45j, MTA-STS TXT-sans-endpoint, sous-domaines vivants/morts + IPs
- Gate de contexte : IP nue = pas de checks DNS/email/subdomains ; 443/HTTP fermé = INFO discret (pas CRITICAL) ; IP privée = pas de finding géo
- `is_subdomain()` helper avec frontière de point obligatoire (`evil-veridy.ca` n'est plus un sous-domaine de `veridy.ca`)
- 8 tests de non-régression (parse_openssl_date avec strip notAfter, json_escape control chars RFC 8259, extract_json_str sans faux positif suffixe, iso_timestamp Rust pur, civil_from_days, sanitize_target, run_guarded panic, is_subdomain boundary)

### Modifié
- 81 corrections de l'audit initial (RFC 8259, IPv6-first fix, SNI, sous-domaines premières N IPs, cookies attrs exacts, CORS split_once, json_escape control chars, sslscan heartbleed sans faux positif, fsanitize_target + RAII, run_tool helper central, run_guarded catch_unwind, etc.)

## [0.1.0] — 2026-09-19

### Ajouté
- Première release publique
- Modules core : ports (pool 24 workers), DNS (DNSSEC flag AD), TLS (IP+SNI, expiration), HTTP (cookies, CSP, HSTS max-age), email_sec (SPF/DKIM/DMARC/MTA-STS/TLS-RPT/BIMI), web_endpoints (security.txt, robots.txt, ALPN/h2), subdomains (CNAME takeover 19 clouds), vuln_audit (jQuery/Bootstrap obsolètes, SRI, mixed content, CORS, secrets exposés), geo (whois IP)
- 12 wrappers Kali : nmap, nuclei, nikto, wafw00f, whatweb, sslscan, dnstwist, ffuf, whois, dnsrecon, theHarvester, obscura
- Profils : `-1` core, `-2` web, `-3` 360°, `-4` infra, `-5` vuln, `-d` discovery
- CLI v2 clap derive (positional + `--target`, `--json`, `--timeout`, `--ports`, `--db`, `--no-db`)
- Sous-commandes : `history [N]`, `tools`
- Console TUI `launch.sh` (check-tools, stats, findings, scan, subdomains, batch, --qa)
- Catalogage PostgreSQL (12 tables relationnelles)
- Sécurité : aucun `sh -c`, timeouts sur tous subprocess, catch_unwind dans orchestrateur

### Sécurité
- Échappement SQL systématique, sanitization des chemins temporaires
- Mutex anti-poison dans progress.rs
- Panic hook global : curseur terminal restauré après crash
- Exit codes corrects (cible absente / DB down → exit 1, pas 0)

[Unreleased]: https://github.com/DeamonDev888/veridy-scanner/compare/v0.1.0...HEAD