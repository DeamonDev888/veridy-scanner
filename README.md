<p align="center">
  <img src="assets/veridy_scanner_banner.png" alt="VERIDY OFFENSIVE SURFACE SCANNER" width="100%">
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Language-Rust%202021-orange?style=for-the-badge&logo=rust" alt="Rust">
  <img src="https://img.shields.io/badge/Platform-Kali%20Linux%20Rolling-blue?style=for-the-badge&logo=kali-linux" alt="Kali Linux">
  <img src="https://img.shields.io/badge/Database-PostgreSQL%2016--Tables-336791?style=for-the-badge&logo=postgresql" alt="PostgreSQL">
  <img src="https://img.shields.io/badge/Modules-16--Offensive-red?style=for-the-badge" alt="16 modules offensifs">
  <img src="https://img.shields.io/badge/Output-JSON%20Ready%20%7C%20TUI-cyan?style=for-the-badge" alt="CLI & JSON">
</p>

---

# 🛡️ VERIDY — Cyber Intelligence & Offensive Surface Engine 360°

> **Moteur modulaire d'audit de sécurité offensif et de cartographie de surface d'attaque.**
> Conçu pour être exécuté aussi bien par un **opérateur humain** (TUI interactif) que par un **agent IA autonome** en ligne de commande (CLI / JSON natif).

---

## 🤖 Guide Spécifique pour Agents IA & Automatisation CLI

> [!IMPORTANT]
> **Règle d'or pour les agents autonomes** :
> - Ne lancez **JAMAIS** `veridy` sans argument en script automatisé : cela déclenche la console TUI interactive qui attend des pressions de touches (`stdin`).
> - Pour une utilisation automatisée, utilisez directement `veridy_scanner` ou le wrapper `veridy` avec une **cible explicite** et des options CLI.
> - Utilisez le flag `--json` (ou `-j`) pour obtenir une sortie structurée directement exploitable par vos fonctions ou via `jq`.
> - **Par défaut, chaque scan est persisté en PostgreSQL** (12 tables relationnelles + payload JSONB). Utilisez `--no-db` pour le mode éphémère.

### 1. Commandes Recommandées pour Agents (Mode Non-Interactif)

```bash
# ⚡ 1. Audit rapide Core Rust (~1.5s) avec sortie JSON pure :
veridy_scanner example.com --fast --json

# 🌐 2. Audit de surface web standard (WAF + Tech + TLS + Typo + Httpx) :
veridy_scanner example.com --web --json

# 👑 3. Audit exhaustif 360° (15 modules Kali : SQLMap EXCLU, opt-in via --sqlmap) :
veridy_scanner example.com --full --json
veridy_scanner example.com --full --sqlmap --json   # avec SQLMap (16 modules actifs)

# 🔬 4. Lancement ciblé de modules précis :
veridy_scanner example.com --nmap --nuclei --json
veridy_scanner example.com -m rustscan,httpx,waf --json
veridy_scanner example.com --httpx --rustscan --sqlmap  # ProjectDiscovery + SQLMap

# 🗄️ 5. Consultation de l'historique PostgreSQL (10 derniers audits) :
veridy_scanner history 10
veridy_scanner history --target example.com  # filtré par cible

# 🛠️ 6. Vérification de l'environnement et disponibilité des outils :
veridy_scanner tools
```

### 2. Extraction & Parsing JSON pour Agents (`jq`)

Lorsque le flag `--json` est actif, le TUI est désactivé et `veridy_scanner` émet un objet JSON strict sur `stdout` :

```bash
# Récupérer uniquement le score global (0 à 100) :
veridy_scanner example.com -1 -j | jq '.overall_score'

# Extraire les vulnérabilités de sévérité CRITICAL ou HIGH :
veridy_scanner example.com -3 -j | jq '.findings[] | select(.severity == "CRITICAL" or .severity == "HIGH")'

# Lister tous les ports ouverts découverts :
veridy_scanner example.com -1 -j | jq '.ports.open_ports'

# Vérifier la présence d'une politique SPF / DMARC valide :
veridy_scanner example.com -1 -j | jq '{spf: .email_sec.has_spf, dmarc: .email_sec.has_dmarc}'

# Lister les technologies détectées par HTTPx (ProjectDiscovery) :
veridy_scanner example.com --httpx -j | jq '.http_probe[].technologies'

# Lister les ports vus par RustScan mais absents du scan Core :
veridy_scanner example.com --rustscan -j | jq '.rustscan.open_ports'

# Lister les injections SQL confirmées par SQLMap :
veridy_scanner example.com --sqlmap -j | jq '.sqli[] | {url, parameter, dbms}'
```

### 3. Matrice des Arguments & Codes de Retour (CLI Matrix)

| Argument / Flag | Description pour l'Agent | Temps Moyen | Dépendances |
|---|---|:---:|:---:|
| `-1`, `--fast` | Scan natif pur Rust (Ports, TLS, DNS, GéoIP) | ~1.5s | Zéro (Rust pur) |
| `-2`, `--web` | WAFW00F + WhatWeb + SSLScan + Dnstwist + **HTTPx** | ~7-12s | Python / Ruby / C / pdhttpx |
| `-3`, `--full` | **Audit complet 360°** (15 modules : SQLMap EXCLU, opt-in) | ~60-90s | Suite Kali |
| `-4`, `--infra` | Nmap (-sV -sC) + SSLScan + **RustScan** | ~25-35s | nmap, sslscan, rustscan |
| `-5`, `--vuln` | Nuclei (templates CVEs) + Nikto + Nmap + **SQLMap** | ~45-60s | nuclei, nikto, nmap, sqlmap |
| `-d`, `--discovery`| Ffuf (SecLists) + Nikto + Wafw00f | ~40s | ffuf, nikto |
| `--httpx` | Probe HTTP massif + tech detect (sous-domaines inclus) | ~5-15s | pdhttpx (ProjectDiscovery) |
| `--rustscan` | Balayage SYN ultra-rapide des 65535 ports | ~7s | rustscan |
| `--sqlmap` | Détection SQL injection (opt-in, EXCLU de --full) | ~5-60s | sqlmap |
| `--subfinder` | Énumération passive sous-domaines (auto si subfinder installé) | ~3s | subfinder |
| `-j`, `--json` | **Désactive le TUI** et émet du JSON machine | - | - |
| `--no-db` | Désactive la persistance PostgreSQL (mode éphémère) | - | - |
| `--timeout <MS>` | Ajuste le timeout TCP (défaut : 800 ms) | - | - |

**Codes de sortie (`Exit Codes`) :**
- `0` : Audit exécuté avec succès, rapport généré et persisté en DB (sauf `--no-db`).
- `1` : Erreur d'arguments CLI, cible invalide/non résoluble, ou échec de connexion critique.

### 4. Persistance PostgreSQL (par défaut)

Chaque scan est **automatiquement persisté** dans une base PostgreSQL locale (`veridy_audit` par défaut, modifiable via `--db <NAME>`).

**Schéma : 12 tables relationnelles** :
- `audit_scans` (header + payload JSONB exhaustif)
- `audit_dns_records`, `audit_ports`, `audit_http_headers`
- `audit_tls_certs` (incluant `valid_from`, `is_self_signed`, `supports_tls10..13`)
- `audit_subdomains`, `audit_findings`
- `audit_geo_compliance`, `audit_email_sec`, `audit_web_endpoints`
- `audit_dns_hardening`, `audit_tool_outputs`

```bash
# Lister les 10 derniers scans de example.com
sudo -u postgres psql veridy_audit -c \
  "SELECT id, target, overall_score, open_ports_count, findings_count, created_at
   FROM audit_scans WHERE target='example.com' ORDER BY id DESC LIMIT 10;"

# Lister les raw_output de tous les outils Kali utilisés dans le scan #42
sudo -u postgres psql veridy_audit -c \
  "SELECT tool_name, status, items_count, LEFT(summary, 80) FROM audit_tool_outputs WHERE scan_id=42;"

# Historique intégré via le binaire :
veridy_scanner history 5 --target example.com
```

---

## ⚡ Aperçu du Terminal TUI (Mode Interactif pour Humains)

Pour un utilisateur en direct sur le serveur Kali, `veridy` propose une console cyberpunk riche avec monitoring des threads en direct, sparkline des durées, ETA dynamique, et banner final adaptatif (💎 EXCELLENT → ☠️ CRITIQUE) :

<p align="center">
  <img src="assets/veridy_tui_logo.svg" alt="Veridy Scanner TUI Interface" width="920">
</p>

---

## 🔬 Les 16 Modules Spécialisés Embarqués (v0.3)

### Modules Core Rust (toujours actifs)
1. **Ports Scanner** : Balayage TCP Connect des 75+ ports critiques (résolution DNS, bannières, services).
2. **Géolocalisation & ASN** : Whois + IP-API, ASN, organisation, pays, région.
3. **TLS Auditor** : Chaîne de certification complète, ciphers, validité, support TLS 1.0-1.3.
4. **DNS & Messagerie** : A/AAAA/MX/NS/TXT/CAA/SPF/DMARC/DKIM + DNSSEC.
5. **HTTP Headers** : HSTS, CSP, X-Frame-Options, X-Content-Type-Options, cookies, referrer-policy.
6. **Sous-domaines (Subfinder)** : Énumération passive via ProjectDiscovery subfinder (+ fallback statique 35 préfixes).
7. **Web Endpoints** : security.txt, robots.txt, ALPN, méthodes HTTP autorisées.
8. **Vulnérabilités applicatives** : Regex strictes jQuery, SRI, mixed content, CORS, secrets exposés.
9. **DNS Hardening** : Open resolver, récursion, zone transfer.

### Modules Kali (optionnels via flags ou profils)
10. **Nmap** : Reconnaissance fine des bannières et scripts NSE de vulnérabilités.
11. **Nuclei** : Détection active de CVEs via templates YAML ProjectDiscovery.
12. **Nikto** : Audit des configurations HTTP et fichiers sensibles.
13. **Wafw00f** : Empreinte de pare-feux applicatifs (Cloudflare, AWS WAF, Imperva).
14. **WhatWeb** : Analyse des stacks web (CMS, frameworks JS, serveurs).
15. **SSLScan** : Solidité des suites de chiffrement TLS 1.0-1.3 et failles.
16. **Dnstwist** : Détection d'usurpation, phishing et typosquatting.
17. **Ffuf** : Fuzzing haute vitesse des routes via dictionnaires SecLists.
18. **Whois** : Analyse des registres (CIRA/ICANN), contacts et expiration.
19. **Dnsrecon** : Cartographie SRV, NS et transferts de zone.
20. **theHarvester** : OSINT emails publics et sous-domaines.
21. **Obscura** : Moteur Headless V8, analyse dynamique DOM et screenshot PNG.

### Nouveaux Modules Offensifs v0.2 (ProjectDiscovery + Kali)
22. **HTTPx** (*ProjectDiscovery pdhttpx*) : Probe HTTP/HTTPS massif sur sous-domaines, détection de technologies (Cloudflare, Apache, nginx, etc.), titres, codes de statut.
23. **RustScan** : Balayage SYN ultra-rapide des 65535 ports en ~7 secondes (chose impossible avec notre scanner Core).
24. **SQLMap** (*opt-in explicite*) : Détection automatisée d'injections SQL sur les routes paramétrées. **EXCLU de `--full`** par défaut pour éviter le bruit réseau (charge active). À activer explicitement : `--sqlmap` ou `-5 --vuln`.

> [!NOTE]
> **Subfinder** (ProjectDiscovery) est utilisé **automatiquement** par le module Sous-domaines dès qu'il est installé. Pas besoin de flag.

---

## 🛠️ Déploiement & Installation

```bash
# 1. Installation complète automatisée (Kali / Debian / Ubuntu) :
sudo ./veridy_install_test.sh
# Ce script :
#   - Installe Rust + PostgreSQL + outils Kali + SecLists
#   - Télécharge pdhttpx + subfinder depuis ProjectDiscovery GitHub releases
#   - Initialise le schéma PostgreSQL (12 tables) + crée le rôle 'demon'
#   - Valide la DB par un INSERT ... RETURNING id
#   - Lance un scan de test pour confirmer la persistance automatique

# 2. Compilation manuelle depuis le repo :
git clone https://github.com/DeamonDev888/veridy-scanner.git
cd veridy-scanner
cargo build --release

# 3. Déploiement global :
sudo cp target/release/veridy_scanner /usr/local/bin/veridy_scanner
sudo cp launch.sh /usr/local/bin/veridy
sudo chmod +x /usr/local/bin/veridy /usr/local/bin/veridy_scanner

# 4. Vérification de l'installation :
veridy_scanner tools   # diagnostique 16 binaires + SecLists + PostgreSQL
```

### Dépendances Optionnelles (modules avancés)

| Outil | Module qui l'utilise | Installation manuelle si absente |
|---|---|---|
| `pdhttpx` | HTTPx (probe HTTP massif) | Téléchargé par `veridy_install_test.sh` ou `curl -sL https://github.com/projectdiscovery/httpx/releases/download/v1.6.9/httpx_1.6.9_linux_amd64.zip \| sudo install -m 0755 /dev/stdin /usr/local/bin/pdhttpx` |
| `subfinder` | Sous-domaines (auto) | Téléchargé par `veridy_install_test.sh` ou binaire pré-compilé depuis GitHub releases |
| `rustscan` | Scan 65535 ports | `sudo apt install rustscan` |
| `sqlmap` | Injection SQL | `sudo apt install sqlmap` |

> [!WARNING]
> **httpx** (le nom seul) sur Kali est le script Python `encode/httpx`, **PAS** ProjectDiscovery. Le scanner détecte cela et télécharge `pdhttpx` automatiquement. Ne cherchez pas à installer `httpx` via apt.

---

## 🧪 Tests & Qualité

- **77 tests unitaires** : `cargo test` (0 failed) — dont 20 anti-régression qui verrouillent les invariants critiques (no compliance mention, score clamp, sql_esc, pas de sh -c, etc.)
- **Clippy strict** : `cargo clippy --all-targets -- -D warnings` (0 warning)
- **Lint format** : `cargo fmt --check`
- **Build release** : 4.7 MB, optimisé LTO

```bash
cargo test                  # 77/77 OK (YOLO : skip les warnings, ship it)
cargo clippy --all-targets -- -D warnings  # strict : 0 warning obligatoire
```

---

## 🧩 Modules d'impact compagnons — `veridy-impact`

> Ces modules **NE FONT PAS PARTIE** de `veridy_scanner` (qui reste pur découverte, lecture-seule). Ils sont livrés dans la crate sœur [`veridy-impact`](https://crates.io/crates/veridy-impact) et chaînés automatiquement par `chainx`.

- **`chainx`** : dispatcher automatique — lit le catalogue DB, route chaque finding vers son bin d'exploitation en chaîne sûre (GET/DNS uniquement).
- **`envx` / `gitdump`** : preuves de contenu pour les WEB CRITICAL (gates anti-faux-positif WAF).
- **`keyprobe` / `gkeyx`** : classification + vérification des clés API (Google Maps non destructive, autres classifiées sans toucher).
- **`spoofcheck`** : usurpabilité email (USURPABLE/PARTIEL/PROTEGE).
- **`subalive` / `surfx` / `cnametake` / `cnamewatch`** : revivification + cartographie + surveillance de takeover des sous-domaines.
- **`ftpx` / `ftplx`** : preuve FTP anonyme (jamais d'upload).
- **`lootx`** : qualification des fichiers lootés (SENSIBLE / NEUTRE / SANS_VALEUR).
- **`impacts`** : tableau de bord DB + re-vérification live des clés (`--live`).

Installation : `cargo install --locked veridy-impact`. Tous les verdicts dans `audit_impact`.

## 📚 Voir aussi


- **`CHANGELOG.md`** : historique des versions (v0.1 → v0.3)
- **`AUDIT-RUST-2026-09-19.md`** : audit statique complet (81 findings corrigés)
- **`MEMO-SERVEUR-KALI.md`** : notes d'environnement Kali et pièges connus

---

<p align="center">
  <img src="assets/veridy_logo.svg" alt="Veridy Logo" width="380">
  <br>
  <sub>Moteur d'audit offensif · 16 modules · Persistance PostgreSQL · CLI/TUI/JSON</sub>
</p>
