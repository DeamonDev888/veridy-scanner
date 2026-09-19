# Veridy Scanner

![VERIDY](https://raw.githubusercontent.com/DeamonDev888/veridy-scanner/main/assets/veridy_scanner_banner.png)

**Moteur modulaire d'audit de sécurité offensif et de cartographie de surface d'attaque** — exécutable par un opérateur humain (TUI interactif) ou un agent IA autonome (CLI, JSON natif).

![Rust](https://img.shields.io/badge/Language-Rust%202021-orange?style=flat-square&logo=rust) ![Kali](https://img.shields.io/badge/Platform-Kali%20Linux-blue?style=flat-square&logo=kali-linux) ![PostgreSQL](https://img.shields.io/badge/Database-PostgreSQL-336791?style=flat-square&logo=postgresql) ![License](https://img.shields.io/badge/License-Apache%202.0-green?style=flat-square) ![crates.io](https://img.shields.io/crates/v/veridy_scanner.svg?color=orange&style=flat-square) ![downloads](https://img.shields.io/crates/d/veridy_scanner.svg?style=flat-square)

## Installation

```bash
cargo install veridy_scanner
```

Prérequis : Rust ≥ 1.75, `openssl`, `curl`, `dig` (dnsutils), `whois`. PostgreSQL 12+ et les outils Kali (nmap, nuclei, nikto…) sont optionnels — les modules correspondants se désactivent proprement s'ils sont absents.

## Démarrage rapide

```bash
# Audit rapide Core Rust (~1.5 s) — JSON strict sur stdout
veridy_scanner example.com --fast --json

# Surface web : WAFW00F + WhatWeb + SSLScan + Dnstwist
veridy_scanner example.com --web --json

# Audit exhaustif 360° (15 outils Kali)
veridy_scanner example.com --full --json

# Score global uniquement
veridy_scanner example.com -1 -j | jq '.overall_score'

# Vulnérabilités CRITICAL / HIGH
veridy_scanner example.com -3 -j | jq '.findings[] | select(.severity == "CRITICAL")'

# Diagnostic environnement (outils détectés, DB joignable)
veridy_scanner tools
```

Sans `--json`, un rapport TUI lisible est affiché. `--no-db` désactive la persistance PostgreSQL.

## Ce que ça scanne

**Core Rust natif (aucune dépendance externe au-delà de curl/dig/openssl) :**

- **DNS** — A/AAAA/MX/NS/TXT/SOA/CAA, SPF (RFC 7208), DMARC, DKIM, MTA-STS, DNSSEC (flag AD)
- **Ports** — scan TCP pool borné 24 workers, bannières de services, 75+ ports catalogués
- **TLS** — chaîne X.509, expiration (jours restants), SANs, ALPN (h2), auto-signé, protocoles obsolètes
- **HTTP** — en-têtes de sécurité (HSTS max-age, CSP, XFO…), cookies, redirection HTTPS, CORS réflexion
- **Subdomains** — énumération (subfinder + liste étendue), vivant/muet, CNAME takeover (19 fournisseurs clouds)
- **Vulnérabilités web** — libs obsolètes, SRI manquant, mixed content, secrets exposés (clés API dans le HTML)
- **Géolocalisation** — ASN, organisation, pays, hébergeur

**Wrappers outils Kali (activation par profil `-2` à `-5`, ou unitaire) :**

nmap · nuclei · nikto · wafw00f · whatweb · sslscan · dnstwist · ffuf (SecLists) · whois · dnsrecon · theHarvester · obscura · rustscan · httpx · sqlmap (opt-in explicite `--sqli` uniquement)

| Profil | Contenu | Durée moyenne |
|---|---|---|
| `-1`, `--fast` | Core Rust pur | ~1.5 s |
| `-2`, `--web` | WAFW00F, WhatWeb, SSLScan, Dnstwist | ~7 s |
| `-3`, `--full` | 360° — tous les outils | ~60-90 s |
| `-4`, `--infra` | Nmap (-sV -sC) + SSLScan | ~25 s |
| `-5`, `--vuln` | Nuclei + Nikto + Nmap | ~45 s |
| `-d`, `--discovery` | Ffuf + Nikto + Wafw00f | ~40 s |

## Persistance PostgreSQL (optionnelle)

12 tables relationnelles `audit_*` (scans, findings, ports, headers, certificats, sous-domaines, géo, email, endpoints…). Historique consultable :

```bash
veridy_scanner history 10
```

## Qualité d'implémentation

- 66 tests unitaires, clippy zéro warning
- Timeout sur **tous** les sous-processus (helper `run_tool` : spawn/poll/kill) — jamais de scan gelé
- Panics de modules capturées (`catch_unwind`) — une tâche qui échoue est marquée ÉCHEC, jamais re-exécutée sur la cible
- Aucun `sh -c` : arguments passés directement, zéro injection shell
- Échappement SQL systématique, sortie JSON conforme RFC 8259

## Avertissement

Outil d'audit offensif destiné aux professionnels de la sécurité. À utiliser **uniquement sur des systèmes pour lesquels vous disposez d'une autorisation explicite**. L'opérateur est responsable de la conformité de ses scans à la loi applicable.

## Liens

- [Documentation & code source](https://github.com/DeamonDev888/veridy-scanner)
- [Signaler un problème](https://github.com/DeamonDev888/veridy-scanner/issues)
- License : Apache License 2.0
