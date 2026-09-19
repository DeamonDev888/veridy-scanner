# Veridy Scanner — Cyber Intelligence & Offensive Surface Engine 360°

![VERIDY](https://raw.githubusercontent.com/DeamonDev888/veridy-scanner/main/assets/veridy_scanner_banner.png)

**Moteur modulaire d'audit de sécurité offensif et de cartographie de surface d'attaque.**
Conçu pour être exécuté aussi bien par un **opérateur humain** (TUI interactif) que par un **agent IA autonome** en ligne de commande (CLI / JSON natif).

![Rust](https://img.shields.io/badge/Language-Rust%202021-orange?style=flat-square&logo=rust) ![Kali](https://img.shields.io/badge/Platform-Kali%20Linux-blue?style=flat-square&logo=kali-linux) ![PostgreSQL](https://img.shields.io/badge/Database-PostgreSQL-336791?style=flat-square&logo=postgresql) ![License](https://img.shields.io/badge/License-Apache%202.0-green?style=flat-square) ![crates.io](https://img.shields.io/crates/v/veridy_scanner.svg?color=orange&style=flat-square) ![downloads](https://img.shields.io/crates/d/veridy_scanner.svg?style=flat-square)

## Installation

```bash
cargo install veridy_scanner
```

Prérequis : Rust ≥ 1.75, `openssl`, `curl`, `dig` (dnsutils), `whois`. PostgreSQL 12+ et les outils Kali (nmap, nuclei, nikto…) sont optionnels — les modules correspondants se désactivent proprement s'ils sont absents.

```bash
veridy_scanner tools   # diagnostic : outils détectés, wordlists, DB joignable
```

## Guide pour Agents IA & Automatisation CLI

> **Important — Règle d'or pour les agents autonomes :**
> - Ne lancez **JAMAIS** `veridy` sans argument en script automatisé : cela déclenche la console TUI interactive qui attend des pressions de touches (`stdin`).
> - Pour une utilisation automatisée, utilisez directement `veridy_scanner` avec une **cible explicite** et des options CLI.
> - Utilisez le flag `--json` (ou `-j`) pour obtenir une sortie structurée directement exploitable par vos fonctions ou via `jq`.

### 1. Commandes recommandées (mode non-interactif)

```bash
# 1. Audit rapide Core Rust (~1.5 s) avec sortie JSON pure :
veridy_scanner example.com --fast --json

# 2. Audit de surface web standard (WAF + Tech + TLS + Typo) :
veridy_scanner example.com --web --json

# 3. Audit exhaustif 360° (tous les 15 outils Kali) :
veridy_scanner example.com --full --json

# 4. Lancement ciblé de modules précis :
veridy_scanner example.com --nmap --nuclei --json
veridy_scanner example.com -m rustscan,httpx,waf --json

# 5. Consultation de l'historique PostgreSQL (10 derniers audits) :
veridy_scanner history 10

# 6. Vérification de l'environnement et disponibilité des outils :
veridy_scanner tools
```

### 2. Extraction & parsing JSON (`jq`)

Lorsque le flag `--json` est actif, le TUI est désactivé et `veridy_scanner` émet un objet JSON strict sur `stdout` :

```bash
# Score global (0 à 100) uniquement :
veridy_scanner example.com -1 -j | jq '.overall_score'

# Vulnérabilités de sévérité CRITICAL ou HIGH :
veridy_scanner example.com -3 -j | jq '.findings[] | select(.severity == "CRITICAL" or .severity == "HIGH")'

# Tous les ports ouverts découverts :
veridy_scanner example.com -1 -j | jq '.ports.open_ports'

# Présence d'une politique SPF / DMARC valide :
veridy_scanner example.com -1 -j | jq '{spf: .email_sec.has_spf, dmarc: .email_sec.has_dmarc}'
```

### 3. Matrice des arguments & codes de retour

| Argument / Flag | Description | Temps moyen | Dépendances |
|---|---|---|---|
| `-1`, `--fast` | Scan natif pur Rust (Ports, TLS, DNS, GéoIP) | ~1.5 s | Zéro (Rust pur) |
| `-2`, `--web` | WAFW00F, WhatWeb, SSLScan, Dnstwist | ~7 s | Python / Ruby / C |
| `-3`, `--full` | Audit complet 360° (15 modules Kali) | ~60-90 s | Suite Kali |
| `-4`, `--infra` | Nmap (-sV -sC) + SSLScan | ~25 s | nmap, sslscan |
| `-5`, `--vuln` | Nuclei (templates CVEs) + Nikto + Nmap | ~45 s | nuclei, nikto |
| `-d`, `--discovery` | Ffuf (SecLists) + Nikto + Wafw00f | ~40 s | ffuf, nikto |
| `-j`, `--json` | Désactive le TUI, émet du JSON machine | - | - |
| `--no-db` | Désactive la persistance PostgreSQL | - | - |
| `--timeout <MS>` | Timeout TCP (défaut : 800 ms) | - | - |

**Codes de sortie :** `0` = audit réussi, rapport généré · `1` = erreur d'arguments, cible invalide/non résoluble, ou échec de connexion critique.

## Les 15 modules spécialisés embarqués

1. **Nmap** — bannières de services et scripts NSE
2. **Nuclei** — détection active de CVEs via templates YAML
3. **Nikto** — configurations serveurs HTTP et fichiers sensibles
4. **Wafw00f** — empreinte de WAF (Cloudflare, AWS WAF, Imperva…)
5. **WhatWeb** — stacks web (CMS, frameworks, serveurs, fuites emails)
6. **SSLScan** — suites de chiffrement TLS 1.0→1.3, failles (Heartbleed…)
7. **Dnstwist** — typosquatting, phishing, usurpation de domaine
8. **Ffuf** — fuzzing haute vitesse des routes masquées (SecLists)
9. **Whois** — registres officiels (CIRA/ICANN), contacts, expiration
10. **Dnsrecon** — enregistrements SRV, serveurs NS, transferts de zone
11. **theHarvester** — OSINT : emails publics et sous-domaines
12. **Obscura** — headless browser V8, analyse dynamique du DOM, screenshots
13. **RustScan** — balayage SYN ultra-rapide des 65535 ports
14. **HTTPx** — probing HTTP/HTTPS massif des sous-domaines
15. **SQLMap** — détection d'injections SQL (opt-in explicite `--sqli`)

## Modules Core Rust natifs

- **DNS** — A/AAAA/MX/NS/TXT/SOA/CAA, SPF (RFC 7208), DMARC, DKIM, MTA-STS, DNSSEC (flag AD)
- **Ports** — scan TCP pool borné 24 workers, bannières de services, 75+ ports catalogués
- **TLS** — chaîne X.509, expiration (jours restants), SANs, ALPN (h2), auto-signé, protocoles obsolètes
- **HTTP** — en-têtes de sécurité (HSTS max-age, CSP, XFO…), cookies, redirection HTTPS, CORS réflexion
- **Subdomains** — énumération (subfinder + liste étendue), vivant/muet, CNAME takeover (19 fournisseurs clouds)
- **Vulnérabilités web** — libs obsolètes, SRI manquant, mixed content, secrets exposés (clés API dans le HTML)
- **Géolocalisation** — ASN, organisation, pays, hébergeur

## Persistance PostgreSQL (optionnelle)

12 tables relationnelles `audit_*` (scans, findings, ports, headers, certificats, sous-domaines, géo, email, endpoints…). Sans PostgreSQL, utiliser `--no-db` (mode éphémère).

```bash
veridy_scanner history 10   # historique des audits catalogués
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

- [Code source & documentation](https://github.com/DeamonDev888/veridy-scanner)
- [Signaler un problème](https://github.com/DeamonDev888/veridy-scanner/issues)
- License : Apache License 2.0
