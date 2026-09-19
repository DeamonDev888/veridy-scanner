# Changelog — veridy_scanner

Format : [Keep a Changelog](https://keepachangelog.com/fr/1.1.0/)
Versions : [SemVer](https://semver.org/)

## [Unreleased] — en cours

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