# Audit des modules Rust — veridy_scanner
**Date :** 2026-09-19 · **Périmètre :** 33 fichiers, 8 205 lignes · **Méthode :** 4 audits parallèles (cœur CLI, réseau/recon, web/report, wrappers/DB) + vérification manuelle des 5 findings les plus graves sur le code + binaire déployé
**État de base :** clippy 0 warning · 24/24 tests OK · zéro `sh -c` résiduel · zéro `unwrap()` non gardé

---

## 🔴 CRITIQUES (2) — corrigés en premier

### C1. `progress.rs:224` — Panic UTF-8 du HUD (confirmé sur code)
```rust
let truncated_act = if act.len() > 68 { format!("{}...", &act[..65]) } else { act };
```
Coupe par **octets** : un caractère accentué (« Géolocalisation », « résolution ») qui chevauche l'octet 65 → panic du thread de rendu, HUD figé en plein scan. Violation de la règle projet #2 (le fix `chars().take()` existe déjà pour le nom l.243, pas pour `active_msg`).
**Fix :**
```rust
let truncated_act = if act.chars().count() > 68 {
    format!("{}...", act.chars().take(65).collect::<String>())
} else { act.clone() };
```

### C2. `tls.rs:180` — Détection d'expiration TLS MORTE (confirmé par exécution)
`parse_openssl_date()` reçoit `notAfter=Jan 15 12:00:00 2027 GMT` **sans strip du préfixe** → `parts[0]="notAfter=Jan"` ne matche aucun mois → `days_remaining` toujours `null` (vérifié live : scanme.nmap.org → `null`). Les alertes « certificat expiré / expire bientôt » (l.192-201) **ne se déclenchent jamais**. L'algo Hinnant lui-même est correct.
**Fix :** `trim_start_matches("notAfter=")` avant parse + test de non-régression :
```rust
assert_eq!(parse_openssl_date("notAfter=Jan 15 12:00:00 2027 GMT"), Some(1800014400));
```
+ Supprimer la 2e connexion `s_client` (l.169-177) : calculer `days_remaining` depuis `valid_until` déjà parsé à l'étape 3 (1 seule connexion au lieu de 5).

---

## 🟠 MAJEURS (26)

### A. Robustesse des threads (orchestrator.rs)
| # | Problème | Fix |
|---|----------|-----|
| A1 | `join().unwrap_or_else(\|_\| Module::audit(target))` ×19 (l.371-442) : une panic → **re-exécution synchrone dans le main** = double attaque sur la cible, et re-panic possible → crash complet | `join().unwrap_or_default()` partout |
| A2 | Aucun `catch_unwind` sur les ~21 threads ; `set_failed` jamais appelé = code mort ; tâche reste « EN COURS » à jamais | Helper `run_task()` : catch_unwind + `tracker.set_failed(idx)` + eprintln |
| A3 | Mutex `if let Ok(...)` → poisoning ignoré silencieusement (progress.rs l.55/84/218) | `unwrap_or_else(\|e\| e.into_inner())` |

### B. Timeouts absents — un outil bloqué = scan gelé à l'infini
Aucun `.output()` n'a de deadline. Touchés : **nmap, nuclei (le -timeout 5 est par-requête, pas global), nikto, ffuf, sslscan, dnsrecon, theHarvester, whois, obscura, psql ×3, openssl s_client ×5, dig ×9 (dns.rs sans +time/+tries)**.
**Fix unique :** helper partagé `run_with_timeout(bin, args, secs)` (spawn + try_wait loop + kill) dans utils.rs, appliqué aux ~31 points d'appel. Natifs en plus : nmap `--host-timeout 120s`, ffuf `-maxtime 90`, dig `+time=2 +tries=1`, sslscan `--timeout`.

### C. Détections mortes ou fausses (résultats faux dans les rapports)
| # | Module | Bug | Fix |
|---|--------|-----|-----|
| C1 | vuln_audit.rs:230 | **CORS réflexion morte** : `split(':').nth(1)` tronque `https://evil...` → `https` → le finding HIGH ne peut JAMAIS se déclencher | `splitn(2, ':')` |
| C2 | dns.rs:245 | **DNSSEC faux négatif** : DNSKEY via resolver → vide sur gmail.com (signé). `is_secure: true` hardcodé ×10 | Détecter le flag `ad` dans `;; flags:` de `dig +comments DS` (vérifié live : fiable), `is_secure` lié au flag AD |
| C3 | http.rs:99 | Flags cookie par substring : `secure_session=1` → Secure=true (faux positif) | Séparer `pair`/`attrs` sur `;`, matcher les attributs exacts |
| C4 | web_endpoints.rs:41 | security.txt : `contains(" 200")` matche `Content-Length: 200` | Parser la ligne de statut uniquement |
| C5 | dns_hardening.rs:38 | Faux open resolver : dig imprime toujours `ANSWER SECTION:` même vide | `dig +short` + sortie non vide parsable en IP |
| C6 | vuln_audit.rs:85 | Regex jQuery trop large → faux CVE HIGH (-12 pts de score) sur n'importe quel texte | Ancrer aux balises script/link + version complète + comparaison semver |
| C7 | ffuf_audit.rs:56 | `-fs 495` codé en dur (tuné pour UN site) → faux négatifs ailleurs | Supprimer, garder `-ac` (auto-calibration) |
| C8 | obscura_audit.rs:113 | `evil-veridy.ca`.ends_with(`veridy.ca`) == true → externe considéré interne | `domain == target \|\| domain.ends_with(&format!(".{}", target))` |
| C9 | web_endpoints.rs:98 | Probe ALPN **sans `-servername`** → faux http2 sur CDN exigeant SNI | Ajouter `-servername domain` |
| C10 | geo.rs:47 | `asn` rempli avec `netname:` (libellé, pas un AS) | Parser `origin:`/`OriginAS:`, valider `^AS?\d+$` |

### D. Base de données (db.rs)
| # | Problème | Fix |
|---|----------|-----|
| D1 | SQL par `format!()` + `sql_esc()` qui n'échappe que les quotes ; valeurs (bannières nmap, records DNS) **contrôlées par les cibles scannées** | Crate `postgres` + bind params `$1..$n` (déjà listée dans le refactoring cible) |
| D2 | `append_tool_output` : `raw_output.replace("$RAW$","")` **mutile les preuves** avant stockage | Dollar-quote à tag unique vérifié absent de la valeur, ou bind params |
| D3 | `save_scan` non atomique : insert `audit_scans` commité même si le batch détail échoue → **ligne orpheline** | Transaction unique BEGIN/COMMIT (ou DELETE compensatoire + CASCADE) |
| D4 | Historique parsé par `split('\|')` : un target avec `\|` décale les colonnes, `unwrap_or(0)` masque | `psql --csv` ou séparateur `\x1f` |

### E. Sérialisation / parsing
| # | Problème | Fix |
|---|----------|-----|
| E1 | `json_escape()` (utils.rs:4) ignore les control chars < 0x20 sauf \n\r\t → **JSON invalide** en `--json` si un outil émet \x00/\x1b (fréquent via from_utf8_lossy) | Map `\u{:04x}` pour tout char < 0x20 — ou migration serde_json |
| E2 | `extract_json_str()` : 2e pattern sans guillemets fait un substring match (`domain` matche `subdomain:`) → **valeurs erronées** de nuclei/whatweb | Supprimer le pattern sans guillemets |
| E3 | `iso_timestamp()` fork `date` avec fallback hardcodé `2026-09-04` → **fausses dates en DB** | Rust pur : `SystemTime::now()` + algo Hinnant (déjà dans tls.rs) |
| E4 | Parseurs maison fragiles : nikto/whatweb/dnstwist/sslscan par find/split/braces ; `contains("vulnerable=\"1\"")` matche n'importe quel attribut ; CBC marqué weak systématiquement | serde_json + quick-xml (déjà dispo) |

### F. Fiabilité des statuts d'outils
- `success: true` codé en dur : **nikto (l.76), ffuf (l.95), whatweb (l.61), wafw00f (l.70), dnstwist (l.56)** ; exit non-zéro masqué (nuclei l.89, obscura l.167) → `audit_tool_outputs` ment en base.
- `http_status` par défaut 200 (tech_stack l.77) masque les échecs.
- **Fix :** `success = output.status.success()` + champ `exit_code` + stderr tronqué dans raw_output.

### G. Fichiers temporaires
- Sanitization `replace('.','_')` insuffisante ×6 modules : `/` survit (écriture hors /tmp), noms prédictibles `cible+PID` en /tmp partagé (symlink attack).
- Fuites : tmp non supprimé sur chemin d'erreur (tls.rs, dnsrecon, theHarvester, obscura PNG).
- **Fix :** whitelist `[a-zA-Z0-9_-]` + hash de repli, guard RAII `struct TmpFile(PathBuf) impl Drop`, `remove_file` inconditionnel.

---

## 🟡 MINEURS (sélection — 25 autres dans les audits détaillés)
- `config.rs:116` — `Config::default()` avec `target: "veridy.ca"` : piège latent si réutilisé → `String::new()`
- `config.rs:189` — `--timeout 0` accepté (scan vide sans warning) → `value_parser!(u64).range(1..=60000)`
- `config.rs:204` — profils `-1 -3 -5` cumulables en silence → `conflicts_with_all`
- `config.rs:489` — `which()` teste `is_file()` sans bit exécutable → diagnostic `tools` faux
- `main.rs:32` — `history` avec DB down → exit 0 (pipeline croit au succès) → `exit(1)`
- `orchestrator.rs:134` — multi-IP : seule `first_ip` auditée en geo/dns_hardening
- `target_parser.rs:60` — getaddrinfo bloquant sans message ni timeout (gel muet)
- `report.rs:233` — `json_escape` appliqué au contexte console (artefacts `\n` à l'écran)
- `report.rs:90` — sévérité inconnue ignorée silencieusement dans le score
- `findings.rs:220` — `{:?}` debug Rust fuite dans un titre client
- `email_sec.rs:88` — `mta_sts_mode` hardcodé `enforce/testing` sans lire le tag `mode=`
- `email_sec.rs:137` — DKIM détecté par `contains("p=")` (faux positifs)
- `subdomains.rs:55` — 1ère IP seulement + alive=false si HTTP-only (pas de fallback port 80)
- `http.rs:69` — `Location` contenant `https://` en query → redirects_to_https faux
- `ports.rs:99` — 1 thread OS par port (75 threads) sans pool borné
- `whois_audit.rs:51` — dates WHOIS non normalisées (alarmes expiration impossibles)
- `nmap_deep.rs:52` — target commençant par `-` = argument injection (valider `^[A-Za-z0-9._-]+$` en amont)
- `allow(dead_code)` périmés (findings.rs:12, vuln_audit.rs:4/17) masquant de vrais morts futurs

---

## Plan de correction proposé

### Lot 1 — Quick wins (~2h, zéro risque, gros gain fiabilité)
C1 progress.rs · C2 tls.rs (strip + connexion unique) · CORS splitn · cookies · security.txt · DNSSEC flag AD · obscura boundary · ffuf -fs · json_escape control chars · extract_json_str · iso_timestamp Rust pur · mta_sts/DKIM parsing · exit codes (history DB down, cible absente)

### Lot 2 — Robustesse (~3h)
Helper `run_with_timeout()` + application aux ~31 appels · `join().unwrap_or_default()` + catch_unwind + set_failed · mutex anti-poison · sanitization tmp + RAII + cleanup inconditionnel · success = exit code réel · nmap --host-timeout · dig +time=2 +tries=1

### Lot 3 — Structure (refactoring, validate par `cargo test`)
Crate `postgres` (bind params + transaction unique) · serde_json/quick-xml à la place des parseurs maison · enum Severity/Category (invalides à la compilation) · validations CLI (timeout, ports, profils) · pool de threads borné (rayon ou custom) · panic hook global (restaure curseur `\x1b[?25h`) · `history --json`

### Tests de non-régression à ajouter (le bug C2 aurait été attrapé par un test trivial)
```rust
parse_openssl_date("notAfter=Jan 15 12:00:00 2027 GMT") == Some(1800014400)
json_escape("a\x00\x1bb")                    // JSON valide
extract_json_str(r#"{"subdomain":"x"}"#, "domain") == None  // pas de faux match
Set-Cookie: "secure_session=1; HttpOnly"      // Secure=false attendu
CORS: "Access-Control-Allow-Origin: https://evil.x" // réflexion détectée
evil-veridy.ca vs veridy.ca                   // externe
```

**Validation post-edit :** `cargo check && cargo clippy -- -D warnings && cargo test` — si un seul échoue, ne pas déployer.
