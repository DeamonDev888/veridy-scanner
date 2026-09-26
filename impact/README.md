# veridy-impact

**Lecture-seule. 14 modules de preuve d'impact pour les objets découverts par [`veridy_scanner`](https://crates.io/crates/veridy_scanner).**

Le scanner trouve des **findings** (signal faible). `veridy-impact` apporte la **preuve d'impact** (signal fort) : exploitation des ressources exposées **sans jamais rien écrire sur la cible**.

## Catégorie unique : `audit_impact`

Tous les verdicts des 14 modules sont persistés dans la table `audit_impact` (PostgreSQL 18, socket Unix peer-auth) avec `module`, `target`, `verdict`, `detail`, `evidence` (masquée).

## Installation

```bash
cargo install --locked veridy-impact
```

ou depuis les sources (Kali Linux) :

```bash
git clone https://github.com/DeamonDev888/veridy-scanner.git
cd impact
cargo build --release
sudo install -m755 target/release/{envx,gitdump,keyprobe,spoofcheck,impacts,subalive,cnametake,ftpx,surfx,cnamewatch,ftplx,lootx,chainx} /usr/local/bin/
sudo install -m755 showkey /usr/local/bin/   # script psql séparé
```

**Zéro dépendance** : la lib utilise `curl` et `dig` via `Command::args()` (jamais `sh -c`).

## Les 14 modules

| Module | Objet | Preuve d'impact |
|---|---|---|
| `envx <url>` | `.env` exposé | parse, masque secrets haute valeur (3 chars + longueur) |
| `gitdump <base>` | `.git/` exposé | remotes + emails devs + HEAD valide (pas de dump complet) |
| `keyprobe` (stdin) | clés API | classification (Google/Stripe/SendGrid/Slack/GitHub/OpenAI) + **vérif Google Maps non destructive** (staticmap) |
| `spoofcheck <dom>` | SPF/DMARC absents | verdict USURPABLE/PARTIEL/PROTEGE (zéro envoi mail) |
| `gkeyx` (stdin) | clé Google AIza | 9 sondes GET lecture-seule + fuite n° projet + phase EXPLOIT |
| `ftpx <hôte>` | FTP port 21 | preuve anonymous (230) vs refus (530) — JAMAIS d'upload |
| `ftplx <hôte[:port]> [--dl]` | FTP anonymous accepté | manifeste LIST récursif (≤20 dirs) + échantillon hashé SHA-256 (≤5 fichiers, ≤64 Ko) |
| `subalive <cible> [--fix]` | subs "morts" du catalogue | re-sonde avec UA navigateur ; `--fix` corrige `audit_subdomains` (corrige les faux négatifs du bug httpx) |
| `surfx <cible> [--max N]` | surface offensive des subs | fingerprint (titre, serveur, technos, flags) — persiste `audit_surface` |
| `cnametake <dom>` / `--db <cible>` | CNAME cloud takeover | 15 fingerprints (heroku/azure/github.io/...) — verdict CONFIRMÉ/PROBABLE/NON PRENABLE |
| `cnamewatch <cible>` | chien de garde takeover | cron-able, alerte TAKEOVER_WINDOW_OPEN (exit 3) sur bascule |
| `lootx [scan_id]` | fichiers lootés (audit_loot) | dédup SHA, qualifie SENSIBLE/NEUTRE/SANS_VALEUR (licences, quotas) |
| `impacts [--live]` | dashboard DB | résumé verdicts, gate envx/gitdump, loot ; `--live` re-vérifie les clés Google en temps réel |
| `chainx [cible] [--force]` | **dispatcher automatique** | lit le catalogue → route chaque finding vers son bin en chaîne sûre (GET/DNS) |

## Chaînage automatique

L'arsenal peut être déclenché en une commande :

```bash
chainx                       # toutes les cibles scannées dans les 30 derniers jours
chainx metro.ca --force      # une cible, même si verdict récent
```

Pipeline exécuté par cible : `subalive --fix` (corrige vivacité factuelle) → `spoofcheck` (DNS) → `cnametake --db` (takeover) → `surfx` (surface) → gates `envx`/`gitdump` (CRITICAL WEB confirmés) → `keyprobe` (clés Google extraites des payloads nuclei) → `ftpx` (port 21) → verdicts persistés dans `audit_impact`.

## Sûreté d'emploi (règles NON NÉGOCIABLES)

1. **Lecture seule stricte** : HTTP GET + DNS uniquement. Jamais de POST/PUT/DELETE/STOR/STOR.
2. Subprocess via `args()` uniquement — jamais `sh -c`.
3. Secrets **toujours masqués** à l'affichage (`mask_secret` : 3 chars + longueur).
4. Timeout dur sur chaque requête (`curl --max-time`).
5. Une requête par objet — les chemins viennent du scanner, pas de brute-force.
6. **Pas de fuite n° projet via les valeurs** : les fingerprints takeover sont lus, l'exploit (recréation de ressource) est explicitement hors périmètre.
7. Exfiltration bornée (`ftplx --dl`) : opt-in opérateur, ≤5 fichiers ≤64 Ko extensions texte, SHA-256.

## Preuves d'exécution (campagne 2026-09-26)

| Cible | Verdict |
|---|---|
| metro.ca | p=reject PROTEGE, clé Google Maps VIVANTE, surface 21/30 flaggés (NetScaler AAA + Ivanti Connect Secure) |
| chirooutaouais.ca / christinenoelcpa.com / notairemtl.ca | USURPABLE (aucun SPF/DMARC) |
| iga.ca / metro.ca | PROTEGE (p=reject) |
| savardplouffe.com / 173.236.254.52 | ANONYME_REFUSE (530 DreamHost, pas d'expo) |

52 verdicts persistés en base en une seule campagne `chainx`.

## Licence

Apache-2.0. Voir [LICENSE](https://github.com/DeamonDev888/veridy-scanner/blob/main/LICENSE).