# Publication Cargo (crates.io)

## Prérequis uniques

1. Compte sur https://crates.io (liée à ton compte GitHub)
2. Token API généré sur https://crates.io/me (Settings → API Tokens)
3. **CRITIQUE** : ce token doit rester dans `~/.cargo/credentials.toml` (POSIX : `chmod 600`), **jamais dans le repo**
4. Git tag `v0.1.0` sur le commit publié

## Préparation (une seule fois)

```bash
# 1. Stocker le token en sécurité (équivalent du .npmrc pour npm)
mkdir -p ~/.cargo
cat > ~/.cargo/credentials.toml <<'EOF'
[registry]
token = "<your-cargo-token>"   # <-- coller ici le token de crates.io (récupéré sur https://crates.io/me → API Tokens)
EOF
chmod 600 ~/.cargo/credentials.toml

# 2. Vérifier l'authentification
cargo login "$(grep '^token' ~/.cargo/credentials.toml | cut -d'"' -f2)"
```

## Procédure de release

```bash
# 1. Dry-run (vérifie que tout est prêt sans publier)
cargo publish --dry-run --allow-dirty

# 2. Vérifier le contenu du paquet :
#    - README.md (lu par crates.io)
#    - LICENSE (champ license + license-file)
#    - Pas de chemin home utilisateur dans le source
#    - Toutes les métadonnées du Cargo.toml

# 3. Bumper la version dans Cargo.toml (semver : MAJOR.MINOR.PATCH)
# 0.1.0 → 0.1.1 (patch)  : corrections sans changement d'API
# 0.1.0 → 0.2.0 (minor)  : nouvelles features rétrocompatibles
# 0.1.0 → 1.0.0 (major)  : breaking changes

# 4. Commit + tag + push
git add Cargo.toml
git commit -m "chore: bump to v0.X.Y"
git tag v0.X.Y
git push origin main --tags

# 5. Publication réelle
cargo publish

# 6. Vérifier sur https://crates.io/crates/veridy_scanner
```

## Vérification post-publication

```bash
# Document téléchargeable par n'importe qui
cargo install veridy_scanner

# Vérifier les versions disponibles
cargo search veridy_scanner
```

## Rotation du token

Si le token est compromis (publié, leaké dans un log, etc.) :

1. **Immédiatement** : https://crates.io/me → API Tokens → Revoke
2. Regénérer un nouveau token
3. Remplacer dans `~/.cargo/credentials.toml`
4. **Ne JAMAIS** versionner ce fichier (vérifier `.gitignore`)

## Sécurité

- Le token donne le droit de **publier et remplacer** n'importe quel crate sous ton nom
- Garde-le comme un mot de passe root : `chmod 600`, jamais dans un script, jamais dans une URL
- En CI (GitHub Actions), utiliser `secrets.CARGO_REGISTRY_TOKEN` et le passer via `cargo login --token $CARGO_REGISTRY_TOKEN`
- `cargo publish` est irréversible pour un `yank` — mais tu peux toujours `cargo yank --version 0.X.Y` pour empêcher de nouvelles installs