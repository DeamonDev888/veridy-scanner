#!/usr/bin/env bash
# install.sh — installation complète pour un nouvel utilisateur/serveur
# Usage : curl -fsSL https://raw.githubusercontent.com/.../install.sh | sudo bash
# ou : sudo ./install.sh
set -euo pipefail

# ----- Couleurs -----
R='\033[1;31m'; G='\033[1;32m'; Y='\033[1;33m'; B='\033[1;34m'; C='\033[1;36m'; N='\033[0m'
info() { echo -e "${C}[*]${N} $*"; }
ok()   { echo -e "${G}[✓]${N} $*"; }
warn() { echo -e "${Y}[!]${N} $*"; }
die()  { echo -e "${R}[✗]${N} $*"; exit 1; }

# ----- Vérifs préliminaires -----
[ "$(id -u)" -eq 0 ] || die "Re-lancer avec sudo : sudo ./install.sh"
. /etc/os-release
info "Système : $(uname -m) ${PRETTY_NAME:-inconnu}"

# ----- veridy_scanner est une application KALI LINUX : refus explicite ailleurs -----
if [ "${ID:-}" != "kali" ]; then
    die "Kali Linux requis — système détecté : ${PRETTY_NAME:-inconnu}.
  veridy_scanner orchestre des outils pré-installés sur Kali uniquement.
  Installez Kali : https://www.kali.org/get-kali/"
fi
ok "Kali Linux confirmé — outils d'audit natifs attendus"

# ----- Gestionnaire : apt (Kali est Debian-based) -----
command -v apt >/dev/null 2>&1 || die "apt introuvable — Kali Linux requis"
PKG=apt
UPDATE="apt update -y"
INSTALL="apt install -y"
info "Gestionnaire : $PKG"

# ----- Choix du répertoire d'installation -----
INSTALL_DIR="${VERIDY_INSTALL_DIR:-/opt/veridy-scanner}"
REPO_URL="${VERIDY_REPO_URL:-https://github.com/DeamonDev888/veridy-scanner.git}"
BRANCH="${VERIDY_BRANCH:-main}"
BIN_NAME="veridy_scanner"
SERVICE_USER="veridy"

# ----- 1. Dépendances système -----
info "Installation des dépendances système…"
case "$PKG" in
    apt)
        $UPDATE
        $INSTALL -y build-essential pkg-config libssl-dev curl ca-certificates \
            postgresql postgresql-contrib dnsutils whois
        ;;
    dnf)
        $INSTALL -y gcc gcc-c++ make openssl-devel curl ca-certificates \
            postgresql postgresql-contrib bind-utils whois
        ;;
    pacman)
        $INSTALL --needed -y base-devel openssl curl ca-certificates \
            postgresql dnsutils whois
        ;;
esac
ok "Dépendances système installées"

# ----- 2. Outils Kali natifs : VÉRIFICATION + MISE À JOUR -----
# Sur Kali, les outils d'audit sont pré-installés : on vérifie leur présence
# et on les maintient à jour via les dépôts. Exceptions hors dépôts : Go tools.
info "Vérification des outils Kali natifs (pré-installés sur Kali)…"
KALI_TOOLS=(nmap nuclei nikto wafw00f whatweb sslscan dnstwist ffuf dnsrecon theharvester)

MISSING=(); STALE=()
for t in "${KALI_TOOLS[@]}"; do
    if command -v "$t" >/dev/null 2>&1; then STALE+=("$t"); else MISSING+=("$t"); fi
done

# Mise à jour des outils présents (dépendances à jour)
if [ ${#STALE[@]} -gt 0 ]; then
    info "Mise à jour des outils natifs présents : ${STALE[*]}…"
    $UPDATE >/dev/null 2>&1 || true
    apt install -y --only-upgrade "${STALE[@]}" >/dev/null 2>&1         || warn "Upgrade partiel — vérifier : apt install --only-upgrade ${STALE[*]}"
fi
# Installation des outils absents (Kali épuré)
if [ ${#MISSING[@]} -gt 0 ]; then
    warn "Outils natifs absents (Kali inhabituel) : ${MISSING[*]} — installation…"
    $UPDATE; $INSTALL "${MISSING[@]}" || warn "Échec pour : ${MISSING[*]} — voir README"
fi

# Exceptions hors dépôts : httpx/subfinder (ProjectDiscovery) + RustScan via Go
command -v go >/dev/null 2>&1 || { info "Installation de Go (requis pour httpx/subfinder/rustscan)…"; $INSTALL golang-go || warn "Go non installé — httpx/subfinder/rustscan manquants"; }
export PATH="$PATH:/usr/local/go/bin:$HOME/go/bin"
install_go_tool() {
    # $1 = chemin go, $2 = nom binaire
    info "Installation $2 (go install)…"
    go install "$1@latest" 2>/dev/null || { warn "go install $2 échoué — commande : go install $1@latest"; return 1; }
    [ -f "$HOME/go/bin/$2" ] && install -m 0755 "$HOME/go/bin/$2" "/usr/local/bin/$2" && ok "$2 → /usr/local/bin/$2"
}
command -v subfinder >/dev/null 2>&1 || install_go_tool github.com/projectdiscovery/subfinder/v2/cmd/subfinder subfinder
command -v rustscan >/dev/null 2>&1 || install_go_tool github.com/RustScan/RustScan rustscan
# httpx : le BON binaire (ProjectDiscovery) répond à -version.
# Le paquet Python homonyme (/usr/bin/httpx, JA3) ne répond pas → on remplace.
if ! httpx -version >/dev/null 2>&1; then
    HTTPX_PATH=$(command -v httpx || true)
    [ -n "$HTTPX_PATH" ] && warn "httpx incompatibles détecté ($HTTPX_PATH — outil Python homonyme) : remplacement…"
    install_go_tool github.com/projectdiscovery/httpx/cmd/httpx httpx
fi

# Vérification finale REQUISE (le scanner refusera sinon de lancer le full scan)
FAIL=()
for t in nmap nuclei nikto wafw00f whatweb sslscan dnstwist ffuf dnsrecon theharvester httpx subfinder rustscan; do
    command -v "$t" >/dev/null 2>&1 || FAIL+=("$t")
done
if [ ${#FAIL[@]} -gt 0 ]; then
    warn "OUTILS TOUJOURS ABSENTS : ${FAIL[*]}"
    warn "veridy_scanner refusera le full scan tant qu'ils manquent (voir README — Prérequis)."
else
    ok "Tous les outils requis sont présents et à jour"
fi

# ----- 3. Rust toolchain -----
if ! command -v cargo >/dev/null 2>&1; then
    info "Installation de Rust (rustup)…"
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain stable
    source "$HOME/.cargo/env"
    ok "Rust $(rustc --version) installé"
else
    ok "Rust $(rustc --version) déjà présent"
fi

# ----- 4. Récupération du code -----
info "Récupération du code source ($BRANCH)…"
if [ -d "$INSTALL_DIR/.git" ]; then
    cd "$INSTALL_DIR"
    git fetch --depth 1 origin "$BRANCH"
    git reset --hard "origin/$BRANCH"
    ok "Repo mis à jour"
else
    [ -d "$INSTALL_DIR" ] && rm -rf "$INSTALL_DIR"
    git clone --depth 1 -b "$BRANCH" "$REPO_URL" "$INSTALL_DIR"
    ok "Repo cloné dans $INSTALL_DIR"
fi

# ----- 5. Compilation release -----
info "Compilation release (peut prendre 2-5 minutes)…"
cd "$INSTALL_DIR"
cargo build --release
ok "Binaire compilé : $INSTALL_DIR/target/release/$BIN_NAME"

# ----- 6. Installation système -----
info "Installation du binaire dans /usr/local/bin/…"
install -m 0755 "target/release/$BIN_NAME" "/usr/local/bin/$BIN_NAME"
install -m 0755 "launch.sh" /usr/local/bin/veridy
ok "Commandes disponibles : veridy_scanner, veridy"

# ----- 7. Base PostgreSQL (optionnel) -----
if command -v psql >/dev/null 2>&1; then
    info "Initialisation PostgreSQL…"
    if systemctl is-active --quiet postgresql 2>/dev/null || service postgresql status >/dev/null 2>&1; then
        DB_NAME="${VERIDY_DB:-veridy_audit}"
        sudo -u postgres psql -tAc "SELECT 1 FROM pg_database WHERE datname='$DB_NAME'" | grep -q 1 \
            || sudo -u postgres createdb "$DB_NAME" \
            || warn "Création de $DB_NAME impossible (continuer sans DB)"
        if sudo -u postgres psql -d "$DB_NAME" -tAc "SELECT 1 FROM information_schema.tables WHERE table_name='audit_scans'" 2>/dev/null | grep -q 1; then
            ok "Schéma déjà présent"
        else
            for f in init_schema.sql schema_full.sql schema_deep.sql schema_tools.sql; do
                [ -f "$f" ] && sudo -u postgres psql -d "$DB_NAME" -v ON_ERROR_STOP=1 -f "$f" \
                    && ok "Schéma : $f chargé"
            done
        fi
    else
        warn "PostgreSQL inactif (start manuel : sudo systemctl start postgresql)"
    fi
else
    warn "psql absent — scan sans persistance"
fi

# ----- 8. Diagnostic final -----
info "Diagnostic de l'installation…"
veridy_scanner tools 2>&1 | head -20

echo
ok "═══════════════════════════════════════════════════════"
ok " Installation veridy_scanner terminée"
ok "═══════════════════════════════════════════════════════"
echo
info "Premier scan :  veridy_scanner example.com --no-db"
info "Console TUI :    sudo veridy"
info "Aide :           veridy_scanner --help"
info "Logs install :   /tmp/veridy-install.log (si redirigé)"