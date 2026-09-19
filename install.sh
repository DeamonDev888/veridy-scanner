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
info "Système : $(uname -m) $(. /etc/os-release && echo "$PRETTY_NAME")"

# ----- Détection gestionnaire de paquets -----
if command -v apt >/dev/null 2>&1; then
    PKG=apt
    UPDATE="apt update -y"
    INSTALL="apt install -y"
elif command -v dnf >/dev/null 2>&1; then
    PKG=dnf
    UPDATE="dnf check-update || true"
    INSTALL="dnf install -y"
elif command -v pacman >/dev/null 2>&1; then
    PKG=pacman
    UPDATE="pacman -Sy"
    INSTALL="pacman -S --noconfirm"
else
    die "Gestionnaire non supporté (apt/dnf/pacman requis)"
fi
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

# ----- 2. Outils Kali REQUIS (full scan par défaut) -----
info "Installation des outils Kali REQUIS (full scan par défaut)…"
KALI_TOOLS=(nmap nuclei nikto wafw00f whatweb sslscan dnstwist ffuf dnsrecon theharvester)
GO_TOOLS=(httpx subfinder rustscan)
MISSING=()
for t in "${KALI_TOOLS[@]}"; do
    if ! command -v "$t" >/dev/null 2>&1; then MISSING+=("$t"); fi
done
if [ ${#MISSING[@]} -gt 0 ]; then
    warn "Outils absents : ${MISSING[*]} — installation via $PKG…"
    case "$PKG" in
        apt) $UPDATE; $INSTALL "${MISSING[@]}" || warn "Échec apt pour : ${MISSING[*]} — installer manuellement" ;;
        dnf) $INSTALL "${MISSING[@]}" || warn "Échec dnf — installer manuellement" ;;
        pacman) $INSTALL "${MISSING[@]}" || warn "Échec pacman — installer manuellement" ;;
    esac
fi
# Outils Go (ProjectDiscovery + RustScan) : requis, installés si Go présent
for t in "${GO_TOOLS[@]}"; do
    if ! command -v "$t" >/dev/null 2>&1; then
        if command -v go >/dev/null 2>&1; then
            info "Installation $t (go install)…"
            case "$t" in
                httpx)    go install github.com/projectdiscovery/httpx/v2/cmd/httpx@latest ;;
                subfinder) go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest ;;
                rustscan) go install github.com/RustScan/RustScan@latest ;;
            esac
            [ -d "$HOME/go/bin" ] && ln -sf "$HOME/go/bin/$t" /usr/local/bin/$t 2>/dev/null
        else
            warn "$t absent et Go non installé — requis pour le full scan :"
            warn "  go install github.com/projectdiscovery/$( [ $t = rustscan ] && echo RustScan/RustScan || echo $t )@latest"
        fi
    fi
done
# Vérification finale REQUISE
FAIL=()
for t in nmap nuclei nikto wafw00f whatweb sslscan dnstwist ffuf dnsrecon theharvester httpx subfinder rustscan; do
    command -v "$t" >/dev/null 2>&1 || FAIL+=("$t")
done
if [ ${#FAIL[@]} -gt 0 ]; then
    warn "OUTILS TOUJOURS ABSENTS : ${FAIL[*]}"
    warn "Le scanner refusera le full scan tant qu'ils ne sont pas installés (voir README — Prérequis)."
else
    ok "Tous les outils Kali requis sont présents"
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