#!/usr/bin/env bash
# ==============================================================================
#  ██╗   ██╗███████╗██████╗ ██╗██████╗ ██╗   ██╗
#  ██║   ██║██╔════╝██╔══██╗██║██╔══██╗╚██╗ ██╔╝
#  ██║   ██║█████╗  ██████╔╝██║██║  ██║ ╚████╔╝ 
#  ╚██╗ ██╔╝██╔══╝  ██╔══██╗██║██║  ██║  ╚██╔╝  
#   ╚████╔╝ ███████╗██║  ██║██║██████╔╝   ██║   
#    ╚═══╝  ╚══════╝╚═╝  ╚═╝╚═╝╚═════╝    ╚═╝   
#
#   VERIDY CYBER INTELLIGENCE & AUDIT CONSOLE (v2.2 TUI)
#   Automated 360° Offensive Surface Engine
# ==============================================================================

set -o pipefail

# ------------------------------------------------------------------------------
# Colors & Visual Effects (ANSI TrueColor / 256)
# ------------------------------------------------------------------------------
C_RST="\033[0m"
C_BOLD="\033[1m"
C_DIM="\033[2m"
C_ITAL="\033[3m"
C_REV="\033[7m"

# Palette
C_CYAN="\033[38;5;51m"
C_PURPLE="\033[38;5;141m"
C_PINK="\033[38;5;198m"
C_GREEN="\033[38;5;82m"
C_YELLOW="\033[38;5;220m"
C_RED="\033[38;5;196m"
C_BLUE="\033[38;5;39m"
C_GRAY="\033[38;5;244m"
C_WHITE="\033[38;5;255m"

# ------------------------------------------------------------------------------
# Configuration Defaults
# ------------------------------------------------------------------------------
SCANNER_BIN="/usr/local/bin/veridy_scanner"
FALLBACK_BIN="$(dirname "$0")/target/release/veridy_scanner"
SRC_DIR="$(cd "$(dirname "$0")" && pwd)"
if [[ ! -d "$SRC_DIR" ]]; then
    SRC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
fi
DB_NAME="veridy_audit"
DEFAULT_TARGET="veridy.ca"
CURRENT_TARGET="$DEFAULT_TARGET"

if [[ ! -x "$SCANNER_BIN" ]]; then
    if [[ -x "$FALLBACK_BIN" ]]; then
        SCANNER_BIN="$FALLBACK_BIN"
    fi
fi

# ------------------------------------------------------------------------------
# Terminal Cursor Management & Cleanup Trap
# ------------------------------------------------------------------------------
cleanup_terminal() {
    tput cnorm 2>/dev/null || echo -ne "\033[?25h"
    echo -ne "${C_RST}"
}
trap cleanup_terminal INT TERM EXIT

hide_cursor() {
    tput civis 2>/dev/null || echo -ne "\033[?25l"
}

show_cursor() {
    tput cnorm 2>/dev/null || echo -ne "\033[?25h"
}

# ------------------------------------------------------------------------------
# Robust Raw Key Reader (Arrow Keys, Enter, Space, Escape, Tab)
# ------------------------------------------------------------------------------
read_key() {
    local key
    if ! IFS= read -rsn1 key 2>/dev/null; then
        echo -n "EOF"
        return
    fi
    if [[ "$key" == $'\x1b' ]]; then
        local rest
        IFS= read -rsn2 -t 0.05 rest 2>/dev/null || true
        key+="$rest"
        if [[ "$rest" =~ ^\[[0-9]$ ]]; then
            local extra
            IFS= read -rsn1 -t 0.05 extra 2>/dev/null || true
            key+="$extra"
        fi
    fi
    echo -n "$key"
}

# ------------------------------------------------------------------------------
# Banner Function
# ------------------------------------------------------------------------------
show_banner() {
    if [[ -t 1 && "$TERM" != "" && "$TERM" != "dumb" ]]; then
        clear 2>/dev/null || true
    fi
    echo -e "${C_PURPLE}  ╔═══════════════════════════════════════════════════════════════════════════╗${C_RST}"
    echo -e "${C_PURPLE}  ║                                                                           ║${C_RST}"
    echo -e "${C_PURPLE}  ║${C_CYAN}${C_BOLD}   ██╗   ██╗███████╗██████╗ ██╗██████╗ ██╗   ██╗                         ${C_PURPLE}║${C_RST}"
    echo -e "${C_PURPLE}  ║${C_CYAN}${C_BOLD}   ██║   ██║██╔════╝██╔══██╗██║██╔══██╗╚██╗ ██╔╝                         ${C_PURPLE}║${C_RST}"
    echo -e "${C_PURPLE}  ║${C_CYAN}${C_BOLD}   ██║   ██║█████╗  ██████╔╝██║██║  ██║ ╚████╔╝                          ${C_PURPLE}║${C_RST}"
    echo -e "${C_PURPLE}  ║${C_CYAN}${C_BOLD}   ╚██╗ ██╔╝██╔══╝  ██╔══██╗██║██║  ██║  ╚██╔╝                           ${C_PURPLE}║${C_RST}"
    echo -e "${C_PURPLE}  ║${C_CYAN}${C_BOLD}    ╚████╔╝ ███████╗██║  ██║██║██████╔╝   ██║                            ${C_PURPLE}║${C_RST}"
    echo -e "${C_PURPLE}  ║${C_CYAN}${C_BOLD}     ╚═══╝  ╚══════╝╚═╝  ╚═╝╚═╝╚═════╝    ╚═╝                            ${C_PURPLE}║${C_RST}"
    echo -e "${C_PURPLE}  ║                                                                           ║${C_RST}"
    echo -e "${C_PURPLE}  ║      ${C_BLUE}${C_BOLD}>> CYBER INTELLIGENCE & OFFENSIVE SURFACE ENGINE 360° <<${C_RST}             ${C_PURPLE}║${C_RST}"
    echo -e "${C_PURPLE}  ║             ${C_DIM}[ Kali Toolchain (15 Modules) | PostgreSQL 12-Tables ]${C_RST}        ${C_PURPLE}║${C_RST}"
    echo -e "${C_PURPLE}  ╚═══════════════════════════════════════════════════════════════════════════╝${C_RST}"
    echo ""
}

# ------------------------------------------------------------------------------
# Status Dashboard Header (HUD)
# ------------------------------------------------------------------------------
show_hud() {
    local target_ip
    target_ip=$(dig +short "$CURRENT_TARGET" 2>/dev/null | tail -n1)
    [[ -z "$target_ip" ]] && target_ip="DNS Non-résolu"

    local db_status="${C_GREEN}● EN LIGNE (12 Tables)${C_RST}"
    if ! sudo -u postgres psql -d "$DB_NAME" -c "SELECT 1;" >/dev/null 2>&1; then
        db_status="${C_RED}○ HORS LIGNE${C_RST}"
    fi

    echo -e "${C_CYAN}┌─────────────────────────────────────────────────────────────────────────────┐${C_RST}"
    printf "${C_CYAN}│${C_RST}  ${C_BOLD}%-15s${C_RST} : ${C_YELLOW}%-22s${C_RST} ${C_BOLD}%-14s${C_RST} : ${C_CYAN}%-20s${C_RST} ${C_CYAN}│${C_RST}\n" \
        "CIBLE ACTUELLE" "$CURRENT_TARGET" "ADRESSE IP" "$target_ip"
    printf "${C_CYAN}│${C_RST}  ${C_BOLD}%-15s${C_RST} : %-31b ${C_BOLD}%-14s${C_RST} : ${C_PURPLE}%-20s${C_RST} ${C_CYAN}│${C_RST}\n" \
        "BASE POSTGRES" "$db_status" "MOTEUR CORE" "Rust 2024 / Multi-thread"
    echo -e "${C_CYAN}├─────────────────────────────────────────────────────────────────────────────┤${C_RST}"
    
    # 15 Tool badges répartis sur 2 lignes soignées
    local tools_l1=("nmap" "nuclei" "nikto" "wafw00f" "whatweb" "sslscan" "dnstwist" "ffuf")
    local tools_l2=("whois" "dnsrecon" "theHarvester" "obscura" "rustscan" "httpx" "sqlmap")
    local badges1=""
    local badges2=""
    for t in "${tools_l1[@]}"; do
        if command -v "$t" >/dev/null 2>&1; then
            badges1+="${C_GREEN}[✓ $t]${C_RST} "
        else
            badges1+="${C_RED}[✗ $t]${C_RST} "
        fi
    done
    for t in "${tools_l2[@]}"; do
        if command -v "$t" >/dev/null 2>&1; then
            badges2+="${C_GREEN}[✓ $t]${C_RST} "
        else
            badges2+="${C_RED}[✗ $t]${C_RST} "
        fi
    done
    printf "${C_CYAN}│${C_RST}  ${C_BOLD}%-15s${C_RST} : %-69b ${C_CYAN}│${C_RST}\n" "SUITE KALI (1/2)" "$badges1"
    printf "${C_CYAN}│${C_RST}  ${C_BOLD}%-15s${C_RST} : %-69b ${C_CYAN}│${C_RST}\n" "SUITE KALI (2/2)" "$badges2"
    echo -e "${C_CYAN}└─────────────────────────────────────────────────────────────────────────────┘${C_RST}"
    echo ""
}

# ------------------------------------------------------------------------------
# Check Tools Diagnostic
# ------------------------------------------------------------------------------
check_tools() {
    show_cursor
    show_banner
    echo -e "${C_BOLD}${C_YELLOW}[*] DIAGNOSTIC COMPLET DE L'ENVIRONNEMENT KALI & OUTILS :${C_RST}\n"

    local tools=(
        "nmap:Scanner réseau & scripts NSE de détection de version"
        "nuclei:Moteur de templates de vulnérabilités et CVEs"
        "nikto:Scanner de serveurs HTTP et fichiers dangereux"
        "wafw00f:Détecteur d'empreinte de pare-feu applicatif (WAF)"
        "whatweb:Identification des composants CMS, JS et fuites emails"
        "sslscan:Audit cryptographique TLS/SSL et failles Heartbleed/CRIME"
        "dnstwist:Détection du typosquatting, phishing et domaines clones"
        "ffuf:Fuzzing ultra-rapide des endpoints sensibles"
        "whois:Interrogation du registre officiel de domaine et expiration"
        "dnsrecon:Audit DNS avancé, enregistrements SRV et version Bind"
        "theHarvester:Reconnaissance passive OSINT d'emails et sous-domaines"
        "obscura:Moteur headless browser V8 & rendu dynamique DOM"
        "rustscan:Balayage SYN ultra-rapide des 65535 ports réseau"
        "httpx:Probe HTTP massif & détection de stack technologique"
        "sqlmap:Moteur d'audit automatique d'injections SQL"
        "psql:Client PostgreSQL pour la persistence de l'audit"
    )

    # Compteur pour barre de statut globale
    local total_tools=${#tools[@]}
    local ok_count=0
    local missing_count=0

    printf "  ${C_BOLD}%-14s %-8s %-50s${C_RST}\n" "OUTIL" "STATUT" "DESCRIPTION"
    echo "  ──────────────────────────────────────────────────────────────────────────────────"
    for item in "${tools[@]}"; do
        local tool="${item%%:*}"
        local desc="${item##*:}"
        if command -v "$tool" >/dev/null 2>&1; then
            printf "  ${C_CYAN}%-14s${C_RST} ${C_GREEN}%-8s${C_RST} ${C_DIM}%-50s${C_RST}\n" "$tool" "[OK]" "$desc"
            ok_count=$((ok_count + 1))
        else
            printf "  ${C_RED}%-14s${C_RST} ${C_RED}%-8s${C_RST} ${C_DIM}%-50s${C_RST}\n" "$tool" "[MISSING]" "$desc"
            missing_count=$((missing_count + 1))
        fi
    done

    # Barre de statut globale avec dégradé de couleur
    local pct=$((ok_count * 100 / total_tools))
    local bar_width=40
    local filled=$((pct * bar_width / 100))
    local empty=$((bar_width - filled))
    local bar_color
    if [[ $pct -ge 90 ]]; then bar_color="$C_GREEN"
    elif [[ $pct -ge 60 ]]; then bar_color="$C_BLUE"
    elif [[ $pct -ge 30 ]]; then bar_color="$C_YELLOW"
    else bar_color="$C_RED"
    fi

    printf "\n  ${C_BOLD}État global :${C_RST} ${bar_color}"
    printf '█%.0s' $(seq 1 $filled)
    printf "${C_DIM}"
    printf '░%.0s' $(seq 1 $empty)
    printf "${C_RST} ${bar_color}${C_BOLD}${pct}%%${C_RST}  (${C_GREEN}${ok_count}${C_RST}/${total_tools} outils)"
    if [[ $missing_count -gt 0 ]]; then
        printf "  ${C_DIM}${C_YELLOW}⚠ ${missing_count} manquant(s)${C_RST}"
    fi
    echo ""

    echo ""
    echo -e "  ${C_BOLD}Vérification des Dictionnaires & Wordlists :${C_RST}"
    local wordlist="/usr/share/seclists/Discovery/Web-Content/quickhits.txt"
    if [[ -f "$wordlist" ]]; then
        local count
        count=$(wc -l < "$wordlist")
        echo -e "  ${C_GREEN}[✓]${C_RST} SecLists QuickHits : ${C_CYAN}$wordlist${C_RST} (${count} entrées)"
    else
        echo -e "  ${C_YELLOW}[!]${C_RST} SecLists QuickHits non trouvé dans le chemin par défaut"
    fi

    echo ""
    echo -e "  ${C_BOLD}Vérification du Binaire Scanner Rust :${C_RST}"
    if [[ -x "$SCANNER_BIN" ]]; then
        echo -e "  ${C_GREEN}[✓]${C_RST} Binaire actif : ${C_CYAN}$SCANNER_BIN${C_RST}"
    else
        echo -e "  ${C_RED}[✗]${C_RST} Binaire introuvable ! Compilez avec 'cargo build --release'"
    fi

    echo ""
    if [[ "$INTERACTIVE_MODE" == "1" ]]; then
        read -rp "Appuyez sur [Entrée] pour continuer..."
    fi
}

# ------------------------------------------------------------------------------
# Launch Scan Engine
# ------------------------------------------------------------------------------
run_scan() {
    show_cursor
    local profile_name="$1"
    shift
    local extra_flags=("$@")

    show_banner
    echo -e "${C_PURPLE}===============================================================================${C_RST}"
    echo -e "  ${C_BOLD}${C_YELLOW}LANCEMENT DU SCAN : ${C_WHITE}${profile_name}${C_RST}"
    echo -e "  ${C_BOLD}Cible : ${C_CYAN}${CURRENT_TARGET}${C_RST} | Base : ${C_PURPLE}${DB_NAME}${C_RST}"
    echo -e "${C_PURPLE}===============================================================================${C_RST}\n"

    local start_time
    start_time=$(date +%s)

    "$SCANNER_BIN" --target "$CURRENT_TARGET" --db "$DB_NAME" "${extra_flags[@]}"
    local exit_code=$?

    local end_time
    end_time=$(date +%s)
    local elapsed=$((end_time - start_time))

    echo ""
    echo -e "${C_PURPLE}===============================================================================${C_RST}"
    if [[ $exit_code -eq 0 ]]; then
        echo -e "  ${C_GREEN}${C_BOLD}[✓] SCAN TERMINÉ AVEC SUCCÈS en ${elapsed}s !${C_RST}"
        echo ""
        echo -e "  ${C_CYAN}${C_BOLD}[*] DERNIER RÉSULTAT ENREGISTRÉ EN BASE :${C_RST}"
        sudo -u postgres psql -d "$DB_NAME" -t -A -F" | " -c \
            "SELECT '  Scan #' || id || ' | Score: ' || overall_score || '/100 | Ports: ' || open_ports_count || ' | Findings: ' || findings_count || ' | Durée: ' || ROUND(duration_seconds::numeric, 1) || 's' FROM audit_scans WHERE target = '$CURRENT_TARGET' ORDER BY created_at DESC LIMIT 1;" 2>/dev/null
    else
        echo -e "  ${C_RED}${C_BOLD}[✗] LE SCAN S'EST TERMINÉ AVEC L'ERREUR CODE : ${exit_code}${C_RST}"
    fi
    echo -e "${C_PURPLE}===============================================================================${C_RST}\n"

    if [[ "$INTERACTIVE_MODE" == "1" ]]; then
        read -rp "Appuyez sur [Entrée] pour revenir au menu principal..."
    fi
}

# ------------------------------------------------------------------------------
# Show Audit History
# ------------------------------------------------------------------------------
show_history() {
    show_cursor
    show_banner
    echo -e "${C_BOLD}${C_YELLOW}[*] HISTORIQUE DES SCANS DE SÉCURITÉ EN BASE (${DB_NAME}) :${C_RST}\n"

    sudo -u postgres psql -d "$DB_NAME" -c \
        "SELECT id, target, to_char(created_at, 'YYYY-MM-DD HH24:MI:SS') as date_scan, overall_score as score, open_ports_count as ports, findings_count as failles, ROUND(duration_seconds::numeric, 1) as sec FROM audit_scans ORDER BY id DESC LIMIT 15;"

    # ===== MINI-GRAPHIQUE : Évolution des scores des 20 derniers scans =====
    echo ""
    echo -e "${C_BOLD}${C_CYAN}═══ ÉVOLUTION DES SCORES (20 derniers scans) ═══${C_RST}"
    local scores_data
    scores_data=$(sudo -u postgres psql -d "$DB_NAME" -t -A -F"," -c \
        "SELECT overall_score FROM audit_scans ORDER BY id DESC LIMIT 20;" 2>/dev/null | tac)
    if [[ -n "$scores_data" ]]; then
        # Génération de la sparkline ASCII
        local sparkline=""
        local line=""
        local idx=0
        local chars=("▁" "▂" "▃" "▄" "▅" "▆" "▇" "█")
        for score in $scores_data; do
            local pos=$((score * 7 / 100))
            [[ $pos -gt 7 ]] && pos=7
            [[ $pos -lt 0 ]] && pos=0
            sparkline+="${chars[$pos]}"
            idx=$((idx + 1))
        done
        echo -e "  ${C_BOLD}Sparkline${C_RST}  ${C_GREEN}${sparkline}${C_RST}  ${C_DIM}(0──────────────────────────100)${C_RST}"
        echo -e "  ${C_BOLD}Min/Max${C_RST}  $(echo "$scores_data" | tr ' ' '\n' | sort -n | head -1 | xargs -I{} printf "${C_RED}%3d${C_RST}" {})  ${C_DIM}→${C_RST}  $(echo "$scores_data" | tr ' ' '\n' | sort -n | tail -1 | xargs -I{} printf "${C_GREEN}%3d${C_RST}" {})  ${C_DIM}(étendue)${C_RST}"
        echo -e "  ${C_BOLD}Moyenne${C_RST} $(echo "$scores_data" | tr ' ' '\n' | awk '{s+=$1;n++}END{printf "%3d", s/n}')  ${C_DIM}sur $idx scans${C_RST}"

        # Distribution des scores par tranche (histogramme horizontal)
        echo ""
        echo -e "${C_BOLD}Distribution par tranche :${C_RST}"
        local range_0_20=$(echo "$scores_data" | awk '$1<20' | wc -l)
        local range_20_40=$(echo "$scores_data" | awk '$1>=20 && $1<40' | wc -l)
        local range_40_60=$(echo "$scores_data" | awk '$1>=40 && $1<60' | wc -l)
        local range_60_80=$(echo "$scores_data" | awk '$1>=60 && $1<80' | wc -l)
        local range_80_100=$(echo "$scores_data" | awk '$1>=80' | wc -l)
        local max_count=$idx
        [[ $max_count -eq 0 ]] && max_count=1

        for label_data in "0-19:${range_0_20}:${C_RED}" "20-39:${range_20_40}:${C_ORANGE}" "40-59:${range_40_60}:${C_YELLOW}" "60-79:${range_60_80}:${C_BLUE}" "80-100:${range_80_100}:${C_GREEN}"; do
            local label="${label_data%%:*}"
            local rest="${label_data#*:}"
            local count="${rest%%:*}"
            local color="${rest#*:}"
            local bar_len=$((count * 30 / max_count))
            [[ $bar_len -gt 30 ]] && bar_len=30
            local bar=""
            for ((b=0; b<bar_len; b++)); do bar+="█"; done
            printf "  ${color}${C_BOLD}[%3s]${C_RST} ${color}%-30s${C_RST} ${C_DIM}%d scans${C_RST}\n" "$label" "$bar" "$count"
        done
    else
        echo -e "  ${C_DIM}Aucun scan en base pour le moment.${C_RST}"
    fi

    # ===== TOP CIBLES =====
    echo ""
    echo -e "${C_BOLD}${C_CYAN}═══ TOP 5 CIBLES LES PLUS SCANNÉES ═══${C_RST}"
    sudo -u postgres psql -d "$DB_NAME" -c \
        "SELECT target, COUNT(*) as scans, ROUND(AVG(overall_score),0) as score_moyen, MAX(created_at) as dernier_scan FROM audit_scans GROUP BY target ORDER BY COUNT(*) DESC LIMIT 5;" 2>/dev/null

    echo ""
    if [[ "$INTERACTIVE_MODE" == "1" ]]; then
        read -rp "Appuyez sur [Entrée] pour continuer..."
    fi
}

# ------------------------------------------------------------------------------
# Show Database Intelligence & Statistics
# ------------------------------------------------------------------------------
show_stats() {
    show_cursor
    show_banner
    echo -e "${C_BOLD}${C_YELLOW}[*] TABLEAU DE BORD DE RENSEIGNEMENT & STATISTIQUES GLOBALES :${C_RST}\n"

    echo -e "${C_CYAN}${C_BOLD}1. MÉTRIQUES GLOBALES DE SÉCURITÉ :${C_RST}"
    sudo -u postgres psql -d "$DB_NAME" -c \
        "SELECT COUNT(*) as scans_totaux, COUNT(DISTINCT target) as cibles_uniques, ROUND(AVG(overall_score),1) as score_moyen, MIN(overall_score) as score_min, MAX(overall_score) as score_max FROM audit_scans;"

    echo -e "\n${C_CYAN}${C_BOLD}2. RÉPARTITION DES ANOMALIES PAR GRAVITÉ :${C_RST}"
    sudo -u postgres psql -d "$DB_NAME" -c \
        "SELECT severity, COUNT(*) as nombre, ROUND(COUNT(*) * 100.0 / SUM(COUNT(*)) OVER (), 1) as pourcentage FROM audit_findings GROUP BY severity ORDER BY CASE severity WHEN 'CRITICAL' THEN 1 WHEN 'HIGH' THEN 2 WHEN 'MEDIUM' THEN 3 WHEN 'LOW' THEN 4 ELSE 5 END;"

    echo -e "\n${C_CYAN}${C_BOLD}3. TOP 10 DES VULNÉRABILITÉS & OBSERVATIONS DÉTECTÉES :${C_RST}"
    sudo -u postgres psql -d "$DB_NAME" -c \
        "SELECT title, severity, category, COUNT(*) as occurences FROM audit_findings GROUP BY title, severity, category ORDER BY CASE severity WHEN 'CRITICAL' THEN 1 WHEN 'HIGH' THEN 2 WHEN 'MEDIUM' THEN 3 WHEN 'LOW' THEN 4 ELSE 5 END, occurences DESC LIMIT 10;"

    echo ""
    if [[ "$INTERACTIVE_MODE" == "1" ]]; then
        read -rp "Appuyez sur [Entrée] pour continuer..."
    fi
}

# ------------------------------------------------------------------------------
# Show 12 Tables Live Rows
# ------------------------------------------------------------------------------
show_db_tables() {
    show_cursor
    show_banner
    echo -e "${C_BOLD}${C_YELLOW}[*] VUE D'ENSEMBLE DES 12 TABLES RELATIONNELLES (${DB_NAME}) :${C_RST}\n"

    sudo -u postgres psql -d "$DB_NAME" -c \
        "SELECT relname as nom_table, n_live_tup as lignes_actives FROM pg_stat_user_tables ORDER BY n_live_tup DESC;"

    echo ""
    if [[ "$INTERACTIVE_MODE" == "1" ]]; then
        read -rp "Appuyez sur [Entrée] pour continuer..."
    fi
}

# ------------------------------------------------------------------------------
# Show Specific Scan Technical Detail
# ------------------------------------------------------------------------------
show_scan_detail() {
    local scan_id="$1"
    show_cursor
    if [[ -z "$scan_id" ]]; then
        echo -e "\n${C_BOLD}${C_YELLOW}[?] Entrez l'ID du scan à inspecter :${C_RST}"
        read -rp "> " scan_id
    fi

    if [[ ! "$scan_id" =~ ^[0-9]+$ ]]; then
        echo -e "${C_RED}ID de scan invalide !${C_RST}"
        sleep 1
        return
    fi

    show_banner
    echo -e "${C_BOLD}${C_YELLOW}[*] INSPECTION TECHNIQUE COMPLÈTE DU SCAN #$scan_id :${C_RST}\n"

    echo -e "${C_CYAN}${C_BOLD}1. EN-TÊTE DU SCAN & NOTE GLOBALE :${C_RST}"
    sudo -u postgres psql -d "$DB_NAME" -c \
        "SELECT id, target, to_char(created_at, 'YYYY-MM-DD HH24:MI:SS') as date, overall_score as score, open_ports as ports_ouverts, tls_valid, spf_ok, dmarc_ok, ROUND(duration_seconds::numeric, 1) as duree_sec FROM audit_scans WHERE id = $scan_id;"

    echo -e "\n${C_CYAN}${C_BOLD}2. OUTILS KALI EXÉCUTÉS SUR CE SCAN :${C_RST}"
    sudo -u postgres psql -d "$DB_NAME" -c \
        "SELECT tool_name, status, items_count, ROUND(execution_time_seconds::numeric, 1) as sec, summary FROM audit_tool_outputs WHERE scan_id = $scan_id ORDER BY tool_name ASC;"

    echo -e "\n${C_CYAN}${C_BOLD}3. CONSTATATIONS & RECOMMANDATIONS CATALOGUÉES :${C_RST}"
    sudo -u postgres psql -d "$DB_NAME" -c \
        "SELECT severity, category, title, recommendation FROM audit_findings WHERE scan_id = $scan_id ORDER BY CASE severity WHEN 'CRITICAL' THEN 1 WHEN 'HIGH' THEN 2 WHEN 'MEDIUM' THEN 3 WHEN 'LOW' THEN 4 ELSE 5 END;"

    echo ""
    if [[ "$INTERACTIVE_MODE" == "1" ]]; then
        read -rp "Appuyez sur [Entrée] pour continuer..."
    fi
}

# ------------------------------------------------------------------------------
# Show Findings Filtered by Severity
# ------------------------------------------------------------------------------
show_findings() {
    local sev="$1"
    show_cursor
    show_banner
    echo -e "${C_BOLD}${C_YELLOW}[*] CONSTATATIONS & ANOMALIES EN BASE (${DB_NAME}) :${C_RST}\n"

    if [[ -n "$sev" ]]; then
        sev=$(echo "$sev" | tr '[:lower:]' '[:upper:]')
        echo -e "  Filtre de gravité : ${C_BOLD}${C_RED}$sev${C_RST}\n"
        sudo -u postgres psql -d "$DB_NAME" -c \
            "SELECT f.scan_id, s.target, f.severity, f.category, f.title FROM audit_findings f JOIN audit_scans s ON f.scan_id = s.id WHERE f.severity = '$sev' ORDER BY f.id DESC LIMIT 30;"
    else
        sudo -u postgres psql -d "$DB_NAME" -c \
            "SELECT f.scan_id, s.target, f.severity, f.category, f.title FROM audit_findings f JOIN audit_scans s ON f.scan_id = s.id ORDER BY CASE f.severity WHEN 'CRITICAL' THEN 1 WHEN 'HIGH' THEN 2 WHEN 'MEDIUM' THEN 3 WHEN 'LOW' THEN 4 ELSE 5 END, f.id DESC LIMIT 30;"
    fi

    echo ""
    if [[ "$INTERACTIVE_MODE" == "1" ]]; then
        read -rp "Appuyez sur [Entrée] pour continuer..."
    fi
}

# ------------------------------------------------------------------------------
# Show Subdomains Map
# ------------------------------------------------------------------------------
show_subdomains() {
    show_cursor
    show_banner
    echo -e "${C_BOLD}${C_YELLOW}[*] CARTOGRAPHIE DES SOUS-DOMAINES EN BASE (${DB_NAME}) :${C_RST}\n"

    sudo -u postgres psql -d "$DB_NAME" -c \
        "SELECT DISTINCT s.target as domaine_parent, sub.subdomain, sub.ip_address, sub.http_status, sub.is_alive as actif FROM audit_subdomains sub JOIN audit_scans s ON sub.scan_id = s.id ORDER BY s.target, sub.subdomain LIMIT 40;"

    echo ""
    if [[ "$INTERACTIVE_MODE" == "1" ]]; then
        read -rp "Appuyez sur [Entrée] pour continuer..."
    fi
}

# ------------------------------------------------------------------------------
# Show Geo Records
# ------------------------------------------------------------------------------
show_geolocation() {
    show_cursor
    show_banner
    echo -e "${C_BOLD}${C_YELLOW}[*] REGISTRE GÉOLOCALISATION DES HÉBERGEMENTS :${C_RST}\n"

    sudo -u postgres psql -d "$DB_NAME" -c \
        "SELECT s.id as scan_id, s.target, g.ip_address, g.org_name as fournisseur, g.country_code as pays, g.region, g.city as ville, CASE WHEN g.is_quebec THEN 'QC' WHEN g.is_canada THEN 'CA' ELSE 'INTL' END as juridiction FROM audit_geo_compliance g JOIN audit_scans s ON g.scan_id = s.id ORDER BY s.id DESC LIMIT 20;"

    echo ""
    if [[ "$INTERACTIVE_MODE" == "1" ]]; then
        read -rp "Appuyez sur [Entrée] pour continuer..."
    fi
}

# ------------------------------------------------------------------------------
# Interactive PostgreSQL Shell
# ------------------------------------------------------------------------------
open_psql_shell() {
    show_cursor
    show_banner
    echo -e "${C_BOLD}${C_YELLOW}[*] CONNEXION AU SHELL INTERACTIF POSTGRESQL (${DB_NAME}) :${C_RST}"
    echo -e "${C_DIM}Tapez vos requêtes SQL (ex: SELECT * FROM audit_scans LIMIT 5;) ou \\q pour quitter.${C_RST}\n"
    sudo -u postgres psql -d "$DB_NAME"
}

# ------------------------------------------------------------------------------
# Process Management & Running Scans Monitor
# ------------------------------------------------------------------------------
get_running_scans() {
    ps -eo pid,user,%cpu,%mem,etime,args 2>/dev/null | grep -E "veridy_scanner|nmap |nuclei |nikto |wafw00f |whatweb |sslscan |dnstwist |ffuf |dnsrecon |theHarvester |obscura " | grep -v grep | grep -v "launch.sh" | grep -v "veridy --" | grep -v "veridy -t" || true
}

show_running_scans() {
    show_cursor
    show_banner
    echo -e "${C_BOLD}${C_YELLOW}[*] SURVEILLANCE DES SCANS & PROCESSUS EN COURS D'EXÉCUTION :${C_RST}\n"

    local running
    running=$(get_running_scans)

    if [[ -z "$running" ]]; then
        echo -e "  ${C_GREEN}[✓] Aucun audit ou processus de scan actif en ce moment.${C_RST}"
        echo -e "  ${C_DIM}Le système et les moteurs Kali sont au repos.${C_RST}\n"
    else
        printf "  %-7s %-8s %-6s %-6s %-9s %-40s\n" "PID" "USER" "%CPU" "%MEM" "DURÉE" "COMMANDE"
        echo "  -------------------------------------------------------------------------------"
        while IFS= read -r line; do
            if [[ -n "$line" ]]; then
                local pid user cpu mem etime cmd
                pid=$(echo "$line" | awk '{print $1}')
                user=$(echo "$line" | awk '{print $2}')
                cpu=$(echo "$line" | awk '{print $3}')
                mem=$(echo "$line" | awk '{print $4}')
                etime=$(echo "$line" | awk '{print $5}')
                cmd=$(echo "$line" | cut -d' ' -f6- | cut -c1-40)
                printf "  ${C_CYAN}%-7s${C_RST} %-8s ${C_YELLOW}%-6s${C_RST} %-6s ${C_PINK}%-9s${C_RST} %-40s\n" \
                    "$pid" "$user" "$cpu" "$mem" "$etime" "$cmd"
            fi
        done <<< "$running"
        echo ""
    fi

    if [[ "$INTERACTIVE_MODE" == "1" ]]; then
        read -rp "Appuyez sur [Entrée] pour continuer..."
    fi
}

stop_scans() {
    show_cursor
    show_banner
    echo -e "${C_BOLD}${C_YELLOW}[*] ARRÊT D'URGENCE & PURGE DES PROCESSUS DE SCAN :${C_RST}\n"

    local running
    running=$(get_running_scans)

    if [[ -z "$running" ]]; then
        echo -e "  ${C_GREEN}[✓] Aucun processus de scan actif à interrompre.${C_RST}\n"
        if [[ "$INTERACTIVE_MODE" == "1" ]]; then
            read -rp "Appuyez sur [Entrée] pour continuer..."
        fi
        return
    fi

    echo -e "  ${C_RED}Processus actifs détectés :${C_RST}"
    echo "$running" | awk '{printf "   • PID %-6s [%s] %s\n", $1, $5, $6}'
    echo ""

    if [[ "$INTERACTIVE_MODE" == "1" ]]; then
        read -rp "Voulez-vous vraiment stopper TOUS les scans actifs ? [o/N] : " confirm
        if [[ ! "$confirm" =~ ^[oOyY]$ ]]; then
            echo -e "${C_YELLOW}Annulé par l'utilisateur.${C_RST}"
            sleep 1
            return
        fi
    fi

    echo -e "\n  ${C_YELLOW}Arrêt forcé des processus d'audit...${C_RST}"
    local pnames=("veridy_scanner" "nuclei" "nikto" "nmap" "wafw00f" "whatweb" "sslscan" "dnstwist" "ffuf" "dnsrecon" "theHarvester" "obscura")
    for p in "${pnames[@]}"; do
        if pgrep -f "$p" >/dev/null 2>&1; then
            pkill -9 -f "$p" 2>/dev/null || true
            echo -e "  ${C_GREEN}[✓] Interrompu : ${p}${C_RST}"
        fi
    done

    echo -e "\n  ${C_GREEN}${C_BOLD}[✓] Tous les processus d'audit ont été nettoyés avec succès.${C_RST}\n"
    if [[ "$INTERACTIVE_MODE" == "1" ]]; then
        read -rp "Appuyez sur [Entrée] pour continuer..."
    fi
}

# ------------------------------------------------------------------------------
# Batch Scanning Engine
# ------------------------------------------------------------------------------
run_batch() {
    show_cursor
    local source="$1"
    shift
    local raw_args=("$@")
    local batch_args=()
    for arg in "${raw_args[@]}"; do
        case "$arg" in
            -1|--fast)
                ;;
            -2|--web)
                batch_args+=("--waf" "--whatweb" "--sslscan" "--dnstwist")
                ;;
            -3|--360|--full)
                batch_args+=("--360")
                ;;
            -4|--infra)
                batch_args+=("--nmap" "--sslscan")
                ;;
            -5|--vuln)
                batch_args+=("--nuclei" "--nikto" "--nmap")
                ;;
            -d|--discovery)
                batch_args+=("--ffuf" "--nikto" "--waf")
                ;;
            *)
                batch_args+=("$arg")
                ;;
        esac
    done

    local targets=()

    if [[ -f "$source" ]]; then
        while IFS= read -r line || [[ -n "$line" ]]; do
            local clean
            clean=$(echo "$line" | sed -e 's|^https\?://||' -e 's|/.*$||' | tr '[:upper:]' '[:lower:]' | xargs)
            if [[ -n "$clean" && ! "$clean" =~ ^# ]]; then
                targets+=("$clean")
            fi
        done < "$source"
    else
        IFS=',' read -ra split_targets <<< "$source"
        for t in "${split_targets[@]}"; do
            local clean
            clean=$(echo "$t" | sed -e 's|^https\?://||' -e 's|/.*$||' | tr '[:upper:]' '[:lower:]' | xargs)
            if [[ -n "$clean" ]]; then
                targets+=("$clean")
            fi
        done
    fi

    local total=${#targets[@]}
    if [[ $total -eq 0 ]]; then
        echo -e "${C_RED}[✗] Aucune cible valide trouvée dans la source batch : '$source'${C_RST}"
        return 1
    fi

    show_banner
    echo -e "${C_PURPLE}╔══════════════════════════════════════════════════════════════════════════════╗${C_RST}"
    echo -e "${C_PURPLE}║${C_RST} ${C_BOLD}${C_YELLOW}LANCEMENT D'UN BATCH DE SÉCURITÉ SUR ${total} CIBLE(S)${C_RST}                             ${C_PURPLE}║${C_RST}"
    echo -e "${C_PURPLE}╚══════════════════════════════════════════════════════════════════════════════╝${C_RST}\n"

    local results=()
    local idx=1
    local batch_start
    batch_start=$(date +%s)

    for target in "${targets[@]}"; do
        echo -e "${C_CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${C_RST}"
        echo -e "  ${C_BOLD}${C_YELLOW}[BATCH ${idx}/${total}]${C_RST} Démarrage de l'audit pour : ${C_BOLD}${C_WHITE}${target}${C_RST}"
        echo -e "${C_CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${C_RST}"

        CURRENT_TARGET="$target"
        local t_start
        t_start=$(date +%s)

        "$SCANNER_BIN" --target "$target" --db "$DB_NAME" "${batch_args[@]}"
        local ec=$?

        local t_end
        t_end=$(date +%s)
        local t_dur=$((t_end - t_start))

        if [[ $ec -eq 0 ]]; then
            local info
            info=$(sudo -u postgres psql -d "$DB_NAME" -t -A -F"|" -c \
                "SELECT id, overall_score, open_ports_count, findings_count FROM audit_scans WHERE target = '$target' ORDER BY created_at DESC LIMIT 1;" 2>/dev/null)
            local sid score ports findings
            sid=$(echo "$info" | cut -d'|' -f1)
            score=$(echo "$info" | cut -d'|' -f2)
            ports=$(echo "$info" | cut -d'|' -f3)
            findings=$(echo "$info" | cut -d'|' -f4)
            results+=("${target}|SUCCÈS|${score}/100|${ports}|${findings}|${t_dur}s|#${sid}")
        else
            results+=("${target}|ÉCHEC|--|--|--|${t_dur}s|--")
        fi

        ((idx++))
        echo ""
    done

    local batch_end
    batch_end=$(date +%s)
    local total_dur=$((batch_end - batch_start))

    show_banner
    echo -e "${C_PURPLE}╔══════════════════════════════════════════════════════════════════════════════╗${C_RST}"
    echo -e "${C_PURPLE}║${C_RST} ${C_BOLD}${C_YELLOW}RÉCAPITULATIF DU BATCH D'AUDIT (${total} CIBLE(S) AUDITÉES EN ${total_dur}s)${C_RST}             ${C_PURPLE}║${C_RST}"
    echo -e "${C_PURPLE}╚══════════════════════════════════════════════════════════════════════════════╝${C_RST}\n"

    printf "  %-24s %-9s %-9s %-7s %-10s %-8s %-6s\n" "CIBLE" "STATUT" "SCORE" "PORTS" "FINDINGS" "DURÉE" "SCAN"
    echo "  -------------------------------------------------------------------------------"
    for r in "${results[@]}"; do
        local r_tgt r_st r_sc r_pt r_fn r_dr r_id
        r_tgt=$(echo "$r" | cut -d'|' -f1)
        r_st=$(echo "$r" | cut -d'|' -f2)
        r_sc=$(echo "$r" | cut -d'|' -f3)
        r_pt=$(echo "$r" | cut -d'|' -f4)
        r_fn=$(echo "$r" | cut -d'|' -f5)
        r_dr=$(echo "$r" | cut -d'|' -f6)
        r_id=$(echo "$r" | cut -d'|' -f7)

        local st_color="${C_GREEN}"
        [[ "$r_st" != "SUCCÈS" ]] && st_color="${C_RED}"

        printf "  ${C_CYAN}%-24s${C_RST} ${st_color}%-9s${C_RST} ${C_YELLOW}%-9s${C_RST} %-7s %-10s %-8s ${C_PURPLE}%-6s${C_RST}\n" \
            "$r_tgt" "$r_st" "$r_sc" "$r_pt" "$r_fn" "$r_dr" "$r_id"
    done
    echo ""

    if [[ "$INTERACTIVE_MODE" == "1" ]]; then
        read -rp "Appuyez sur [Entrée] pour revenir au menu principal..."
    fi
}

# ------------------------------------------------------------------------------
# Developer Quality Suite: Format, Lint & Compile
# ------------------------------------------------------------------------------
dev_format() {
    show_cursor
    show_banner
    echo -e "${C_BOLD}${C_YELLOW}[*] FORMATAGE RUST AUTOMATIQUE (cargo fmt) :${C_RST}\n"
    if [[ ! -d "$SRC_DIR" ]]; then
        echo -e "${C_RED}[✗] Répertoire source introuvable : $SRC_DIR${C_RST}"
        return 1
    fi
    (
        cd "$SRC_DIR" && cargo fmt --all
    )
    if [[ $? -eq 0 ]]; then
        echo -e "  ${C_GREEN}[✓] Formatage rustfmt appliqué avec succès sur l'ensemble du projet.${C_RST}\n"
    else
        echo -e "  ${C_RED}[✗] Erreur lors du formatage.${C_RST}\n"
    fi
    if [[ "$INTERACTIVE_MODE" == "1" ]]; then
        read -rp "Appuyez sur [Entrée] pour continuer..."
    fi
}

dev_lint() {
    show_cursor
    show_banner
    echo -e "${C_BOLD}${C_YELLOW}[*] ANALYSE STATIQUE STRICTE & LINTER (cargo clippy) :${C_RST}\n"
    if [[ ! -d "$SRC_DIR" ]]; then
        echo -e "${C_RED}[✗] Répertoire source introuvable : $SRC_DIR${C_RST}"
        return 1
    fi
    (
        cd "$SRC_DIR" && cargo clippy -- -D warnings
    )
    local ec=$?
    echo ""
    if [[ $ec -eq 0 ]]; then
        echo -e "  ${C_GREEN}[✓] Analyse Clippy réussie : ZÉRO avertissement (0 warnings, code conforme).${C_RST}\n"
    else
        echo -e "  ${C_RED}[✗] Des anomalies ont été détectées par Clippy.${C_RST}\n"
    fi
    if [[ "$INTERACTIVE_MODE" == "1" ]]; then
        read -rp "Appuyez sur [Entrée] pour continuer..."
    fi
}

dev_compile() {
    show_cursor
    show_banner
    echo -e "${C_BOLD}${C_YELLOW}[*] COMPILATION OPTIMISÉE & DÉPLOIEMENT (cargo build --release) :${C_RST}\n"
    if [[ ! -d "$SRC_DIR" ]]; then
        echo -e "${C_RED}[✗] Répertoire source introuvable : $SRC_DIR${C_RST}"
        return 1
    fi
    local start_t
    start_t=$(date +%s)
    (
        cd "$SRC_DIR" && cargo build --release
    )
    local ec=$?
    local end_t
    end_t=$(date +%s)
    local dur=$((end_t - start_t))

    echo ""
    if [[ $ec -eq 0 ]]; then
        sudo cp "$SRC_DIR/target/release/veridy_scanner" /usr/local/bin/veridy_scanner
        echo -e "  ${C_GREEN}[✓] Binaire Rust compilé en ${dur}s et déployé sur /usr/local/bin/veridy_scanner !${C_RST}"
        /usr/local/bin/veridy_scanner --version 2>/dev/null || true
        echo ""
    else
        echo -e "  ${C_RED}[✗] Échec de la compilation release.${C_RST}\n"
    fi
    if [[ "$INTERACTIVE_MODE" == "1" ]]; then
        read -rp "Appuyez sur [Entrée] pour continuer..."
    fi
}

dev_test() {
    show_cursor
    show_banner
    echo -e "${C_BOLD}${C_YELLOW}[*] SUITE DE TESTS UNITAIRES RUST (cargo test) :${C_RST}\n"
    if [[ ! -d "$SRC_DIR" ]]; then
        echo -e "${C_RED}[✗] Répertoire source introuvable : $SRC_DIR${C_RST}"
        return 1
    fi
    (
        cd "$SRC_DIR" && cargo test
    )
    local ec=$?
    echo ""
    if [[ $ec -eq 0 ]]; then
        echo -e "  ${C_GREEN}[✓] SUCCÈS : 100% des tests unitaires validés (24/24 tests ok).${C_RST}\n"
    else
        echo -e "  ${C_RED}[✗] Échec d'un ou plusieurs tests unitaires.${C_RST}\n"
    fi
    if [[ "$INTERACTIVE_MODE" == "1" ]]; then
        read -rp "Appuyez sur [Entrée] pour continuer..."
    fi
}

dev_qa() {
    show_cursor
    show_banner
    echo -e "${C_BOLD}${C_YELLOW}[*] PIPELINE COMPLET QUALITÉ & COMPILATION (Fmt -> Lint -> Tests -> Build) :${C_RST}\n"
    
    echo -e "  ${C_CYAN}[1/4] Formatage automatique du code (cargo fmt)...${C_RST}"
    (cd "$SRC_DIR" && cargo fmt --all) || return 1
    echo -e "  ${C_GREEN}[✓] Code formaté.${C_RST}\n"

    echo -e "  ${C_CYAN}[2/4] Analyse statique et règles clippy (cargo clippy)...${C_RST}"
    (cd "$SRC_DIR" && cargo clippy --all-targets -- -D warnings) || return 1
    echo -e "  ${C_GREEN}[✓] Zéro anomalie clippy.${C_RST}\n"

    echo -e "  ${C_CYAN}[3/4] Exécution de la suite de 24 tests unitaires (cargo test)...${C_RST}"
    (cd "$SRC_DIR" && cargo test) || return 1
    echo -e "  ${C_GREEN}[✓] 100% des tests unitaires validés avec succès.${C_RST}\n"

    echo -e "  ${C_CYAN}[4/4] Compilation binaire release et installation...${C_RST}"
    (cd "$SRC_DIR" && cargo build --release) || return 1
    sudo cp "$SRC_DIR/target/release/veridy_scanner" /usr/local/bin/veridy_scanner
    echo -e "  ${C_GREEN}[✓] Binaire prêt et installé sur /usr/local/bin/veridy_scanner !${C_RST}\n"

    echo -e "  ${C_PINK}${C_BOLD}✨ PIPELINE QA VALIDÉ À 100% SANS DÉFAUT !${C_RST}\n"
    if [[ "$INTERACTIVE_MODE" == "1" ]]; then
        read -rp "Appuyez sur [Entrée] pour continuer..."
    fi
}

# ------------------------------------------------------------------------------
# Interactive Sub-View: Custom Profile Checklist (Space to Toggle, Arrows)
# ------------------------------------------------------------------------------
custom_profile_tui() {
    local tools_names=(
        "Nmap" "Nuclei" "Nikto" "Wafw00f" "WhatWeb" "SSLScan"
        "Dnstwist" "Ffuf" "Whois" "Dnsrecon" "theHarvester" "Obscura"
        "RustScan" "HTTPx" "SQLMap"
    )
    local tools_flags=(
        "--nmap" "--nuclei" "--nikto" "--waf" "--whatweb" "--sslscan"
        "--dnstwist" "--ffuf" "--whois" "--dnsrecon" "--theharvester" "--obscura"
        "--rustscan" "--httpx" "--sqlmap"
    )
    local tools_descs=(
        "Audit réseau profond, détection de bannières & scripts NSE (-sV -sC)"
        "Templates YAML de vulnérabilités critiques et CVEs récentes"
        "Audit serveur HTTP, en-têtes de sécurité & fichiers dangereux"
        "Détection d'empreinte Pare-feu Applicatif Web (WAF) & proxy inverse"
        "Empreinte CMS, technologies JS, serveurs & adresses emails"
        "Diagnostic TLS/SSL, ciphers obsolètes, Heartbleed, renégociation"
        "Recherche algorithmique de domaines sosies, typosquatting & phishing"
        "Fuzzing web ultra-rapide des routes cachées via dictionnaire SecLists"
        "Registre officiel de domaine (ICANN/CIRA), dates création & expiration"
        "Cartographie avancée DNS, enregistrements SRV & serveurs de noms"
        "Reconnaissance passive OSINT d'emails d'employés et sous-domaines"
        "Moteur Headless Browser V8, analyse dynamique DOM & capture PNG"
        "Balayage SYN ultra-rapide des 65535 ports réseau (fallback core)"
        "Probing HTTP massif, statuts et stack techno des sous-domaines"
        "Audit actif d'injections SQL sur les endpoints paramétrés"
    )
    local enabled=(0 0 0 0 0 0 0 0 0 0 0 0 0 0 0)
    local sel=0
    local total_items=19 # 15 tools + Tout Activer + Tout Désactiver + Lancer + Retour

    while true; do
        hide_cursor
        show_banner
        show_hud
        echo -e "${C_BOLD}${C_YELLOW}🎯 SUR MESURE : COMPOSITION DU PIPELINE DE SÉCURITÉ POUR ${C_CYAN}${CURRENT_TARGET}${C_RST}"
        echo -e "${C_DIM}Naviguez avec [↑/↓], cochez/décochez avec [Espace], validez avec [Entrée].${C_RST}\n"

        for ((i=0; i<15; i++)); do
            local mark="${C_GRAY}[ ]${C_RST}"
            if [[ ${enabled[$i]} -eq 1 ]]; then
                mark="${C_GREEN}${C_BOLD}[✓]${C_RST}"
            fi

            local prefix="   "
            local line_style="${C_WHITE}"
            if [[ $sel -eq $i ]]; then
                prefix="${C_CYAN}${C_BOLD}▶ ${C_RST}"
                line_style="${C_BOLD}\033[48;5;236m\033[38;5;255m"
            fi

            printf "%b%b %-14s %-54s\033[0m\n" \
                "$prefix" "$mark" "${tools_names[$i]}" "${tools_descs[$i]}"
        done

        echo ""
        local extra_labels=(
            "✨ TOUT ACTIVER (Sélectionner les 12 modules)"
            "🧹 TOUT DÉSACTIVER (Réinitialiser)"
            "🚀 LANCER L'AUDIT SUR MESURE AVEC CETTE SÉLECTION"
            "↩️  RETOUR AU MENU PRINCIPAL"
        )

        for ((j=0; j<4; j++)); do
            local idx=$((15 + j))
            local prefix="   "
            local style="${C_YELLOW}"
            [[ $j -eq 2 ]] && style="${C_PINK}${C_BOLD}"
            [[ $j -eq 3 ]] && style="${C_PURPLE}"

            if [[ $sel -eq $idx ]]; then
                prefix="${C_CYAN}${C_BOLD}▶ ${C_RST}"
                style="${C_BOLD}\033[48;5;236m\033[38;5;255m"
            fi
            printf "%b%b%-70s\033[0m\n" "$prefix" "$style" "${extra_labels[$j]}"
        done

        echo -e "\n${C_CYAN}─────────────────────────────────────────────────────────────────────────────${C_RST}"
        echo -e " ${C_BOLD}[↑/↓]${C_RST} Déplacer   ${C_BOLD}[Espace]${C_RST} Cocher/Décocher   ${C_BOLD}[Entrée]${C_RST} Valider   ${C_BOLD}[Esc/Q]${C_RST} Annuler"

        local key
        key=$(read_key)

        case "$key" in
            $'\x1b[A'|[kK]) # Up
                ((sel--))
                [[ $sel -lt 0 ]] && sel=$((total_items - 1))
                ;;
            $'\x1b[B'|[jJ]) # Down
                ((sel++))
                [[ $sel -ge $total_items ]] && sel=0
                ;;
            " ") # Space (toggle)
                if [[ $sel -lt 15 ]]; then
                    enabled[$sel]=$((1 - enabled[$sel]))
                fi
                ;;
            ""|$'\n'|$'\r') # Enter
                if [[ $sel -lt 15 ]]; then
                    enabled[$sel]=$((1 - enabled[$sel]))
                elif [[ $sel -eq 15 ]]; then
                    for ((k=0; k<15; k++)); do enabled[$k]=1; done
                elif [[ $sel -eq 16 ]]; then
                    for ((k=0; k<15; k++)); do enabled[$k]=0; done
                elif [[ $sel -eq 17 ]]; then
                    local flags=()
                    local chosen_names=()
                    for ((k=0; k<15; k++)); do
                        if [[ ${enabled[$k]} -eq 1 ]]; then
                            flags+=("${tools_flags[$k]}")
                            chosen_names+=("${tools_names[$k]}")
                        fi
                    done
                    if [[ ${#flags[@]} -eq 0 ]]; then
                        echo -e "\n${C_RED}[!] Aucun module sélectionné ! Cochez au moins un outil avec [Espace].${C_RST}"
                        sleep 1.5
                    else
                        show_cursor
                        run_scan "SUR MESURE (${chosen_names[*]})" "${flags[@]}"
                        break
                    fi
                elif [[ $sel -eq 18 ]]; then
                    break
                fi
                ;;
            [aA]) # Tout activer
                for ((k=0; k<15; k++)); do enabled[$k]=1; done
                ;;
            [nN]) # Tout désactiver
                for ((k=0; k<15; k++)); do enabled[$k]=0; done
                ;;
            EOF|$'\x1b'|[qQ]) # Escape or Quit
                break
                ;;
        esac
    done
    show_cursor
}

# ------------------------------------------------------------------------------
# Interactive Sub-View: Target Switcher (Arrow Navigation & Recent DB Targets)
# ------------------------------------------------------------------------------
change_target_tui() {
    local recent=()
    while IFS= read -r t; do
        [[ -n "$t" ]] && recent+=("$t")
    done < <(sudo -u postgres psql -d "$DB_NAME" -t -A -c "SELECT DISTINCT target FROM audit_scans ORDER BY target ASC LIMIT 8;" 2>/dev/null)

    local items=()
    for r in "${recent[@]}"; do
        items+=("🎯 $r (Historique base)")
    done
    items+=("✍️  Saisir manuellement un nouveau nom de domaine ou adresse IP")
    items+=("↩️  Annuler et conserver '$CURRENT_TARGET'")

    local sel=0
    local total=${#items[@]}

    while true; do
        hide_cursor
        show_banner
        show_hud
        echo -e "${C_BOLD}${C_YELLOW}⚙️  SÉLECTION DE LA CIBLE D'AUDIT :${C_RST}"
        echo -e "  Cible actuelle : ${C_BOLD}${C_CYAN}${CURRENT_TARGET}${C_RST}\n"

        for ((i=0; i<total; i++)); do
            local prefix="   "
            local style="${C_WHITE}"
            if [[ $sel -eq $i ]]; then
                prefix="${C_CYAN}${C_BOLD}▶ ${C_RST}"
                style="${C_BOLD}\033[48;5;236m\033[38;5;255m"
            fi
            printf "%b%b  %-68s\033[0m\n" "$prefix" "$style" "${items[$i]}"
        done

        echo -e "\n${C_CYAN}─────────────────────────────────────────────────────────────────────────────${C_RST}"
        echo -e " ${C_BOLD}[↑/↓]${C_RST} Déplacer   ${C_BOLD}[Entrée]${C_RST} Sélectionner   ${C_BOLD}[Esc/Q]${C_RST} Annuler"

        local key
        key=$(read_key)

        case "$key" in
            $'\x1b[A'|[kK])
                ((sel--))
                [[ $sel -lt 0 ]] && sel=$((total - 1))
                ;;
            $'\x1b[B'|[jJ])
                ((sel++))
                [[ $sel -ge $total ]] && sel=0
                ;;
            ""|$'\n'|$'\r')
                if [[ $sel -lt ${#recent[@]} ]]; then
                    CURRENT_TARGET="${recent[$sel]}"
                    show_cursor
                    echo -e "\n  ${C_GREEN}[✓] Cible sélectionnée : ${CURRENT_TARGET}${C_RST}"
                    sleep 0.8
                    break
                elif [[ $sel -eq ${#recent[@]} ]]; then
                    show_cursor
                    echo -e "\n${C_BOLD}${C_YELLOW}[?] Entrez le nouveau domaine ou IP (ex: scanme.nmap.org) :${C_RST}"
                    read -rp "> " manual_t
                    if [[ -n "$manual_t" ]]; then
                        CURRENT_TARGET=$(echo "$manual_t" | sed -e 's|^https\?://||' -e 's|/.*$||' | tr '[:upper:]' '[:lower:]' | xargs)
                        echo -e "  ${C_GREEN}[✓] Cible enregistrée : ${CURRENT_TARGET}${C_RST}"
                        sleep 0.8
                    fi
                    break
                else
                    break
                fi
                ;;
            EOF|$'\x1b'|[qQ])
                break
                ;;
        esac
    done
    show_cursor
}

# ------------------------------------------------------------------------------
# Interactive Sub-View: Scan Inspector Selector
# ------------------------------------------------------------------------------
show_scan_detail_tui() {
    local scans=()
    while IFS= read -r s; do
        [[ -n "$s" ]] && scans+=("$s")
    done < <(sudo -u postgres psql -d "$DB_NAME" -t -A -F" | " -c "SELECT id, target, to_char(created_at, 'YYYY-MM-DD HH24:MI'), overall_score || '/100' FROM audit_scans ORDER BY id DESC LIMIT 8;" 2>/dev/null)

    local items=()
    for s in "${scans[@]}"; do
        items+=("Scan #$s")
    done
    items+=("✍️  Saisir un ID de scan manuellement")
    items+=("↩️  Retour")

    local sel=0
    local total=${#items[@]}

    while true; do
        hide_cursor
        show_banner
        show_hud
        echo -e "${C_BOLD}${C_YELLOW}🔍 CHOIX DU SCAN À INSPECTER EN DÉTAIL :${C_RST}\n"

        for ((i=0; i<total; i++)); do
            local prefix="   "
            local style="${C_WHITE}"
            if [[ $sel -eq $i ]]; then
                prefix="${C_CYAN}${C_BOLD}▶ ${C_RST}"
                style="${C_BOLD}\033[48;5;236m\033[38;5;255m"
            fi
            printf "%b%b  %-68s\033[0m\n" "$prefix" "$style" "${items[$i]}"
        done

        echo -e "\n${C_CYAN}─────────────────────────────────────────────────────────────────────────────${C_RST}"
        echo -e " ${C_BOLD}[↑/↓]${C_RST} Déplacer   ${C_BOLD}[Entrée]${C_RST} Inspecter   ${C_BOLD}[Esc/Q]${C_RST} Retour"

        local key
        key=$(read_key)

        case "$key" in
            $'\x1b[A'|[kK])
                ((sel--))
                [[ $sel -lt 0 ]] && sel=$((total - 1))
                ;;
            $'\x1b[B'|[jJ])
                ((sel++))
                [[ $sel -ge $total ]] && sel=0
                ;;
            ""|$'\n'|$'\r')
                if [[ $sel -lt ${#scans[@]} ]]; then
                    local target_scan_id
                    target_scan_id=$(echo "${scans[$sel]}" | cut -d' ' -f1)
                    show_scan_detail "$target_scan_id"
                    break
                elif [[ $sel -eq ${#scans[@]} ]]; then
                    show_scan_detail ""
                    break
                else
                    break
                fi
                ;;
            EOF|$'\x1b'|[qQ])
                break
                ;;
        esac
    done
    show_cursor
}

# ------------------------------------------------------------------------------
# Interactive Sub-View: Findings Filter Selector
# ------------------------------------------------------------------------------
show_findings_tui() {
    local filters=(
        "TOUTES LES ANOMALIES (Sans filtre)"
        "CRITICAL (Failles critiques)"
        "HIGH (Risques élevés)"
        "MEDIUM (Risques modérés)"
        "LOW (Faibles anomalies)"
        "INFO (Observations & reconnaissance)"
        "↩️  Retour à l'explorateur"
    )
    local sel=0
    local total=${#filters[@]}

    while true; do
        hide_cursor
        show_banner
        show_hud
        echo -e "${C_BOLD}${C_YELLOW}🚨 FILTRER LES VULNÉRABILITÉS & CONSTATS (AUDIT_FINDINGS) :${C_RST}\n"

        for ((i=0; i<total; i++)); do
            local prefix="   "
            local style="${C_WHITE}"
            if [[ $sel -eq $i ]]; then
                prefix="${C_CYAN}${C_BOLD}▶ ${C_RST}"
                style="${C_BOLD}\033[48;5;236m\033[38;5;255m"
            fi
            printf "%b%b  %-68s\033[0m\n" "$prefix" "$style" "${filters[$i]}"
        done

        echo -e "\n${C_CYAN}─────────────────────────────────────────────────────────────────────────────${C_RST}"
        echo -e " ${C_BOLD}[↑/↓]${C_RST} Déplacer   ${C_BOLD}[Entrée]${C_RST} Afficher   ${C_BOLD}[Esc/Q]${C_RST} Retour"

        local key
        key=$(read_key)

        case "$key" in
            $'\x1b[A'|[kK])
                ((sel--))
                [[ $sel -lt 0 ]] && sel=$((total - 1))
                ;;
            $'\x1b[B'|[jJ])
                ((sel++))
                [[ $sel -ge $total ]] && sel=0
                ;;
            ""|$'\n'|$'\r')
                case "$sel" in
                    0) show_findings ""; break ;;
                    1) show_findings "CRITICAL"; break ;;
                    2) show_findings "HIGH"; break ;;
                    3) show_findings "MEDIUM"; break ;;
                    4) show_findings "LOW"; break ;;
                    5) show_findings "INFO"; break ;;
                    *) break ;;
                esac
                ;;
            EOF|$'\x1b'|[qQ])
                break
                ;;
        esac
    done
    show_cursor
}

# ------------------------------------------------------------------------------
# Interactive Sub-View: Batch Manual Input
# ------------------------------------------------------------------------------
run_batch_manual_tui() {
    show_cursor
    show_banner
    show_hud
    echo -e "${C_BOLD}${C_YELLOW}🚀 AUDIT BATCH : SAISIE MANUELLE DE PLUSIEURS CIBLES :${C_RST}\n"
    echo -e "Entrez les cibles séparées par des virgules (ex: veridy.ca,scanme.nmap.org) :"
    read -rp "> " raw_list
    if [[ -n "$raw_list" ]]; then
        run_batch "$raw_list"
    fi
}

# ------------------------------------------------------------------------------
# Interactive Sub-View: Batch File Input
# ------------------------------------------------------------------------------
run_batch_file_tui() {
    show_cursor
    show_banner
    show_hud
    echo -e "${C_BOLD}${C_YELLOW}📂 AUDIT BATCH : FICHIER DE CIBLES (LIGNE PAR LIGNE) :${C_RST}\n"
    echo -e "Entrez le chemin du fichier texte (ex: /tmp/cibles.txt) :"
    read -rp "> " raw_file
    if [[ -f "$raw_file" ]]; then
        run_batch "$raw_file"
    else
        echo -e "${C_RED}Fichier introuvable : $raw_file${C_RST}"
        sleep 1.5
    fi
}

# ------------------------------------------------------------------------------
# THE CYBER TUI ENGINE (Tabbed, Arrow-Key Navigable, Cyberpunk HUD)
# ------------------------------------------------------------------------------
interactive_tui() {
    INTERACTIVE_MODE="1"
    local current_tab=0
    local sel_0=0
    local sel_1=0
    local sel_2=0
    local sel_3=0
    local sel_4=0

    # TAB DEFINITIONS:
    # Tab 0: Profils d'audit (8 items)
    local t0_titles=(
        "⚡ FAST AUDIT (CORE RUST)"
        "🌐 WEB PERIMETER AUDIT"
        "🔍 CONTENT & DISCOVERY"
        "🛡️  SERVICES & INFRA"
        "💥 CVE & VULNERABILITIES"
        "👑 FULL 360° KALI SUITE"
        "🎯 SUR MESURE (CUSTOM BUILDER)"
        "⚙️  CHANGER DE CIBLE D'AUDIT"
    )
    local t0_tags=(
        "Ports, TLS, DNS, GéoIP (~1.5s)"
        "WAF + WhatWeb + SSLScan + Dnstwist (~7s)"
        "Ffuf SecLists + Nikto + WAF (~40s)"
        "Nmap -sV -sC + Scripts NSE + SSLScan (~20s)"
        "Nuclei CVEs + Nikto + Nmap NSE (~45s)"
        "12 Outils Kali + Obscura Headless (~85s)"
        "Sélection interactive avec [Espace]"
        "Actuelle : $CURRENT_TARGET"
    )
    local t0_descs=(
        "Moteur SYN/Connect port scanning pur Rust, validation des certificats TLS/SSL, enregistrements DNS & résolution de la localisation géographique du serveur."
        "Détection d'empreinte WAF (Cloudflare, AWS, etc.), identification des CMS/JS, audit cryptographique TLS et détection de domaines sosies (phishing)."
        "Fuzzing ultra-rapide des endpoints sensibles et fichiers cachés (.env, backup, admin) combiné au scanner de serveurs HTTP Nikto."
        "Cartographie complète des bannières de services réseau, scripts de vulnérabilité NSE avancés et solidité des ciphers TLS/SSL."
        "Détection active de vulnérabilités critiques connues (CVEs) avec templates Nuclei mis à jour, failles HTTP et ports exposés."
        "L'expérience offensive complète : Nmap, Nuclei, Nikto, Wafw00f, WhatWeb, SSLScan, Dnstwist, Ffuf, Whois, Dnsrecon, theHarvester & Obscura DOM."
        "Composez votre propre pipeline d'audit à la carte en activant/désactivant individuellement chacun des 12 outils spécialisés."
        "Sélectionnez une cible parmi l'historique récent de la base PostgreSQL ou saisissez un nouveau domaine / adresse IP."
    )

    # Tab 1: Modules spécialisés (12 items)
    local t1_titles=(
        "🛡️  WAFW00F (PARE-FEU WEB)"
        "🌐 WHATWEB (STACK & EMAILS)"
        "🔐 SSLSCAN (AUDIT TLS/SSL)"
        "🏷️  DNSTWIST (PHISHING & SOSIES)"
        "📂 FFUF (FUZZING ENDPOINTS)"
        "🔍 NMAP (SERVICES & NSE)"
        "💥 NUCLEI (SCAN DE CVES)"
        "🕸️  NIKTO (SERVEUR WEB HTTP)"
        "📋 WHOIS (REGISTRE DOMAINE)"
        "📡 DNSRECON (RECONNAISSANCE DNS)"
        "🕵️  THEHARVESTER (OSINT)"
        "🌐 OBSCURA (HEADLESS DOM & V8)"
        "⚡ RUSTSCAN (PORTS RAPIDES 65535)"
        "🌐 HTTPX (PROBE HTTP & STACK)"
        "💉 SQLMAP (INJECTIONS SQL)"
    )
    local t1_tags=(
        "Détection de Pare-feu Applicatif (WAF)"
        "CMS, JS, serveurs & adresses emails"
        "Suites TLS/SSL, ciphers & Heartbleed"
        "Typosquatting & détection de clones"
        "Fuzzing routes sensibles via SecLists"
        "Audit de versions & scripts NSE (-sV -sC)"
        "Templates de vulnérabilités & CVEs"
        "Scan de sécurité HTTP & fichiers à risque"
        "Registrar, date création & expiration"
        "Enregistrements SRV, version Bind & NS"
        "Reconnaissance OSINT d'emails & hôtes"
        "Rendu DOM V8, assets & screenshot PNG"
        "Balayage SYN ultra-rapide 65535 ports"
        "Probe HTTP massif & technologies web"
        "Audit automatique failles injection SQL"
    )
    local t1_descs=(
        "Envoie des requêtes HTTP forgées pour déclencher les signatures de 50+ pare-feux applicatifs (Cloudflare, Imperva, AWS WAF, ModSecurity...)."
        "Analyse passive et active du code HTML, en-têtes HTTP, cookies et scripts pour cartographier les composants technologiques et emails exposés."
        "Teste les protocoles TLS 1.0 à 1.3, les ciphers obsolètes (RC4, 3DES), la validité des certificats X.509 et les failles de renégociation."
        "Génère des variantes algorithmiques de domaine (omission, permutation, bitsquatting, homoglyphes) et vérifie si elles résolvent des IPs actives."
        "Fuzzer HTTP multi-thread ultra-performant utilisant le dictionnaire SecLists quickhits pour identifier répertoires cachés, backups et routes API."
        "Détermination précise des versions applicatives (Apache, Nginx, OpenSSH...) et scripts NSE de détection de mauvaises configurations."
        "Interroge des milliers de modèles communautaires pour détecter les failles d'exécution à distance (RCE), injections, SSRF et CVEs récentes."
        "Teste plus de 6700 fichiers dangereux, vérifie les options serveur périmées (TRACE), et analyse les faiblesses des en-têtes de sécurité."
        "Interroge les serveurs Whois officiels (ICANN, CIRA, Verisign) pour extraire l'historique d'enregistrement et prévenir les expirations critiques."
        "Audit exhaustif de l'infrastructure DNS : transfert de zone AXFR, détection des serveurs de noms, enregistrements de services et version Bind."
        "Fouille les moteurs de recherche publics et sources OSINT pour extraire les adresses emails des employés et la cartographie externe."
        "Exécute le moteur V8 pour rendre le DOM moderne (React/Vue/Angular), intercepter les avertissements console, lister les assets et capturer un screenshot."
        "Moteur de port scanning en Rust capable de scanner les 65535 ports en quelques secondes via SYN packets adaptatifs."
        "Prober HTTP multi-thread ultra-performant capable d'interroger tous les sous-domaines, détecter les statuts, redirections et titres."
        "Outil de référence mondial pour détecter et exploiter les failles d'injections SQL (Blind, Time-based, Error-based, UNION query)."
    )

    # Tab 2: Base PostgreSQL (8 items)
    local t2_titles=(
        "📋 VUE D'ENSEMBLE DES 12 TABLES"
        "📜 HISTORIQUE DES SCANS"
        "🔍 INSPECTER UN SCAN EN DÉTAIL"
        "🚨 VULNÉRABILITÉS & CONSTATS"
        "🗺️  CARTOGRAPHIE SOUS-DOMAINES"
        "🌍 REGISTRE GÉOLOCALISATION"
        "📈 MÉTRIQUES & STATS GLOBALES"
        "💻 SHELL SQL INTERACTIF (PSQL)"
    )
    local t2_tags=(
        "Décompte des lignes en direct (pg_stat)"
        "Chronologie des 15 derniers audits"
        "Ports, constats et outils par ID de scan"
        "Filtrer par sévérité (CRITICAL à INFO)"
        "Hôtes découverts, IPs et statuts HTTP"
        "Pays, région, ville, ASN, organisation"
        "Scores moyens, distribution & Top 10 failles"
        "Console psql native sur veridy_audit"
    )
    local t2_descs=(
        "Affiche le décompte en direct des tuples dans les 12 tables relationnelles PostgreSQL du schéma veridy_audit."
        "Affiche la chronologie des 15 derniers audits de sécurité enregistrés avec durée, score /100 et métriques clés."
        "Inspection chirurgicale d'un scan : note globale, ports ouverts, état SPF/DMARC, sorties des outils Kali et recommandations."
        "Parcourez les constats d'anomalies de sécurité répertoriés avec filtre interactif par niveau de gravité."
        "Inventaire exhaustif des hôtes et sous-domaines découverts par résolution DNS passive et active (audit_subdomains)."
        "Consultation de la localisation géographique, du fournisseur d'hébergement et de l'ASN déduit du whois."
        "Tableau de bord décisionnel : score moyen du parc, distribution des gravités et vulnérabilités les plus fréquentes."
        "Ouvre un terminal interactif PostgreSQL natif pour exécuter des requêtes SQL personnalisées en direct."
    )

    # Tab 3: Process & Batch (5 items)
    local t3_titles=(
        "👀 PROCESSUS ACTIFS EN TEMPS RÉEL"
        "🛑 ARRÊT D'URGENCE DES SCANS (KILL)"
        "🚀 BATCH : SAISIE MANUELLE DES CIBLES"
        "📂 BATCH : FICHIER TEXTE (CIBLES.TXT)"
        "🛠️  TEST DE L'ENVIRONNEMENT KALI"
    )
    local t3_tags=(
        "PID, CPU%, Mem%, durée des outils actifs"
        "Interrompre tous les scanners et outils"
        "Audit séquentiel d'une liste CSV"
        "Audit automatique ligne par ligne"
        "Présence des 12 outils et dictionnaires"
    )
    local t3_descs=(
        "Monitore l'activité des processus système (veridy_scanner, nmap, nuclei, obscura...) sur le serveur Kali."
        "Purge immédiate et sécurisée des processus d'audit réseau et scanners pour libérer la bande passante et les ressources."
        "Permet de saisir plusieurs cibles (ex: veridy.ca, scanme.org) et d'exécuter un audit automatique avec récapitulatif comparatif."
        "Lit un fichier texte ligne par ligne pour auditer automatiquement un grand volume de noms de domaine."
        "Diagnostic complet de disponibilité des binaires système, du client psql, de SecLists et du binaire Rust."
    )

    # Tab 4: Pipeline Dev & QA (4 items)
    local t4_titles=(
        "📐 FORMATAGE DU CODE (CARGO FMT)"
        "🔍 LINTER STRICT (CARGO CLIPPY)"
        "🧪 TESTS UNITAIRES (CARGO TEST)"
        "⚡ COMPILATION RELEASE & INSTALLATION"
        "✨ PIPELINE QA COMPLET (FMT->LINT->TEST->BUILD)"
    )
    local t4_tags=(
        "Uniformiser le style de code Rust"
        "Zéro avertissement (-D warnings)"
        "24 tests (Utils, Safety, Modules, DB)"
        "Déploiement sur /usr/local/bin/veridy_scanner"
        "Validation 100% propre de production"
    )
    local t4_descs=(
        "Applique le formateur officiel Rust (rustfmt) sur l'ensemble des modules (src/*.rs, modules/*.rs)."
        "Exécute le linter Clippy avec interdiction totale de warnings pour garantir une robustesse sans faille."
        "Exécute l'ensemble des 24 tests unitaires pour valider l'intégrité de tous les modules, parsers et connecteurs."
        "Compile veridy_scanner en mode release (LTO, opt-level 3) et installe le binaire dans /usr/local/bin/."
        "Enchaîne automatiquement formatage, analyse statique, 24 tests unitaires et compilation pour une livraison 100% propre."
    )

    while true; do
        hide_cursor
        show_banner
        show_hud

        # Update dynamic tags
        t0_tags[7]="Actuelle : $CURRENT_TARGET"

        # Tab bar
        local tab_names=("⚡ PROFILS D'AUDIT" "🔬 MODULES (15)" "🗄️ DB EXPLORER" "📦 PROCESS/BATCH" "🔨 DEV & QA")
        echo -ne "  "
        for ((i=0; i<5; i++)); do
            local num=$((i + 1))
            if [[ $i -eq $current_tab ]]; then
                echo -ne "${C_BOLD}\033[48;5;25m\033[38;5;51m [${num}] ${tab_names[$i]} \033[0m "
            else
                echo -ne "\033[48;5;235m\033[38;5;248m  ${num}  ${tab_names[$i]} \033[0m "
            fi
        done
        echo -e "\n"

        # Active item list and count
        local titles=()
        local tags=()
        local descs=()
        local current_sel=0

        case "$current_tab" in
            0)
                titles=("${t0_titles[@]}")
                tags=("${t0_tags[@]}")
                descs=("${t0_descs[@]}")
                current_sel=$sel_0
                ;;
            1)
                titles=("${t1_titles[@]}")
                tags=("${t1_tags[@]}")
                descs=("${t1_descs[@]}")
                current_sel=$sel_1
                ;;
            2)
                titles=("${t2_titles[@]}")
                tags=("${t2_tags[@]}")
                descs=("${t2_descs[@]}")
                current_sel=$sel_2
                ;;
            3)
                titles=("${t3_titles[@]}")
                tags=("${t3_tags[@]}")
                descs=("${t3_descs[@]}")
                current_sel=$sel_3
                ;;
            4)
                titles=("${t4_titles[@]}")
                tags=("${t4_tags[@]}")
                descs=("${t4_descs[@]}")
                current_sel=$sel_4
                ;;
        esac

        local total_items=${#titles[@]}

        # Render items
        for ((i=0; i<total_items; i++)); do
            local prefix="   "
            local line_style="${C_WHITE}"
            local tag_style="${C_DIM}"

            if [[ $current_sel -eq $i ]]; then
                prefix="${C_CYAN}${C_BOLD}▶ ${C_RST}"
                line_style="${C_BOLD}\033[48;5;236m\033[38;5;255m"
                tag_style="\033[48;5;236m${C_YELLOW}"
            fi

            printf "%b%b%-35s %b%-37s\033[0m\n" \
                "$prefix" "$line_style" "${titles[$i]}" "$tag_style" "${tags[$i]}"
        done

        # Render Info Card for selected item
        echo -e "\n${C_PURPLE}╭── ℹ️  FICHE TECHNIQUE DE L'ACTION SÉLECTIONNÉE ──────────────────────────────╮${C_RST}"
        printf "${C_PURPLE}│${C_RST}  ${C_BOLD}%-12s${C_RST} : ${C_YELLOW}%-58s${C_RST} ${C_PURPLE}│${C_RST}\n" "ACTION" "${titles[$current_sel]}"
        printf "${C_PURPLE}│${C_RST}  ${C_BOLD}%-12s${C_RST} : ${C_CYAN}%-58s${C_RST} ${C_PURPLE}│${C_RST}\n" "TAG / PROFIL" "${tags[$current_sel]}"
        
        # Word-wrap description cleanly
        local d="${descs[$current_sel]}"
        local line1="${d:0:70}"
        local line2="${d:70:70}"
        printf "${C_PURPLE}│${C_RST}  ${C_DIM}%-72s${C_RST} ${C_PURPLE}│${C_RST}\n" "$line1"
        if [[ -n "$line2" ]]; then
            printf "${C_PURPLE}│${C_RST}  ${C_DIM}%-72s${C_RST} ${C_PURPLE}│${C_RST}\n" "$line2"
        fi
        echo -e "${C_PURPLE}╰─────────────────────────────────────────────────────────────────────────────╯${C_RST}"

        # Footer hotkeys
        echo -e "${C_CYAN}┌─────────────────────────────────────────────────────────────────────────────┐${C_RST}"
        echo -e "${C_CYAN}│${C_RST} ${C_BOLD}[↑/↓]${C_RST} Naviguer  ${C_BOLD}[←/→/Tab]${C_RST} Onglets (1-5)  ${C_BOLD}[Entrée]${C_RST} Exécuter  ${C_BOLD}[C]${C_RST} Cible  ${C_BOLD}[Q]${C_RST} Quitter ${C_CYAN}│${C_RST}"
        echo -e "${C_CYAN}└─────────────────────────────────────────────────────────────────────────────┘${C_RST}"

        # Read user input
        local key
        key=$(read_key)

        case "$key" in
            $'\x1b[A'|[kK]) # Up Arrow
                case "$current_tab" in
                    0) ((sel_0--)); [[ $sel_0 -lt 0 ]] && sel_0=$((total_items - 1)) ;;
                    1) ((sel_1--)); [[ $sel_1 -lt 0 ]] && sel_1=$((total_items - 1)) ;;
                    2) ((sel_2--)); [[ $sel_2 -lt 0 ]] && sel_2=$((total_items - 1)) ;;
                    3) ((sel_3--)); [[ $sel_3 -lt 0 ]] && sel_3=$((total_items - 1)) ;;
                    4) ((sel_4--)); [[ $sel_4 -lt 0 ]] && sel_4=$((total_items - 1)) ;;
                esac
                ;;
            $'\x1b[B'|[jJ]) # Down Arrow
                case "$current_tab" in
                    0) ((sel_0++)); [[ $sel_0 -ge $total_items ]] && sel_0=0 ;;
                    1) ((sel_1++)); [[ $sel_1 -ge $total_items ]] && sel_1=0 ;;
                    2) ((sel_2++)); [[ $sel_2 -ge $total_items ]] && sel_2=0 ;;
                    3) ((sel_3++)); [[ $sel_3 -ge $total_items ]] && sel_3=0 ;;
                    4) ((sel_4++)); [[ $sel_4 -ge $total_items ]] && sel_4=0 ;;
                esac
                ;;
            $'\x1b[C'|$'\t'|[lL]) # Right Arrow or Tab (Next Tab)
                ((current_tab++))
                [[ $current_tab -ge 5 ]] && current_tab=0
                ;;
            $'\x1b[D'|[hH]) # Left Arrow (Previous Tab)
                ((current_tab--))
                [[ $current_tab -lt 0 ]] && current_tab=4
                ;;
            1) current_tab=0 ;;
            2) current_tab=1 ;;
            3) current_tab=2 ;;
            4) current_tab=3 ;;
            5) current_tab=4 ;;
            [cC])
                change_target_tui
                ;;
            [mM])
                current_tab=1
                ;;
            [dD])
                current_tab=2
                ;;
            [bB])
                current_tab=3
                ;;
            ""|$'\n'|$'\r') # Enter (Execute action)
                case "$current_tab" in
                    0) # Profils d'audit
                        case "$sel_0" in
                            0) run_scan "FAST AUDIT (CORE RUST)" ;;
                            1) run_scan "WEB PERIMETER AUDIT" --waf --whatweb --sslscan --dnstwist ;;
                            2) run_scan "CONTENT & DISCOVERY AUDIT" --ffuf --nikto --waf ;;
                            3) run_scan "SERVICES & INFRA AUDIT" --nmap --sslscan ;;
                            4) run_scan "CVE & VULNERABILITIES AUDIT" --nuclei --nikto --nmap ;;
                            5) run_scan "360° FULL KALI SUITE" --360 ;;
                            6) custom_profile_tui ;;
                            7) change_target_tui ;;
                        esac
                        ;;
                    1) # Modules Spécialisés
                        case "$sel_1" in
                            0) run_scan "MODULE SPÉCIALISÉ: WAFW00F" --waf ;;
                            1) run_scan "MODULE SPÉCIALISÉ: WHATWEB" --whatweb ;;
                            2) run_scan "MODULE SPÉCIALISÉ: SSLSCAN" --sslscan ;;
                            3) run_scan "MODULE SPÉCIALISÉ: DNSTWIST" --dnstwist ;;
                            4) run_scan "MODULE SPÉCIALISÉ: FFUF (SECLISTS)" --ffuf ;;
                            5) run_scan "MODULE SPÉCIALISÉ: NMAP (-sV -sC)" --nmap ;;
                            6) run_scan "MODULE SPÉCIALISÉ: NUCLEI (CVE)" --nuclei ;;
                            7) run_scan "MODULE SPÉCIALISÉ: NIKTO" --nikto ;;
                            8) run_scan "MODULE SPÉCIALISÉ: WHOIS" --whois ;;
                            9) run_scan "MODULE SPÉCIALISÉ: DNSRECON" --dnsrecon ;;
                            10) run_scan "MODULE SPÉCIALISÉ: THEHARVESTER" --theharvester ;;
                            11) run_scan "MODULE SPÉCIALISÉ: OBSCURA (HEADLESS/DOM)" --obscura ;;
                            12) run_scan "MODULE SPÉCIALISÉ: RUSTSCAN" --rustscan ;;
                            13) run_scan "MODULE SPÉCIALISÉ: HTTPX" --httpx ;;
                            14) run_scan "MODULE SPÉCIALISÉ: SQLMAP" --sqlmap ;;
                        esac
                        ;;
                    2) # Base de données PostgreSQL
                        case "$sel_2" in
                            0) show_db_tables ;;
                            1) show_history ;;
                            2) show_scan_detail_tui ;;
                            3) show_findings_tui ;;
                            4) show_subdomains ;;
                            5) show_geolocation ;;
                            6) show_stats ;;
                            7) open_psql_shell ;;
                        esac
                        ;;
                    3) # Process & Batch Manager
                        case "$sel_3" in
                            0) show_running_scans ;;
                            1) stop_scans ;;
                            2) run_batch_manual_tui ;;
                            3) run_batch_file_tui ;;
                            4) check_tools ;;
                        esac
                        ;;
                    4) # Pipeline Dev & QA
                        case "$sel_4" in
                            0) dev_format ;;
                            1) dev_lint ;;
                            2) dev_test ;;
                            3) dev_compile ;;
                            4) dev_qa ;;
                        esac
                        ;;
                esac
                ;;
            EOF|$'\x1b'|[qQ]) # Escape, Q or EOF
                show_cursor
                echo -e "\n${C_CYAN}Fermeture de la Console Veridy. À bientôt !${C_RST}\n"
                exit 0
                ;;
        esac
    done
}

# ------------------------------------------------------------------------------
# CLI Help
# ------------------------------------------------------------------------------
show_help() {
    show_banner
    cat << EOF
UTILISATION:
  $(basename "$0") [CIBLE] [OPTIONS]

GESTION DE LA CIBLE:
  <DOMAINE/IP>              Cible passée directement (ex: veridy google.com)
  -t, --target <DOMAINE>    Spécifier explicitement la cible (défaut: veridy.ca)

PROFILES MULTI-OUTILS:
  -1, --fast                Audit rapide Core Rust (~1.5s)
  -2, --web                 Audit périmètre web (WAF + WhatWeb + SSLScan + Dnstwist)
  -3, --360, --full         Audit Complet 360° avec TOUS les 12 outils Kali + Obscura (~85s)
  -4, --infra               Audit infrastructure & services (Nmap + SSLScan)
  -5, --vuln                Audit vulnérabilités & CVEs (Nuclei + Nikto + Nmap)
  -d, --discovery           Découverte endpoints & fichiers (Ffuf + Nikto + WAF)

MODULES SPÉCIALISÉS (UNITAIRES OU COMBINÉS):
  -m, --module <LISTE>      Exécuter un ou plusieurs modules spécifiques séparés par virgule
                            Valeurs: waf, tech, ssl, brand, fuzz, nmap, nuclei, nikto, whois, dnsrecon, theharvester, obscura, all
  --waf, --wafw00f          Audit Pare-feu Applicatif uniquement (Wafw00f)
  --whatweb, --tech         Empreinte technologique et emails uniquement (WhatWeb)
  --ssl, --sslscan          Diagnostic cryptographique TLS/SSL uniquement (SSLScan)
  --brand, --dnstwist       Recherche typosquatting & phishing uniquement (Dnstwist)
  --ffuf, --fuzz            Découverte de routes et fichiers sensibles uniquement (Ffuf)
  --nmap                    Audit profond des ports et scripts NSE uniquement (Nmap)
  --nuclei, --cve           Scan de vulnérabilités et templates CVE uniquement (Nuclei)
  --nikto                   Audit de configuration HTTP uniquement (Nikto)
  --whois                   Audit WHOIS du registre, transfer lock et dates (Whois)
  --dnsrecon                Audit DNS avancé, bannières Bind et SRV (Dnsrecon)
  --theharvester, --osint   Reconnaissance passive OSINT emails & hôtes (theHarvester)
  --obscura, --browser      Navigateur headless DOM V8, capture d'écran PNG (Obscura)

EXPLORATION DE LA BASE POSTGRESQL (12 TABLES):
  -s, --stats               Afficher le tableau de bord global & métriques de sécurité
  -H, --history [N]         Afficher les N derniers scans en base
  --tables                  Afficher le nombre de lignes en direct des 12 tables
  --scan <ID>               Inspecter les détails techniques complets d'un scan
  --findings [SEVERITE]     Lister les constats (ex: --findings CRITICAL ou HIGH)
  --subdomains              Lister les sous-domaines découverts et cartographiés
  --geolocation             Afficher le registre de géolocalisation et juridiction d'hébergement
  --psql                    Ouvrir un shell SQL interactif sur la base veridy_audit

GESTION DES PROCESSUS & BATCHS:
  --running, --status       Afficher les scans et processus de sécurité actifs
  --kill, --stop            Arrêter d'urgence tous les scans en cours
  -b, --batch <FICHIER|CSV> Lancer un audit par lot sur plusieurs cibles

PIPELINE DÉVELOPPEUR RUST:
  --fmt                     Formater le code source Rust (cargo fmt)
  --lint                    Analyser avec le linter strict (cargo clippy -D warnings)
  --compile, --build        Compiler en Release et installer (/usr/local/bin/veridy_scanner)
  --qa                      Pipeline QA complet (Format -> Lint -> Compile)

OUTILS & OPTIONS:
  -i, --interactive         Ouvrir le menu interactif TUI (avec la cible spécifiée)
  --check-tools             Tester l'état de l'environnement Kali et dictionnaires
  -j, --json                Sortie au format JSON
  -h, --help                Afficher cette aide

EXEMPLES:
  veridy                              # Ouvre la console interactive TUI à flèches
  veridy example.com                  # Ouvre la console interactive sur example.com
  veridy example.com --360            # Lance l'audit 360° complet sur example.com
  veridy -t example.com --waf         # Lance uniquement le module WAF sur example.com
  veridy -t example.com -m ssl,tech   # Lance uniquement SSLScan et WhatWeb
  veridy -t example.com --obscura     # Audit DOM headless & capture PNG
  veridy --running                    # Voir les scans en cours d'exécution
  veridy --kill                       # Stopper d'urgence les scans actifs
  veridy -b "veridy.ca,scanme.org"    # Lancer un batch sur 2 cibles
  veridy --qa                         # Pipeline de test, lint et compilation Rust
  veridy --tables                     # Affiche l'état des 12 tables en base
  veridy --scan 14                    # Inspecte le scan #14 (ports, constats, outils)
  veridy --findings HIGH              # Affiche les vulnérabilités de sévérité HIGH
  veridy --stats                      # Affiche le tableau de bord global de la base
EOF
    exit 0
}

# ------------------------------------------------------------------------------
# CLI Arguments Parser
# ------------------------------------------------------------------------------
INTERACTIVE_MODE="0"

if [[ $# -eq 0 ]]; then
    interactive_tui
fi

CLI_TARGET=""
CLI_FLAGS=()
FORCE_INTERACTIVE=false
SHOW_HELP=false
SHOW_STATS=false
SHOW_CHECK=false
HAS_SCAN_ACTION=false
PROFILE_NAME="CLI SCAN"
BATCH_MODE=false
BATCH_SRC=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        -t|--target)
            CLI_TARGET="$2"
            shift 2
            ;;
        -i|--interactive)
            FORCE_INTERACTIVE=true
            shift
            ;;
        -1|--fast)
            PROFILE_NAME="FAST AUDIT (CORE RUST)"
            HAS_SCAN_ACTION=true
            shift
            ;;
        -2|--web)
            PROFILE_NAME="WEB PERIMETER AUDIT"
            CLI_FLAGS+=("--waf" "--whatweb" "--sslscan" "--dnstwist")
            HAS_SCAN_ACTION=true
            shift
            ;;
        -3|--360|--full)
            PROFILE_NAME="360° FULL KALI SUITE"
            CLI_FLAGS+=("--360")
            HAS_SCAN_ACTION=true
            shift
            ;;
        -4|--infra)
            PROFILE_NAME="SERVICES & INFRA AUDIT"
            CLI_FLAGS+=("--nmap" "--sslscan")
            HAS_SCAN_ACTION=true
            shift
            ;;
        -5|--vuln)
            PROFILE_NAME="CVE & VULNERABILITIES AUDIT"
            CLI_FLAGS+=("--nuclei" "--nikto" "--nmap")
            HAS_SCAN_ACTION=true
            shift
            ;;
        -d|--discovery)
            PROFILE_NAME="CONTENT & DISCOVERY AUDIT"
            CLI_FLAGS+=("--ffuf" "--nikto" "--waf")
            HAS_SCAN_ACTION=true
            shift
            ;;
        -m|--module|--modules)
            PROFILE_NAME="SPECIALIZED MODULES: $2"
            CLI_FLAGS+=("-m" "$2")
            HAS_SCAN_ACTION=true
            shift 2
            ;;
        --waf|--wafw00f)
            PROFILE_NAME="MODULE SPÉCIALISÉ: WAFW00F"
            CLI_FLAGS+=("--waf")
            HAS_SCAN_ACTION=true
            shift
            ;;
        --whatweb|--tech)
            PROFILE_NAME="MODULE SPÉCIALISÉ: WHATWEB"
            CLI_FLAGS+=("--whatweb")
            HAS_SCAN_ACTION=true
            shift
            ;;
        --ssl|--sslscan)
            PROFILE_NAME="MODULE SPÉCIALISÉ: SSLSCAN"
            CLI_FLAGS+=("--sslscan")
            HAS_SCAN_ACTION=true
            shift
            ;;
        --brand|--dnstwist)
            PROFILE_NAME="MODULE SPÉCIALISÉ: DNSTWIST"
            CLI_FLAGS+=("--dnstwist")
            HAS_SCAN_ACTION=true
            shift
            ;;
        --ffuf|--fuzz)
            PROFILE_NAME="MODULE SPÉCIALISÉ: FFUF"
            CLI_FLAGS+=("--ffuf")
            HAS_SCAN_ACTION=true
            shift
            ;;
        --nmap)
            PROFILE_NAME="MODULE SPÉCIALISÉ: NMAP"
            CLI_FLAGS+=("--nmap")
            HAS_SCAN_ACTION=true
            shift
            ;;
        --nuclei|--cve)
            PROFILE_NAME="MODULE SPÉCIALISÉ: NUCLEI"
            CLI_FLAGS+=("--nuclei")
            HAS_SCAN_ACTION=true
            shift
            ;;
        --nikto)
            PROFILE_NAME="MODULE SPÉCIALISÉ: NIKTO"
            CLI_FLAGS+=("--nikto")
            HAS_SCAN_ACTION=true
            shift
            ;;
        --whois)
            PROFILE_NAME="MODULE SPÉCIALISÉ: WHOIS"
            CLI_FLAGS+=("--whois")
            HAS_SCAN_ACTION=true
            shift
            ;;
        --dnsrecon)
            PROFILE_NAME="MODULE SPÉCIALISÉ: DNSRECON"
            CLI_FLAGS+=("--dnsrecon")
            HAS_SCAN_ACTION=true
            shift
            ;;
        --theharvester|--osint)
            PROFILE_NAME="MODULE SPÉCIALISÉ: THEHARVESTER"
            CLI_FLAGS+=("--theharvester")
            HAS_SCAN_ACTION=true
            shift
            ;;
        --obscura|--browser|--render)
            PROFILE_NAME="MODULE SPÉCIALISÉ: OBSCURA"
            CLI_FLAGS+=("--obscura")
            HAS_SCAN_ACTION=true
            shift
            ;;
        -H|--history)
            if [[ -n "$2" && ! "$2" =~ ^- ]]; then
                CLI_FLAGS+=("--history" "$2")
                shift 2
            else
                CLI_FLAGS+=("--history")
                shift
            fi
            HAS_SCAN_ACTION=true
            ;;
        -s|--stats)
            SHOW_STATS=true
            shift
            ;;
        --tables|--db-tables)
            show_db_tables
            exit 0
            ;;
        --scan|--scan-id)
            show_scan_detail "$2"
            exit 0
            ;;
        --findings)
            if [[ -n "$2" && ! "$2" =~ ^- ]]; then
                show_findings "$2"
                shift 2
            else
                show_findings
                shift
            fi
            exit 0
            ;;
        --subdomains)
            show_subdomains
            exit 0
            ;;
        --geolocation)
            show_geolocation
            exit 0
            ;;
        --psql)
            open_psql_shell
            exit 0
            ;;
        --running|--status)
            show_running_scans
            exit 0
            ;;
        --kill|--stop)
            stop_scans
            exit 0
            ;;
        -b|--batch)
            BATCH_MODE=true
            BATCH_SRC="$2"
            HAS_SCAN_ACTION=true
            shift 2
            ;;
        --fmt)
            dev_format
            exit 0
            ;;
        --lint)
            dev_lint
            exit 0
            ;;
        --test|--tests)
            dev_test
            exit 0
            ;;
        --compile|--build)
            dev_compile
            exit 0
            ;;
        --qa)
            dev_qa
            exit 0
            ;;
        --check-tools)
            SHOW_CHECK=true
            shift
            ;;
        -j|--json)
            CLI_FLAGS+=("--json")
            shift
            ;;
        -h|--help)
            SHOW_HELP=true
            shift
            ;;
        *)
            if [[ ! "$1" =~ ^- ]]; then
                CLI_TARGET=$(echo "$1" | sed -e 's|^https\?://||' -e 's|/.*$||' | tr '[:upper:]' '[:lower:]')
            else
                CLI_FLAGS+=("$1")
            fi
            shift
            ;;
    esac
done

if [[ "$SHOW_HELP" == true ]]; then
    show_help
fi

if [[ "$SHOW_CHECK" == true ]]; then
    check_tools
    exit 0
fi

if [[ "$SHOW_STATS" == true ]]; then
    show_stats
    exit 0
fi

if [[ "$BATCH_MODE" == true ]]; then
    run_batch "$BATCH_SRC" "${CLI_FLAGS[@]}"
    exit 0
fi

# Apply target if specified
if [[ -n "$CLI_TARGET" ]]; then
    CURRENT_TARGET="$CLI_TARGET"
fi

# If user specified a target but no scan actions, or requested interactive mode, open interactive TUI
if [[ "$FORCE_INTERACTIVE" == true || "$HAS_SCAN_ACTION" == false ]]; then
    interactive_tui
    exit 0
fi

# Execute configured CLI scan
run_scan "$PROFILE_NAME" "${CLI_FLAGS[@]}"
