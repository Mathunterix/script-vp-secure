#!/usr/bin/env bash
#===============================================================================
# securisation-post-coolify.sh
# Fermeture des ports d'administration Coolify apres config HTTPS
# Version : 1.0 (2026-03-06)
#
# A lancer APRES :
#   1. script-vps-secure-coolify-v7.sh (securisation VPS)
#   2. Installation de Coolify (curl ... | sudo bash)
#   3. Configuration du domaine HTTPS dans Coolify (FQDN)
#
# Ce script ferme les ports 8000, 6001, 6002 qui etaient ouverts
# temporairement pour l'installation de Coolify.
# Double protection : UFW (INPUT) + DOCKER-USER (FORWARD/iptables)
#
# Usage : sudo bash securisation-post-coolify.sh
#===============================================================================

set -euo pipefail

#===============================================================================
# COULEURS ET HELPERS
#===============================================================================
NC="\033[0m"
RED="\033[1;31m"
GREEN="\033[1;32m"
YELLOW="\033[1;33m"
BLUE="\033[1;34m"
CYAN="\033[1;36m"
BOLD="\033[1m"
DIM="\033[2m"

info()    { echo -e "${BLUE}[INFO]${NC} $*"; }
ok()      { echo -e "${GREEN}[OK]${NC} $*"; }
warn()    { echo -e "${YELLOW}[ATTENTION]${NC} $*"; }
err()     { echo -e "${RED}[ERREUR]${NC} $*" >&2; }
die()     { err "$*"; exit 1; }

header() {
    echo ""
    echo -e "${CYAN}=================================================================${NC}"
    echo -e "${CYAN}  $*${NC}"
    echo -e "${CYAN}=================================================================${NC}"
    echo ""
}

section() {
    echo ""
    echo -e "${BOLD}--- $* ---${NC}"
    echo ""
}

prompt_with_help() {
    local varname="$1"
    local prompt_text="$2"
    local default_value="$3"
    local help_text="$4"
    local validator="${5:-}"
    local result=""

    echo ""
    echo -e "${YELLOW}${BOLD}$prompt_text${NC}"
    if [[ -n "$help_text" ]]; then
        echo -e "${DIM}$help_text${NC}"
    fi

    while true; do
        echo -en "${CYAN}Votre reponse${NC}"
        if [[ -n "$default_value" ]]; then
            echo -en " ${DIM}[defaut: ${default_value}]${NC}"
        fi
        echo -en ": "
        read -r result

        # Utiliser la valeur par defaut si vide
        result="${result:-$default_value}"

        # Valider si un validateur est fourni
        if [[ -n "$validator" ]]; then
            if $validator "$result"; then
                break
            fi
        else
            break
        fi
    done

    eval "$varname='$result'"
}

prompt_yn() {
    local varname="$1"
    local prompt_text="$2"
    local default_value="$3"
    local help_text="${4:-}"
    local result=""

    echo ""
    echo -e "${YELLOW}${BOLD}$prompt_text${NC}"
    if [[ -n "$help_text" ]]; then
        echo -e "${DIM}$help_text${NC}"
    fi

    local default_display="o/N"
    [[ "${default_value,,}" == "oui" || "${default_value,,}" == "o" ]] && default_display="O/n"

    while true; do
        echo -en "${CYAN}Votre reponse${NC} ${DIM}[$default_display]${NC}: "
        read -r result
        result="${result:-$default_value}"

        case "${result,,}" in
            oui|o|yes|y) result="oui"; break ;;
            non|n|no)    result="non"; break ;;
            *)           err "Repondez 'oui' (o) ou 'non' (n)" ;;
        esac
    done

    eval "$varname='$result'"
}

#===============================================================================
# BANNER
#===============================================================================
show_banner() {
    clear
    echo -e "${CYAN}"
    echo "  ____           _        ____            _ _  __       "
    echo " |  _ \\ ___  ___| |_     / ___|___   ___ | (_)/ _|_   _"
    echo " | |_) / _ \\/ __| __|   | |   / _ \\ / _ \\| | | |_| | | |"
    echo " |  __/ (_) \\__ \\ |_    | |__| (_) | (_) | | |  _| |_| |"
    echo " |_|   \\___/|___/\\__|    \\____\\___/ \\___/|_|_|_|  \\__, |"
    echo "                                                   |___/ "
    echo -e "${NC}"
    echo -e "${DIM}Fermeture des ports d'administration Coolify v1.0${NC}"
    echo ""
}

#===============================================================================
# VERIFICATIONS PRELIMINAIRES
#===============================================================================
[[ $EUID -eq 0 ]] || die "Ce script doit etre lance en root : sudo bash $0"

# Verifier que Docker est installe (signe que Coolify est la)
command -v docker >/dev/null 2>&1 || die "Docker non detecte. Coolify est-il installe ?"

# Verifier que UFW est actif
ufw status | grep -q "Status: active" || die "UFW n'est pas actif. Le script V7 a-t-il ete lance ?"

#===============================================================================
# ETAPE 1 : FQDN COOLIFY
#===============================================================================
show_banner
header "Verification du domaine HTTPS Coolify"

prompt_with_help COOLIFY_FQDN \
    "Domaine HTTPS de votre dashboard Coolify" \
    "" \
    "Exemple: coolify.mondomaine.com (sans https://)"

# Normaliser (retirer https:// si present)
COOLIFY_FQDN="${COOLIFY_FQDN#https://}"
COOLIFY_FQDN="${COOLIFY_FQDN#http://}"
COOLIFY_FQDN="${COOLIFY_FQDN%/}"

# Verifier HTTPS
info "Verification de https://$COOLIFY_FQDN ..."
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" --connect-timeout 10 \
    "https://$COOLIFY_FQDN" 2>/dev/null || echo "000")

if [[ "$HTTP_CODE" == "000" ]]; then
    die "Impossible de joindre https://$COOLIFY_FQDN (timeout ou erreur DNS)"
elif [[ "$HTTP_CODE" -ge 200 && "$HTTP_CODE" -lt 400 ]]; then
    ok "Dashboard accessible en HTTPS (HTTP $HTTP_CODE)"
elif [[ "$HTTP_CODE" == "401" || "$HTTP_CODE" == "302" ]]; then
    ok "Dashboard accessible en HTTPS (HTTP $HTTP_CODE - redirection/auth, c'est normal)"
else
    warn "HTTPS repond avec code $HTTP_CODE. Verifiez que le dashboard fonctionne."
    prompt_yn CONTINUE_ANYWAY "Continuer quand meme ?" "non"
    [[ "$CONTINUE_ANYWAY" == "oui" ]] || die "Annule. Configurez le FQDN HTTPS d'abord."
fi

#===============================================================================
# ETAPE 2 : DETECTION PORT SSH
#===============================================================================
SSH_PORT_DETECTED=$(grep -E "^Port " /etc/ssh/sshd_config | head -1 | awk '{print $2}')
# Si plusieurs ports, prendre le premier qui n'est pas 22
for p in $(grep -E "^Port " /etc/ssh/sshd_config | awk '{print $2}'); do
    if [[ "$p" != "22" ]]; then
        SSH_PORT_DETECTED="$p"
        break
    fi
done
info "Port SSH detecte : ${SSH_PORT_DETECTED:-22}"

#===============================================================================
# RESUME ET CONFIRMATION
#===============================================================================
header "Resume"

echo "  FQDN Coolify     : https://$COOLIFY_FQDN"
echo "  Port SSH          : ${SSH_PORT_DETECTED:-22}"
echo ""
echo -e "${BOLD}Actions a effectuer :${NC}"
echo "  1. Fermer le port 8000 (dashboard Coolify)"
echo "  2. Fermer le port 6001 (WebSocket realtime)"
echo "  3. Fermer le port 6002 (terminal/metriques)"
echo ""

prompt_yn CONFIRM "Lancer la fermeture des ports ?" "oui"
[[ "$CONFIRM" == "oui" ]] || die "Annule par l'utilisateur."

#===============================================================================
# BACKUP
#===============================================================================
header "Sauvegarde de l'etat actuel"

TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
UFW_BAK="/root/ufw-backup-postcoolify-$TIMESTAMP.tgz"
tar czf "$UFW_BAK" /etc/ufw 2>/dev/null || true
ok "Backup UFW : $UFW_BAK"

# Backup iptables aussi (pour les regles DOCKER-USER)
IPTABLES_BAK_DIR="/root/iptables-backups"
mkdir -p "$IPTABLES_BAK_DIR"
IPTABLES_BAK="$IPTABLES_BAK_DIR/pre-postcoolify-$TIMESTAMP.v4"
iptables-save > "$IPTABLES_BAK" 2>/dev/null || true
ok "Backup iptables : $IPTABLES_BAK"

#===============================================================================
# FERMETURE DES PORTS
#===============================================================================
header "Fermeture des ports d'administration"

# 1. UFW : retirer les allow et ajouter des deny
section "Protection UFW (INPUT)"
for port in 8000 6001 6002; do
    ufw delete allow ${port}/tcp 2>/dev/null || true
    # Verifier si le deny existe deja (idempotent)
    if ! ufw status | grep -q "${port}/tcp.*DENY"; then
        ufw deny ${port}/tcp comment "Coolify admin FERME" >/dev/null 2>&1
    fi
    ok "Port $port ferme (UFW)"
done

# 2. DOCKER-USER : bloquer le forwarding Docker
section "Protection DOCKER-USER (iptables/FORWARD)"

# Auto-detecter le port interne du container Coolify pour le dashboard
# Coolify mappe host:8000 -> container:8080 par defaut
COOLIFY_INTERNAL_PORT=$(docker inspect coolify 2>/dev/null \
    | grep -oP '"8000/tcp".*?"HostPort":\s*"\K[^"]+' 2>/dev/null || echo "8080")

# Ports a bloquer dans DOCKER-USER (ports internes des containers)
DOCKER_PORTS_TO_BLOCK="8080 6001 6002"
if [[ "$COOLIFY_INTERNAL_PORT" != "8080" && "$COOLIFY_INTERNAL_PORT" != "8000" ]]; then
    DOCKER_PORTS_TO_BLOCK="$COOLIFY_INTERNAL_PORT 8080 6001 6002"
fi

# Installer iptables-persistent si pas present
info "Installation de iptables-persistent..."
DEBIAN_FRONTEND=noninteractive apt-get install -y iptables-persistent >/dev/null 2>&1 || true

for port in $DOCKER_PORTS_TO_BLOCK; do
    if ! iptables -C DOCKER-USER -p tcp --dport "$port" -j DROP 2>/dev/null; then
        iptables -I DOCKER-USER -p tcp --dport "$port" -j DROP
        ok "Port $port bloque (DOCKER-USER/iptables)"
    else
        ok "Port $port deja bloque (DOCKER-USER/iptables)"
    fi
done

# Sauvegarder iptables
netfilter-persistent save 2>/dev/null || true
ok "Regles iptables sauvegardees"

#===============================================================================
# VERIFICATION POST-FERMETURE
#===============================================================================
header "Verification"

echo -e "${YELLOW}IMPORTANT : Ouvrez un SECOND terminal et verifiez :${NC}"
echo ""
echo -e "  1. ${BOLD}SSH fonctionne :${NC}"
echo -e "     ssh -p ${SSH_PORT_DETECTED:-22} VOTRE_USER@IP_DU_VPS"
echo ""
echo -e "  2. ${BOLD}HTTPS fonctionne :${NC}"
echo -e "     Ouvrez https://$COOLIFY_FQDN dans votre navigateur"
echo ""
echo -e "  3. ${BOLD}Port 8000 ferme :${NC}"
echo -e "     Ouvrez http://IP_DU_VPS:8000 -> doit etre inaccessible"
echo ""

#===============================================================================
# CONFIRMATION AVEC AUTO-ROLLBACK 5 MIN
#===============================================================================
echo -e "${RED}${BOLD}=================================================================${NC}"
echo -e "${RED}${BOLD}  CONFIRMATION OBLIGATOIRE (5 minutes max)${NC}"
echo -e "${RED}${BOLD}=================================================================${NC}"
echo ""
echo -e "${YELLOW}Tapez exactement ${BOLD}CONFIRMER${NC}${YELLOW} si tout fonctionne.${NC}"
echo -e "${YELLOW}Tapez autre chose ou attendez 5 min pour rollback automatique.${NC}"
echo ""

# Vider le buffer stdin
read -t 0.1 -n 10000 discard 2>/dev/null || true

echo -en "${CYAN}Votre reponse (5 min max)${NC}: "
if ! read -t 300 -r CONFIRM_RESPONSE; then
    echo ""
    warn "Timeout (5 minutes). Rollback automatique..."
    # Restaurer UFW
    ufw --force disable 2>/dev/null || true
    tar xzf "$UFW_BAK" -C / 2>/dev/null || true
    ufw --force enable 2>/dev/null || true
    # Restaurer iptables
    iptables-restore < "$IPTABLES_BAK" 2>/dev/null || true
    die "Rollback effectue. Relancez le script quand vous etes pret."
fi

if [[ "$CONFIRM_RESPONSE" != "CONFIRMER" ]]; then
    warn "Non confirme. Rollback..."
    ufw --force disable 2>/dev/null || true
    tar xzf "$UFW_BAK" -C / 2>/dev/null || true
    ufw --force enable 2>/dev/null || true
    iptables-restore < "$IPTABLES_BAK" 2>/dev/null || true
    die "Rollback effectue."
fi

ok "Configuration validee et permanente !"

#===============================================================================
# INSTRUCTIONS FINALES
#===============================================================================
header "Ports d'administration Coolify fermes"

echo -e "${GREEN}${BOLD}Votre VPS n'expose plus que :${NC}"
echo ""
echo "  ┌────────────────────────┬─────────────────────────────────┐"
printf "  │ Port %-17s │ SSH (votre acces)               │\n" "${SSH_PORT_DETECTED:-22}"
echo "  │ Port 80                │ HTTP (redirige vers HTTPS)      │"
echo "  │ Port 443               │ HTTPS (Coolify + vos services)  │"
echo "  └────────────────────────┴─────────────────────────────────┘"
echo ""
echo -e "${DIM}Pour rouvrir temporairement le port 8000 :${NC}"
echo "  sudo ufw delete deny 8000/tcp && sudo ufw allow 8000/tcp"
echo "  sudo iptables -D DOCKER-USER -p tcp --dport 8080 -j DROP"
echo ""
echo -e "${DIM}Pour refermer :${NC}"
echo "  Relancez ce script (il est idempotent)"
echo ""

ok "Script termine. Votre VPS est securise."
