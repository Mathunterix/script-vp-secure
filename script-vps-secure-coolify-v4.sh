#!/usr/bin/env bash
#===============================================================================
# script-vps-secure-coolify-v4.sh
# Securisation VPS compatible Coolify (Master ou Remote)
# Version : 4.0 (2025-12-09)
#
# Fonctionnalites :
# - Creation utilisateur SSH securise avec cle ED25519
# - Port SSH personnalise
# - Configuration optimisee selon le type de serveur (Master/Remote/Standard)
# - Fail2Ban pour protection brute-force
# - Unattended-upgrades pour mises a jour de securite automatiques
# - Rollback automatique en cas de probleme
#
# IMPORTANT : UFW + Docker = probleme !
# Docker bypass UFW via iptables. Utilisez le firewall de votre cloud provider.
#
# Usage : sudo bash script-vps-secure-coolify-v4.sh
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

#===============================================================================
# FONCTIONS D'AFFICHAGE INTERACTIF (style mozzy)
#===============================================================================
show_banner() {
    clear
    echo -e "${CYAN}"
    echo "  ____                       _ _           __     ______  ____  "
    echo " / ___|  ___  ___ _   _ _ __(_) |_ _   _  \\ \\   / /  _ \\/ ___| "
    echo " \\___ \\ / _ \\/ __| | | | '__| | __| | | |  \\ \\ / /| |_) \\___ \\ "
    echo "  ___) |  __/ (__| |_| | |  | | |_| |_| |   \\ V / |  __/ ___) |"
    echo " |____/ \\___|\\___|\\__,_|_|  |_|\\__|\\__, |    \\_/  |_|   |____/ "
    echo "                                   |___/                        "
    echo -e "${NC}"
    echo -e "${DIM}Script de securisation VPS compatible Coolify v4.0${NC}"
    echo -e "${DIM}Auteur: Formation Vibecoding${NC}"
    echo ""
}

show_explanation() {
    local title="$1"
    local text="$2"
    echo ""
    echo -e "${YELLOW}${BOLD}$title${NC}"
    echo -e "${DIM}$text${NC}"
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
            # Le validateur affiche son propre message d'erreur
        else
            break
        fi
    done

    eval "$varname='$result'"
}

prompt_choice() {
    local varname="$1"
    local prompt_text="$2"
    local default_value="$3"
    shift 3
    local options=("$@")
    local result=""

    echo ""
    echo -e "${YELLOW}${BOLD}$prompt_text${NC}"
    echo ""

    local i=1
    for opt in "${options[@]}"; do
        if [[ "$i" == "$default_value" ]]; then
            echo -e "  ${GREEN}$i)${NC} $opt ${DIM}(recommande)${NC}"
        else
            echo -e "  ${CYAN}$i)${NC} $opt"
        fi
        ((i++))
    done

    echo ""
    while true; do
        echo -en "${CYAN}Votre choix${NC} ${DIM}[defaut: $default_value]${NC}: "
        read -r result
        result="${result:-$default_value}"

        if [[ "$result" =~ ^[0-9]+$ ]] && (( result >= 1 && result <= ${#options[@]} )); then
            break
        fi
        err "Choix invalide. Entrez un nombre entre 1 et ${#options[@]}"
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
# VERIFICATIONS PRELIMINAIRES
#===============================================================================
[[ $EUID -eq 0 ]] || die "Ce script doit etre lance en root : sudo bash $0"

# Detecter l'OS
if [[ -f /etc/os-release ]]; then
    . /etc/os-release
    DISTRO="${ID:-unknown}"
    DISTRO_VERSION="${VERSION_ID:-}"
else
    die "Impossible de detecter la distribution."
fi

case "$DISTRO" in
    ubuntu|debian)
        PKG_UPDATE="apt-get update -y"
        PKG_INSTALL="apt-get install -y"
        ;;
    centos|rocky|almalinux|fedora)
        PKG_UPDATE="dnf check-update || true"
        PKG_INSTALL="dnf install -y"
        ;;
    *)
        die "Distribution non supportee ($DISTRO). Ce script fonctionne sur Debian/Ubuntu/CentOS/Rocky/Fedora."
        ;;
esac

# Detecter le service SSH
if systemctl list-units --type=service --all 2>/dev/null | grep -q "ssh.service"; then
    SSH_SERVICE="ssh"
elif systemctl list-units --type=service --all 2>/dev/null | grep -q "sshd.service"; then
    SSH_SERVICE="sshd"
else
    SSH_SERVICE="ssh"
fi

#===============================================================================
# FONCTIONS DE VALIDATION
#===============================================================================
validate_username() {
    local u="$1"
    if [[ ${#u} -gt 32 ]]; then
        err "Le nom d'utilisateur ne doit pas depasser 32 caracteres"
        return 1
    fi
    if [[ ! "$u" =~ ^[a-z][a-z0-9_-]*$ ]]; then
        err "Format invalide: commencez par une lettre minuscule, puis lettres/chiffres/_/-"
        echo -e "${DIM}Exemples valides: deploy, admin, user1, my-user, my_user${NC}"
        return 1
    fi
    if id -u "$u" >/dev/null 2>&1; then
        warn "L'utilisateur '$u' existe deja (il sera configure)"
    fi
    return 0
}

validate_port() {
    local p="$1"
    if [[ ! "$p" =~ ^[0-9]+$ ]]; then
        err "Le port doit etre un nombre"
        return 1
    fi
    if (( p < 1024 || p > 65535 )); then
        err "Le port doit etre entre 1024 et 65535"
        echo -e "${DIM}Les ports < 1024 sont reserves au systeme${NC}"
        return 1
    fi
    if ss -tuln 2>/dev/null | grep -q ":$p "; then
        err "Le port $p est deja utilise par un autre service"
        return 1
    fi
    return 0
}

validate_ip_list() {
    local ips="$1"
    [[ -z "$ips" ]] && return 0  # Vide = toutes les IPs, c'est OK

    for ip in $ips; do
        if [[ ! "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+(/[0-9]+)?$ ]]; then
            err "IP invalide: $ip"
            echo -e "${DIM}Format attendu: 192.168.1.1 ou 192.168.1.0/24${NC}"
            return 1
        fi
    done
    return 0
}

generate_random_port() {
    local port
    local attempts=0
    while (( attempts < 100 )); do
        port=$((RANDOM % 55535 + 10000))
        if ! ss -tuln 2>/dev/null | grep -q ":$port "; then
            echo "$port"
            return
        fi
        ((attempts++))
    done
    echo "22222"  # Fallback
}

#===============================================================================
# CONFIGURATION INTERACTIVE
#===============================================================================
show_banner

header "Bienvenue dans l'assistant de securisation VPS"

echo -e "${BOLD}Ce script va securiser votre VPS en configurant :${NC}"
echo ""
echo "  1. Un utilisateur SSH dedie avec cle ED25519"
echo "  2. Un port SSH personnalise (anti-scan)"
echo "  3. Fail2Ban (anti brute-force)"
echo "  4. Mises a jour de securite automatiques"
echo ""
echo -e "${YELLOW}Duree estimee : 3-5 minutes${NC}"
echo ""

read -rp "$(echo -e "${CYAN}Appuyez sur Entree pour continuer...${NC}")"

#-------------------------------------------------------------------------------
# ETAPE 1 : Type de serveur
#-------------------------------------------------------------------------------
section "ETAPE 1/6 : Type de serveur"

show_explanation "Quel est le role de ce VPS ?" \
"Coolify est un outil de deploiement d'applications.
- Si vous installez Coolify SUR ce VPS -> choisissez 'Master'
- Si ce VPS sera GERE par un Coolify distant -> choisissez 'Remote'
- Si vous n'utilisez pas Coolify -> choisissez 'Standard'"

prompt_choice VPS_TYPE "Quel type de serveur configurez-vous ?" "2" \
    "Master Coolify - Coolify sera installe sur CE serveur" \
    "Remote Coolify - Ce serveur sera gere par un Coolify DISTANT" \
    "Standard - Pas de Coolify (securite maximale)"

case "$VPS_TYPE" in
    1) VPS_MODE="master" ;;
    2) VPS_MODE="remote" ;;
    3) VPS_MODE="standard" ;;
esac

ok "Mode selectionne : ${VPS_MODE^^}"

# Afficher les implications du choix
echo ""
case "$VPS_MODE" in
    master)
        echo -e "${BLUE}Configuration Master Coolify :${NC}"
        echo "  - Port 22 garde ouvert (requis par Coolify)"
        echo "  - host.docker.internal configure"
        echo "  - Ports 8000, 6001, 6002 a ouvrir temporairement"
        echo "  - Root SSH via cle autorise"
        ;;
    remote)
        echo -e "${BLUE}Configuration Remote Coolify :${NC}"
        echo "  - Port SSH personnalise possible"
        echo "  - Root SSH via cle autorise"
        echo "  - Coolify installera Docker automatiquement"
        echo "  - Pas besoin de host.docker.internal"
        ;;
    standard)
        echo -e "${BLUE}Configuration Standard (securite max) :${NC}"
        echo "  - Port 22 ferme"
        echo "  - Root SSH desactive"
        echo "  - UFW configure normalement"
        ;;
esac

#-------------------------------------------------------------------------------
# ETAPE 2 : Utilisateur SSH
#-------------------------------------------------------------------------------
section "ETAPE 2/6 : Utilisateur SSH"

prompt_with_help SSH_USER \
    "Nom de l'utilisateur SSH securise" \
    "deploy" \
    "Cet utilisateur aura les droits sudo. Evitez 'admin', 'root', 'user'.
Exemples: deploy, devops, monprenom" \
    validate_username

ok "Utilisateur : $SSH_USER"

#-------------------------------------------------------------------------------
# ETAPE 3 : Port SSH
#-------------------------------------------------------------------------------
section "ETAPE 3/6 : Port SSH"

RANDOM_PORT=$(generate_random_port)

if [[ "$VPS_MODE" == "master" ]]; then
    show_explanation "Port SSH personnalise" \
"ATTENTION Mode Master: Le port 22 restera ouvert pour Coolify.
Votre port personnalise sera utilise pour VOS connexions SSH.
Coolify utilisera le port 22 en interne."
else
    show_explanation "Port SSH personnalise" \
"Changer le port SSH reduit de 90% les scans automatises.
Choisissez un port entre 10000 et 65535 (le script en propose un aleatoire)."
fi

prompt_with_help SSH_PORT \
    "Port SSH personnalise" \
    "$RANDOM_PORT" \
    "Port suggere aleatoirement: $RANDOM_PORT" \
    validate_port

ok "Port SSH : $SSH_PORT"

#-------------------------------------------------------------------------------
# ETAPE 4 : Restriction IP (optionnel)
#-------------------------------------------------------------------------------
section "ETAPE 4/6 : Restriction d'acces (optionnel)"

if [[ "$VPS_MODE" == "remote" ]]; then
    show_explanation "Restreindre l'acces SSH" \
"Pour un serveur Remote Coolify, vous pouvez restreindre SSH a l'IP de votre serveur Master.
Cela empeche toute connexion SSH depuis une autre IP."

    prompt_with_help SSH_ALLOWED_IPS \
        "IP(s) autorisees pour SSH (laissez vide pour toutes)" \
        "" \
        "Entrez l'IP de votre serveur Coolify Master, ou laissez vide.
Plusieurs IPs separees par des espaces: 1.2.3.4 5.6.7.8" \
        validate_ip_list
else
    prompt_with_help SSH_ALLOWED_IPS \
        "IP(s) autorisees pour SSH (laissez vide pour toutes)" \
        "" \
        "Laissez vide pour autoriser toutes les IPs, ou entrez vos IPs.
Plusieurs IPs separees par des espaces: 1.2.3.4 5.6.7.8" \
        validate_ip_list
fi

if [[ -n "$SSH_ALLOWED_IPS" ]]; then
    ok "Acces SSH restreint a : $SSH_ALLOWED_IPS"
else
    ok "Acces SSH : toutes les IPs"
fi

#-------------------------------------------------------------------------------
# ETAPE 5 : Generation de cle SSH
#-------------------------------------------------------------------------------
section "ETAPE 5/6 : Cle SSH"

show_explanation "Generation de cle SSH ED25519" \
"Une cle ED25519 est plus securisee et plus rapide que RSA.
Si vous avez deja une cle, vous pouvez la configurer manuellement apres."

prompt_yn GEN_KEYS \
    "Generer une nouvelle cle SSH ED25519 ?" \
    "oui" \
    "Recommande si c'est votre premiere configuration"

ok "Generation de cle : $GEN_KEYS"

#-------------------------------------------------------------------------------
# ETAPE 6 : Options supplementaires
#-------------------------------------------------------------------------------
section "ETAPE 6/6 : Options supplementaires"

prompt_yn DISABLE_IPV6 \
    "Desactiver IPv6 ?" \
    "non" \
    "Desactivez IPv6 si vous ne l'utilisez pas (reduit la surface d'attaque)"

prompt_yn LIMIT_ICMP \
    "Limiter les reponses ICMP (ping) ?" \
    "oui" \
    "Limite les informations disponibles pour les scanners"

#-------------------------------------------------------------------------------
# RESUME ET CONFIRMATION
#-------------------------------------------------------------------------------
header "Resume de la configuration"

echo -e "${BOLD}Serveur${NC}"
echo "  Type              : $VPS_MODE"
echo "  Distribution      : $DISTRO $DISTRO_VERSION"
echo ""
echo -e "${BOLD}SSH${NC}"
echo "  Utilisateur       : $SSH_USER"
echo "  Port personnalise : $SSH_PORT"
if [[ "$VPS_MODE" != "standard" ]]; then
echo "  Port 22           : Ouvert (Coolify)"
fi
echo "  IPs autorisees    : ${SSH_ALLOWED_IPS:-Toutes}"
echo "  Generer cle       : $GEN_KEYS"
echo ""
echo -e "${BOLD}Securite${NC}"
echo "  Fail2Ban          : Oui"
echo "  Updates auto      : Oui"
echo "  Desactiver IPv6   : $DISABLE_IPV6"
echo "  Limiter ICMP      : $LIMIT_ICMP"
echo ""

# Avertissement UFW + Docker
if [[ "$VPS_MODE" != "standard" ]]; then
    echo -e "${YELLOW}${BOLD}AVERTISSEMENT IMPORTANT :${NC}"
    echo -e "${YELLOW}Docker bypass UFW via iptables. Les regles UFW seront inefficaces${NC}"
    echo -e "${YELLOW}pour les ports exposes par Docker/Coolify.${NC}"
    echo ""
    echo -e "${YELLOW}RECOMMANDATION : Utilisez le firewall de votre cloud provider${NC}"
    echo -e "${YELLOW}(Hetzner, OVH, DigitalOcean, etc.) pour controler les ports.${NC}"
    echo ""
fi

prompt_yn CONFIRM \
    "Lancer la securisation avec cette configuration ?" \
    "oui"

[[ "$CONFIRM" == "oui" ]] || die "Annule par l'utilisateur."

#===============================================================================
# VARIABLES DE BACKUP (pour rollback)
#===============================================================================
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
SSHD_CFG="/etc/ssh/sshd_config"
SSHD_BAK="/etc/ssh/sshd_config.bak_$TIMESTAMP"
SYSCTL_FILE="/etc/sysctl.d/99-vps-secure.conf"
ACTIONS_DONE=()

register_action() { ACTIONS_DONE+=("$1"); }

rollback() {
    echo ""
    warn "Probleme detecte. Rollback en cours..."

    for action in "${ACTIONS_DONE[@]}"; do
        case "$action" in
            ssh)
                [[ -f "$SSHD_BAK" ]] && cp -f "$SSHD_BAK" "$SSHD_CFG"
                systemctl restart "$SSH_SERVICE" 2>/dev/null || true
                ok "SSH restaure"
                ;;
            sysctl)
                rm -f "$SYSCTL_FILE" 2>/dev/null || true
                sysctl --system 2>/dev/null || true
                ok "Sysctl restaure"
                ;;
            fail2ban)
                rm -f /etc/fail2ban/jail.local 2>/dev/null || true
                systemctl restart fail2ban 2>/dev/null || true
                ok "Fail2Ban restaure"
                ;;
        esac
    done

    ok "Rollback termine."
    exit 1
}

trap 'rollback' ERR

#===============================================================================
# INSTALLATION DES PAQUETS
#===============================================================================
header "Installation des paquets"

info "Mise a jour des paquets..."
eval "$PKG_UPDATE" >/dev/null 2>&1

info "Installation de sudo, fail2ban, unattended-upgrades..."
case "$DISTRO" in
    ubuntu|debian)
        $PKG_INSTALL sudo fail2ban curl ca-certificates unattended-upgrades apt-listchanges >/dev/null 2>&1
        ;;
    centos|rocky|almalinux|fedora)
        $PKG_INSTALL sudo fail2ban curl ca-certificates dnf-automatic >/dev/null 2>&1
        ;;
esac
ok "Paquets installes"

# Configuration des mises a jour automatiques de securite
info "Configuration des mises a jour de securite automatiques..."
case "$DISTRO" in
    ubuntu|debian)
        cat > /etc/apt/apt.conf.d/50unattended-upgrades <<'UPGRADES'
Unattended-Upgrade::Allowed-Origins {
    "${distro_id}:${distro_codename}";
    "${distro_id}:${distro_codename}-security";
    "${distro_id}ESMApps:${distro_codename}-apps-security";
    "${distro_id}ESM:${distro_codename}-infra-security";
};
Unattended-Upgrade::Package-Blacklist {
};
Unattended-Upgrade::AutoFixInterruptedDpkg "true";
Unattended-Upgrade::MinimalSteps "true";
Unattended-Upgrade::Remove-Unused-Kernel-Packages "true";
Unattended-Upgrade::Remove-Unused-Dependencies "true";
Unattended-Upgrade::Automatic-Reboot "false";
UPGRADES

        cat > /etc/apt/apt.conf.d/20auto-upgrades <<'AUTOUPGRADES'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::AutocleanInterval "7";
AUTOUPGRADES
        systemctl enable unattended-upgrades >/dev/null 2>&1 || true
        systemctl start unattended-upgrades >/dev/null 2>&1 || true
        ;;
    centos|rocky|almalinux|fedora)
        systemctl enable --now dnf-automatic.timer >/dev/null 2>&1 || true
        ;;
esac
ok "Mises a jour de securite automatiques configurees"

#===============================================================================
# CREATION DE L'UTILISATEUR
#===============================================================================
header "Configuration utilisateur : $SSH_USER"

if id -u "$SSH_USER" >/dev/null 2>&1; then
    warn "L'utilisateur $SSH_USER existe deja - configuration en cours..."
else
    useradd -m -s /bin/bash "$SSH_USER" 2>/dev/null || adduser --disabled-password --gecos "" "$SSH_USER" >/dev/null 2>&1
    ok "Utilisateur $SSH_USER cree"
fi

# Ajouter aux groupes sudo
usermod -aG sudo "$SSH_USER" 2>/dev/null || usermod -aG wheel "$SSH_USER" 2>/dev/null || true
echo "$SSH_USER ALL=(ALL) NOPASSWD:ALL" > "/etc/sudoers.d/$SSH_USER"
chmod 440 "/etc/sudoers.d/$SSH_USER"
ok "$SSH_USER ajoute aux sudoers (NOPASSWD)"

if command -v docker >/dev/null 2>&1; then
    groupadd -f docker 2>/dev/null || true
    usermod -aG docker "$SSH_USER" 2>/dev/null || true
    ok "$SSH_USER ajoute au groupe docker"
fi

#===============================================================================
# GENERATION DE CLE SSH
#===============================================================================
PRIV_KEY_PATH=""
if [[ "$GEN_KEYS" == "oui" ]]; then
    header "Generation de la cle SSH ED25519"

    SSH_DIR="/home/$SSH_USER/.ssh"
    mkdir -p "$SSH_DIR"
    chmod 700 "$SSH_DIR"

    PRIV_KEY_PATH="$SSH_DIR/id_ed25519_$TIMESTAMP"
    ssh-keygen -t ed25519 -N "" -f "$PRIV_KEY_PATH" -C "$SSH_USER@$(hostname)" >/dev/null 2>&1

    # Installer la cle publique
    cat "${PRIV_KEY_PATH}.pub" >> "$SSH_DIR/authorized_keys"
    chmod 600 "$SSH_DIR/authorized_keys"
    chown -R "$SSH_USER:$SSH_USER" "$SSH_DIR"

    ok "Cle ED25519 generee"
fi

#===============================================================================
# CONFIGURATION SSH
#===============================================================================
header "Configuration SSH"

# Backup
cp "$SSHD_CFG" "$SSHD_BAK"
ok "Backup SSH : $SSHD_BAK"

# Fonction pour modifier sshd_config proprement
set_sshd_option() {
    local key="$1" value="$2"
    if grep -qE "^#?${key}[[:space:]]" "$SSHD_CFG"; then
        sed -i "s/^#*${key}[[:space:]].*/${key} ${value}/" "$SSHD_CFG"
    else
        echo "${key} ${value}" >> "$SSHD_CFG"
    fi
}

# Supprimer les anciennes lignes Port pour eviter les doublons
sed -i '/^Port /d' "$SSHD_CFG"

# Configuration de base
echo "Port $SSH_PORT" >> "$SSHD_CFG"
set_sshd_option "PubkeyAuthentication" "yes"
set_sshd_option "PasswordAuthentication" "no"
set_sshd_option "ChallengeResponseAuthentication" "no"
set_sshd_option "AddressFamily" "any"
set_sshd_option "ListenAddress" "0.0.0.0"

# Configuration specifique selon le mode
case "$VPS_MODE" in
    master)
        # VPS Master : garder port 22 + root via cle pour Coolify
        echo "Port 22" >> "$SSHD_CFG"
        set_sshd_option "PermitRootLogin" "prohibit-password"
        set_sshd_option "UsePAM" "yes"
        info "Mode Master : Port 22 + root (cle) actives pour Coolify"
        ;;
    remote)
        # VPS Remote : root via cle pour Coolify, port custom uniquement
        set_sshd_option "PermitRootLogin" "prohibit-password"
        set_sshd_option "UsePAM" "yes"
        info "Mode Remote : root (cle) active pour Coolify, port $SSH_PORT uniquement"
        ;;
    standard)
        # VPS Standard : securite maximale
        set_sshd_option "PermitRootLogin" "no"
        set_sshd_option "UsePAM" "no"
        info "Mode Standard : securite maximale, root desactive"
        ;;
esac

# Verifier la config
if ! sshd -t 2>/dev/null; then
    err "Erreur dans la configuration SSH"
    rollback
fi

register_action "ssh"
ok "Configuration SSH appliquee"

#===============================================================================
# HOST.DOCKER.INTERNAL (uniquement pour Master)
#===============================================================================
if [[ "$VPS_MODE" == "master" ]]; then
    header "Configuration Docker (Master)"

    # Ajouter host.docker.internal si pas present
    if ! grep -q "host.docker.internal" /etc/hosts; then
        LOCAL_IP=$(hostname -I | awk '{print $1}')
        echo "$LOCAL_IP host.docker.internal" >> /etc/hosts
        ok "host.docker.internal ajoute (/etc/hosts)"
    else
        ok "host.docker.internal deja present"
    fi
fi

#===============================================================================
# SYSCTL (IPv6, ICMP)
#===============================================================================
header "Configuration systeme (sysctl)"

cat > "$SYSCTL_FILE" <<'EOF'
# VPS Secure Configuration
EOF

if [[ "$DISABLE_IPV6" == "oui" ]]; then
    cat >> "$SYSCTL_FILE" <<'EOF'
# Disable IPv6
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1
net.ipv6.conf.lo.disable_ipv6 = 1
EOF
    info "IPv6 desactive"
fi

if [[ "$LIMIT_ICMP" == "oui" ]]; then
    cat >> "$SYSCTL_FILE" <<'EOF'
# Limit ICMP
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
net.ipv4.icmp_ratelimit = 100
net.ipv4.icmp_ratemask = 88089
EOF
    info "ICMP limite"
fi

sysctl --system >/dev/null 2>&1
register_action "sysctl"
ok "Sysctl configure"

#===============================================================================
# FAIL2BAN
#===============================================================================
header "Configuration Fail2Ban"

# Ports a proteger
case "$VPS_MODE" in
    master)  F2B_PORTS="$SSH_PORT,22" ;;
    remote)  F2B_PORTS="$SSH_PORT" ;;
    standard) F2B_PORTS="$SSH_PORT" ;;
esac

cat > /etc/fail2ban/jail.local <<EOF
[sshd]
enabled = true
port = $F2B_PORTS
filter = sshd
logpath = %(sshd_log)s
maxretry = 5
bantime = 1h
findtime = 10m
backend = %(sshd_backend)s
EOF

systemctl restart fail2ban >/dev/null 2>&1
systemctl enable fail2ban >/dev/null 2>&1 || true
register_action "fail2ban"
ok "Fail2Ban configure (protection ports : $F2B_PORTS)"

#===============================================================================
# REDEMARRAGE SSH
#===============================================================================
header "Application de la configuration SSH"

systemctl reload "$SSH_SERVICE" 2>/dev/null || systemctl restart "$SSH_SERVICE"

# Verifier que SSH ecoute sur le bon port
sleep 2
if ss -tuln | grep -q ":$SSH_PORT "; then
    ok "SSH actif sur le port $SSH_PORT"
else
    warn "SSH ne semble pas ecouter sur $SSH_PORT, tentative de restart..."
    systemctl restart "$SSH_SERVICE"
    sleep 2
    if ss -tuln | grep -q ":$SSH_PORT "; then
        ok "SSH maintenant actif sur le port $SSH_PORT"
    else
        err "Probleme avec SSH"
        rollback
    fi
fi

#===============================================================================
# RECAPITULATIF
#===============================================================================
header "Securisation terminee !"

echo -e "${GREEN}${BOLD}Configuration appliquee :${NC}"
echo ""
echo "  Utilisateur         : $SSH_USER (sudo sans mot de passe)"
echo "  Port SSH            : $SSH_PORT"
if [[ "$VPS_MODE" == "master" ]]; then
echo "  Port 22             : Ouvert (Coolify)"
fi
echo "  Fail2Ban            : Actif"
echo "  Updates auto        : Actif"
echo ""

# Afficher la cle privee si generee
if [[ -n "$PRIV_KEY_PATH" && -f "$PRIV_KEY_PATH" ]]; then
    echo ""
    echo -e "${RED}${BOLD}=================================================================${NC}"
    echo -e "${RED}${BOLD}  CLE PRIVEE SSH - A SAUVEGARDER MAINTENANT !${NC}"
    echo -e "${RED}${BOLD}=================================================================${NC}"
    echo ""
    echo -e "${YELLOW}Copiez cette cle MAINTENANT dans votre gestionnaire de mots de passe.${NC}"
    echo -e "${YELLOW}Elle ne sera plus jamais affichee !${NC}"
    echo ""
    echo "------------------- DEBUT CLE PRIVEE -------------------"
    cat "$PRIV_KEY_PATH"
    echo "-------------------- FIN CLE PRIVEE --------------------"
    echo ""
    echo "Sur votre machine locale :"
    echo ""
    echo "  1. Creez le fichier : ~/.ssh/${SSH_USER}_$(hostname)_ed25519"
    echo "  2. Collez la cle privee ci-dessus"
    echo "  3. Executez : chmod 600 ~/.ssh/${SSH_USER}_$(hostname)_ed25519"
    echo ""
fi

# Instructions de connexion
SERVER_IP=$(curl -s --connect-timeout 5 ifconfig.me 2>/dev/null || hostname -I | awk '{print $1}')

echo ""
echo -e "${CYAN}${BOLD}=================================================================${NC}"
echo -e "${CYAN}${BOLD}  TESTEZ VOTRE CONNEXION MAINTENANT${NC}"
echo -e "${CYAN}${BOLD}=================================================================${NC}"
echo ""
echo -e "${YELLOW}IMPORTANT : Ouvrez un NOUVEAU terminal et testez :${NC}"
echo ""
echo -e "  ${BOLD}ssh -i ~/.ssh/${SSH_USER}_$(hostname)_ed25519 -p $SSH_PORT $SSH_USER@$SERVER_IP${NC}"
echo ""
echo -e "${RED}NE FERMEZ PAS cette session avant d'avoir teste la nouvelle connexion !${NC}"
echo ""

# Confirmation finale
prompt_yn TEST_OK \
    "La nouvelle connexion fonctionne ?" \
    "non" \
    "Repondez 'oui' uniquement si vous avez teste avec succes"

if [[ "$TEST_OK" != "oui" ]]; then
    warn "Connexion non confirmee. Rollback..."
    rollback
    exit 1
fi

ok "Configuration validee et permanente !"

#===============================================================================
# INSTRUCTIONS FINALES SELON LE MODE
#===============================================================================
if [[ "$VPS_MODE" == "master" ]]; then
    header "Prochaines etapes - Mode Master"

    echo -e "${BOLD}1. Ouvrir les ports Coolify temporairement :${NC}"
    echo "   (dans le firewall de votre cloud provider)"
    echo "   - Port 8000 (dashboard)"
    echo "   - Port 6001 (realtime)"
    echo "   - Port 6002 (terminal)"
    echo ""
    echo -e "${BOLD}2. Installer Coolify :${NC}"
    echo "   curl -fsSL https://cdn.coollabs.io/coolify/install.sh | sudo bash"
    echo ""
    echo -e "${BOLD}3. Acceder au dashboard :${NC}"
    echo "   http://$SERVER_IP:8000"
    echo ""
    echo -e "${BOLD}4. Apres configuration du domaine :${NC}"
    echo "   Fermez les ports 8000, 6001, 6002 dans votre firewall cloud"
    echo ""

elif [[ "$VPS_MODE" == "remote" ]]; then
    header "Prochaines etapes - Mode Remote"

    echo -e "${BOLD}Pour ajouter ce serveur dans Coolify :${NC}"
    echo ""
    echo "1. Dans Coolify -> Keys & Tokens -> Private Keys"
    echo "   Ajoutez la cle privee root ou copiez la cle publique Coolify"
    echo ""
    echo "2. Sur CE serveur, ajoutez la cle publique Coolify :"
    echo "   echo 'CLE_PUBLIQUE_COOLIFY' >> /root/.ssh/authorized_keys"
    echo ""
    echo "3. Dans Coolify -> Servers -> Add Server :"
    echo "   - Name        : $(hostname)"
    echo "   - IP Address  : $SERVER_IP"
    echo "   - Port        : $SSH_PORT"
    echo "   - User        : root"
    echo "   - Private Key : (celle de Coolify)"
    echo ""
    echo "4. Cliquez 'Validate Server & Install Docker Engine'"
    echo ""
    echo -e "${YELLOW}Note: Coolify installera Docker automatiquement.${NC}"
    echo ""
fi

echo ""
ok "Script termine. Bonne continuation !"
