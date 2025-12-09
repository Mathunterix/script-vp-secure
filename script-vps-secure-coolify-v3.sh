#!/usr/bin/env bash
#===============================================================================
# script-vps-secure-coolify-v3.sh
# Sécurisation VPS compatible Coolify (Maître ou Agent)
# Version : 3.1 (2025-12-09)
#
# Fonctionnalités :
# - Création utilisateur SSH sécurisé avec clé ED25519
# - Port SSH personnalisé (port 22 gardé pour Coolify)
# - UFW compatible Docker/Coolify
# - Fail2Ban pour protection brute-force
# - Unattended-upgrades pour mises à jour de sécurité automatiques
# - Mode Coolify : autorise root via clé SSH + host.docker.internal
# - Rollback automatique en cas de problème
#
# Ce script protège contre 95% des attaques automatisées :
# - Brute-force SSH (fail2ban + clé ED25519)
# - Scans de ports (UFW + port non-standard)
# - Exploits connus (unattended-upgrades)
#
# Usage : sudo bash script-vps-secure-coolify-v3.sh
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

info()    { echo -e "${BLUE}ℹ${NC}  $*"; }
ok()      { echo -e "${GREEN}✅${NC} $*"; }
warn()    { echo -e "${YELLOW}⚠️${NC}  $*"; }
err()     { echo -e "${RED}❌${NC} $*" >&2; }
die()     { err "$*"; exit 1; }
header()  { echo -e "\n${CYAN}═══════════════════════════════════════════════════════════${NC}"; echo -e "${CYAN}  $*${NC}"; echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}\n"; }

#===============================================================================
# VÉRIFICATIONS PRÉLIMINAIRES
#===============================================================================
[[ $EUID -eq 0 ]] || die "Ce script doit être lancé en root : sudo bash $0"

# Détecter l'OS
if [[ -f /etc/os-release ]]; then
    . /etc/os-release
    DISTRO="${ID:-unknown}"
else
    die "Impossible de détecter la distribution."
fi

case "$DISTRO" in
    ubuntu|debian)
        PKG_UPDATE="apt-get update -y"
        PKG_INSTALL="apt-get install -y"
        ;;
    *)
        die "Distribution non supportée ($DISTRO). Ce script fonctionne sur Debian/Ubuntu."
        ;;
esac

# Détecter le service SSH
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
    [[ ${#u} -le 32 && "$u" =~ ^[a-z][a-z0-9_-]*$ ]] && return 0
    err "Username invalide (minuscules, chiffres, _ ou -, max 32 chars)"
    return 1
}

validate_port() {
    local p="$1"
    if [[ "$p" =~ ^[0-9]+$ && "$p" -ge 1024 && "$p" -le 65535 ]]; then
        if ! ss -tuln 2>/dev/null | grep -q ":$p "; then
            return 0
        fi
        err "Le port $p est déjà utilisé"
    else
        err "Port invalide (doit être entre 1024 et 65535)"
    fi
    return 1
}

generate_random_port() {
    local port
    while true; do
        port=$((RANDOM % 55535 + 10000))
        if ! ss -tuln 2>/dev/null | grep -q ":$port "; then
            echo "$port"
            return
        fi
    done
}

prompt() {
    local msg="$1" default="$2" var
    echo -en "${CYAN}$msg${NC} [${default}]: "
    read -r var
    echo "${var:-$default}"
}

prompt_yn() {
    local msg="$1" default="$2" var
    echo -en "${CYAN}$msg${NC} (oui/non) [${default}]: "
    read -r var
    var="${var:-$default}"
    [[ "${var,,}" =~ ^(oui|o|yes|y)$ ]] && echo "oui" || echo "non"
}

#===============================================================================
# CONFIGURATION INTERACTIVE
#===============================================================================
clear
header "🔐 Sécurisation VPS Compatible Coolify"

echo -e "${YELLOW}Ce script va :${NC}"
echo "  • Créer un utilisateur SSH sécurisé avec clé ED25519"
echo "  • Configurer un port SSH personnalisé"
echo "  • Configurer UFW (compatible Docker/Coolify)"
echo "  • Installer Fail2Ban"
echo "  • Garder le port 22 accessible pour Coolify"
echo ""

# Type de VPS
echo -e "${YELLOW}Type de VPS :${NC}"
echo "  1) VPS Maître (Coolify installé dessus)"
echo "  2) VPS Agent (géré par Coolify distant)"
echo "  3) VPS Standard (pas de Coolify)"
echo -en "${CYAN}Votre choix${NC} [2]: "
read -r VPS_TYPE
VPS_TYPE="${VPS_TYPE:-2}"

case "$VPS_TYPE" in
    1) VPS_MODE="master" ;;
    3) VPS_MODE="standard" ;;
    *) VPS_MODE="agent" ;;
esac

echo ""
info "Mode sélectionné : ${VPS_MODE^^}"
echo ""

# Username
while true; do
    SSH_USER=$(prompt "Nom d'utilisateur SSH sécurisé" "deploy")
    validate_username "$SSH_USER" && break
done

# Port SSH
RANDOM_PORT=$(generate_random_port)
while true; do
    SSH_PORT=$(prompt "Port SSH personnalisé" "$RANDOM_PORT")
    validate_port "$SSH_PORT" && break
done

# IPs autorisées
SSH_ALLOWED_IPS=$(prompt "IPs autorisées pour SSH (espace = toutes)" "")

# Génération de clé
GEN_KEYS=$(prompt_yn "Générer une nouvelle clé SSH ED25519" "oui")

# Options supplémentaires
DISABLE_IPV6=$(prompt_yn "Désactiver IPv6" "non")
LIMIT_ICMP=$(prompt_yn "Limiter les réponses ICMP (ping)" "oui")

# Résumé
header "📋 Résumé de la configuration"
echo "  Mode VPS         : $VPS_MODE"
echo "  Utilisateur      : $SSH_USER"
echo "  Port SSH         : $SSH_PORT"
echo "  IPs autorisées   : ${SSH_ALLOWED_IPS:-Toutes}"
echo "  Générer clé      : $GEN_KEYS"
echo "  Désactiver IPv6  : $DISABLE_IPV6"
echo "  Limiter ICMP     : $LIMIT_ICMP"
echo ""

CONFIRM=$(prompt_yn "Confirmer et lancer la sécurisation" "oui")
[[ "$CONFIRM" == "oui" ]] || die "Annulé par l'utilisateur."

#===============================================================================
# VARIABLES DE BACKUP (pour rollback)
#===============================================================================
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
SSHD_CFG="/etc/ssh/sshd_config"
SSHD_BAK="/etc/ssh/sshd_config.bak_$TIMESTAMP"
UFW_BAK="/root/ufw-backup-$TIMESTAMP.tgz"
SYSCTL_FILE="/etc/sysctl.d/99-vps-secure.conf"
ACTIONS_DONE=()

register_action() { ACTIONS_DONE+=("$1"); }

rollback() {
    echo ""
    warn "Problème détecté. Rollback en cours..."
    
    for action in "${ACTIONS_DONE[@]}"; do
        case "$action" in
            ssh)
                [[ -f "$SSHD_BAK" ]] && cp -f "$SSHD_BAK" "$SSHD_CFG"
                systemctl restart "$SSH_SERVICE" 2>/dev/null || true
                ok "SSH restauré"
                ;;
            ufw)
                ufw --force disable 2>/dev/null || true
                if [[ -f "$UFW_BAK" ]]; then
                    tar xzf "$UFW_BAK" -C / 2>/dev/null || true
                    ufw --force enable 2>/dev/null || true
                else
                    ufw --force reset 2>/dev/null || true
                fi
                ok "UFW restauré"
                ;;
            sysctl)
                rm -f "$SYSCTL_FILE" 2>/dev/null || true
                sysctl --system 2>/dev/null || true
                ok "Sysctl restauré"
                ;;
            fail2ban)
                rm -f /etc/fail2ban/jail.local 2>/dev/null || true
                systemctl restart fail2ban 2>/dev/null || true
                ok "Fail2Ban restauré"
                ;;
        esac
    done
    
    ok "Rollback terminé."
    exit 1
}

trap 'rollback' ERR

#===============================================================================
# INSTALLATION DES PAQUETS
#===============================================================================
header "📦 Installation des paquets"

info "Mise à jour des paquets..."
eval "$PKG_UPDATE" >/dev/null 2>&1

info "Installation de sudo, ufw, fail2ban, unattended-upgrades..."
$PKG_INSTALL sudo ufw fail2ban curl ca-certificates unattended-upgrades apt-listchanges >/dev/null 2>&1
ok "Paquets installés"

# Configuration des mises à jour automatiques de sécurité
info "Configuration des mises à jour de sécurité automatiques..."
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
ok "Mises à jour de sécurité automatiques configurées"

#===============================================================================
# CRÉATION DE L'UTILISATEUR
#===============================================================================
header "👤 Configuration utilisateur : $SSH_USER"

if id -u "$SSH_USER" >/dev/null 2>&1; then
    warn "L'utilisateur $SSH_USER existe déjà"
else
    adduser --disabled-password --gecos "" "$SSH_USER" >/dev/null 2>&1
    ok "Utilisateur $SSH_USER créé"
fi

# Ajouter aux groupes sudo et docker
usermod -aG sudo "$SSH_USER" 2>/dev/null || true
echo "$SSH_USER ALL=(ALL) NOPASSWD:ALL" > "/etc/sudoers.d/$SSH_USER"
chmod 440 "/etc/sudoers.d/$SSH_USER"
ok "$SSH_USER ajouté aux sudoers (NOPASSWD)"

if command -v docker >/dev/null 2>&1; then
    groupadd -f docker 2>/dev/null || true
    usermod -aG docker "$SSH_USER" 2>/dev/null || true
    ok "$SSH_USER ajouté au groupe docker"
fi

#===============================================================================
# GÉNÉRATION DE CLÉ SSH
#===============================================================================
PRIV_KEY_PATH=""
if [[ "$GEN_KEYS" == "oui" ]]; then
    header "🔑 Génération de la clé SSH ED25519"
    
    SSH_DIR="/home/$SSH_USER/.ssh"
    mkdir -p "$SSH_DIR"
    chmod 700 "$SSH_DIR"
    
    PRIV_KEY_PATH="$SSH_DIR/id_ed25519_$TIMESTAMP"
    ssh-keygen -t ed25519 -N "" -f "$PRIV_KEY_PATH" -C "$SSH_USER@$(hostname)" >/dev/null 2>&1
    
    # Installer la clé publique
    cat "${PRIV_KEY_PATH}.pub" >> "$SSH_DIR/authorized_keys"
    chmod 600 "$SSH_DIR/authorized_keys"
    chown -R "$SSH_USER:$SSH_USER" "$SSH_DIR"
    
    ok "Clé ED25519 générée"
fi

#===============================================================================
# CONFIGURATION SSH
#===============================================================================
header "🔧 Configuration SSH"

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

# Configuration de base
set_sshd_option "Port" "$SSH_PORT"
set_sshd_option "PubkeyAuthentication" "yes"
set_sshd_option "PasswordAuthentication" "no"
set_sshd_option "ChallengeResponseAuthentication" "no"
set_sshd_option "AddressFamily" "any"
set_sshd_option "ListenAddress" "0.0.0.0"

# Configuration spécifique selon le mode
case "$VPS_MODE" in
    master)
        # VPS Maître : garder port 22 + root via clé pour Coolify local
        grep -qE "^Port 22$" "$SSHD_CFG" || echo "Port 22" >> "$SSHD_CFG"
        set_sshd_option "PermitRootLogin" "prohibit-password"
        set_sshd_option "UsePAM" "yes"
        info "Mode Maître : Port 22 + root (clé) activés pour Coolify"
        ;;
    agent)
        # VPS Agent : garder port 22 + root via clé pour déploiement Coolify distant
        grep -qE "^Port 22$" "$SSHD_CFG" || echo "Port 22" >> "$SSHD_CFG"
        set_sshd_option "PermitRootLogin" "prohibit-password"
        set_sshd_option "UsePAM" "yes"
        info "Mode Agent : Port 22 + root (clé) pour Coolify distant"
        ;;
    standard)
        # VPS Standard : sécurité maximale, pas de port 22
        set_sshd_option "PermitRootLogin" "no"
        set_sshd_option "UsePAM" "no"
        info "Mode Standard : sécurité maximale"
        ;;
esac

# Vérifier la config
if ! sshd -t 2>/dev/null; then
    err "Erreur dans la configuration SSH"
    rollback
fi

register_action "ssh"
ok "Configuration SSH appliquée"

#===============================================================================
# HOST.DOCKER.INTERNAL (pour Coolify)
#===============================================================================
if [[ "$VPS_MODE" != "standard" ]]; then
    header "🐳 Configuration Docker/Coolify"
    
    # Ajouter host.docker.internal si pas présent
    if ! grep -q "host.docker.internal" /etc/hosts; then
        # Utiliser l'IP locale ou l'IP principale
        LOCAL_IP=$(hostname -I | awk '{print $1}')
        echo "$LOCAL_IP host.docker.internal" >> /etc/hosts
        ok "host.docker.internal ajouté (/etc/hosts)"
    else
        ok "host.docker.internal déjà présent"
    fi
fi

#===============================================================================
# CONFIGURATION UFW
#===============================================================================
header "🔥 Configuration Firewall (UFW)"

# Backup UFW
tar czf "$UFW_BAK" /etc/ufw 2>/dev/null || true

# Configuration pour Docker
if [[ -f /etc/default/ufw ]]; then
    sed -i 's/^DEFAULT_FORWARD_POLICY=.*/DEFAULT_FORWARD_POLICY="ACCEPT"/' /etc/default/ufw
fi

if [[ -f /etc/ufw/sysctl.conf ]]; then
    if grep -q '^#\?net/ipv4/ip_forward=' /etc/ufw/sysctl.conf; then
        sed -i 's/^#\?net\/ipv4\/ip_forward=.*/net\/ipv4\/ip_forward=1/' /etc/ufw/sysctl.conf
    else
        echo 'net/ipv4/ip_forward=1' >> /etc/ufw/sysctl.conf
    fi
fi

# Reset et configuration
ufw --force reset >/dev/null 2>&1
ufw default deny incoming >/dev/null 2>&1
ufw default allow outgoing >/dev/null 2>&1

# Loopback
ufw allow in on lo >/dev/null 2>&1

# HTTP/HTTPS (obligatoire pour services web)
ufw allow 80/tcp comment 'HTTP' >/dev/null 2>&1
ufw allow 443/tcp comment 'HTTPS' >/dev/null 2>&1

# SSH personnalisé
if [[ -n "$SSH_ALLOWED_IPS" ]]; then
    for ip in $SSH_ALLOWED_IPS; do
        ufw allow from "$ip" to any port "$SSH_PORT" proto tcp comment "SSH custom" >/dev/null 2>&1
    done
    info "SSH port $SSH_PORT restreint aux IPs : $SSH_ALLOWED_IPS"
else
    ufw allow "$SSH_PORT"/tcp comment 'SSH custom' >/dev/null 2>&1
    info "SSH port $SSH_PORT ouvert à tous"
fi

# Port 22 pour Coolify
if [[ "$VPS_MODE" != "standard" ]]; then
    ufw allow 22/tcp comment 'SSH Coolify' >/dev/null 2>&1
    info "Port 22 ouvert pour Coolify"
fi

register_action "ufw"
ufw --force enable >/dev/null 2>&1
ok "UFW configuré et activé"

#===============================================================================
# SYSCTL (IPv6, ICMP)
#===============================================================================
header "⚙️ Configuration système (sysctl)"

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
    info "IPv6 désactivé"
fi

if [[ "$LIMIT_ICMP" == "oui" ]]; then
    cat >> "$SYSCTL_FILE" <<'EOF'
# Limit ICMP
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
net.ipv4.icmp_ratelimit = 100
net.ipv4.icmp_ratemask = 88089
EOF
    info "ICMP limité"
fi

sysctl --system >/dev/null 2>&1
register_action "sysctl"
ok "Sysctl configuré"

#===============================================================================
# FAIL2BAN
#===============================================================================
header "🛡️ Configuration Fail2Ban"

# Ports à protéger
if [[ "$VPS_MODE" != "standard" ]]; then
    F2B_PORTS="$SSH_PORT,22"
else
    F2B_PORTS="$SSH_PORT"
fi

cat > /etc/fail2ban/jail.local <<EOF
[sshd]
enabled = true
port = $F2B_PORTS
filter = sshd
logpath = /var/log/auth.log
maxretry = 5
bantime = 1h
findtime = 10m
EOF

systemctl restart fail2ban >/dev/null 2>&1
systemctl enable fail2ban >/dev/null 2>&1 || true
register_action "fail2ban"
ok "Fail2Ban configuré (protection ports : $F2B_PORTS)"

#===============================================================================
# REDÉMARRAGE SSH
#===============================================================================
header "🔄 Application de la configuration SSH"

systemctl reload "$SSH_SERVICE" 2>/dev/null || systemctl restart "$SSH_SERVICE"

# Vérifier que SSH écoute sur le bon port
sleep 2
if ss -tuln | grep -q ":$SSH_PORT "; then
    ok "SSH actif sur le port $SSH_PORT"
else
    warn "SSH ne semble pas écouter sur $SSH_PORT, tentative de restart..."
    systemctl restart "$SSH_SERVICE"
    sleep 2
    if ss -tuln | grep -q ":$SSH_PORT "; then
        ok "SSH maintenant actif sur le port $SSH_PORT"
    else
        err "Problème avec SSH"
        rollback
    fi
fi

#===============================================================================
# RÉCAPITULATIF
#===============================================================================
header "🎉 Sécurisation terminée !"

echo -e "${GREEN}Configuration appliquée :${NC}"
echo "  • Utilisateur         : $SSH_USER (sudo sans mot de passe)"
echo "  • Port SSH            : $SSH_PORT"
if [[ "$VPS_MODE" != "standard" ]]; then
echo "  • Port 22             : Ouvert (Coolify)"
fi
echo "  • Fail2Ban            : Actif"
echo "  • UFW                 : Actif (Docker compatible)"
echo "  • Unattended-Upgrades : Actif (mises à jour sécurité auto)"
echo ""

# Afficher la clé privée si générée
if [[ -n "$PRIV_KEY_PATH" && -f "$PRIV_KEY_PATH" ]]; then
    echo -e "${YELLOW}╔══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${YELLOW}║  ⚠️  CLÉ PRIVÉE SSH - À SAUVEGARDER IMMÉDIATEMENT !          ║${NC}"
    echo -e "${YELLOW}╚══════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "${RED}Copiez cette clé dans votre gestionnaire de mots de passe !${NC}"
    echo -e "${RED}Elle ne sera plus jamais affichée.${NC}"
    echo ""
    echo "─────────────────── DÉBUT CLÉ PRIVÉE ───────────────────"
    cat "$PRIV_KEY_PATH"
    echo "────────────────────── FIN CLÉ PRIVÉE ──────────────────"
    echo ""
    echo -e "Sur votre machine locale, créez le fichier :"
    echo -e "  ${CYAN}~/.ssh/${SSH_USER}_$(hostname)_ed25519${NC}"
    echo -e "Puis : ${CYAN}chmod 600 ~/.ssh/${SSH_USER}_$(hostname)_ed25519${NC}"
    echo ""
fi

# Instructions de connexion
SERVER_IP=$(curl -s ifconfig.me 2>/dev/null || hostname -I | awk '{print $1}')
echo -e "${YELLOW}═══════════════════════════════════════════════════════════${NC}"
echo -e "${YELLOW}  📡 TESTEZ VOTRE CONNEXION (NOUVELLE FENÊTRE TERMINAL)${NC}"
echo -e "${YELLOW}═══════════════════════════════════════════════════════════${NC}"
echo ""
echo -e "  ${CYAN}ssh -i ~/.ssh/${SSH_USER}_$(hostname)_ed25519 -p $SSH_PORT $SSH_USER@$SERVER_IP${NC}"
echo ""
echo -e "${RED}⚠️  NE FERMEZ PAS CETTE SESSION avant d'avoir testé !${NC}"
echo ""

# Confirmation finale
read -r -p "$(echo -e "${CYAN}La nouvelle connexion fonctionne ? (oui/non)${NC} [non]: ")" TEST_OK
TEST_OK="${TEST_OK:-non}"

if [[ ! "${TEST_OK,,}" =~ ^(oui|o|yes|y)$ ]]; then
    rollback
    exit 1
fi

ok "Configuration validée et permanente !"

#===============================================================================
# OPTION : FERMER LE PORT 22 (uniquement mode standard ou si souhaité)
#===============================================================================
if [[ "$VPS_MODE" == "standard" ]]; then
    echo ""
    ok "Mode standard : le port 22 n'a pas été ouvert."
else
    echo ""
    warn "Le port 22 reste ouvert pour Coolify."
    echo "Si vous n'utilisez plus Coolify sur ce serveur, vous pouvez le fermer avec :"
    echo "  sudo ufw delete allow 22/tcp"
    echo "  sudo sed -i '/^Port 22$/d' /etc/ssh/sshd_config"
    echo "  sudo systemctl reload ssh"
fi

#===============================================================================
# INFORMATIONS COOLIFY
#===============================================================================
if [[ "$VPS_MODE" != "standard" ]]; then
    header "📋 Configuration Coolify"
    
    echo -e "${GREEN}Pour ajouter ce serveur dans Coolify :${NC}"
    echo ""
    echo "1. Dans Coolify → Keys & Tokens → Private Keys"
    echo "   Ajoutez la clé privée root du serveur"
    echo "   (ou copiez la clé publique Coolify dans /root/.ssh/authorized_keys)"
    echo ""
    echo "2. Dans Coolify → Servers → Add Server"
    echo "   • Name        : $(hostname)"
    echo "   • IP Address  : $SERVER_IP"
    echo "   • Port        : 22"
    echo "   • User        : root"
    echo "   • Private Key : (celle ajoutée à l'étape 1)"
    echo ""
    
    if [[ "$VPS_MODE" == "master" ]]; then
        echo -e "${YELLOW}Pour ce VPS Maître, n'oubliez pas :${NC}"
        echo "  • Ouvrir temporairement le port 8000 pour l'installation Coolify"
        echo "  • Installer Coolify : curl -fsSL https://cdn.coollabs.io/coolify/install.sh | sudo bash"
    fi
fi

echo ""
ok "Script terminé. Bonne continuation ! 🚀"
