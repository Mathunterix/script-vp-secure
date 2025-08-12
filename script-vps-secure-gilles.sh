#!/bin/bash

# Script pour sécuriser son VPS + compatibilité Coolify
# Inspiré MozzyPC (https://www.youtube.com/@mozzypc) + optimisé IA/Consultant IA
# Dernière mise à jour 05/2025

set -e  # Arrête le script en cas d'erreur

# === Déclaration des variables ===
ACTIONS_DONE=()  # Liste des actions effectuées pour un éventuel rollback
TIMESTAMP=$(date +"%Y-%m-%d_%H%M%S") # Timestamp unique pour les fichiers de backup

# === Ajout de couleurs pour améliorer l'affichage ===
RED="\033[1;31m"
GREEN="\033[1;32m"
BLUE="\033[1;34m"
CYAN="\033[1;36m"
YELLOW="\033[1;33m"
NC="\033[0m"  # No Color

# === Fonction d'affichage de message ===
show_info() {
    echo -e "${BLUE}$1${NC}"
}

show_secondary() {
    echo -e "${CYAN}$1${NC}" >&2
}

show_success() {
    echo -e "${GREEN}$1${NC}"
}

show_warn() {
    echo -e "${YELLOW}$1${NC}"
}

show_error() {
    echo -e "${RED}❌ $1${NC}" >&2
}

# Fonction générique pour demander une entrée utilisateur avec validation
prompt_user() {
    local prompt_text="$1"
    local default_value="$2"
    local validate_func="$3"
    local user_input

    while true; do
        show_secondary "$prompt_text [${default_value}]: "
        read -r user_input
        user_input="${user_input:-$default_value}"  # Si entrée vide, prendre la valeur par défaut

        if [[ -n "$validate_func" ]]; then
            if "$validate_func" "$user_input"; then
                echo "$user_input"
                return 0
            fi
        fi
    done
}

# Fonctions de validation pour un username linux
validate_username() {
    local username="$1"
    if [[ ${#username} -gt 64 ]]; then
        show_error "Le nom d'utilisateur ne peut pas dépasser 64 caractères."
        return 1
    fi
    if [[ "$username" =~ ^[a-z][-a-z0-9_]*\$?$ ]]; then
        return 0
    else
        show_error "Le nom d'utilisateur '$username' est invalide."
        return 1
    fi
}

# Fonction de validation pour une IP ou CIDR
validate_ip() {
    local ip=$1
    if [[ "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}(/([0-9]|[1-2][0-9]|3[0-2]))?$ ]]; then
        return 0
    else
        show_error "L'adresse IP ou CIDR $ip est invalide."
        return 1
    fi
}

# Fonction de validation pour une liste d'IPs/CIDR
validate_ips_list() {
    local ips=$1
    for ip in $ips; do
        if ! validate_ip "$ip"; then
            return 1
        fi
    done
    return 0
}

# Fonction de validation pour un port SSH libre
validate_port() {
    local port="$1"
    if [[ "$port" =~ ^[0-9]+$ && "$port" -ge 1024 && "$port" -le 65535 ]]; then
        if ss -tuln | grep -q ":$port"; then
            show_error "Le port $port est déjà utilisé."
            return 1
        else
            return 0
        fi
    else
        show_error "Le port doit être un nombre entre 1024 et 65535."
        return 1
    fi
}

# Fonction de validation pour oui/non
validate_yes_no() {
    local input="$1"
    if [[ "$input" =~ ^(oui|non|y|n|O|N)$ ]]; then
        return 0
    else
        show_error "Réponse invalide. Veuillez répondre par 'oui' ou 'non'."
        return 1
    fi
}

# Génère un port SSH aléatoire entre 10000 et 65535 non utilisé
generate_random_port() {
    local port
    while true; do
        port=$((RANDOM % 55535 + 10000))
        if ! ss -tuln | grep -q ":$port "; then
            echo "$port"
            return
        fi
    done
}

# Vérification du port SSH (avec ss et fallback netstat)
check_ssh_port() {
    local port="$1"
    if command -v ss &>/dev/null; then
        ss -tuln | grep -q ":$port"
    elif command -v netstat &>/dev/null; then
        netstat -tuln | grep -q ":$port"
    else
        show_warn "⚠️ Impossible de vérifier le port SSH, ni ss ni netstat n'est disponible."
        return 1
    fi
}

# Wrapper pour gérer les services avec fallback de system manager
manage_service() {
    local service_name="$1"
    local action="$2"  # start, stop, restart, enable, disable

    if systemctl list-units --full -all | grep -q "$service_name.service"; then
        systemctl "$action" "$service_name" &>/dev/null
        show_info "Service $service_name $action avec systemd."
    elif command -v service &>/dev/null && service --status-all 2>/dev/null | grep -q "$service_name"; then
        service "$service_name" "$action" &>/dev/null
        show_info "Service $service_name $action avec service."
    else
        show_warn "⚠️ Impossible de $action $service_name (non détecté ou incompatible)."
    fi
}

# Fonction pour enregistrer une action
register_action() {
    ACTIONS_DONE+=("$1")
}

# Fonction de rollback
rollback() {
    show_error "Un problème est survenu. Annulation des changements..."
    for action in "${ACTIONS_DONE[@]}"; do
        case "$action" in
            "ssh")
                # rollback to backup
                mv "/etc/ssh/sshd_config.bak_$TIMESTAMP" /etc/ssh/sshd_config
                manage_service $SSH_SERVICE restart
                show_success "✅ Configuration SSH restaurée."
                ;;
            "ipv6")
                # rollback to default values
                echo "net.ipv6.conf.all.disable_ipv6 = 0" >> /etc/sysctl.conf
                echo "net.ipv6.conf.default.disable_ipv6 = 0" >> /etc/sysctl.conf
                echo "net.ipv6.conf.lo.disable_ipv6 = 0" >> /etc/sysctl.conf
                sysctl -p &>/dev/null
                show_success "✅ IPv6 restauré."
                ;;
            "icmp")
                # rollback to default values
                echo "net.ipv4.icmp_echo_ignore_all = 0" >> /etc/sysctl.conf
                echo "net.ipv4.icmp_echo_ignore_broadcasts = 1" >> /etc/sysctl.conf
                echo "net.ipv4.icmp_ratelimit = 1000" >> /etc/sysctl.conf
                echo "net.ipv4.icmp_ratemask = 6168" >> /etc/sysctl.conf
                sysctl -p &>/dev/null
                show_success "✅ ICMP Echo restauré."
                ;;
            "firewall")
                # rollback by disabling firewall
                if [[ "$FIREWALL_SERVICE" == "ufw" ]]; then
                    ufw --force reset &>/dev/null
                    ufw disable &>/dev/null
                elif [[ "$FIREWALL_SERVICE" == "firewalld" ]]; then
                    manage_service firewalld stop
                    manage_service firewalld disable
                fi
                show_success "✅ Firewall désactivé."
                ;;
            "fail2ban")
                # rollback by removing custom parameters
                rm -f /etc/fail2ban/jail.local
                manage_service fail2ban restart
                show_success "✅ Fail2ban désactivé."
                ;;
        esac
    done
    show_success "✅ Rollback terminé."
    exit 1
}

# Active le rollback en cas d'échec
trap 'rollback' ERR

# === Precheck ===

# Vérifier si le script est exécuté en tant que root
if [[ $EUID -ne 0 ]]; then
   show_error "Ce script doit être exécuté en tant que root ou avec sudo."
   exit 1
fi

if [[ -f /etc/os-release ]]; then
    . /etc/os-release
    DISTRO=$ID
else
    show_error "Impossible de détecter la distribution. Script interrompu."
    exit 1
fi

# Vérifier le gestionnaire de paquets en fonction de la distribution
if [[ "$DISTRO" =~ ^(ubuntu|debian)$ ]]; then
    PKG_MANAGER="apt"
    FIREWALL_SERVICE="ufw"
    INSTALL_CMD() {
        apt update && apt install -y "$@" &>/dev/null
    }
elif [[ "$DISTRO" =~ ^(centos|rhel|rocky|alma)$ ]]; then
    PKG_MANAGER="dnf"
    FIREWALL_SERVICE="firewalld"
    INSTALL_CMD() {
        dnf install -y "$@" &>/dev/null
    }
elif [[ "$DISTRO" == "fedora" ]]; then
    PKG_MANAGER="dnf"
    FIREWALL_SERVICE="firewalld"
    INSTALL_CMD() {
        dnf install -y "$@" &>/dev/null
    }
elif [[ "$DISTRO" == "arch" ]]; then
    PKG_MANAGER="pacman"
    FIREWALL_SERVICE="ufw"
    INSTALL_CMD() {
        pacman -Syu --noconfirm "$@" &>/dev/null
    }
else
    echo "Distribution non supportée. Script interrompu."
    exit 1
fi

if command -v systemctl &>/dev/null; then
    if systemctl list-units --type=service --all | awk '$2 == "loaded" && $3 == "active"' | grep -E -q '\bssh\.service\b'; then
        SSH_SERVICE="ssh"
    elif systemctl list-units --type=service --all | awk '$2 == "loaded" && $3 == "active"' | grep -E -q '\bsshd\.service\b'; then
        SSH_SERVICE="sshd"
    else
        show_error "Impossible de détecter le service SSH. Script interrompu."
        exit 1
    fi
elif command -v service &>/dev/null; then
    if service --status-all 2>/dev/null | grep -E -q '\bssh\b'; then
        SSH_SERVICE="ssh"
    elif service --status-all 2>/dev/null | grep -E -q '\bsshd\b'; then
        SSH_SERVICE="sshd"
    else
        show_error "Impossible de détecter le service SSH. Script interrompu."
        exit 1
    fi
fi

# === Collecte des informations ===
clear
echo -e "${GREEN}🌟 Configuration du serveur 🌟${NC}"

NEW_USER=$(prompt_user "Quel nom souhaitez-vous pour l'utilisateur sécurisé SSH ?" "secureuser" "validate_username")
RANDOM_SSH_PORT=$(generate_random_port)
SSH_PORT=$(prompt_user "Quel port souhaitez-vous pour SSH ?" "$RANDOM_SSH_PORT" "validate_port")
ALLOWED_SSH_IPS=$(prompt_user "Entrez les IPs ou CIDR autorisés pour SSH (séparées par des espaces)" "" "validate_ips_list")
DISABLE_IPV6=$(prompt_user "Voulez-vous désactiver IPv6 ?" "oui" "validate_yes_no")
LIMIT_ICMP=$(prompt_user "Voulez-vous limiter les réponses ICMP (Ping) ?" "oui" "validate_yes_no")

show_success "🔒 Début de la sécurisation du serveur VPS..."

# === 1. Création du nouvel utilisateur ===
show_info "👤 Création de l'utilisateur SSH : $NEW_USER"
if ! id "$NEW_USER" &>/dev/null; then
    adduser --disabled-password --gecos "" "$NEW_USER"
    show_success "✅ Utilisateur $NEW_USER créé."
else
    show_warn "⚠️ L'utilisateur $NEW_USER existe déjà."
fi

# Ajouter à sudoers
usermod -aG sudo "$NEW_USER"
echo "$NEW_USER ALL=(ALL) NOPASSWD:ALL" | tee /etc/sudoers.d/$NEW_USER >/dev/null
show_success "✅ Ajout de $NEW_USER aux sudoers."

# Ajout au groupe docker pour gestion Coolify sans sudo (reconnexion nécessaire)
if getent group docker > /dev/null; then
    usermod -aG docker "$NEW_USER"
    show_success "✅ Ajout de $NEW_USER au groupe docker (accès Docker/Coolify sans sudo après reconnexion)."
else
    show_warn "❗ Groupe docker non trouvé. Installez Docker pour gestion avancée Coolify."
fi

# === 2. Génération et configuration des clés SSH ===
show_info "🔑 Configuration des clés SSH..."

SSH_DIR="/home/$NEW_USER/.ssh"
mkdir -p "$SSH_DIR"
chmod 700 "$SSH_DIR"

if [[ ! -f "$SSH_DIR/id_ed25519" ]]; then
    ssh-keygen -t ed25519 -f "$SSH_DIR/id_ed25519" -N ""
    show_success "✅ Clé SSH ED25519 générée."
fi

cat "$SSH_DIR/id_ed25519.pub" >> "$SSH_DIR/authorized_keys"
chmod 600 "$SSH_DIR/authorized_keys"
chown -R "$NEW_USER:$NEW_USER" "$SSH_DIR"

show_success "✅ Clé SSH installée pour $NEW_USER."

# === 3. Sécurisation du service SSH ===
show_info "🔧 Sécurisation du service SSH..."

cp /etc/ssh/sshd_config "/etc/ssh/sshd_config.bak_$TIMESTAMP"

sed -i "s/^#Port .*/Port $SSH_PORT/" /etc/ssh/sshd_config
sed -i "s/^#PermitRootLogin .*/PermitRootLogin no/" /etc/ssh/sshd_config
sed -i "s/^#PasswordAuthentication .*/PasswordAuthentication no/" /etc/ssh/sshd_config
sed -i "s/^#PubkeyAuthentication .*/PubkeyAuthentication yes/" /etc/ssh/sshd_config
sed -i "s/^#ChallengeResponseAuthentication .*/ChallengeResponseAuthentication no/" /etc/ssh/sshd_config
sed -i "s/^#UsePAM .*/UsePAM no/" /etc/ssh/sshd_config

manage_service "$SSH_SERVICE" restart

show_success "✅ SSH sécurisé et redémarré."
register_action "ssh"

# === 4. Désactivation de l'IPv6 si demandé ===
if [[ "$DISABLE_IPV6" =~ ^(oui|y|O|o)$ ]]; then
    show_info "🌍 Désactivation de IPv6..."
    echo "net.ipv6.conf.all.disable_ipv6 = 1" >> /etc/sysctl.conf
    echo "net.ipv6.conf.default.disable_ipv6 = 1" >> /etc/sysctl.conf
    echo "net.ipv6.conf.lo.disable_ipv6 = 1" >> /etc/sysctl.conf
    sysctl -p &>/dev/null
    show_success "✅ IPv6 désactivé."
    register_action "ipv6"
else
    show_warn "🌍 IPv6 reste activé."
fi

# === 5. Limitation du Ping (ICMP Echo Reply) si demandé ===
if [[ "$LIMIT_ICMP" =~ ^(oui|y|O|o)$ ]]; then
    show_info "📡 Limitation des réponses aux pings..."
    echo "net.ipv4.icmp_echo_ignore_all = 0" >> /etc/sysctl.conf
    echo "net.ipv4.icmp_echo_ignore_broadcasts = 1" >> /etc/sysctl.conf
    echo "net.ipv4.icmp_ratelimit = 100" >> /etc/sysctl.conf
    echo "net.ipv4.icmp_ratemask = 88089" >> /etc/sysctl.conf
    sysctl -p &>/dev/null
    show_success "✅ ICMP Echo limité."
    register_action "icmp"
else
    show_warn "🔄 Réponses ICMP non limitées."
fi

# === 6. Configuration du firewall ===
show_info "🌐 Configuration du firewall $FIREWALL_SERVICE..."

if [[ "$FIREWALL_SERVICE" == "ufw" ]]; then
    if ! command -v ufw &>/dev/null; then
        show_warn "📦 Installation de UFW..."
        INSTALL_CMD ufw
    fi
    ufw --force reset &>/dev/null
    ufw default deny incoming &>/dev/null
    ufw default allow outgoing &>/dev/null
    ufw allow in on lo &>/dev/null
    ufw allow 80/tcp &>/dev/null
    ufw allow 443/tcp &>/dev/null
    if [[ -n "$ALLOWED_SSH_IPS" ]]; then
        show_info "🔒 Restriction SSH : Seules les IPs/réseaux suivants sont autorisés : $ALLOWED_SSH_IPS"
        for IP in $ALLOWED_SSH_IPS; do
            ufw allow from "$IP" to any port "$SSH_PORT" proto tcp &>/dev/null
        done
    else
        show_success "🌍 SSH ouvert à tous sur le port $SSH_PORT"
        ufw allow "$SSH_PORT"/tcp &>/dev/null
    fi
    ufw deny 22/tcp &>/dev/null
    ufw --force enable &>/dev/null
elif [[ "$FIREWALL_SERVICE" == "firewalld" ]]; then
    firewall-cmd --complete-reload &>/dev/null
    firewall-cmd --set-default-zone=drop &>/dev/null
    firewall-cmd --permanent --zone=drop --add-masquerade &>/dev/null
    firewall-cmd --permanent --zone=trusted --add-interface=lo &>/dev/null
    firewall-cmd --permanent --zone=public --add-service=http &>/dev/null
    firewall-cmd --permanent --zone=public --add-service=https &>/dev/null
    if [[ -n "$ALLOWED_SSH_IPS" ]]; then
        echo "🔒 Restriction SSH : Seules les IPs/réseaux suivants sont autorisés : $ALLOWED_SSH_IPS"
        for IP in $ALLOWED_SSH_IPS; do
            firewall-cmd --permanent --zone=trusted --add-rich-rule="rule family='ipv4' source address='$IP' port protocol='tcp' port='$SSH_PORT' accept" &>/dev/null
        done
    else
        echo "🌍 SSH ouvert à tous sur le port $SSH_PORT"
        firewall-cmd --permanent --zone=public --add-port="$SSH_PORT"/tcp &>/dev/null
    fi
    firewall-cmd --permanent --zone=public --remove-service=ssh &>/dev/null
    firewall-cmd --permanent --zone=public --remove-port=22/tcp &>/dev/null
    firewall-cmd --reload &>/dev/null
fi

show_success "✅ Firewall activé avec règles sécurisées."
register_action "firewall"

# === 7. Installation et configuration de Fail2Ban ===
show_info "🛡️ Installation et configuration de Fail2Ban..."

if ! command -v fail2ban-client &>/dev/null; then
    INSTALL_CMD fail2ban
fi

cat <<EOF > /etc/fail2ban/jail.local
[sshd]
enabled = true
port = $SSH_PORT
filter = sshd
logpath = /var/log/auth.log
maxretry = 5
bantime = 1h
findtime = 10m
EOF

manage_service fail2ban restart
manage_service fail2ban enable

show_success "✅ Fail2Ban configuré pour SSH."
register_action "fail2ban"

sleep 2

if check_ssh_port "$SSH_PORT"; then
    show_success "✅ SSH fonctionne sur le port $SSH_PORT"
else
    show_warn "⚠️ Le service SSH ne semble pas actif sur le bon port. Redémarrage forcé..."
    manage_service "$SSH_SERVICE" restart
    sleep 2
    if check_ssh_port "$SSH_PORT"; then
        show_success "✅ SSH est maintenant actif sur le port $SSH_PORT"
    else
        show_error "SSH ne répond toujours pas ! Vérifiez /etc/ssh/sshd_config et les logs avec journalctl -xe."
        rollback
    fi
fi

show_warn "⚠️  ATTENTION : Sauvegardez bien cette clé privée ! ⚠️"
show_warn "Cette clé est nécessaire pour vous connecter au serveur. Ne la partagez avec personne."
show_warn "Copiez-la et stockez-la dans un endroit sûr (ex: ~/.ssh/vps sur votre machine locale)."
show_info "Votre clé privée SSH :"
show_info "----------------------------------------"
show_info "$(cat $SSH_DIR/id_ed25519)"
show_info "----------------------------------------"

show_success "🎉 Sécurisation terminée !"
show_warn "⚠️  IMPORTANT : NE FERMEZ PAS CETTE SESSION SSH ! ⚠️"
show_warn "Avant de quitter, testez votre nouvelle connexion SSH depuis une autre machine :"
show_secondary "➡ ssh -i ~/.ssh/id_ed25519 -p $SSH_PORT $NEW_USER@<VOTRE_IP>"
show_info "Si la connexion fonctionne, alors vous pouvez fermer cette session."

# === Vérification finale ===
show_info "\n----------------------------------------"
CONFIRM=$(prompt_user "Tout fonctionne bien ? (oui/non) : " "non" "validate_yes_no")

if [[ ! "$CONFIRM" =~ ^(oui|[OoYy])$ ]]; then
    rollback
else
    show_success "✅ Sécurisation validée !"
fi

# --- Notice spéciale Coolify/Docker/n8n ---
show_info "${CYAN}\n--- CONSEILS POUR ADMINISTRER COOLIFY / DOCKER / n8n ---${NC}"
show_info "Pour manipuler Coolify, Docker et tous les services nécessitant des droits root/protégés :"
show_info "1. Pour travailler dans un dossier protégé :"
show_info "   sudo -i"
show_info "   cd /data/coolify/proxy/caddy"
show_info "   # puis gérez vos fichiers (ls, nano, docker-compose...)"
show_info "2. Pour utiliser Docker sans sudo (après reconnexion) :"
show_info "   docker ps"
show_info "   docker compose up -d"
show_info "   (Le groupe docker a été ajouté à $NEW_USER)"
show_info "3. Ne changez jamais les permissions globales de /data/coolify sauf cas particulier."
show_info "4. Refermez le shell root dès que possible ('exit')."
show_info "${CYAN}----------------------------------------${NC}"
