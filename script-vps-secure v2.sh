#!/usr/bin/env bash
# script-vps-secure.sh — version “Coolify-safe”
# - Ajoute un utilisateur SSH, clés, sudo et groupe docker
# - Durcit SSH (ajoute un port custom SANS supprimer 22 tant que non validé)
# - Configure UFW compatible Docker (forwarding OK), ouvre 80/443 + SSH
# - Optionnel: désactive IPv6, limite ICMP
# - Installe et configure Fail2Ban pour le port SSH choisi
#
# Sûr à relancer: idempotent autant que possible.
# Exécution: sudo bash script-vps-secure.sh

set -euo pipefail

### ===== Helpers =====
die(){ echo "ERROR: $*" >&2; exit 1; }
confirm(){ read -r -p "$1 [o/N]: " _r; [[ "${_r:-N}" =~ ^[oOyY]$ ]]; }
ensure_cmd(){ command -v "$1" >/dev/null 2>&1 || die "Commande manquante: $1"; }

### ===== Checks =====
ensure_cmd sed
ensure_cmd grep
ensure_cmd awk
ensure_cmd tee
ensure_cmd systemctl || true

if [[ $EUID -ne 0 ]]; then
  die "Lance-moi en root: sudo bash $0"
fi

OS="$(. /etc/os-release; echo "${ID:-unknown}")"
case "$OS" in
  ubuntu|debian) PKG_UPDATE="apt-get update -y"; PKG_INSTALL="apt-get install -y"; ;;
  *) die "OS non supporté automatiquement ($OS). Script testé sur Debian/Ubuntu." ;;
esac

### ===== Input =====
echo "🌟 Configuration du serveur 🌟"
read -r -p "Quel nom souhaitez-vous pour l'utilisateur sécurisé SSH ? [secureuser]: " SSH_USER
SSH_USER="${SSH_USER:-secureuser}"

read -r -p "Quel port souhaitez-vous pour SSH ? [23214]: " SSH_PORT
SSH_PORT="${SSH_PORT:-23214}"
[[ "$SSH_PORT" =~ ^[0-9]{2,5}$ ]] || die "Port SSH invalide: $SSH_PORT"

read -r -p "Entrez les IPs/CIDR autorisés pour SSH (séparées par espaces, vide = tout le monde) []: " SSH_ALLOWED_IPS
SSH_ALLOWED_IPS="${SSH_ALLOWED_IPS:-}"

read -r -p "Voulez-vous désactiver IPv6 ? [oui/non] [oui]: " DISABLE_IPV6
DISABLE_IPV6="${DISABLE_IPV6:-oui}"

read -r -p "Voulez-vous limiter les réponses ICMP (Ping) ? [oui/non] [oui]: " LIMIT_ICMP
LIMIT_ICMP="${LIMIT_ICMP:-oui}"

SSH_PUBKEY=""
echo "🔑 Si vous voulez installer une clé publique SSH, collez-la (ligne complète 'ssh-ed25519 ...' ou 'ssh-rsa ...')."
echo "   Laissez vide pour ne rien installer (ou si déjà présent)."
read -r -p "Clé publique SSH: " SSH_PUBKEY

echo

### ===== System packages =====
echo "📦 Installation des paquets de base (sudo, ufw, fail2ban, docker si présent déjà pris en compte)..."
eval "$PKG_UPDATE"
$PKG_INSTALL sudo ufw fail2ban curl ca-certificates

### ===== User & groups =====
echo "👤 Création/ajout utilisateur: $SSH_USER"
if id -u "$SSH_USER" >/dev/null 2>&1; then
  echo "⚠️ L'utilisateur $SSH_USER existe déjà."
else
  adduser --disabled-password --gecos "" "$SSH_USER"
fi
usermod -aG sudo "$SSH_USER" || true

# Groupe docker si docker installé
if command -v docker >/dev/null 2>&1; then
  echo "🐳 Ajout de $SSH_USER au groupe docker"
  groupadd -f docker
  usermod -aG docker "$SSH_USER" || true
fi

### ===== SSH key =====
if [[ -n "$SSH_PUBKEY" ]]; then
  echo "🔑 Installation de la clé publique SSH pour $SSH_USER"
  su - "$SSH_USER" -c "mkdir -p ~/.ssh && chmod 700 ~/.ssh"
  AUTH_KEYS="$(eval echo "~$SSH_USER")/.ssh/authorized_keys"
  grep -qxF "$SSH_PUBKEY" "$AUTH_KEYS" 2>/dev/null || echo "$SSH_PUBKEY" >> "$AUTH_KEYS"
  chown "$SSH_USER":"$SSH_USER" "$AUTH_KEYS"
  chmod 600 "$AUTH_KEYS"
else
  echo "ℹ️ Aucune clé publique fournie. (OK si déjà configuré)"
fi

### ===== SSHD configuration =====
SSHD_CFG="/etc/ssh/sshd_config"
echo "🔧 Durcissement SSH dans $SSHD_CFG"

# Sauvegarde
if [[ ! -f "${SSHD_CFG}.bak" ]]; then
  cp "$SSHD_CFG" "${SSHD_CFG}.bak"
fi

# Ajoute ports sans supprimer 22 tant que non validé
grep -qE "^Port[[:space:]]+$SSH_PORT$" "$SSHD_CFG" || echo "Port $SSH_PORT" >> "$SSHD_CFG"
grep -qE "^Port[[:space:]]+22$" "$SSHD_CFG"       || echo "Port 22" >> "$SSHD_CFG"

# Forcer écoute toutes interfaces IPv4 (et IPv6 si actif)
grep -qE "^AddressFamily" "$SSHD_CFG" || echo "AddressFamily any" >> "$SSHD_CFG"
grep -qE "^ListenAddress 0\.0\.0\.0$" "$SSHD_CFG" || echo "ListenAddress 0.0.0.0" >> "$SSHD_CFG"
# On ne force pas ListenAddress :: si IPv6 désactivé derrière

# Interdire password auth si clé installée (optionnel mais recommandé)
if [[ -n "$SSH_PUBKEY" ]]; then
  if grep -qE "^[#]*PasswordAuthentication" "$SSHD_CFG"; then
    sed -i 's/^[#]*PasswordAuthentication.*/PasswordAuthentication no/' "$SSHD_CFG"
  else
    echo "PasswordAuthentication no" >> "$SSHD_CFG"
  fi
fi

# Laisser UsePAM par défaut (évite des surprises)
# On ne touche pas à ChallengeResponseAuthentication, PermitRootLogin, etc., à toi d’ajuster si besoin.

# Tester la conf avant reload
echo "🧪 Test de configuration SSHD"
sshd -t

### ===== UFW (Docker-friendly) =====
echo "🌐 Configuration du firewall UFW (compat Docker)"

# Préparer forwarding pour Docker/Coolify
if [[ -f /etc/default/ufw ]]; then
  sed -i 's/^DEFAULT_FORWARD_POLICY=.*/DEFAULT_FORWARD_POLICY="ACCEPT"/' /etc/default/ufw
fi
if [[ -f /etc/ufw/sysctl.conf ]]; then
  # IPv4 forwarding
  if grep -q '^#\?net/ipv4/ip_forward=' /etc/ufw/sysctl.conf; then
    sed -i 's/^#\?net\/ipv4\/ip_forward=.*/net\/ipv4\/ip_forward=1/' /etc/ufw/sysctl.conf
  else
    echo 'net/ipv4/ip_forward=1' >> /etc/ufw/sysctl.conf
  fi
  # IPv6 forwarding (laisser si IPv6 actif)
  if [[ "${DISABLE_IPV6,,}" != "oui" ]]; then
    if ! grep -q '^net/ipv6/conf/all/forwarding=1' /etc/ufw/sysctl.conf; then
      echo 'net/ipv6/conf/all/forwarding=1' >> /etc/ufw/sysctl.conf
    fi
  fi
fi

# Reset UFW propre
ufw --force reset
ufw default deny incoming
ufw default allow outgoing
ufw allow in on lo

# Règles HTTP/HTTPS
ufw allow 80/tcp  comment 'HTTP'
ufw allow 443/tcp comment 'HTTPS'

# SSH rules
if [[ -n "$SSH_ALLOWED_IPS" ]]; then
  echo "🔒 SSH restreint aux IPs: $SSH_ALLOWED_IPS"
  for ip in $SSH_ALLOWED_IPS; do
    ufw allow from "$ip" to any port "$SSH_PORT" proto tcp comment "SSH custom from $ip"
    ufw allow from "$ip" to any port 22 proto tcp comment "SSH fallback 22 from $ip"
  done
else
  echo "🌍 SSH ouvert à tous (temporaire) sur $SSH_PORT et 22 (filet)"
  ufw allow "$SSH_PORT"/tcp comment 'SSH custom'
  ufw allow 22/tcp           comment 'SSH fallback'
fi

# ICMP (ping)
if [[ "${LIMIT_ICMP,,}" == "oui" ]]; then
  # UFW ne gère pas finement l’ICMP; on agit via sysctl pour limiter echo responses
  SYSCTL="/etc/sysctl.d/99-custom-icmp.conf"
  cat > "$SYSCTL" <<'EOF'
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
net.ipv4.icmp_echo_ignore_all = 0
# Rate limit via token bucket (global kernel tunables)
net.ipv4.icmp_ratelimit = 100
net.ipv4.icmp_ratemask = 88089
EOF
  sysctl --system >/dev/null
  echo "✅ ICMP réglé (limité, pas coupé)."
else
  echo "ℹ️ ICMP laissé par défaut."
fi

# Activer UFW maintenant (avant de toucher au service SSH)
ufw --force enable

### ===== IPv6 global (optionnel) =====
if [[ "${DISABLE_IPV6,,}" == "oui" ]]; then
  echo "🌍 Désactivation globale IPv6 (sysctl)"
  SYSCTL6="/etc/sysctl.d/99-disable-ipv6.conf"
  cat > "$SYSCTL6" <<'EOF'
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1
EOF
  sysctl --system >/dev/null || true
else
  echo "ℹ️ IPv6 conservé."
fi

### ===== Fail2Ban =====
echo "🛡️ Installation/Configuration Fail2Ban"
JAIL_LOCAL="/etc/fail2ban/jail.local"
if [[ ! -f "$JAIL_LOCAL" ]]; then
  touch "$JAIL_LOCAL"
fi

# Jail SSHD sur port custom + fallback 22
if grep -q '^\[sshd\]' "$JAIL_LOCAL"; then
  # update ports line
  sed -i "0,/^port[[:space:]]*=.*/s//port    = $SSH_PORT,22/" "$JAIL_LOCAL" || true
else
  cat >> "$JAIL_LOCAL" <<EOF

[sshd]
enabled = true
port    = $SSH_PORT,22
filter  = sshd
logpath = /var/log/auth.log
maxretry = 5
bantime = 1h
findtime = 10m
EOF
fi

systemctl restart fail2ban
systemctl enable fail2ban

### ===== Reload SSH (après firewall ouvert) =====
echo "🔄 Reload du service SSH"
if systemctl status ssh >/dev/null 2>&1; then
  systemctl reload ssh
elif systemctl status sshd >/dev/null 2>&1; then
  systemctl reload sshd
else
  # fallback
  service ssh reload || service sshd reload || true
fi

### ===== Post-check =====
echo "🧪 Vérification écoute des ports"
ss -ltn | awk 'NR==1 || /:(22|'"$SSH_PORT"')\b/ {print}'

echo
echo "📋 Rappels IMPORTANTS:"
echo "  1) Ouvre le port TCP/$SSH_PORT dans le FIREWALL DU PROVIDER (panel VPS / security group)."
echo "  2) Teste depuis un autre terminal:"
echo "     ssh -p $SSH_PORT $SSH_USER@VOTRE_IP -i ~/.ssh/VOTRE_CLE"
echo "  3) Quand c'est OK, tu peux fermer le filet de sécurité (port 22) avec:"
echo "     sudo ufw delete allow 22/tcp"
echo "     sudo sed -i '/^Port 22\$/d' $SSHD_CFG && sudo sshd -t && sudo systemctl reload ssh || sudo systemctl reload sshd"
echo

echo "✅ Configuration terminée."
