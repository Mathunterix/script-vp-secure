#!/usr/bin/env bash
# script-vps-secure-v3.sh — Fusion "comfort + safe"
# - UI interactive (couleurs), génération et AFFICHAGE de la clé privée (à ta demande)
# - Séquence safe: UFW (compat Docker) AVANT reload SSH, Port 22 conservé en filet
# - AddressFamily any + ListenAddress 0.0.0.0 pour éviter l'écoute locale-only
# - Fail2Ban protège le port custom + 22 pendant la transition
# - Test guidé : si tu réponds "non", ROLLBACK propre (sshd_config + UFW + sysctl)
# - Compatible Debian/Ubuntu

set -euo pipefail

# -------- UI helpers --------
C0="\033[0m"; C1="\033[1;36m"; C2="\033[1;32m"; C3="\033[1;33m"; C4="\033[1;31m"
info(){ echo -e "${C1}ℹ${C0} $*"; }
ok(){   echo -e "${C2}✅${C0} $*"; }
warn(){ echo -e "${C3}⚠️ ${C0} $*"; }
err(){  echo -e "${C4}❌${C0} $*"; }
die(){ err "$*"; exit 1; }

require_cmd(){ command -v "$1" >/dev/null 2>&1 || die "Commande manquante: $1"; }

[[ $EUID -eq 0 ]] || die "Lance-moi en root: sudo bash $0"
require_cmd sed; require_cmd grep; require_cmd awk; require_cmd tee; require_cmd systemctl || true

. /etc/os-release || true
OS="${ID:-unknown}"
case "$OS" in
  ubuntu|debian) PKG_UPDATE="apt-get update -y"; PKG_INSTALL="apt-get install -y";;
  *) die "OS non supporté ($OS). Testé sur Debian/Ubuntu.";;
esac

# -------- Inputs --------
echo -e "${C1}🌟 Configuration du serveur 🌟${C0}"
read -r -p "Quel nom d'utilisateur SSH sécurisé ? [secureuser]: " SSH_USER
SSH_USER="${SSH_USER:-secureuser}"

read -r -p "Quel port souhaitez-vous pour SSH ? [23214]: " SSH_PORT
SSH_PORT="${SSH_PORT:-23214}"
[[ "$SSH_PORT" =~ ^[0-9]{2,5}$ ]] || die "Port SSH invalide: $SSH_PORT"

read -r -p "IPs/CIDR autorisés pour SSH (séparés par espaces, vide = tout le monde) []: " SSH_ALLOWED_IPS
SSH_ALLOWED_IPS="${SSH_ALLOWED_IPS:-}"

read -r -p "Désactiver IPv6 ? [oui/non] [non]: " DISABLE_IPV6
DISABLE_IPV6="${DISABLE_IPV6:-non}"

read -r -p "Limiter les réponses ICMP (Ping) ? [oui/non] [oui]: " LIMIT_ICMP
LIMIT_ICMP="${LIMIT_ICMP:-oui}"

read -r -p "Générer une nouvelle PAIRE DE CLÉS SSH pour $SSH_USER et L'AFFICHER à l'écran ? [oui/non] [oui]: " GEN_KEYS
GEN_KEYS="${GEN_KEYS:-oui}"

# -------- Packages --------
info "Installation des paquets (sudo, ufw, fail2ban)…"
eval "$PKG_UPDATE"
$PKG_INSTALL sudo ufw fail2ban curl ca-certificates

# -------- User --------
info "Création/ajout utilisateur: $SSH_USER"
if id -u "$SSH_USER" >/dev/null 2>&1; then
  warn "L'utilisateur $SSH_USER existe déjà."
else
  adduser --disabled-password --gecos "" "$SSH_USER"
fi
usermod -aG sudo "$SSH_USER" || true
if command -v docker >/dev/null 2>&1; then
  groupadd -f docker
  usermod -aG docker "$SSH_USER" || true
fi

# -------- Keypair (optional) --------
PRIV_TMP=""
PUB_TMP=""
if [[ "${GEN_KEYS,,}" == "oui" ]]; then
  require_cmd ssh-keygen
  info "Génération d'une paire de clés ed25519 pour $SSH_USER…"
  PRIV_TMP="/root/${SSH_USER}_${SSH_PORT}_ed25519"
  PUB_TMP="${PRIV_TMP}.pub"
  ssh-keygen -t ed25519 -N "" -f "$PRIV_TMP" >/dev/null
  ok "Clés générées: $PRIV_TMP (privée), $PUB_TMP (publique)"
  # Install pubkey for user
  su - "$SSH_USER" -c "mkdir -p ~/.ssh && chmod 700 ~/.ssh"
  AUTH_KEYS="$(eval echo "~$SSH_USER")/.ssh/authorized_keys"
  touch "$AUTH_KEYS"; chmod 600 "$AUTH_KEYS"; chown "$SSH_USER":"$SSH_USER" "$AUTH_KEYS"
  grep -qxF "$(cat "$PUB_TMP")" "$AUTH_KEYS" || cat "$PUB_TMP" >> "$AUTH_KEYS"
else
  info "Pas de génération de clé. (On laisse tes clés en place telles quelles.)"
fi

# -------- Backups for rollback --------
SSHD_CFG="/etc/ssh/sshd_config"
SSHD_BAK="/etc/ssh/sshd_config.v3.bak.$(date +%s)"
UFW_BAK_TGZ="/root/ufw-backup-v3-$(date +%s).tgz"
SYSCTL_IPV6_FILE="/etc/sysctl.d/99-disable-ipv6-v3.conf"
SYSCTL_ICMP_FILE="/etc/sysctl.d/99-icmp-v3.conf"

cp "$SSHD_CFG" "$SSHD_BAK"
tar czf "$UFW_BAK_TGZ" /etc/ufw >/dev/null 2>&1 || true
ok "Sauvegardes: $SSHD_BAK et $UFW_BAK_TGZ"

# -------- SSHD config (add, don't break) --------
info "Durcissement SSH (ports + écoute globale)…"
grep -qE "^Port[[:space:]]+$SSH_PORT$" "$SSHD_CFG" || echo "Port $SSH_PORT" >> "$SSHD_CFG"
grep -qE "^Port[[:space:]]+22$" "$SSHD_CFG"       || echo "Port 22" >> "$SSHD_CFG"
grep -qE "^AddressFamily" "$SSHD_CFG" || echo "AddressFamily any" >> "$SSHD_CFG"
grep -qE "^ListenAddress 0\.0\.0\.0$" "$SSHD_CFG" || echo "ListenAddress 0.0.0.0" >> "$SSHD_CFG"
# Ne touche pas UsePAM/PermitRootLogin ici; tu ajusteras après validation

sshd -t

# -------- UFW (Docker friendly) --------
info "Configuration UFW compatible Docker/Coolify…"
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

ufw --force reset
ufw default deny incoming
ufw default allow outgoing
ufw allow in on lo
ufw allow 80/tcp  comment 'HTTP'
ufw allow 443/tcp comment 'HTTPS'

if [[ -n "$SSH_ALLOWED_IPS" ]]; then
  for ip in $SSH_ALLOWED_IPS; do
    ufw allow from "$ip" to any port "$SSH_PORT" proto tcp comment "SSH custom from $ip"
    ufw allow from "$ip" to any port 22 proto tcp comment "SSH fallback 22 from $ip"
  done
else
  ufw allow "$SSH_PORT"/tcp comment 'SSH custom'
  ufw allow 22/tcp           comment 'SSH fallback'
fi

# -------- ICMP/IPv6 toggles --------
if [[ "${LIMIT_ICMP,,}" == "oui" ]]; then
  cat > "$SYSCTL_ICMP_FILE" <<'EOF'
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
net.ipv4.icmp_echo_ignore_all = 0
net.ipv4.icmp_ratelimit = 100
net.ipv4.icmp_ratemask = 88089
EOF
else
  rm -f "$SYSCTL_ICMP_FILE" || true
fi

if [[ "${DISABLE_IPV6,,}" == "oui" ]]; then
  cat > "$SYSCTL_IPV6_FILE" <<'EOF'
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1
EOF
else
  rm -f "$SYSCTL_IPV6_FILE" || true
fi

sysctl --system >/dev/null || true
ufw --force enable

# -------- Fail2Ban --------
info "Configuration Fail2Ban (sshd)…"
JAIL_LOCAL="/etc/fail2ban/jail.local"
touch "$JAIL_LOCAL"
if grep -q '^\[sshd\]' "$JAIL_LOCAL"; then
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
systemctl enable fail2ban >/dev/null 2>&1 || true

# -------- Reload SSH only after firewall --------
info "Reload du service SSH…"
if systemctl status ssh >/dev/null 2>&1; then
  systemctl reload ssh
elif systemctl status sshd >/dev/null 2>&1; then
  systemctl reload sshd
else
  service ssh reload || service sshd reload || true
fi

# -------- Post-check --------
echo
ok "SSH ouvert à tous sur le port $SSH_PORT (et 22 en filet)"
ok "Firewall activé avec règles compatibles Docker."
ok "Fail2Ban actif pour SSH."
echo

if [[ -n "$PRIV_TMP" ]]; then
  warn "ATTENTION : Sauvegarde cette clé PRIVÉE ! Ne la partage à personne."
  echo "----------------------------------------"
  echo "-----  VOTRE CLÉ PRIVÉE SSH (ed25519) -----"
  cat "$PRIV_TMP"
  echo "----------------------------------------"
  echo
  echo "Copie-la en local (ex: ~/.ssh/${SSH_USER}_${SSH_PORT}_ed25519) et mets-lui: chmod 600"
fi

echo "👉 TESTE TA NOUVELLE SESSION SSH depuis une autre machine :"
echo "   ssh -i ~/.ssh/${SSH_USER}_${SSH_PORT}_ed25519 -p $SSH_PORT $SSH_USER@<VOTRE_IP>"
echo "   (N'oublie pas d'ouvrir le port $SSH_PORT dans le FIREWALL DU PROVIDER si applicable.)"
echo

read -r -p "Tout fonctionne bien ? (oui/non) [non]: " ALL_GOOD
ALL_GOOD="${ALL_GOOD:-non}"

rollback(){
  echo
  warn "Un problème est survenu. Annulation des changements…"
  # Restore sshd_config
  cp -f "$SSHD_BAK" "$SSHD_CFG" || true
  if systemctl status ssh >/dev/null 2>&1; then
    systemctl restart ssh || true
  else
    systemctl restart sshd || true
  fi
  ok "Configuration SSH restaurée."

  # Restore UFW
  if [[ -s "$UFW_BAK_TGZ" ]]; then
    ufw --force disable || true
    tar xzf "$UFW_BAK_TGZ" -C / || true
    ufw --force enable || true
    ok "UFW restauré."
  else
    # Fallback: état minimal sane
    ufw --force reset
    ufw default deny incoming
    ufw default allow outgoing
    ufw allow in on lo
    ufw allow 22/tcp
    ufw allow 80/tcp
    ufw allow 443/tcp
    ufw --force enable
    ok "UFW réinitialisé (fallback)."
  fi

  # Remove sysctl toggles
  rm -f "$SYSCTL_IPV6_FILE" "$SYSCTL_ICMP_FILE" || true
  sysctl --system >/dev/null || true
  ok "ICMP/IPv6 restaurés."

  systemctl restart fail2ban || true
  ok "Fail2Ban restarté."
  ok "Rollback terminé."
}

if [[ "${ALL_GOOD,,}" != "oui" ]]; then
  rollback
  exit 1
fi

# Optionally close 22 now
read -r -p "Tout est bon. Voulez-vous FERMER le port 22 maintenant ? (oui/non) [non]: " CLOSE22
CLOSE22="${CLOSE22:-non}"
if [[ "${CLOSE22,,}" == "oui" ]]; then
  sed -i '/^Port 22$/d' "$SSHD_CFG"
  sshd -t
  if systemctl status ssh >/dev/null 2>&1; then
    systemctl reload ssh || true
  else
    systemctl reload sshd || true
  fi
  ufw delete allow 22/tcp >/dev/null 2>&1 || true
  ok "Port 22 fermé proprement."
else
  warn "Port 22 laissé ouvert (filet). Tu pourras le fermer plus tard."
fi

# Final recap
echo
ok "Sécurisation terminée !"
echo "Rappels :"
echo "- Clé privée (si générée) copiée localement et chmod 600."
echo "- Port $SSH_PORT ouvert côté provider si nécessaire."
echo "- Tu peux ensuite durcir: PasswordAuthentication no, PermitRootLogin no, etc."
