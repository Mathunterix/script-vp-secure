# Script VPS Secure v3.1 - Compatible Coolify

Script de sécurisation VPS pour vibecoders. Configure un serveur sécurisé en 5 minutes, compatible avec Coolify.

## TL;DR

```bash
# Sur un VPS fraîchement installé
curl -O https://raw.githubusercontent.com/[ton-repo]/script-vps-secure-coolify-v3.sh
sudo bash script-vps-secure-coolify-v3.sh
```

---

## Prérequis

- VPS Debian/Ubuntu (testé sur Debian 11/12, Ubuntu 22.04/24.04)
- Accès root (connexion initiale fournie par l'hébergeur)
- Terminal SSH (Terminus recommandé)
- Gestionnaire de mots de passe pour sauvegarder la clé privée

---

## Ce que le script fait

### Sécurité SSH
- Crée un utilisateur dédié avec sudo sans mot de passe
- Génère une clé ED25519 (impossible à brute-forcer)
- Configure un port SSH personnalisé (réduit 90% des scans)
- Désactive l'authentification par mot de passe

### Firewall (UFW)
- Configuration compatible Docker (forwarding activé)
- Ports 80/443 ouverts (HTTP/HTTPS)
- Port SSH personnalisé ouvert
- Port 22 ouvert si mode Coolify (pour les déploiements)

### Protection brute-force (Fail2Ban)
- Ban après 5 tentatives échouées
- Durée de ban : 1 heure
- Protège tous les ports SSH

### Mises à jour automatiques (Unattended-Upgrades)
- Installe automatiquement les patches de sécurité
- Nettoie les anciens kernels
- Ne redémarre PAS automatiquement (tu gardes le contrôle)

### Coolify
- Ajoute `host.docker.internal` dans /etc/hosts
- Garde root accessible via clé SSH (nécessaire pour Coolify)

---

## Les 3 modes

### Mode Maître (choix 1)
Pour le VPS où Coolify est installé directement.

| Configuration | Valeur |
|---------------|--------|
| Port 22 | Ouvert |
| Port personnalisé | Ouvert |
| Root SSH | Via clé uniquement |
| host.docker.internal | Configuré |

**Après le script :**
```bash
# Ouvrir temporairement le port 8000
sudo ufw allow 8000/tcp

# Installer Coolify
curl -fsSL https://cdn.coollabs.io/coolify/install.sh | sudo bash

# Fermer le port 8000
sudo ufw delete allow 8000/tcp
```

### Mode Agent (choix 2) - Par défaut
Pour les VPS gérés à distance par Coolify.

| Configuration | Valeur |
|---------------|--------|
| Port 22 | Ouvert (pour Coolify) |
| Port personnalisé | Ouvert (pour toi) |
| Root SSH | Via clé uniquement |
| host.docker.internal | Configuré |

C'est le mode le plus courant. Tu utilises ton port personnalisé au quotidien, Coolify utilise le port 22.

### Mode Standard (choix 3)
Sécurité maximale, pas de Coolify.

| Configuration | Valeur |
|---------------|--------|
| Port 22 | Fermé |
| Port personnalisé | Ouvert |
| Root SSH | Désactivé |
| host.docker.internal | Non configuré |

---

## Ce que le script protège

| Menace | Protection | Efficacité |
|--------|------------|------------|
| Brute-force SSH | Fail2Ban + clé ED25519 | 99.9% |
| Scans de ports | Port non-standard | ~90% |
| Exploits connus | Unattended-upgrades | ~94% |
| Accès non autorisé | UFW deny incoming | 100% |

**Score de sécurité : 85-90/100** (suffisant pour un VPS de vibecoder)

---

## Ce que le script NE fait PAS

| Non inclus | Raison |
|------------|--------|
| VPN Wireguard | Overkill, complique l'accès aux services |
| SELinux/AppArmor | Courbe d'apprentissage trop élevée |
| Audit/AIDE | Pas nécessaire pour ce cas d'usage |
| CrowdSec | Fail2Ban suffit pour 1-3 VPS |

Ces outils sont utiles pour des infrastructures plus complexes, mais ajoutent de la complexité sans bénéfice majeur pour un vibecoder.

---

## Workflow recommandé

### 1. Première connexion
```bash
# Connexion avec les credentials fournis par l'hébergeur
ssh root@IP_DU_VPS -p 22
```

### 2. Changer le mot de passe root
```bash
passwd
# -> Sauvegarder dans ton gestionnaire de mots de passe
```

### 3. Exécuter le script
```bash
curl -O https://raw.githubusercontent.com/[ton-repo]/script-vps-secure-coolify-v3.sh
chmod +x script-vps-secure-coolify-v3.sh
sudo bash script-vps-secure-coolify-v3.sh
```

### 4. Suivre les instructions
- Choisir le mode (1/2/3)
- Entrer le nom d'utilisateur
- Entrer le port SSH personnalisé (ou accepter celui généré)
- Répondre aux questions optionnelles

### 5. SAUVEGARDER LA CLÉ PRIVÉE
Le script affiche la clé privée à la fin. **Copie-la immédiatement** dans ton gestionnaire de mots de passe !

### 6. Tester la connexion (IMPORTANT)
**Dans un NOUVEAU terminal** (garde l'ancien ouvert) :
```bash
ssh -i ~/.ssh/ta_cle -p PORT_PERSO utilisateur@IP_DU_VPS
```

### 7. Valider
Si la connexion fonctionne, réponds "oui" dans le terminal du script.
Si elle ne fonctionne pas, réponds "non" et le script fera un rollback.

---

## Ajouter le serveur dans Coolify

### Option A : Utiliser la clé Coolify (recommandé)

1. Dans Coolify → **Keys & Tokens** → **Private Keys**
2. Copier la clé publique affichée
3. Sur le VPS :
```bash
echo "LA_CLÉ_PUBLIQUE_COOLIFY" >> /root/.ssh/authorized_keys
```
4. Dans Coolify → **Servers** → **Add Server**
   - Name : nom-du-vps
   - IP : IP_DU_VPS
   - Port : 22
   - User : root
   - Private Key : (celle de Coolify)

### Option B : Créer une clé dédiée

1. Sur le VPS :
```bash
ssh-keygen -t ed25519 -N "" -f /root/.ssh/coolify_key
cat /root/.ssh/coolify_key
# -> Copier la clé privée
```
2. Dans Coolify → **Keys & Tokens** → **Add Private Key**
   - Coller la clé privée
3. Ajouter le serveur comme ci-dessus

---

## Vérification post-installation

### Vérifier UFW
```bash
sudo ufw status verbose
```
Doit afficher :
- Port personnalisé : ALLOW
- Port 22 : ALLOW (si mode Coolify)
- 80/tcp : ALLOW
- 443/tcp : ALLOW

### Vérifier Fail2Ban
```bash
sudo fail2ban-client status sshd
```
Doit afficher : `Status for the jail: sshd`

### Vérifier Unattended-Upgrades
```bash
sudo systemctl status unattended-upgrades
```
Doit afficher : `Active: active (running)`

### Vérifier SSH
```bash
sudo ss -tuln | grep -E ":(22|PORT_PERSO) "
```
Doit afficher les deux ports en LISTEN.

---

## Troubleshooting

### "Connection refused" sur le nouveau port

1. Vérifier que SSH écoute :
```bash
sudo ss -tuln | grep :PORT
```

2. Vérifier UFW :
```bash
sudo ufw status | grep PORT
```

3. Redémarrer SSH :
```bash
sudo systemctl restart ssh
```

### Bloqué après rollback

Si tu es complètement bloqué, utilise la console VNC/KVM de ton hébergeur pour te reconnecter.

### Fail2Ban me ban moi-même

```bash
# Voir les IPs bannies
sudo fail2ban-client status sshd

# Débannir une IP
sudo fail2ban-client set sshd unbanip TON_IP
```

### Les mises à jour automatiques ne marchent pas

```bash
# Vérifier le statut
sudo unattended-upgrades --dry-run --debug

# Forcer une exécution
sudo unattended-upgrades -v
```

### Docker ne peut pas exposer de ports

Vérifier que le forwarding est activé :
```bash
cat /proc/sys/net/ipv4/ip_forward
# Doit afficher : 1
```

---

## Différences avec les autres scripts

### vs Script mozzypc (original)

| Aspect | mozzypc | Ce script |
|--------|---------|-----------|
| Port 22 | Bloqué | Gardé pour Coolify |
| Root SSH | Désactivé | Via clé (Coolify en a besoin) |
| Docker | Non configuré | Forwarding activé |
| Mises à jour | Manuel | Automatique |
| Modes | Un seul | 3 modes |

### vs Script Durkul (VPN)

| Aspect | Durkul | Ce script |
|--------|--------|-----------|
| Wireguard VPN | Oui | Non (overkill) |
| Complexité | Élevée | Simple |
| Temps setup | ~30 min | ~5 min |
| Accès Supabase | Compliqué | Direct |

---

## Fichiers modifiés

| Fichier | Modification |
|---------|--------------|
| `/etc/ssh/sshd_config` | Port, auth, root login |
| `/etc/hosts` | host.docker.internal |
| `/etc/ufw/*` | Règles firewall |
| `/etc/fail2ban/jail.local` | Config fail2ban |
| `/etc/sysctl.d/99-vps-secure.conf` | IPv6, ICMP |
| `/etc/apt/apt.conf.d/50unattended-upgrades` | Config upgrades |
| `/etc/apt/apt.conf.d/20auto-upgrades` | Activation upgrades |

---

## Changelog

### v3.1 (2025-12-09)
- Ajout unattended-upgrades pour mises à jour de sécurité automatiques
- Amélioration de la documentation
- Ajout des infos de version dans l'en-tête

### v3.0
- 3 modes explicites (Maître/Agent/Standard)
- host.docker.internal automatique
- Rollback amélioré
- Instructions Coolify intégrées

### v2.0
- Première version compatible Coolify
- Port 22 gardé ouvert

---

## Ressources

- [Best practices sécurité VPS 2025](../../../docs/deepsearch/vps-security-best-practices-beginners-2025.md)
- [Coolify Documentation](https://coolify.io/docs/)
- [Fail2Ban Wiki](https://fail2ban.org/wiki/index.php/Main_Page)
- [UFW Documentation](https://help.ubuntu.com/community/UFW)

---

*Script créé pour la formation Vibecoding Débutant - Module 0*
