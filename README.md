# Script VPS Secure v4 - Compatible Coolify

Script de securisation VPS pour vibecoders. Configure un serveur securise en 5 minutes, compatible avec Coolify.

## Installation rapide

```bash
sudo bash -c "$(curl -fsSL https://raw.githubusercontent.com/Mathunterix/script-vp-secure/main/script-vps-secure-coolify-v4.sh)"
```

---

## Les 3 modes

### Mode Master (choix 1)
Pour le VPS ou Coolify est installe directement.

| Configuration | Valeur |
|---------------|--------|
| Port 22 | Ouvert (requis par Coolify) |
| Port personnalise | Ouvert (pour vous) |
| Root SSH | Via cle uniquement |
| host.docker.internal | Configure |

### Mode Remote (choix 2) - Par defaut
Pour les VPS geres a distance par Coolify.

| Configuration | Valeur |
|---------------|--------|
| Port 22 | Ferme |
| Port personnalise | Ouvert |
| Root SSH | Via cle (pour Coolify) |
| host.docker.internal | Non necessaire |

### Mode Standard (choix 3)
Securite maximale, pas de Coolify.

| Configuration | Valeur |
|---------------|--------|
| Port 22 | Ferme |
| Port personnalise | Ouvert |
| Root SSH | Desactive |

---

## Ce que le script fait

### Securite SSH
- Cree un utilisateur dedie avec sudo sans mot de passe
- Genere une cle ED25519 (impossible a brute-forcer)
- Configure un port SSH personnalise (reduit 90% des scans)
- Desactive l'authentification par mot de passe

### Protection brute-force (Fail2Ban)
- Ban apres 5 tentatives echouees
- Duree de ban : 1 heure
- Protege tous les ports SSH

### Mises a jour automatiques
- Installe automatiquement les patches de securite
- Nettoie les anciens kernels
- Ne redemarre PAS automatiquement

---

## IMPORTANT : UFW + Docker

**Docker bypass UFW via iptables.** Les regles UFW sont inefficaces pour controler les ports des containers Docker.

**Recommandation :** Utilisez le firewall de votre cloud provider (Hetzner, OVH, DigitalOcean, Vultr, etc.) pour controler les ports. Il bloque le trafic AVANT qu'il atteigne votre serveur.

---

## Workflow recommande

### 1. Premiere connexion
```bash
ssh root@IP_DU_VPS
```

### 2. Changer le mot de passe root
```bash
passwd
```

### 3. Executer le script
```bash
sudo bash -c "$(curl -fsSL https://raw.githubusercontent.com/Mathunterix/script-vp-secure/main/script-vps-secure-coolify-v4.sh)"
```

### 4. Suivre l'assistant interactif
- Choisir le mode (Master/Remote/Standard)
- Entrer le nom d'utilisateur
- Configurer le port SSH
- Repondre aux questions

### 5. SAUVEGARDER LA CLE PRIVEE
Le script affiche la cle privee a la fin. **Copiez-la immediatement** dans votre gestionnaire de mots de passe !

### 6. Tester la connexion
**Dans un NOUVEAU terminal** (gardez l'ancien ouvert) :
```bash
ssh -i ~/.ssh/votre_cle -p PORT_PERSO utilisateur@IP_DU_VPS
```

---

## Apres l'installation

### Mode Master - Installer Coolify

1. Ouvrir les ports dans le firewall cloud :
   - 8000 (dashboard)
   - 6001 (realtime)
   - 6002 (terminal)

2. Installer Coolify :
```bash
curl -fsSL https://cdn.coollabs.io/coolify/install.sh | sudo bash
```

3. Acceder au dashboard : `http://IP:8000`

4. Configurer un domaine avec SSL

5. Fermer les ports 8000, 6001, 6002

### Mode Remote - Ajouter dans Coolify

1. Sur le serveur remote, ajouter la cle publique Coolify :
```bash
echo "CLE_PUBLIQUE_COOLIFY" >> /root/.ssh/authorized_keys
```

2. Dans Coolify UI -> Servers -> Add Server :
   - IP : IP du serveur
   - Port : votre port SSH personnalise
   - User : root
   - Private Key : celle de Coolify

3. Cliquer "Validate Server & Install Docker Engine"

---

## Distributions supportees

- Ubuntu LTS (20.04, 22.04, 24.04)
- Debian 11, 12
- CentOS 7+
- Rocky Linux
- AlmaLinux
- Fedora

---

## Changelog

### v4.0 (2025-12-09)
- Interface interactive amelioree (style guide)
- Vraies differences Master vs Remote basees sur la doc Coolify
- Mode Remote : port 22 ferme, port custom pour Coolify
- Mode Master : host.docker.internal configure automatiquement
- Avertissement UFW + Docker
- Support multi-distro (Debian/Ubuntu/CentOS/Rocky/Fedora)
- Instructions post-installation selon le mode

### v3.1
- Ajout unattended-upgrades
- 3 modes (Master/Agent/Standard)

### v3.0
- Premiere version compatible Coolify

---

## Ressources

- [Documentation Coolify](https://coolify.io/docs/)
- [Coolify Firewall Best Practices](https://coolify.io/docs/knowledge-base/server/firewall)
- [Fail2Ban Wiki](https://fail2ban.org/wiki/index.php/Main_Page)

---

*Script cree pour la formation Vibecoding Debutant - Module 0*
