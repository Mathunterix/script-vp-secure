# Script VPS Secure v5 - Compatible Coolify

Script de securisation VPS pour vibecoders. Configure un serveur securise en 5 minutes, compatible avec Coolify.

## Installation rapide

```bash
sudo bash -c "$(curl -fsSL https://raw.githubusercontent.com/Mathunterix/script-vp-secure/main/script-vps-secure-coolify-v5.sh)"
```

---

## Differences Master vs Remote

| Configuration        | MASTER                        | REMOTE                        |
|---------------------|-------------------------------|-------------------------------|
| Port 22             | OUVERT (obligatoire)          | OUVERT (pour Coolify)         |
| host.docker.internal| OUI (obligatoire)             | NON (pas necessaire)          |
| Ports 8000/6001/6002| OUVERTS (dashboard)           | NON                           |
| Docker              | Pre-installe par vous         | Installe auto par Coolify     |
| Root SSH            | Via cle                       | Via cle                       |
| UFW                 | Configure                     | Configure                     |

### Pourquoi ces differences ?

**Master (ou Coolify est installe) :**
- Coolify tourne dans un container Docker et doit se connecter a son propre host via SSH
- `host.docker.internal` permet cette connexion interne
- Les ports 8000/6001/6002 sont pour le dashboard (fermables apres config domaine)

**Remote (gere par Coolify distant) :**
- Coolify Master se connecte en SSH pour deployer
- Pas besoin de `host.docker.internal` car la connexion vient de l'exterieur
- Docker est installe automatiquement par Coolify via le bouton "Validate Server"

---

## Les 3 modes

### Mode Master (choix 1)
Pour le VPS ou Coolify est installe directement.

### Mode Remote (choix 2) - Par defaut
Pour les VPS geres a distance par Coolify.

### Mode Standard (choix 3)
Securite maximale, pas de Coolify.

---

## Ce que le script fait

### Securite SSH
- Cree un utilisateur dedie avec sudo sans mot de passe
- Genere une cle ED25519 (impossible a brute-forcer)
- Configure un port SSH personnalise (reduit 90% des scans)
- Desactive l'authentification par mot de passe

### Firewall (UFW)
- Configuration compatible Docker (forwarding active)
- Ports 80/443 ouverts (HTTP/HTTPS)
- Port SSH personnalise ouvert
- Port 22 ouvert si mode Coolify
- Ports Coolify (8000/6001/6002) si mode Master

### Protection brute-force (Fail2Ban)
- Ban apres 5 tentatives echouees
- Duree de ban : 1 heure
- Protege tous les ports SSH

### Mises a jour automatiques
- Installe automatiquement les patches de securite
- Nettoie les anciens kernels
- Ne redemarre PAS automatiquement

---

## NOTE : UFW + Docker

Docker peut bypass UFW via iptables pour les ports des containers. UFW protege les services non-Docker (SSH, etc.).

**Recommandation :** Pour une securite complete, utilisez AUSSI le firewall de votre cloud provider (Hetzner, OVH, DigitalOcean, etc.).

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
sudo bash -c "$(curl -fsSL https://raw.githubusercontent.com/Mathunterix/script-vp-secure/main/script-vps-secure-coolify-v5.sh)"
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

### 7. Confirmer ou Rollback
- Si ca marche -> repondez "oui" -> configuration permanente
- Si ca marche pas -> repondez "non" -> rollback automatique

---

## Apres l'installation

### Mode Master - Installer Coolify

1. Les ports sont deja ouverts par le script (8000, 6001, 6002)

2. Installer Coolify :
```bash
curl -fsSL https://cdn.coollabs.io/coolify/install.sh | sudo bash
```

3. Acceder au dashboard : `http://IP:8000`

4. Configurer un domaine avec SSL

5. Fermer les ports 8000, 6001, 6002 :
```bash
sudo ufw delete allow 8000/tcp
sudo ufw delete allow 6001/tcp
sudo ufw delete allow 6002/tcp
```

### Mode Remote - Ajouter dans Coolify

1. Sur le serveur remote, ajouter la cle publique Coolify :
```bash
echo "CLE_PUBLIQUE_COOLIFY" >> /root/.ssh/authorized_keys
```

2. Dans Coolify UI -> Servers -> Add Server :
   - IP : IP du serveur
   - Port : 22 (ou votre port custom si configure dans Coolify)
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

### v5.0 (2025-12-09)
- Ajout UFW avec configuration compatible Docker
- Tableaux comparatifs Master vs Remote dans l'interface
- Documentation des vraies differences basees sur la doc Coolify officielle
- Ports Coolify (8000/6001/6002) ouverts automatiquement en mode Master
- Rollback UFW en cas de probleme

### v4.0
- Interface interactive amelioree (style guide)
- Support multi-distro
- host.docker.internal uniquement pour Master

### v3.1
- Ajout unattended-upgrades
- 3 modes (Master/Agent/Standard)

---

## Ressources

- [Documentation Coolify](https://coolify.io/docs/)
- [Coolify Firewall Best Practices](https://coolify.io/docs/knowledge-base/server/firewall)
- [Coolify Multiple Servers](https://coolify.io/docs/knowledge-base/server/multiple-servers)
- [Fail2Ban Wiki](https://fail2ban.org/wiki/index.php/Main_Page)

---

*Script cree pour la formation Vibecoding Debutant - Module 0*
