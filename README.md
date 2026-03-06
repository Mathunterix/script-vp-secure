# Script VPS Secure v7 - Compatible Coolify

Script de securisation VPS pour vibecoders. Configure un serveur securise en 5 minutes, compatible avec Coolify.

## Workflow en 4 etapes

```
Etape 1          Etape 2           Etape 3              Etape 4
Securiser VPS -> Installer      -> Configurer         -> Fermer les ports
(Script 1)       Coolify           domaine HTTPS        d'admin (Script 2)
```

---

## Etape 1 : Securiser le VPS (Script 1)

```bash
sudo bash -c "$(curl -fsSL https://raw.githubusercontent.com/Mathunterix/script-vp-secure/main/script-vps-secure-coolify-v7.sh)"
```

> **Attention au copier-coller :** Si vous copiez cette commande depuis Google Docs, Notion ou un autre editeur de texte riche, les tirets `-` peuvent etre remplaces par des tirets typographiques unicode qui ne fonctionnent pas dans le terminal. Copiez toujours depuis ce README GitHub ou retapez manuellement les tirets.

### Ce que fait le Script 1

**Securite SSH**
- Cree un utilisateur dedie avec sudo sans mot de passe
- Genere une cle ED25519 (impossible a brute-forcer)
- Configure un port SSH personnalise (reduit 90% des scans)
- Desactive l'authentification par mot de passe

**Firewall (UFW)**
- Configuration compatible Docker (forwarding active)
- Ports 80/443 ouverts (HTTP/HTTPS)
- Port SSH personnalise ouvert
- Port 22 ouvert si mode Coolify
- Ports Coolify (8000/6001/6002) si mode Master (temporaires)

**Protection brute-force (Fail2Ban)**
- Ban apres 5 tentatives echouees
- Duree de ban : 1 heure
- Protege tous les ports SSH

**Mises a jour automatiques**
- Installe automatiquement les patches de securite
- Nettoie les anciens kernels
- Ne redemarre PAS automatiquement

**Swap (2 Go)**
- Cree un fichier swap de 2 Go (optionnel, active par defaut)
- Swappiness a 10 (privilegie la RAM, swap en dernier recours)
- Persiste au reboot via fstab

**Auto-rollback**
- Si vous ne confirmez pas dans les 5 minutes, toutes les modifications sont annulees
- Rollback en ordre inverse (LIFO) pour une restauration propre
- Capture Ctrl+C, fermeture session SSH, erreurs -> rollback automatique

### Deroulement

1. **Premiere connexion** : `ssh root@IP_DU_VPS`
2. **Changer le mot de passe root** : `passwd`
3. **Lancer le script** (commande ci-dessus)
4. **Suivre l'assistant interactif** (6 etapes)
   - Type de serveur (Master/Remote/Standard)
   - Nom d'utilisateur SSH
   - Port SSH personnalise
   - Restriction IP Coolify (mode Remote)
   - Generation de cle SSH
   - Options (IPv6, ICMP)
5. **Sauvegarder la cle privee** affichee a la fin
6. **Tester la connexion** dans un NOUVEAU terminal
7. **Taper `CONFIRMER`** pour valider (ou attendre 5 min pour rollback)

---

## Etape 2 : Installer Coolify

```bash
curl -fsSL https://cdn.coollabs.io/coolify/install.sh | sudo bash
```

Accedez au dashboard : `http://IP_DU_VPS:8000`

---

## Etape 3 : Configurer le domaine HTTPS

1. Dans Coolify : **Settings -> General -> FQDN**
2. Entrez `https://coolify.votre-domaine.com`
3. Verifiez que le dashboard est accessible en HTTPS

---

## Etape 4 : Fermer les ports d'admin (Script 2)

```bash
sudo bash securisation-post-coolify.sh
```

### Ce que fait le Script 2

1. **Verifie** que votre FQDN HTTPS fonctionne (curl)
2. **Ferme les ports 8000/6001/6002** avec double protection :
   - UFW : supprime les `allow` + ajoute des `deny` (protection INPUT)
   - DOCKER-USER : bloque via iptables (protection FORWARD/Docker)
3. **Auto-rollback 5 minutes** : si vous ne confirmez pas, tout est restaure

### Resultat final

| Port | Usage |
|------|-------|
| Port SSH custom | Votre acces SSH |
| Port 80 | HTTP (redirige vers HTTPS) |
| Port 443 | HTTPS (Coolify + vos services) |

Tous les autres ports sont fermes.

---

## Les 3 modes du Script 1

### Mode Master (choix 1)
Pour le VPS ou Coolify est installe directement.

| Configuration | Valeur |
|--------------|--------|
| Port 22 | LOCAL (Docker uniquement) |
| host.docker.internal | CONFIGURE (obligatoire) |
| Ports 8000/6001/6002 | OUVERTS (temporaires) |
| Root SSH | Via cle uniquement |

### Mode Remote (choix 2) - Par defaut
Pour les VPS geres a distance par Coolify.

| Configuration | Valeur |
|--------------|--------|
| Port 22 | OUVERT (pour Coolify Master) |
| host.docker.internal | NON |
| Ports 8000/6001/6002 | NON |
| Docker | Installe auto par Coolify |

### Mode Standard (choix 3)
Securite maximale, pas de Coolify.

| Configuration | Valeur |
|--------------|--------|
| Port 22 | FERME |
| Root SSH | DESACTIVE |

---

## NOTE : UFW + Docker

Docker peut bypass UFW via iptables pour les ports des containers. C'est pourquoi le Script 2 utilise une double protection :
- **UFW** pour bloquer au niveau INPUT (services non-Docker)
- **DOCKER-USER** (iptables) pour bloquer au niveau FORWARD (ports Docker)

**Recommandation supplementaire :** Utilisez aussi le firewall de votre cloud provider (Hetzner, OVH, DigitalOcean, etc.).

---

## Depannage

### Je suis bloque apres le script (lockout SSH)

Le script a un auto-rollback de 5 minutes. Si vous n'avez pas tape `CONFIRMER`, attendez et les modifications seront annulees automatiquement.

Si le rollback ne s'est pas declenche (session fermee brutalement), connectez-vous via la console VNC/KVM de votre hebergeur et restaurez le backup SSH :
```bash
cp /etc/ssh/sshd_config.bak_TIMESTAMP /etc/ssh/sshd_config
systemctl restart ssh
```

### Le dashboard Coolify n'est plus accessible apres le Script 2

C'est normal si vous accedez via `http://IP:8000`. Utilisez votre domaine HTTPS : `https://coolify.votre-domaine.com`

Pour rouvrir temporairement le port 8000 :
```bash
sudo ufw delete deny 8000/tcp && sudo ufw allow 8000/tcp
sudo iptables -D DOCKER-USER -p tcp --dport 8080 -j DROP
```

Pour refermer : relancez `sudo bash securisation-post-coolify.sh` (il est idempotent).

### Les regles iptables DOCKER-USER disparaissent au reboot

Le Script 2 installe `iptables-persistent` et sauvegarde les regles avec `netfilter-persistent save`. Si les regles disparaissent quand meme :
```bash
sudo netfilter-persistent save
sudo netfilter-persistent reload
```

### Mode Remote : Coolify n'arrive pas a se connecter

1. Verifiez que la cle publique Coolify est dans `/root/.ssh/authorized_keys`
2. Dans Coolify -> Servers -> votre serveur : verifiez le port (doit etre votre port SSH custom)
3. Verifiez que le port 22 est bien ouvert : `sudo ufw status | grep 22`

---

## FAQ

### Quand lancer le Script 2 ?

Uniquement en **mode Master**, apres avoir :
1. Installe Coolify
2. Configure le FQDN HTTPS
3. Verifie que le dashboard est accessible en HTTPS

Le mode Remote n'a pas besoin du Script 2 (pas de ports d'admin a fermer).

### Peut-on relancer les scripts ?

Le Script 2 est **idempotent** : il verifie si les regles existent deja avant de les ajouter. Vous pouvez le relancer sans risque.

Le Script 1 fait un `ufw reset` et reconfigure tout. Il peut etre relance sur un VPS deja securise, mais les anciennes regles UFW seront remplacees.

### Pourquoi ne pas fermer les ports dans le Script 1 directement ?

Parce que Coolify n'est pas encore installe a ce moment. Il faut :
1. Que Coolify soit installe (Docker, containers)
2. Que le domaine HTTPS soit configure (Traefik, certificat SSL)
3. Que le dashboard soit accessible via HTTPS (port 443)

Seulement ensuite on peut fermer les ports 8000/6001/6002 en toute securite.

### Pourquoi utiliser DOCKER-USER en plus de UFW ?

Docker gere ses propres regles iptables et bypass la chaine INPUT (ou agit UFW). Les ports publies par Docker (`-p 8000:8080`) passent par la chaine FORWARD. La chaine DOCKER-USER est le point d'insertion recommande par Docker pour ajouter des regles de filtrage sur ces ports.

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

### v7.0 (2026-03-06)
- **Auto-rollback 5 minutes** : si pas de confirmation dans les 5 minutes, rollback automatique
- **Script 2 (securisation-post-coolify.sh)** : nouveau script pour fermer les ports d'admin apres config HTTPS
  - Double protection UFW + DOCKER-USER (iptables)
  - Verification HTTPS du FQDN Coolify
  - Auto-rollback 5 minutes
  - Idempotent
- **Warning ameliore** : les ports 8000/6001/6002 sont marques TEMPORAIRE dans UFW
- **Instructions finales** : mention explicite du Script 2 a lancer apres Coolify

### v6.2 (2025-12-23)
- Restriction port 22 aux reseaux Docker (172.16.0.0/12 et 10.0.0.0/8) en mode Master

### v6.1 (2025-12-15)
- **Rollback bulletproof** :
  - Rollback en ordre inverse (LIFO) pour une restauration propre
  - Capture Ctrl+C, fermeture session SSH, kill -> rollback automatique
  - Lock file pour empecher les executions simultanees
  - Nettoyage automatique du lock file meme en cas d'erreur

### v6.0 (2025-12-09)
- Option AJOUTER ou REMPLACER les cles SSH existantes
- Detection automatique des cles existantes
- Backup des anciennes cles avant remplacement

### v5.0
- Ajout UFW avec configuration compatible Docker
- Tableaux comparatifs Master vs Remote dans l'interface
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
