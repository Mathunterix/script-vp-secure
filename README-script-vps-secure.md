# Script VPS Secure - Compatible Coolify

## Le problème avec le script original (mozzypc)

Le script de mozzypc est excellent pour sécuriser un VPS classique, mais il pose plusieurs problèmes avec Coolify :

| Problème | Script Original | Ce script |
|----------|----------------|-----------|
| Port 22 | `ufw deny 22/tcp` - bloqué | Gardé ouvert pour Coolify |
| Root SSH | `PermitRootLogin no` | `prohibit-password` (clé uniquement) |
| UsePAM | `no` | `yes` (nécessaire pour certains setups) |
| Docker forwarding | Non configuré | `DEFAULT_FORWARD_POLICY="ACCEPT"` |
| host.docker.internal | Absent | Ajouté automatiquement |
| Mode VPS | Un seul mode | 3 modes (Maître/Agent/Standard) |

## Les 3 modes

### Mode Maître (choix 1)
Pour le VPS où Coolify est installé directement :
- Port 22 ouvert + port personnalisé
- Root via clé SSH autorisé
- `host.docker.internal` configuré
- Prêt pour `curl -fsSL https://cdn.coollabs.io/coolify/install.sh | sudo bash`

### Mode Agent (choix 2) - Par défaut
Pour les VPS gérés à distance par Coolify :
- Port 22 ouvert pour les déploiements
- Root via clé SSH autorisé (Coolify en a besoin)
- Port personnalisé pour ton accès SSH quotidien
- `host.docker.internal` configuré

### Mode Standard (choix 3)
Pour les VPS sans Coolify (sécurité maximale) :
- Pas de port 22
- Root SSH complètement désactivé
- Uniquement le port personnalisé

## Utilisation

```bash
# Télécharger et exécuter
wget -O script-vps-secure-coolify.sh https://raw.githubusercontent.com/TON_REPO/script-vps-secure-coolify.sh
sudo bash script-vps-secure-coolify.sh
```

Ou directement :
```bash
sudo bash -c "$(wget -qLO - URL_DU_SCRIPT)"
```

## Ce que le script fait

1. **Crée un utilisateur SSH sécurisé** avec sudo sans mot de passe
2. **Génère une clé ED25519** et l'affiche à l'écran
3. **Configure SSH** avec le port personnalisé + port 22 (sauf mode standard)
4. **Configure UFW** compatible Docker :
   - Forwarding activé
   - Ports 80/443 ouverts
   - Port SSH personnalisé
   - Port 22 selon le mode
5. **Configure Fail2Ban** pour protéger les ports SSH
6. **Configure sysctl** (IPv6, ICMP selon tes choix)
7. **Ajoute host.docker.internal** dans /etc/hosts

## Workflow recommandé

### Pour un nouveau VPS Agent

1. Lancer le script en mode Agent (2)
2. Noter :
   - Username
   - Port personnalisé  
   - Clé privée SSH
3. Dans Coolify :
   - Ajouter la clé publique root dans les authorized_keys du VPS
   - Ou créer une clé dans Coolify et l'ajouter sur le VPS
   - Ajouter le serveur avec IP publique, port 22, user root

### Pour un VPS Maître

1. Lancer le script en mode Maître (1)
2. Ouvrir temporairement le port 8000 : `sudo ufw allow 8000/tcp`
3. Installer Coolify
4. Fermer le port 8000 : `sudo ufw delete allow 8000/tcp`

## Rollback automatique

Si tu réponds "non" à la question de validation, le script :
- Restaure la config SSH d'origine
- Restaure les règles UFW
- Supprime les modifications sysctl
- Redémarre les services

## Pourquoi garder le port 22 ?

Coolify utilise le port 22 pour :
- Le terminal web dans l'interface
- Les déploiements automatiques
- Les health checks
- La communication avec les agents

Tu peux utiliser ton port personnalisé pour ta connexion quotidienne, et le port 22 reste réservé à Coolify.

## Différences avec ton script v2

Ton script v2 était sur la bonne voie, j'ai ajouté :
- Les 3 modes explicites (plus clair)
- `host.docker.internal` automatique
- Meilleure gestion de `PermitRootLogin`
- Documentation intégrée
- Instructions Coolify à la fin
- Détection automatique de l'IP publique pour les instructions
