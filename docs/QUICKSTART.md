# Guide de Demarrage Rapide

Ce guide permet de lancer rapidement un premier scan avec l'outil de decouverte reseau.

## Installation

1. Verifier que Python 3, pip et nmap sont installes :

```bash
python3 --version
pip3 --version
nmap --version
```

Si pip n'est pas installe :
- Sur Debian/Ubuntu : `sudo apt install python3-pip`
- Sur Fedora : `sudo dnf install python3-pip`
- Sur MacOS : `brew install python3` (pip inclus)

2. Installer les dependances systeme (necessaires pour lxml) :

Sur Debian/Ubuntu :
```bash
sudo apt install libxml2-dev libxslt-dev python3-dev
```

Sur Fedora :
```bash
sudo dnf install libxml2-devel libxslt-devel python3-devel
```

Sur MacOS :
```bash
brew install libxml2 libxslt
```

3. Installer les dependances Python :

```bash
cd network_discovery_tool
pip3 install -r requirements.txt
```

Si `requirements.txt` n'existe pas, installer manuellement :

```bash
pip3 install python-nmap scapy netifaces networkx matplotlib lxml flask tabulate
```

## Premier Scan

### Lancement avec Menu Interactif

Pour lancer l'outil avec le menu interactif (mode par defaut) :

```bash
sudo python3 src/principal.py
```

Le script va d'abord :
- Analyser la machine locale (interfaces, IP, passerelles)
- Afficher les reseaux detectes automatiquement
- Proposer un menu avec les differentes options

### Menu Principal

Apres l'analyse initiale, le menu propose :

1. **Scan rapide** - Scan leger avec detection basique (recommande pour commencer)
2. **Scan approfondi** - Scan complet avec detection OS et version des services
3. **Reseau specifique** - Entrer manuellement un reseau en CIDR
4. **Configuration** - Modifier les parametres
5. **Quitter** - Sortir du programme

Pour un premier test, choisir l'option 1 (scan rapide).

### Scan Sans Menu

Pour lancer directement un scan sans passer par le menu :

```bash
sudo python3 src/principal.py --no-interactive
```

### Scan d'un Reseau Specifique

Si on connait le reseau a scanner :

```bash
sudo python3 src/principal.py --target 192.168.1.0/24
```

## Profondeur de Scan

L'outil propose trois niveaux de profondeur :

| Niveau | Description | Temps estime |
|--------|-------------|--------------|
| LEGER | Ports principaux, pas de detection OS | 3-5 min |
| NORMAL | Detection version services | 5-15 min |
| COMPLET | Detection OS + scripts NSE | 15-30 min |

Le scan rapide utilise le niveau LEGER, le scan approfondi utilise COMPLET.

## Consulter les Resultats

Apres le scan, les fichiers generes se trouvent dans `output/` :

1. Ouvrir le rapport textuel :

```bash
cat output/network_scan_*_report.txt
```

2. Voir la visualisation graphique :

```bash
open output/network_scan_*_topology.png
```

3. Utiliser l'interface web :

```bash
python3 webapp/app.py
```

Puis charger le fichier JSON dans l'interface a l'adresse http://localhost:5001

## Utilisation Avancee

### Avec Pas de Cote Automatique

Si des pivots sont detectes, on peut automatiser l'exploratoin :

```bash
sudo python3 src/principal.py --pas-de-cote --ssh-password "motdepasse"
```

Ou avec une cle SSH :

```bash
sudo python3 src/principal.py --pas-de-cote --ssh-key ~/.ssh/id_rsa
```

### Configuration SSH pour les Pivots

Pour faciliter le pas de cote, configurer l'authentification par cle :

```bash
# Generer une paire de cles si necessaire
ssh-keygen -t rsa -b 4096 -f ~/.ssh/pivot_key

# Copier la cle publique sur le pivot
ssh-copy-id -i ~/.ssh/pivot_key.pub root@IP_DU_PIVOT

# Utiliser avec le script
sudo python3 src/principal.py --pas-de-cote --ssh-key ~/.ssh/pivot_key
```

## Problemes Courants

### Erreur "Permission denied"

Le script necessite les privileges root pour certaines fonctionnalites. Utiliser `sudo`.

Ou lancer le script en mode sans privileges root :

```bash
python3 src/principal.py --no-root
```

Ce mode utilise un scan TCP connect (-sT) et desactive la detection OS.

### Erreur "nmap: command not found"

Installer nmap :
- Sur Debian/Ubuntu : `sudo apt install nmap`
- Sur MacOS : `brew install nmap`
- Sur RedHat/CentOS : `sudo yum install nmap`

### Module Python manquant

Installer le module manquant avec pip3 :

```bash
pip3 install nom_du_module
```

### Scan trop long

Quelques solutions :
- Utiliser le scan rapide (option 1 du menu)
- Reduire le nombre de reseaux a scanner via le menu
- Modifier `config.py` pour reduire les ports scannes

### Aucun hote trouve

Verifier que :
- Le reseau cible est correct
- La machine a bien une adresse IP sur ce reseau
- Nmap est lance avec sudo (pour le scan ARP)

### Tous les hotes sont UNKNOWN

Cela peut arriver si :
- Aucun port n'est ouvert sur les machines
- Le firewall bloque les scans
- Le scan est en mode LEGER (moins de detection)

Essayer avec l'option scan approfondi pour avoir plus de details.

## Interpretation des Resultats

### Types d'Equipements

- **WEBSERVER** : Serveur web (Apache, nginx, IIS)
- **FIREWALL** : Pare-feu ou equipement de securite
- **ROUTER** : Routeur reseau (souvent en .1 ou .254)
- **NAT** : Equipement faisant du NAT
- **DNS** : Serveur DNS (port 53)
- **MAILSERVER** : Serveur de messagerie
- **DATABASE** : Serveur de base de donnees
- **PRINTER** : Imprimante reseau
- **IOT** : Objet connecte (Raspberry, ESP32, etc.)
- **WEBCLIENT** : Poste client avec peu de services
- **UNKNOWN** : Type non determine

### Detection des Routeurs

Les routeurs sont detectes par :
- Adresse IP se terminant par .1 ou .254
- Fabricant MAC connu (Cisco, Juniper, Mikrotik, etc.)
- OS identifie comme routeur (Cisco IOS, RouterOS, etc.)

### Niveau de Confiance des Pivots

- **HIGH** : Pivot tres fiable (routeur/firewall avec SSH)
- **MEDIUM** : Pivot moyennement fiable
- **LOW** : Pivot peu fiable (a verifier manuellment)

## Support

Pour les problemes specifiques ou questions :
- Consulter les logs dans le dossier `logs/`
- Verifier la documentation complete dans `README.md`
- Lancer sans l'option `--quiet` pour voir plus de details
