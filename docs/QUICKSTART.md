# Guide de Demarrage Rapide

Ce guide permet de lancer rapidement un premier scan avec l'outil de decouverte reseau.

## Installation

1. Verifier que Python 3 et nmap sont installes :

```bash
python3 --version
nmap --version
```

2. Installer les dependances Python :

```bash
cd network_discovery_tool
pip3 install -r requirements.txt
```

Si `requirements.txt` n'existe pas, installer manuellement :

```bash
pip3 install python-nmap scapy netifaces networkx matplotlib lxml flask tabulate
```

## Premier Scan

### Scan Simple

Pour lancer un scan basique du reseau local :

```bash
sudo python3 src/principal.py
```

Le script va :
- Detecter automatiquement votre reseau local
- Scanner tous les equipements actifs
- Identifier leur type (serveur web, firewall, etc.)
- Generer les resultats dans le dossier `output/`

Temps estime : 5-15 minutes selon la taille du reseau.

### Scan Approfondi

Pour un scan plus detaille avec detection OS :

```bash
sudo python3 src/principal.py --deep
```

Attention : ce mode est plus lent (15-30 minutes).

### Scan d'un Reseau Specifique

Si on connait le reseau a scanner :

```bash
sudo python3 src/principal.py --target 192.168.1.0/24
```

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

Si des pivots sont detectes, on peut automatiser l'exploration :

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

Utiliser l'option `--quiet` et reduire le nombre de ports scannes en modifiant `config.py` :

```python
PORTS_TOP_NMAP = 100  # Au lieu de 1000
```

### Pas de pivot detecte

Verifier que :
- L'option `--no-pivot` n'est pas activee
- Des reseaux bloques ont bien ete detectes
- Les passerelles ont des ports d'acces ouverts (SSH, Telnet, etc.)

## Interpretation des Resultats

### Types d'Equipements

- WEBSERVER : Serveur web (Apache, nginx, IIS)
- FIREWALL : Pare-feu ou equipement de securite
- ROUTER : Routeur reseau
- NAT : Equipement faisant du NAT
- DNS : Serveur DNS
- MAILSERVER : Serveur de messagerie
- DATABASE : Serveur de base de donnees
- WEBCLIENT : Poste client
- UNKNOWN : Type non determine

### Niveau de Confiance des Pivots

- HIGH : Pivot tres fiable (routeur/firewall avec SSH)
- MEDIUM : Pivot moyennement fiable
- LOW : Pivot peu fiable (a verifier manuellement)

## Support

Pour les problemes specifiques ou questions :
- Consulter les logs dans le dossier `logs/`
- Verifier la documentation complete dans `README.md`
- Tester avec l'option `--quiet` desactivee pour voir plus de details
