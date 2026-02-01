# Outil de Decouverte Reseau Automatise

Projet realise dans le cadre de la SAE 5.01 - Administration Reseau
IUT de Lannion - BUT Reseaux et Telecommunications

## Presentation

Cet outil permet de faire une decouverte automatique des equipements sur un reseau local et de generer une cartographie complete de l'infrastructure. Le projet utilise nmap pour scanner les reseaux et identifier les differents types d'equipements (serveurs web, firewalls, routeurs, imprimantes, objets connectes, etc.).

L'outil est capable de :
- Analyser la machine locale au demarrage pour afficher le contexte
- Proposer un menu interactif pour choisir le type de scan
- Detecter automatiquement les reseaux accessibles
- Scanner les equipements et identifier leurs services
- Determiner le type fonctionel de chaque machine (avec detection amelioree)
- Detecter les reseaux bloques par des firewalls
- Suggerer des pivots pour continuer l'exploration
- Executer automatiquement des "pas de cote" vers les pivots
- Generer des exports au format Verefoo, JSON et GraphML
- Produire une visualisation graphique de la topologie

## Architecture

Le projet est organise en plusieurs modules :
- `config.py` - Configuration globale et parametres
- `menu_interactif.py` - Interface interactive en ligne de commande
- `utilitaires_reseau.py` - Reconnaissance locale passive
- `enveloppe_nmap.py` - Interface avec nmap pour les scans
- `inference_type.py` - Detection du type fonctionel des equipements
- `explorateur_frontieres.py` - Exploration des reseaux bloques
- `detecteur_pivot.py` - Identification des pivots potentiels
- `mouvement_lateral.py` - Execution automatique des pas de cote
- `constructeur_topologie.py` - Construction du graphe reseau
- `exporteur_verefoo.py` - Export au format Verefoo et JSON
- `generateur_rapports.py` - Generation de rapports textuels
- `principal.py` - Orchestrateur principal

## Prerequis

### Logiciels requis
- Python 3.8 ou superieur
- Nmap 7.80 ou superieur
- Privileges root (pour certains types de scans)

### Installation des dependances

```bash
pip3 install -r requirements.txt
```

Les dependances principales sont :
- python-nmap - Interface Python pour nmap
- scapy - Manipulation de paquets reseau
- netifaces - Acces aux interfaces reseau
- networkx - Construction et analyse de graphes
- matplotlib - Visualisation graphique
- lxml - Traitement XML
- flask - Interface web de visualisation
- tabulate - Formatage de tableaux

Pour le pas de cote automatique (optionnel) :
- pexpect - Automatisation de Telnet
- pywinrm - Support de Windows Remote Management

## Utilisation

### Mode Interactif (par defaut)

Lancement du script avec le menu interactif :

```bash
sudo python3 src/principal.py
```

Le script va d'abord analyser la machine locale et affciher les informations de contexte (interfaces, reseaux detectes, passerelles). Ensuite un menu permet de choisir parmi plusieurs options :

1. **Scan rapide** - Scan leger avec detection de services basique
2. **Scan approfondi** - Scan complet avec detection OS et scripts NSE
3. **Reseau specifique** - Scanner un reseau precis en CIDR
4. **Configuration** - Modifier les parametres de scan
5. **Quitter** - Sortir du programme

### Niveaux de Profondeur

Le scan peut etre effectue avec differents niveauxde profondeur :

- **LEGER (1)** : Scan rapide, ports principaux uniquement
- **NORMAL (2)** : Detection de version des services activee
- **COMPLET (3)** : Detection OS + scripts NSE + version intensive

### Scan en Ligne de Commande

Pour un scan sans interface interactive :

```bash
sudo python3 src/principal.py --no-interactive --target 192.168.1.0/24
```

### Scan approfondi

Avec detection OS et scripts NSE :

```bash
sudo python3 src/principal.py --deep
```

### Avec pas de cote automatique

Active l'exploitation automatique des pivots detectes :

```bash
sudo python3 src/principal.py --pas-de-cote --ssh-password "motdepasse"
```

Avec cle SSH :

```bash
sudo python3 src/principal.py --pas-de-cote --ssh-key ~/.ssh/id_rsa
```

### Scan sans privileges root

Pour lancer un scan sans avoir besoin de sudo :

```bash
python3 src/principal.py --no-root
```

Ce mode utilise des techniques de scan TCP connect qui ne necessitent pas de privileges root, mais la detection OS n'est pas disponble.

### Options disponibles

```
--target NETWORK        Reseau cible au format CIDR
--deep                  Active le scan approfondi (profondeur COMPLET)
--no-pivot              Desactive la detection de pivots
--no-root               Mode sans privileges root (pas de detection OS)
--no-interactive        Desactive le menu interactif
--pas-de-cote           Active l'execution automatique sur les pivots
--ssh-user USER         Utilisateur pour connexion SSH (defaut: root)
--ssh-key PATH          Chemin vers la cle SSH privee
--ssh-password PASS     Mot de passe pour connexion distante
--output-dir DIR        Repertoire de sortie personnalise
--quiet                 Mode silencieux
```

## Resultats

Les resultats sont generes dans le repertoire `output/` :

- `network_scan_YYYYMMDD_HHMMSS_verefoo.xml` - Export XML Verefoo
- `network_scan_YYYYMMDD_HHMMSS_data.json` - Donnees completes JSON
- `network_scan_YYYYMMDD_HHMMSS_topology.graphml` - Graphe au format GraphML
- `network_scan_YYYYMMDD_HHMMSS_topology.png` - Visualisation graphique
- `network_scan_YYYYMMDD_HHMMSS_report.txt` - Rapport textuel complet
- `network_scan_YYYYMMDD_HHMMSS_pivots.txt` - Rapport des pivots (si detectes)

Les logs sont sauvegardes dans le repertoire `logs/`.

## Interface Web

Une interface web est disponible pour visualiser les resultats :

```bash
python3 webapp/app.py
```

Puis ouvrir http://localhost:5001 dans un navigateur.

L'interface permet de :
- Charger un fichier JSON de resultats
- Visualiser les statistiques du scan
- Explorer la liste des equipements
- Voir les details de chaque machine
- Filtrer par type d'equipement

## Types d'Equipements Detectes

L'outil peut identifier les types suivants :

- **WEBSERVER** : Serveur web (Apache, nginx, IIS, etc.)
- **WEBCLIENT** : Poste client avec peu de services
- **FIREWALL** : Pare-feu ou equipement de securite
- **NAT** : Equipement faisant de la traduction d'adresses
- **DNS** : Serveur DNS
- **MAILSERVER** : Serveur de messagerie (SMTP, IMAP, POP3)
- **DATABASE** : Serveur de base de donnees (MySQL, PostgreSQL, etc.)
- **ROUTER** : Routeur reseau (detecte par IP .1/.254 ou fabricant MAC)
- **PRINTER** : Imprimante reseau (HP, Canon, Epson, etc.)
- **IOT** : Objet connecte (ESP32, Raspberry Pi, capteurs, etc.)
- **UNKNOWN** : Type non determine

La detection utilise plusieurs criteres : ports ouverts, services detectes, fabricant MAC, nom d'hote et informations OS.

## Fonctionnement du Pas de Cote

Le pas de cote (lateral movement) permet d'explorer automatiquement les reseaux bloques en utilisant les pivots detectes. Le systeme supporte plusieurs protocoles :

1. SSH (port 22) - Methode principale
2. WinRM (ports 5985/5986) - Pour Windows
3. Telnet (port 23) - Pour equipements anciens

Le processus est le suivant :
1. Detection d'un reseau bloque
2. Identification d'un pivot ayant acces a ce reseau
3. Connexion automatique au pivot
4. Deploiement de l'outil sur le pivot
5. Execution du scan depuis le pivot
6. Recuperation des resultats
7. Fusion avec les donnees principales
8. Nettoyage du pivot

## Limitations Connues

- Necessite des privileges root pour certaines fonctionnalites (scan ARP, detection OS)
- Les scans peuvent etre longs sur des reseaux de grande taille
- La detection OS est approximative et peut donner des faux positifs
- Le pas de cote necessite un acces SSH/Telnet/WinRM au pivot
- Certains firewalls peuvent bloquer completemnt le scan
- Les reseaux virtuels (Docker, link-local) sont filtrés automatiquement

## Aspects Ethiques et Legaux

ATTENTION : Cet outil doit etre utilise uniquement sur des reseaux pour lesquels on dispose d'une autorisation explicite. Le scan de reseaux sans autorisation peut etre illegal et considere comme une intrusion.

L'outil a ete developpe dans un cadre pedagogique pour comprendre les mecanismes de decouverte reseau et de cartographie d'infrastructure.

## Auteur

Projet SAE 5.01 - IUT de Lannion
Annee universitaire 2025-2026

## Licence

Ce projet est fourni dans le cadre d'un travail academique.
