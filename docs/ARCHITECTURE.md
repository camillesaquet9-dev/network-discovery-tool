# Architecture Technique du Projet

Document d'architecture pour le projet de decouverte reseau automatisee.

## Vue d'Ensemble

Le projet est structure en plusieurs couches :

```
Interface Utilisateur (Menu Interactif + Web)
           |
    Orchestrateur (principal.py)
           |
    +------+------+------+------+
    |      |      |      |      |
  Scan  Inference Topo  Export Pivot
```

## Modules Principaux

### 1. Configuration (config.py)

Centralise tous les parametres de configuration :
- Parametres nmap (timing, ports, timeouts)
- Seuils pour l'inference de type
- Chemins de sortie
- Couleurs pour la visualisation
- Mode interactif

Variables importantes :
- TIMING_NMAP : Vitesse de scan (0-5)
- PORTS_SPECIFIQUES : Liste des ports a scanner
- MAX_ITERATIONS_DECOUVERTE : Profondeur de l'exploration
- MODE_INTERACTIF : Active/desactive le menu
- PLAGE_EXPLORATION_OCTET : Etendue de l'exploration reseau

Niveaux de profondeur :
- PROFONDEUR_LEGER (1) : Scan basique
- PROFONDEUR_NORMAL (2) : Avec detection version
- PROFONDEUR_COMPLET (3) : Detection OS + scripts NSE

### 2. Menu Interactif (menu_interactif.py)

Classes : MenuInteractif, AnalyseurMachineLocale

Module ajoute pour fournir une interface utilisateur en ligne de commande.

Responsabilites :
- Analyse de la machine locale au demarrage
- Affichage du contexte reseau (interfaces, IPs, passerelles)
- Menu de selection du type de scan
- Selection des reseaux a scanner
- Confirmation avant chaque operation

Methodes principales :
- afficher_banniere() : Affiche le titre du programme
- afficher_info_machine() : Montre les infos de la machine locale
- afficher_menu_principal() : Menu de choix
- selectionner_reseaux() : Permet de choisir les reseaux
- confirmer_scan_reseaux() : Demande confirmaton avant scan

### 3. Reconnaissance Locale (utilitaires_reseau.py)

Classe : ReconnaissanceLocale

Responsabilites :
- Lecture des interfaces reseau locales
- Analyse de la table de routage
- Lecture du cache ARP
- Detection des serveurs DNS
- Generation de la liste des reseaux cibles

Methodes principales :
- executer_reconnaissance_complete()
- obtenir_interfaces()
- obtenir_routes()
- obtenir_cibles_initiales()

### 4. Scanner Nmap (enveloppe_nmap.py)

Classe : ScannerNmap

Encapsule les appels a nmap et le parsing XML.

Methodes principales :
- balayage_ping() : Detection d'hotes actifs
- scanner_hote(ip, profondeur) : Scan detaille avec niveau de profondeur
- scanner_reseau() : Scan complet d'un reseau
- traceroute() : Trace de route vers une cible

Le parametre profondeur controle :
- LEGER : Scan SYN basique
- NORMAL : Ajout de -sV pour detection version
- COMPLET : Ajout de -O et scripts NSE

Utilise des fichiers XML temporaires pour recuperer les resultats nmap.

### 5. Inference de Type (inference_type.py)

Classe : MoteurInferenceType

Determine le type fonctionel d'un equipement base sur :
- Ports ouverts/filtres
- Services detectes
- Banniere OS
- Fabricant MAC (via OUI)
- Adresse IP (detection routeur par .1/.254)
- Nom d'hote
- Sorties de scripts NSE

Types supportes :
- WEBSERVER, WEBCLIENT, FIREWALL, NAT, DNS, MAILSERVER, DATABASE, ROUTER, PRINTER, IOT, UNKNOWN

Listes de fabricants pour detection :
- FABRICANTS_ROUTEUR : Cisco, Juniper, Mikrotik, etc.
- FABRICANTS_SERVEUR : Dell, HP, IBM, etc.
- FABRICANTS_IOT : Espressif, Raspberry, Arduino, etc.
- FABRICANTS_IMPRIMANTE : HP, Canon, Epson, Brother, etc.

Heuristiques :
- ROUTER : IP en .1/.254 ou fabricant reseau connu
- FIREWALL : Nombreux ports filtres + mots-cles
- WEBSERVER : Ports 80/443 + services HTTP
- DNS : Port 53 ouvert
- PRINTER : Ports 9100/515/631 ou fabricant imprimante
- IOT : Fabricant IoT ou ports MQTT (1883)
- UNKNOWN : Si aucun critere ne correspond

### 6. Exploration des Frontieres (explorateur_frontieres.py)

Classe : ExplorateurFrontieres

Responsabilites :
- Identification des passerelles (routeurs, firewalls)
- Generation de reseaux candidats adjacents
- Filtrage des reseaux virtuels (Docker, link-local, CGNAT)
- Test d'accessibilite via ping et traceroute
- Categorisation des blocages

Filtrage automatique des reseaux :
- 169.254.x.x (link-local)
- 172.17.x.x et 172.18.x.x (Docker)
- 100.64.x.x (CGNAT)

Parametre limite pour controler le nombre de reseaux explores.

Types de blocage :
- FIREWALL_FILTERED : Blocage explicite
- NO_ROUTE : Pas de route configuree
- TIMEOUT : Pas de reponse
- ROUTING_STOPPED : Traceroute arrete

### 7. Detection de Pivots (detecteur_pivot.py)

Classe : DetecteurPivot

Identifie les machines pouvant servir de point de rebond.

Criteres de selection :
- Type fonctionel (ROUTER, FIREWALL, NAT)
- Ports d'acces ouverts (SSH, Telnet, RDP)
- Position dans le traceroute
- Presence d'OS identifie

Scoring de confiance :
- HIGH : Score >= 5
- MEDIUM : Score >= 3
- LOW : Score < 3

### 8. Mouvement Lateral (mouvement_lateral.py)

Classe : GestionnaireMouvementLateral

Execute le pas de cote automatique.

Protocoles supportes (ordre de priorite) :
1. SSH (port 22)
2. WinRM (ports 5985/5986)
3. Telnet (port 23)

Processus :
1. Test de connexion avec chaque protocole
2. Deploiement de l'outil sur le pivot
3. Execution du scan distant
4. Recuperation des resultats JSON
5. Fusion avec les donnees principales
6. Nettoyage du pivot

### 9. Construction de Topologie (constructeur_topologie.py)

Classe : ConstructeurTopologie

Utilise NetworkX pour creer un graphe de la topologie.

Structure :
- Noeuds : Equipements reseau
- Aretes : Connexions reseau

Types d'aretes :
- meme_reseau : Equipements sur le meme segment
- inter_reseau : Connexion via passerelle

Fonctionnalites :
- Visualisation avec matplotlib
- Export GraphML pour Gephi/Cytoscape
- Calcul de centralite (noeuds critiques)
- Recherche de chemins

### 10. Export Verefoo (exporteur_verefoo.py)

Classe : ExporteurVerefoo

Genere les exports pour l'outil Verefoo.

Formats :
- XML Verefoo : Format specifique avec types fonctionels
- JSON : Donnees completes pour l'interface web

Structure XML :
- NFV/graphs/graph : Graphe principal
- node : Equipements avec type fonctionel
- neighbour : Voisins directs
- configuration : Config specifique au type
- PropertyDefinition : Proprietes de reachability

### 11. Generation de Rapports (generateur_rapports.py)

Classe : GenerateurRapports

Produit des rapports textuels lisibles.

Sections :
- Entete avec informations de scan
- Resume executif
- Reseaux cartographies
- Inventaire des equipements
- Reseaux bloques
- Pivots suggeres
- Statistiques detaillees
- Recommandations

Utilise tabulate pour le formatage de tableaux.

### 12. Orchestrateur (principal.py)

Classe : OrchestrateurDecouverteReseau

Coordonne l'execution de toutes les phases.

Integration du menu interactif :
1. Analyse machine locale via AnalyseurMachineLocale
2. Affichage du contexte via MenuInteractif
3. Selection du mode de scan par l'utilisateur
4. Configuration de la profondeur selon le choix

Phases d'execution :
1. Reconnaissance locale
2. Affichage menu (si mode interactif)
3. Decouverte reseau (iterative)
4. Fingerprinting et inference de type
5. Exploration des frontieres
6. Construction de la topologie
7. Export des resultats
8. Generation des rapports

Gere aussi les arguments de ligne de commande et la configuration du logging.

## Flux de Donnees

```
Analyse Machine Locale
        |
        v
   Menu Interactif
        |
        v
Interfaces/Routes/ARP
        |
        v
   Reseaux cibles
        |
        v
   Scan nmap (XML)
        |
        v
 Parsing + Inference
        |
        v
 Hotes avec types
        |
        v
Exploration frontieres
        |
        v
 Detection pivots
        |
        v
 Pas de cote (optionel)
        |
        v
   Fusion resultats
        |
        v
Construction graphe
        |
        v
 Export + Rapports
```

## Format de Donnees

### Structure d'un hote

```python
{
    "ip": "192.168.1.50",
    "nom_hote": "webserver01",
    "mac": "aa:bb:cc:dd:ee:ff",
    "fabricant_mac": "Cisco",
    "os": "Linux 5.4",
    "precision_os": "95",
    "type_fonctionel": "WEBSERVER",
    "ports": [
        {
            "port": 80,
            "protocole": "tcp",
            "etat": "open",
            "service": "http",
            "produit": "Apache",
            "version": "2.4.41"
        }
    ],
    "services": [...],
    "sortie_scripts": {...}
}
```

### Structure d'un pivot

```python
{
    "ip_pivot": "192.168.1.254",
    "nom_hote_pivot": "gateway",
    "type_pivot": "ROUTER",
    "reseaux_cibles": ["10.0.0.0/24", "172.16.0.0/24"],
    "methode_acces": "ssh",
    "commande_acces": "ssh root@192.168.1.254",
    "confiance": "high",
    "raison": "identifie comme ROUTER, acces SSH disponible",
    "ports_ouverts": [22, 23, 80, 443]
}
```

## Performance

Temps de scan moyens (reseau /24) :
- Scan LEGER : 3-5 minutes
- Scan NORMAL : 5-15 minutes
- Scan COMPLET : 15-30 minutes
- Avec pas de cote : Variable selon nombre de pivots

Optimisations possibles :
- Reduire PORTS_SPECIFIQUES dans config.py
- Augmenter TIMING_NMAP
- Reduire PLAGE_EXPLORATION_OCTET
- Limiter MAX_ITERATIONS_DECOUVERTE
- Utiliser le niveau LEGER pour un premier apercu

## Dependances Externes

### Obligatoires
- nmap : Scanner reseau
- Python 3.8+ : Langage
- netifaces : Acces interfaces
- networkx : Graphes
- lxml : XML

### Optionnelles
- pexpect : Telnet automatise
- pywinrm : Windows Remote Management
- matplotlib : Visualisation
- flask : Interface web
