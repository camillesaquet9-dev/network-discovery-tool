# Compte Rendu de Projet - SAE 5.01
## Outil de Découverte et Exploration Réseau Automatisée

**Formation :** BUT Réseaux et Télécommunications - IUT de Lannion
**Année universitaire :** 2025-2026
**Module :** SAE 5.01 - Administration Réseau

---

## 1. Présentation du Projet

### 1.1 Contexte et Objectifs

Dans le cadre de la SAE 5.01, nous avons été amenés à développer un outil de découverte réseau automatisée. L'objectif principal était de créer un script capable de cartographier une infrastructure réseau de manière autonome, en identifiant les équipements présents, leurs services, et en déterminant leur rôle fonctionnel (serveur web, routeur, firewall, etc.).

Le projet devait répondre à plusieurs exigences :
- Scanner automatiquement les réseaux accessibles depuis une machine "attaquante"
- Identifier les hôtes actifs et leurs services
- Classifier les équipements selon leur type fonctionnel
- Détecter les réseaux bloqués et proposer des pivots pour continuer l'exploration
- Générer des exports exploitables (XML, JSON, GraphML) et des visualisations

On voulait vraiment que l'outil soit utilisable dans un contexte réel, pas juste un proof of concept. Du coup on a passé pas mal de temps sur l'ergonomie et la robustesse du code.

### 1.2 Organisation de l'Équipe

Notre groupe a travaillé de manière collaborative, avec une répartition des tâches assez organique. Certains se sont concentrés sur la partie infrastructure et tests sur CyberRange, d'autres sur le développement du code Python. On communiquait principalement par Discord pour se tenir au courant des avancées et des problèmes rencontrés.

---

## 2. Infrastructure de Test - CyberRange

### 2.1 Topologie Prévue

Pour tester notre outil dans des conditions réalistes, nous devions déployer une topologie réseau sur la plateforme CyberRange de l'IUT. L'idée était de simuler une infrastructure d'entreprise avec plusieurs segments réseau, des routeurs, des firewalls, et différents types de machines (serveurs, clients, équipements réseau).

La topologie initiale comprenait :
- Plusieurs réseaux isolés interconnectés par des routeurs
- Des firewalls pour segmenter les zones
- Des machines variées (Debian, Ubuntu, Kali Linux)
- Une machine "attaquante" depuis laquelle lancer nos scans

### 2.2 Problèmes Rencontrés - Chronologie

On va pas se mentir, la partie CyberRange a été... compliquée. Vraiment très compliquée. On a enchaîné les problèmes techniques et on a dû s'adapter en permanence. Voici le détail de ce qu'on a vécu.

#### 2.2.1 Les Routeurs qui ne Démarrent Pas

Le premier gros problème a concerné les routeurs. Quand on clonait les routeurs depuis les templates disponibles sur CyberRange, ils restaient bloqués dans la phase de boot. On avait le choix entre différents systèmes d'exploitation à lancer, mais une fois qu'on sélectionnait un système, la machine restait figée sur le booting. Rien ne se lançait.

On a tenté plusieur choses :
- Supprimer la topologie et la recréer de zéro
- Éteindre et rallumer les équipements
- Supprimer uniquement l'équipement problématique et le recloner
- Repartir complètement de zéro à chaque fois

Aucune de ces solutions n'a fonctionné. Les routeurs refusaient obstinément de démarrer correctement.

#### 2.2.2 Solution de Contournement - Debian comme Routeur

Face à cette impasse, on a décidé de remplacer les routeurs par des machines Debian 12 configurées pour faire du routage. L'idée était simple : activer le forwarding IP et configurer des routes statiques.

Pour le routage basique avec des routes par défaut, ça fonctionnait plutôt bien. Mais dès qu'on essayait d'ajouter des routes statiques... le service réseau refusait de démarrer. On a testé de les configurer à froid (dans les fichiers de config) et à chaud (en ligne de commande), mais à chaque fois qu'on ajoutait une route statique, le service réseau plantait.

Résultat : on était obligés de se contenter de routes par défaut uniquement. Ce qui signifiait qu'on ne pouvait pas avoir de réseaux isolés, alors que c'était exactement ce dont on avait besoin pour tester notre outil correctement.

#### 2.2.3 Le Problème des Mots de Passe

Un autre souci plutôt agaçant : les machines Debian qu'on clonait n'avaient pas leurs identifiants documentés. Normalement, quand on fait un clic droit sur une machine et qu'on regarde ses informations, on voit l'identifiant et le mot de passe. Là, rien.

On a dû trouver une solution un peu technique : aller modifier le mot de passe directement avant le boot du système. Plus concrètement, au moment du choix du système d'exploitation dans GRUB, on accédait à une interface spéciale pour modifier la ligne de démarrage. Dans cette interface, on pouvait atteindre le fichier de configuration de base et modifier les paramètres d'authentification.

On a donc configuré toutes les Debian 12 avec les identifiants **root / lannion**.

Pour info, les autres machines avaient les identifiants suivants :
- Ubuntu : **os / os**
- Kali Linux : **kali / kali**

#### 2.2.4 Les Stormshield

Voyant qu'on n'arrivait à rien avec nos solutions de contournement, on est allés voir Monsieur Allain qui nous a fourni des Stormshield. Il nous avait prévenu qu'il y avait potentiellement des problèmes avec certains de ces équipements, car ils avaient déjà buggé lors de projets précédents. Mais on a tenté le coup quand même.

Au début, ça semblait prometteur. La fonction de routage fonctionnait, on pouvait mettre des routes par défaut et même des routes statiques. On a configuré les politiques en "pass all" pour que tout le trafic passe sans restriction.

Malheureusement, dès qu'on interconnectait deux Stormshield, impossible de pinger au-delà. Pour illustrer :

```
Machine A <---> [Stormshield A] <---> [Stormshield B] <---> Machine B
```

Depuis la Machine A :
- On pouvait pinger l'interface du Stormshield A côté Machine A ✓
- On pouvait pinger l'interface du Stormshield A côté Stormshield B ✓
- Mais impossible de pinger la première interface du Stormshield B ✗

On a vraiment pas compris pourquoi. Les routes étaient là, les politiques étaient en pass all, tout était logique sur le papier. Mais ça ne passait pas.

#### 2.2.5 Tentatives de Résolution

On a essayé pas mal de choses pour résoudre ce problème de connectivité entre Stormshield :

1. **Ajouter un switch entre les deux Stormshield** : On s'est dit que c'était peut-être un problème d'interface, que le switch pourrait servir d'intermédiaire. Ça n'a pas marché.

2. **Ajouter des routes statiques explicites** : Même si les routes par défaut auraient dû suffire, on a ajouté des routes spécifiques. Sans succès.

3. **Ajouter des routes de retour** : On s'est demandé si le problème venait du retour des paquets. Le Stormshield est normalement sensé gérer ça automatiquement, mais on a essayé quand même. Toujours rien.

On arrivait à atteindre les réseaux directement connectés, mais les réseaux isolés restaient inaccessibles. On n'a jamais réussi à comprendre pourquoi.

#### 2.2.6 Limitation du Nombre de Machines

Autre contrainte qu'on a découverte : on était limités à 16 machines maximum sur notre topologie. Pas une de plus. Comme on en avait prévu 17 ou 18, il fallait choisir lesquelles ne pas lancer. On gardait éteintes celles qui n'étaient pas essentielles pour les tests en cours.

### 2.3 Résolution Finale - Tests à Domicile

Face à tous ces problèmes accumulés, on a dû se résoudre à tester notre outil chez nous. Sur nos propres réseaux domestiques.

Et là, surprise : ça marchait plutôt bien ! Les données qu'on récupérait étaient intéressantes et cohérentes. On a pu valider le fonctionnement de notre script dans un environnement réel, même si ce n'était pas la topologie contrôlée qu'on avait initialement prévue.

C'est un peu frustrant de ne pas avoir pu utiliser CyberRange comme prévu, mais au moins on a pu démontrer que notre outil fonctionnait correctement.

---

## 3. Développement du Script

### 3.1 Architecture Générale

Notre outil est structuré en plusieurs modules Python, chacun ayant une responsabilité spécifique. On a voulu garder une architecture modulaire pour faciliter la maintenance et les évolutions futures.

Voici un schéma de l'architecture globale :

```
┌─────────────────────────────────────────────────────────────────┐
│              Interface Utilisateur                               │
│         (Menu Interactif CLI + Interface Web)                   │
└───────────────────────────┬─────────────────────────────────────┘
                            │
                            v
┌─────────────────────────────────────────────────────────────────┐
│           OrchestrateurDecouverteReseau (principal.py)          │
│                    Coordinateur Central                          │
└───────────────────────────┬─────────────────────────────────────┘
                            │
        ┌───────────────────┼───────────────────┐
        │                   │                   │
        v                   v                   v
┌───────────────┐   ┌───────────────┐   ┌───────────────┐
│ Reconnaissance│   │   Scanner     │   │  Inférence    │
│    Locale     │   │    Nmap       │   │   de Type     │
│ (utilitaires_ │   │ (enveloppe_   │   │ (inference_   │
│  reseau.py)   │   │   nmap.py)    │   │   type.py)    │
└───────────────┘   └───────────────┘   └───────────────┘
        │                   │                   │
        │                   │                   │
        v                   v                   v
┌───────────────┐   ┌───────────────┐   ┌───────────────┐
│  Exploration  │   │  Détection    │   │  Mouvement    │
│  Frontières   │   │    Pivot      │   │   Latéral     │
│(explorateur_  │   │ (detecteur_   │   │ (mouvement_   │
│frontieres.py) │   │   pivot.py)   │   │  lateral.py)  │
└───────────────┘   └───────────────┘   └───────────────┘
                            │
                            v
┌─────────────────────────────────────────────────────────────────┐
│                     Sortie et Exports                           │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐          │
│  │ Constructeur │  │  Exporteur   │  │  Générateur  │          │
│  │  Topologie   │  │   Verefoo    │  │   Rapports   │          │
│  └──────────────┘  └──────────────┘  └──────────────┘          │
└─────────────────────────────────────────────────────────────────┘
```

### 3.2 Flux de Fonctionnement

Le script suit un pipeline en 7 phases :

```
┌─────────────────────────────────────────────────────────────────┐
│ PHASE 1 : Reconnaissance Locale                                  │
│ - Lecture des interfaces réseau                                  │
│ - Analyse table de routage                                       │
│ - Lecture cache ARP                                              │
│ - Détection serveurs DNS                                         │
└───────────────────────────┬─────────────────────────────────────┘
                            v
┌─────────────────────────────────────────────────────────────────┐
│ PHASE 2 : Découverte des Réseaux                                │
│ - Balayage ping des réseaux détectés                            │
│ - Scan détaillé de chaque hôte actif                            │
│ - Itération sur les nouveaux réseaux trouvés                    │
└───────────────────────────┬─────────────────────────────────────┘
                            v
┌─────────────────────────────────────────────────────────────────┐
│ PHASE 3 : Fingerprinting et Inférence                           │
│ - Classification des équipements                                 │
│ - Attribution du type fonctionnel                                │
│   (ROUTER, FIREWALL, WEBSERVER, etc.)                           │
└───────────────────────────┬─────────────────────────────────────┘
                            v
┌─────────────────────────────────────────────────────────────────┐
│ PHASE 4 : Exploration des Frontières                            │
│ - Identification des passerelles                                 │
│ - Test des réseaux adjacents                                     │
│ - Détection des réseaux bloqués                                  │
└───────────────────────────┬─────────────────────────────────────┘
                            v
┌─────────────────────────────────────────────────────────────────┐
│ PHASE 5 : Détection des Pivots                                  │
│ - Identification des machines pouvant servir de rebond          │
│ - Calcul du score de confiance                                   │
│ - [Optionnel] Exécution du pas de côté                          │
└───────────────────────────┬─────────────────────────────────────┘
                            v
┌─────────────────────────────────────────────────────────────────┐
│ PHASE 6 : Construction Topologie                                │
│ - Création du graphe NetworkX                                    │
│ - Calcul des noeuds critiques                                    │
│ - Génération de la visualisation                                 │
└───────────────────────────┬─────────────────────────────────────┘
                            v
┌─────────────────────────────────────────────────────────────────┐
│ PHASE 7 : Exports et Rapports                                   │
│ - Export XML (format Verefoo)                                    │
│ - Export JSON (pour interface web)                               │
│ - Export GraphML (pour Gephi/Cytoscape)                         │
│ - Visualisation PNG                                              │
│ - Rapport textuel                                                │
└─────────────────────────────────────────────────────────────────┘
```

### 3.3 Modules Détaillés

#### 3.3.1 config.py - Configuration Centralisée

Ce module regroupe tous les paramètres de configuration :
- Paramètres Nmap (timing, ports, timeouts)
- Niveaux de profondeur (LEGER, NORMAL, COMPLET)
- Seuils pour l'inférence de type
- Chemins de sortie
- Couleurs pour la visualisation

On a choisi de tout centraliser pour faciliter les ajustements sans avoir à modifier le code métier.

#### 3.3.2 utilitaires_reseau.py - Reconnaissance Locale

Ce module analyse la machine locale pour déterminer :
- Les interfaces réseau actives et leurs IP
- La table de routage (compatible Linux, macOS, Windows)
- Le cache ARP (machines déjà connues)
- Les serveurs DNS configurés

C'est la première étape pour savoir quels réseaux scanner.

#### 3.3.3 enveloppe_nmap.py - Interface Nmap

Encapsule toutes les interactions avec Nmap :
- Balayage ping pour trouver les hôtes actifs
- Scan détaillé avec trois niveaux de profondeur
- Traceroute pour détecter les blocages
- Parsing des résultats XML

On a géré plusieurs cas particuliers, comme les timeouts ou les scans incomplets, pour que le script ne plante pas si un hôte ne répond pas.

#### 3.3.4 inference_type.py - Classification des Équipements

C'est un des modules les plus importants. Il détermine le type fonctionnel de chaque équipement en se basant sur :
- Les ports ouverts (80/443 = probablement serveur web)
- Les services détectés
- Le fabricant MAC (Cisco = routeur, HP = peut-être imprimante)
- L'adresse IP (x.x.x.1 ou x.x.x.254 = souvent passerelle)
- Le nom d'hôte
- Les sorties des scripts NSE

On a défini 11 types différents : WEBSERVER, WEBCLIENT, FIREWALL, NAT, ROUTER, DNS, DATABASE, MAILSERVER, PRINTER, IOT, UNKNOWN.

#### 3.3.5 explorateur_frontieres.py - Exploration des Frontières

Ce module pousse l'exploration au-delà des réseaux directement accessibles :
- Identifie les passerelles (routeurs, firewalls)
- Génère des réseaux candidats adjacents
- Teste leur accessibilité
- Catégorise les blocages (FIREWALL_FILTERED, NO_ROUTE, TIMEOUT, etc.)

On a ajouté un filtrage pour éviter les réseaux virtuels (Docker, link-local) qui polluaient les résultats.

#### 3.3.6 detecteur_pivot.py - Détection des Pivots

Identifie les machines pouvant servir de point de rebond :
- Score basé sur le type (ROUTER/FIREWALL = plus de points)
- Ports d'accès disponibles (SSH, Telnet, RDP)
- Position dans le traceroute
- Niveau de confiance (HIGH, MEDIUM, LOW)

#### 3.3.7 mouvement_lateral.py - Pas de Côté

Permet d'exécuter automatiquement des scans depuis les pivots détectés :
- Connexion au pivot (SSH, WinRM, Telnet)
- Déploiement de l'outil
- Exécution du scan
- Récupération et fusion des résultats

Cette partie est optionnelle et s'active avec l'option --pas-de-cote.

### 3.4 Interface Web (webapp/)

On a également développé une interface web pour visualiser les résultats de manière plus agréable qu'un fichier JSON brut.

L'interface propose :
- Upload du fichier JSON de résultats
- Statistiques globales (nombre d'hôtes, réseaux, ports)
- Graphique de distribution des types d'équipements
- Liste des fabricants MAC détectés
- Tableau interactif des équipements avec recherche et filtres
- Vue détaillée pour chaque équipement
- Thème clair/sombre

L'interface est construite avec Flask côté serveur et du JavaScript vanilla côté client, avec Chart.js pour les graphiques.

### 3.5 Utilisation de l'Intelligence Artificielle

On a utilisé l'intelligence artificielle à plusieurs étapes du projet, et on pense que c'est important de le mentioner car ça a vraiment accéléré notre travail.

#### 3.5.1 Mise en Lien des Modules

Notre projet étant constitué de plusieurs fichiers Python qui doivent fonctionner ensemble, on a utilisé l'IA pour vérifier que les modules s'intégraient correctement. Elle nous a aidé à :
- Vérifier la cohérence des imports entre fichiers
- S'assurer que les interfaces entre modules étaient compatibles
- Détecter des problèmes potentiels avant l'exécution

#### 3.5.2 Interface Web

Pour la partie visuelle de la webapp, on a été assistés par l'IA. On avait une idée de ce qu'on voulait (un dashboard moderne avec des stats et un tableau), mais on n'était pas experts en CSS/JavaScript. L'IA nous a aidé à :
- Structurer le HTML de manière sémantique
- Créer un design responsive et moderne
- Implémenter les interactions (drag-drop, modales, theme switcher)

On a quand même fait des ajustements manuels pour que ça corresponde exactement à nos besoins.

#### 3.5.3 Analyse de Dépôts GitHub

Avant de coder, on a cherché des projets similaires sur GitHub pour s'inspirer des bonnes pratiques. L'IA nous a permis de scanner ces dépôts et de nous indiquer :
- Les points importants à étudier
- Les patterns de code intéressants
- Les fonctionnalités qu'on pourrait adapter

Ça nous a fait gagner pas mal de temps par rapport à lire tout le code nous-mêmes.

---

## 4. Fonctionnalités Implémentées

### 4.1 Menu Interactif

Au lancement, l'outil affiche un menu avec les informations de la machine locale :

```
======================================================================
   OUTIL DE DÉCOUVERTE ET EXPLORATION RÉSEAU
======================================================================

------------------------- MACHINE ATTAQUANTE -------------------------

  IP locale       : 192.168.1.131
  Passerelle      : 192.168.1.1

  Interfaces actives:
    - en0: 192.168.1.131 (réseau: 192.168.1.0/24)

  Serveurs DNS    : 192.168.1.1
  Entrées ARP     : 13 machines connues
  Routes          : 77 réseaux accessibles

--------------------------- MENU PRINCIPAL ---------------------------

  [1] Scan rapide (réseau local uniquement)
  [2] Scan approfondi (avec détection OS et services)
  [3] Explorer les réseaux voisins
  [4] Scan manuel (choisir le réseau)
  [5] Quitter

  Votre choix [1]:
```

### 4.2 Trois Niveaux de Profondeur

On a implémenté trois niveaux de scan pour s'adapter aux besoins :

| Niveau | Description | Temps estimé |
|--------|-------------|--------------|
| LEGER (1) | Scan rapide, ports principaux | 3-5 min |
| NORMAL (2) | Détection version services | 5-15 min |
| COMPLET (3) | Détection OS + scripts NSE | 15-30 min |

### 4.3 Classification des Équipements

L'outil détecte automatiquement 11 types d'équipements :

- **ROUTER** : Détecté par IP (.1/.254), fabricant (Cisco, Juniper, etc.), ou OS (Cisco IOS)
- **FIREWALL** : Nombreux ports filtrés, mots-clés spécifiques
- **NAT** : Keywords NAT/masquerade, scripts UPnP
- **WEBSERVER** : Ports 80/443, services HTTP
- **MAILSERVER** : Ports SMTP/IMAP/POP3
- **DNS** : Port 53 ouvert
- **DATABASE** : Ports MySQL/PostgreSQL/MongoDB
- **PRINTER** : Ports 9100/631, fabricants HP/Canon/Epson
- **IOT** : Fabricants Espressif/Raspberry, ports MQTT
- **WEBCLIENT** : Peu de ports ouverts (SSH/RDP seulement)
- **UNKNOWN** : Type non déterminé

### 4.4 Exports Multiples

Les résultats sont exportés dans plusieurs formats :

- **JSON** : Données complètes pour l'interface web
- **XML Verefoo** : Format spécifique pour l'outil Verefoo
- **GraphML** : Compatible Gephi/Cytoscape pour analyses avancées
- **PNG** : Visualisation graphique de la topologie
- **TXT** : Rapport textuel lisible

---

## 5. Tests et Résultats

### 5.1 Environnement de Test Final

Faute de pouvoir utiliser CyberRange correctement, on a effectué nos tests sur des réseaux domestiques. Même si ce n'était pas l'environnement idéal, ça nous a permis de valider le fonctionnement du script.

### 5.2 Résultats Obtenus

Les tests ont montré que l'outil était capable de :
- Détecter correctement les hôtes actifs sur le réseau
- Identifier les services en écoute
- Classifier les équipements de manière cohérente (la box internet était bien identifiée comme ROUTER par exemple)
- Générer des exports exploitables

On a été agréablement surpris par la quantité d'informations récupérées, même sur un simple réseau domestique.

### 5.3 Limitations Observées

Quelques limitations qu'on a identifiées :
- La détection OS nécessite les privilèges root et reste parfois approximative
- Les scans complets peuvent être longs sur de grands réseaux
- Certains équipements restent en UNKNOWN faute d'informations suffisantes

---

## 6. Conclusion

### 6.1 Bilan du Projet

Malgré les nombreux problèmes techniques rencontrés avec CyberRange, on a réussi à développer un outil fonctionnel qui répond aux objectifs initiaux. Le script est capable de découvrir automatiquement une infrastructure réseau, de classifier les équipements, et de générer des rapports exploitables.

La partie la plus frustrante a été l'impossibilité de tester sur une topologie contrôlée. On a passé beaucoup de temps à essayer de faire fonctionner CyberRange, temps qu'on aurait préféré consacrer au développement de fonctionnalités supplémentaires.

### 6.2 Compétences Acquises

Ce projet nous a permis de développer des compétences dans plusieurs domaines :
- Programmation Python (architecture modulaire, gestion d'erreurs)
- Utilisation de Nmap et compréhension des techniques de scan
- Développement web (Flask, JavaScript, CSS moderne)
- Travail en équipe et gestion des problèmes techniques

### 6.3 Évolutions Possibles

Si on devait continuer le projet, on envisagerait :
- Améliorer la précision de la détection de type avec du machine learning
- Ajouter un mode "stealth" pour des scans plus discrets
- Implémenter une API REST complète pour l'intégration avec d'autres outils
- Créer une version Docker pour faciliter le déploiement

---

## 7. Annexes

### 7.1 Identifiants CyberRange

Pour référence, voici les identifiants configurés sur les machines CyberRange :

| Machine | Identifiant | Mot de passe |
|---------|-------------|--------------|
| Debian 12 | root | lannion |
| Ubuntu | os | os |
| Kali Linux | kali | kali |

### 7.2 Commandes Principales

```bash
# Lancement avec menu interactif
sudo python3 src/principal.py

# Scan d'un réseau spécifique
sudo python3 src/principal.py --target 192.168.1.0/24

# Scan approfondi
sudo python3 src/principal.py --deep

# Mode sans privilèges root
python3 src/principal.py --no-root

# Avec pas de côté automatique
sudo python3 src/principal.py --pas-de-cote --ssh-key ~/.ssh/id_rsa

# Lancement de l'interface web
python3 webapp/app.py
```

### 7.3 Structure du Projet

```
network_discovery_tool/
├── src/
│   ├── principal.py           # Orchestrateur principal
│   ├── config.py              # Configuration centralisée
│   ├── menu_interactif.py     # Interface CLI
│   ├── utilitaires_reseau.py  # Reconnaissance locale
│   ├── enveloppe_nmap.py      # Wrapper Nmap
│   ├── inference_type.py      # Classification équipements
│   ├── explorateur_frontieres.py  # Exploration réseau
│   ├── detecteur_pivot.py     # Détection pivots
│   ├── mouvement_lateral.py   # Pas de côté
│   ├── constructeur_topologie.py  # Graphe NetworkX
│   ├── exporteur_verefoo.py   # Exports XML/JSON
│   └── generateur_rapports.py # Rapports textuels
├── webapp/
│   ├── app.py                 # Backend Flask
│   ├── templates/
│   │   └── index.html         # Interface web
│   └── static/
│       ├── css/style.css      # Styles
│       └── js/app.js          # JavaScript
├── docs/
│   ├── README.md              # Documentation principale
│   ├── QUICKSTART.md          # Guide démarrage rapide
│   └── ARCHITECTURE.md        # Documentation technique
├── output/                    # Résultats des scans
├── logs/                      # Fichiers de log
└── requirements.txt           # Dépendances Python
```

---

*Rapport rédigé dans le cadre de la SAE 5.01 - IUT de Lannion*
