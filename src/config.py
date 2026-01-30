import os

# Parametres Nmap
TIMING_NMAP = 3
PORTS_TOP_NMAP = 1000
TIMEOUT_HOTE_NMAP = 120
ACTIVER_DETECTION_OS = True
ACTIVER_SCRIPTS_NSE = True
SCRIPTS_NSE = "default,discovery,safe"

# Decouverte reseau
MASQUES_RESEAU = [24, 16]
PLAGES_PRIVEES = [
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16"
]
MAX_ITERATIONS_DECOUVERTE = 5

# Detection blocages
NB_TENTATIVES_BLOCAGE = 3
TIMEOUT_TRACEROUTE = 10
MAX_SAUTS_TRACEROUTE = 30

# Export
REPERTOIRE_SORTIE = os.path.join(os.path.dirname(os.path.dirname(__file__)), "output")
REPERTOIRE_LOGS = os.path.join(os.path.dirname(os.path.dirname(__file__)), "logs")
PREFIXE_SORTIE = "network_scan"
FORMAT_EXPORT = "both"

# Inference de type
PORTS_WEBSERVER = [80, 443, 8080, 8443, 8000, 8888]
PORTS_SERVEUR = [21, 22, 23, 25, 53, 80, 110, 143, 443, 3306, 5432, 6379, 8080]
MIN_PORTS_SERVEUR = 2

MOTS_CLES_WEBSERVER = ["apache", "nginx", "iis", "httpd", "lighttpd", "caddy"]
MOTS_CLES_FIREWALL = ["firewall", "iptables", "pfsense", "fortinet", "checkpoint", "cisco asa"]
MOTS_CLES_NAT = ["nat", "masquerade", "snat", "dnat"]

# Logging
NIVEAU_LOG = "INFO"
FORMAT_LOG = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"

# Visualisation
TAILLE_FIGURE_GRAPHE = (20, 14)
TAILLE_NOEUD_GRAPHE = 3000
TAILLE_POLICE_GRAPHE = 8

COULEURS_TYPE_FONCTIONNEL = {
    "WEBSERVER": "#4CAF50",
    "WEBCLIENT": "#2196F3",
    "FIREWALL": "#F44336",
    "NAT": "#FF9800",
    "DNS": "#FFEB3B",
    "MAILSERVER": "#9C27B0",
    "DATABASE": "#795548",
    "ROUTER": "#607D8B",
    "UNKNOWN": "#9E9E9E"
}

def creer_repertoires():
    os.makedirs(REPERTOIRE_SORTIE, exist_ok=True)
    os.makedirs(REPERTOIRE_LOGS, exist_ok=True)

def obtenir_chemin_sortie(nom_fichier):
    return os.path.join(REPERTOIRE_SORTIE, nom_fichier)

def obtenir_chemin_log(nom_fichier):
    return os.path.join(REPERTOIRE_LOGS, nom_fichier)
