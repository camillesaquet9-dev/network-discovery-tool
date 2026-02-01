import logging
from typing import Dict, List, Optional

from config import (
    PORTS_WEBSERVER,
    PORTS_SERVEUR,
    MIN_PORTS_SERVEUR,
    MOTS_CLES_WEBSERVER,
    MOTS_CLES_FIREWALL,
    MOTS_CLES_NAT
)

FABRICANTS_ROUTEUR = [
    "cisco", "juniper", "mikrotik", "ubiquiti", "netgear", "tp-link",
    "d-link", "asus", "linksys", "zyxel", "huawei", "fortinet", "paloalto"
]

FABRICANTS_SERVEUR = [
    "dell", "hp", "hpe", "ibm", "lenovo", "supermicro", "fujitsu"
]

FABRICANTS_IOT = [
    "espressif", "raspberry", "arduino", "particle", "texas instruments",
    "tuya", "sonoff", "shelly", "tasmota", "xiaomi", "philips hue"
]

FABRICANTS_IMPRIMANTE = [
    "hp", "canon", "epson", "brother", "xerox", "lexmark", "ricoh", "kyocera"
]

logger = logging.getLogger(__name__)


class MoteurInferenceType:
    TYPES = [
        "WEBSERVER",
        "WEBCLIENT",
        "FIREWALL",
        "NAT",
        "MAILSERVER",
        "DNS",
        "DATABASE",
        "ROUTER",
        "PRINTER",
        "IOT",
        "FORWARDER",
        "UNKNOWN"
    ]

    def __init__(self):
        pass

    def inferer_type(self, donnees_hote: Dict) -> str:
        ip = donnees_hote.get("ip", "inconnu")
        logger.debug(f"[InferenceType] Analyse du type pour {ip}")

        ports = donnees_hote.get("ports", [])
        services = donnees_hote.get("services", [])
        info_os = donnees_hote.get("os") or ""
        sortie_scripts = donnees_hote.get("sortie_scripts", {})
        fabricant_mac = donnees_hote.get("fabricant_mac", "") or ""
        nom_hote = donnees_hote.get("nom_hote", "") or ""

        ports_ouverts = [p["port"] for p in ports if p.get("etat") in ["open", "open|filtered"]]
        ports_filtres = [p["port"] for p in ports if p.get("etat") == "filtered"]

        noms_services = [s.get("service", "").lower() for s in ports if s.get("service")]
        produits_services = [s.get("produit", "").lower() for s in ports if s.get("produit")]

        tout_texte = " ".join([
            info_os.lower() if info_os else "",
            " ".join(noms_services),
            " ".join(produits_services),
            " ".join(sortie_scripts.values()),
            fabricant_mac.lower(),
            nom_hote.lower()
        ])

        logger.debug(f"  Ports ouverts: {ports_ouverts}")
        logger.debug(f"  Ports filtres: {ports_filtres}")
        logger.debug(f"  Services: {noms_services}")
        logger.debug(f"  Fabricant MAC: {fabricant_mac}")

        if self._est_routeur_par_ip(ip):
            logger.info(f"[InferenceType] {ip} -> ROUTER (IP passerelle)")
            return "ROUTER"

        if self._est_routeur_par_fabricant(fabricant_mac):
            logger.info(f"[InferenceType] {ip} -> ROUTER (fabricant {fabricant_mac})")
            return "ROUTER"

        if self._est_firewall(ports_ouverts, ports_filtres, tout_texte, sortie_scripts):
            logger.info(f"[InferenceType] {ip} -> FIREWALL")
            return "FIREWALL"

        if self._est_nat(tout_texte, sortie_scripts):
            logger.info(f"[InferenceType] {ip} -> NAT")
            return "NAT"

        if self._est_routeur(info_os, tout_texte):
            logger.info(f"[InferenceType] {ip} -> ROUTER")
            return "ROUTER"

        if self._est_webserver(ports_ouverts, noms_services, produits_services):
            logger.info(f"[InferenceType] {ip} -> WEBSERVER")
            return "WEBSERVER"

        if self._est_mailserver(ports_ouverts, noms_services):
            logger.info(f"[InferenceType] {ip} -> MAILSERVER")
            return "MAILSERVER"

        if self._est_dns(ports_ouverts, noms_services):
            logger.info(f"[InferenceType] {ip} -> DNS")
            return "DNS"

        if self._est_database(ports_ouverts, noms_services):
            logger.info(f"[InferenceType] {ip} -> DATABASE")
            return "DATABASE"

        if self._est_imprimante(ports_ouverts, fabricant_mac, tout_texte):
            logger.info(f"[InferenceType] {ip} -> PRINTER")
            return "PRINTER"

        if self._est_iot(ports_ouverts, fabricant_mac, tout_texte):
            logger.info(f"[InferenceType] {ip} -> IOT")
            return "IOT"

        if self._est_serveur_generique(ports_ouverts, fabricant_mac):
            logger.info(f"[InferenceType] {ip} -> WEBSERVER (serveur generique)")
            return "WEBSERVER"

        if len(ports_ouverts) == 0 and len(ports_filtres) == 0:
            logger.info(f"[InferenceType] {ip} -> UNKNOWN (aucun port)")
            return "UNKNOWN"

        if self._est_webclient(ports_ouverts):
            logger.info(f"[InferenceType] {ip} -> WEBCLIENT")
            return "WEBCLIENT"

        logger.info(f"[InferenceType] {ip} -> UNKNOWN")
        return "UNKNOWN"

    def _est_routeur_par_ip(self, ip: str) -> bool:
        try:
            octets = ip.split('.')
            if len(octets) == 4:
                dernier_octet = int(octets[3])
                if dernier_octet in [1, 254]:
                    return True
        except (ValueError, IndexError):
            pass
        return False

    def _est_routeur_par_fabricant(self, fabricant: str) -> bool:
        fabricant_lower = fabricant.lower()
        for fab in FABRICANTS_ROUTEUR:
            if fab in fabricant_lower:
                return True
        return False

    def _est_serveur_generique(self, ports_ouverts: List[int], fabricant: str) -> bool:
        fabricant_lower = fabricant.lower()
        for fab in FABRICANTS_SERVEUR:
            if fab in fabricant_lower:
                return True

        ports_serveur = [22, 80, 443, 3389, 5900]
        if any(p in ports_ouverts for p in ports_serveur):
            return len(ports_ouverts) >= 2

        return False

    def _est_firewall(self, ports_ouverts: List[int], ports_filtres: List[int],
                     texte: str, scripts: Dict) -> bool:
        if len(ports_filtres) > 10:
            logger.debug("    Indice FIREWALL: nombreux ports filtres")
            return True

        for mot_cle in MOTS_CLES_FIREWALL:
            if mot_cle in texte:
                logger.debug(f"    Indice FIREWALL: mot-cle '{mot_cle}'")
                return True

        ports_mgmt_firewall = [4444, 8443, 10443, 4118]
        if any(p in ports_ouverts for p in ports_mgmt_firewall):
            logger.debug("    Indice FIREWALL: port management")
            return True

        return False

    def _est_nat(self, texte: str, scripts: Dict) -> bool:
        for mot_cle in MOTS_CLES_NAT:
            if mot_cle in texte:
                logger.debug(f"    Indice NAT: mot-cle '{mot_cle}'")
                return True

        scripts_nat = ["nat-pmp-info", "upnp-info"]
        for script in scripts_nat:
            if script in scripts:
                logger.debug(f"    Indice NAT: script NSE '{script}'")
                return True

        return False

    def _est_webserver(self, ports_ouverts: List[int], noms_services: List[str],
                      produits_services: List[str]) -> bool:
        ports_web_ouverts = [p for p in ports_ouverts if p in PORTS_WEBSERVER]
        if ports_web_ouverts:
            logger.debug(f"    Indice WEBSERVER: ports web {ports_web_ouverts}")

            if any("http" in s for s in noms_services):
                logger.debug("    Indice WEBSERVER confirme: service HTTP")
                return True

            for mot_cle in MOTS_CLES_WEBSERVER:
                if any(mot_cle in p for p in produits_services):
                    logger.debug(f"    Indice WEBSERVER confirme: produit '{mot_cle}'")
                    return True

            return True

        return False

    def _est_mailserver(self, ports_ouverts: List[int], noms_services: List[str]) -> bool:
        ports_mail = [25, 110, 143, 465, 587, 993, 995]
        services_mail = ["smtp", "pop3", "imap"]

        ports_mail_ouverts = [p for p in ports_ouverts if p in ports_mail]
        if ports_mail_ouverts:
            logger.debug(f"    Indice MAILSERVER: ports mail {ports_mail_ouverts}")
            return True

        if any(ms in noms_services for ms in services_mail):
            logger.debug("    Indice MAILSERVER: service mail")
            return True

        return False

    def _est_dns(self, ports_ouverts: List[int], noms_services: List[str]) -> bool:
        if 53 in ports_ouverts:
            logger.debug("    Indice DNS: port 53")
            return True

        if "domain" in noms_services or "dns" in noms_services:
            logger.debug("    Indice DNS: service detecte")
            return True

        return False

    def _est_database(self, ports_ouverts: List[int], noms_services: List[str]) -> bool:
        ports_db = [3306, 5432, 1433, 1521, 27017, 6379, 5984]
        services_db = ["mysql", "postgresql", "mssql", "oracle", "mongodb", "redis", "couchdb"]

        ports_db_ouverts = [p for p in ports_ouverts if p in ports_db]
        if ports_db_ouverts:
            logger.debug(f"    Indice DATABASE: ports DB {ports_db_ouverts}")
            return True

        if any(db in noms_services for db in services_db):
            logger.debug("    Indice DATABASE: service DB")
            return True

        return False

    def _est_routeur(self, info_os: str, texte: str) -> bool:
        mots_cles_routeur = ["cisco ios", "junos", "mikrotik", "routeros", "vyos", "pfsense"]

        os_minuscule = (info_os or "").lower()
        for mot_cle in mots_cles_routeur:
            if mot_cle in os_minuscule:
                logger.debug(f"    Indice ROUTER: OS '{mot_cle}'")
                return True

        return False

    def _est_webclient(self, ports_ouverts: List[int]) -> bool:
        if len(ports_ouverts) == 0:
            return False

        ports_client_typiques = [22, 3389, 5900]
        ports_non_client = [p for p in ports_ouverts if p not in ports_client_typiques]

        if len(ports_non_client) == 0 and len(ports_ouverts) <= 2:
            logger.debug("    Indice WEBCLIENT: ports client uniquement (SSH/RDP/VNC)")
            return True

        ports_serveur_ouverts = [p for p in ports_ouverts if p in PORTS_SERVEUR]
        if len(ports_serveur_ouverts) < MIN_PORTS_SERVEUR and len(ports_ouverts) > 0:
            logger.debug(f"    Indice WEBCLIENT: peu de ports serveur ({len(ports_serveur_ouverts)})")
            return True

        return False

    def _est_imprimante(self, ports_ouverts: List[int], fabricant: str, texte: str) -> bool:
        ports_imprimante = [9100, 515, 631, 9101, 9102]

        ports_imp_ouverts = [p for p in ports_ouverts if p in ports_imprimante]
        if ports_imp_ouverts:
            logger.debug(f"    Indice PRINTER: ports imprimante {ports_imp_ouverts}")
            return True

        fabricant_lower = fabricant.lower()
        for fab in FABRICANTS_IMPRIMANTE:
            if fab in fabricant_lower:
                logger.debug(f"    Indice PRINTER: fabricant {fab}")
                return True

        mots_cles_imprimante = ["printer", "print", "laserjet", "inkjet", "deskjet", "officejet"]
        for mot in mots_cles_imprimante:
            if mot in texte:
                logger.debug(f"    Indice PRINTER: mot-cle '{mot}'")
                return True

        return False

    def _est_iot(self, ports_ouverts: List[int], fabricant: str, texte: str) -> bool:
        fabricant_lower = fabricant.lower()
        for fab in FABRICANTS_IOT:
            if fab in fabricant_lower:
                logger.debug(f"    Indice IOT: fabricant {fab}")
                return True

        mots_cles_iot = ["esp8266", "esp32", "raspberry", "arduino", "tasmota", "shelly",
                        "smart", "sensor", "thermostat", "camera ip", "iot", "mqtt"]
        for mot in mots_cles_iot:
            if mot in texte:
                logger.debug(f"    Indice IOT: mot-cle '{mot}'")
                return True

        ports_iot = [1883, 8883, 5683, 5684]
        if any(p in ports_ouverts for p in ports_iot):
            logger.debug("    Indice IOT: port MQTT/CoAP")
            return True

        return False

    def annoter_hote_avec_type(self, donnees_hote: Dict) -> Dict:
        type_fonctionnel = self.inferer_type(donnees_hote)
        donnees_hote["type_fonctionnel"] = type_fonctionnel
        return donnees_hote

    def annoter_plusieurs_hotes(self, hotes: List[Dict]) -> List[Dict]:
        logger.info(f"[InferenceType] Annotation de {len(hotes)} hotes")

        annotes = []
        for hote in hotes:
            hote_annote = self.annoter_hote_avec_type(hote)
            annotes.append(hote_annote)

        compteurs_types = {}
        for hote in annotes:
            ftype = hote.get("type_fonctionnel", "UNKNOWN")
            compteurs_types[ftype] = compteurs_types.get(ftype, 0) + 1

        logger.info(f"[InferenceType] Types detectes: {compteurs_types}")

        return annotes
