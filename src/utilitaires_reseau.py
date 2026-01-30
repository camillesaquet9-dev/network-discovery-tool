import subprocess
import ipaddress
import netifaces
import logging
from typing import List, Dict, Tuple, Optional

logger = logging.getLogger(__name__)


class ReconnaissanceLocale:
    def __init__(self):
        self.ip_locale = None
        self.interfaces = []
        self.routes = []
        self.cache_arp = []
        self.serveurs_dns = []
        self.passerelle_defaut = None

    def executer_reconnaissance_complete(self) -> Dict:
        logger.info("[ReconnaissanceLocale] Demarrage")

        self.obtenir_interfaces()
        self.obtenir_routes()
        self.obtenir_cache_arp()
        self.obtenir_serveurs_dns()

        resultats = {
            "ip_locale": self.ip_locale,
            "interfaces": self.interfaces,
            "routes": self.routes,
            "cache_arp": self.cache_arp,
            "serveurs_dns": self.serveurs_dns,
            "passerelle_defaut": self.passerelle_defaut
        }

        logger.info(f"[ReconnaissanceLocale] Termine: {len(self.interfaces)} interfaces, "
                   f"{len(self.routes)} routes, {len(self.cache_arp)} entrees ARP")

        return resultats

    def obtenir_interfaces(self) -> List[Dict]:
        logger.debug("[ReconnaissanceLocale] Lecture des interfaces")

        try:
            for interface in netifaces.interfaces():
                try:
                    adresses = netifaces.ifaddresses(interface)

                    if interface == 'lo' or interface.startswith('lo'):
                        continue

                    if netifaces.AF_INET in adresses:
                        for info_addr in adresses[netifaces.AF_INET]:
                            ip = info_addr.get('addr')
                            masque = info_addr.get('netmask')

                            if ip and masque:
                                reseau = ipaddress.ip_network(f"{ip}/{masque}", strict=False)

                                donnees_interface = {
                                    "nom": interface,
                                    "ip": ip,
                                    "masque": masque,
                                    "reseau": str(reseau),
                                    "cidr": reseau.prefixlen
                                }

                                self.interfaces.append(donnees_interface)

                                if not self.ip_locale and not ip.startswith('127.'):
                                    self.ip_locale = ip

                                logger.debug(f"  Interface {interface}: {ip}/{reseau.prefixlen} "
                                           f"(reseau: {reseau})")

                except Exception as e:
                    logger.warning(f"  Erreur traitement interface {interface}: {e}")

        except Exception as e:
            logger.error(f"[ReconnaissanceLocale] Erreur lecture interfaces: {e}")

        return self.interfaces

    def obtenir_routes(self) -> List[Dict]:
        logger.debug("[ReconnaissanceLocale] Lecture table de routage")

        try:
            resultat = subprocess.run(
                ["ip", "route"],
                capture_output=True,
                text=True,
                timeout=5
            )

            if resultat.returncode == 0:
                self._analyser_ip_route(resultat.stdout)
            else:
                resultat = subprocess.run(
                    ["netstat", "-rn"],
                    capture_output=True,
                    text=True,
                    timeout=5
                )
                if resultat.returncode == 0:
                    self._analyser_netstat_route(resultat.stdout)

        except FileNotFoundError:
            try:
                resultat = subprocess.run(
                    ["netstat", "-rn"],
                    capture_output=True,
                    text=True,
                    timeout=5
                )
                if resultat.returncode == 0:
                    self._analyser_netstat_route(resultat.stdout)
            except Exception as e:
                logger.error(f"[ReconnaissanceLocale] Erreur lecture table routage: {e}")

        except Exception as e:
            logger.error(f"[ReconnaissanceLocale] Erreur execution ip route: {e}")

        return self.routes

    def _analyser_ip_route(self, sortie: str):
        for ligne in sortie.strip().split('\n'):
            if not ligne:
                continue

            parties = ligne.split()

            if ligne.startswith("default"):
                if len(parties) >= 3:
                    passerelle = parties[2]
                    self.passerelle_defaut = passerelle
                    self.routes.append({
                        "destination": "0.0.0.0/0",
                        "passerelle": passerelle,
                        "type": "defaut"
                    })
                    logger.debug(f"  Route par defaut via {passerelle}")

            else:
                try:
                    destination = parties[0]
                    reseau = ipaddress.ip_network(destination, strict=False)

                    donnees_route = {
                        "destination": str(reseau),
                        "passerelle": None,
                        "type": "directe"
                    }

                    if "via" in parties:
                        idx_via = parties.index("via")
                        if idx_via + 1 < len(parties):
                            donnees_route["passerelle"] = parties[idx_via + 1]
                            donnees_route["type"] = "indirecte"

                    self.routes.append(donnees_route)
                    logger.debug(f"  Route vers {reseau} via {donnees_route.get('passerelle', 'direct')}")

                except ValueError:
                    continue

    def _analyser_netstat_route(self, sortie: str):
        for ligne in sortie.strip().split('\n'):
            if not ligne or ligne.startswith("Routing") or ligne.startswith("Destination") or ligne.startswith("Internet"):
                continue

            parties = ligne.split()
            if len(parties) < 2:
                continue

            destination = parties[0]
            passerelle = parties[1]

            if destination == "default" or destination == "0.0.0.0":
                self.passerelle_defaut = passerelle
                self.routes.append({
                    "destination": "0.0.0.0/0",
                    "passerelle": passerelle,
                    "type": "defaut"
                })
                logger.debug(f"  Route par defaut via {passerelle}")

            else:
                try:
                    if '/' in destination:
                        reseau = ipaddress.ip_network(destination, strict=False)
                    else:
                        reseau = ipaddress.ip_network(f"{destination}/32", strict=False)

                    type_route = "indirecte" if passerelle != "link#" and passerelle != destination else "directe"

                    self.routes.append({
                        "destination": str(reseau),
                        "passerelle": passerelle if type_route == "indirecte" else None,
                        "type": type_route
                    })

                    logger.debug(f"  Route vers {reseau} via {passerelle}")

                except ValueError:
                    continue

    def obtenir_cache_arp(self) -> List[Dict]:
        logger.debug("[ReconnaissanceLocale] Lecture cache ARP")

        try:
            resultat = subprocess.run(
                ["ip", "neigh"],
                capture_output=True,
                text=True,
                timeout=5
            )

            if resultat.returncode == 0:
                self._analyser_ip_neigh(resultat.stdout)
            else:
                resultat = subprocess.run(
                    ["arp", "-an"],
                    capture_output=True,
                    text=True,
                    timeout=5
                )
                if resultat.returncode == 0:
                    self._analyser_arp(resultat.stdout)

        except FileNotFoundError:
            try:
                resultat = subprocess.run(
                    ["arp", "-an"],
                    capture_output=True,
                    text=True,
                    timeout=5
                )
                if resultat.returncode == 0:
                    self._analyser_arp(resultat.stdout)
            except Exception as e:
                logger.error(f"[ReconnaissanceLocale] Erreur lecture cache ARP: {e}")

        except Exception as e:
            logger.error(f"[ReconnaissanceLocale] Erreur execution ip neigh: {e}")

        return self.cache_arp

    def _analyser_ip_neigh(self, sortie: str):
        for ligne in sortie.strip().split('\n'):
            if not ligne:
                continue

            parties = ligne.split()
            if len(parties) < 5:
                continue

            ip = parties[0]
            if "lladdr" in parties:
                idx_mac = parties.index("lladdr")
                if idx_mac + 1 < len(parties):
                    mac = parties[idx_mac + 1]
                    etat = parties[-1] if len(parties) > idx_mac + 2 else "INCONNU"

                    self.cache_arp.append({
                        "ip": ip,
                        "mac": mac,
                        "etat": etat
                    })

                    logger.debug(f"  ARP: {ip} -> {mac} ({etat})")

    def _analyser_arp(self, sortie: str):
        for ligne in sortie.strip().split('\n'):
            if not ligne or "incomplete" in ligne.lower():
                continue

            try:
                if '(' in ligne and ')' in ligne and ' at ' in ligne:
                    debut_ip = ligne.index('(') + 1
                    fin_ip = ligne.index(')')
                    ip = ligne[debut_ip:fin_ip]

                    debut_mac = ligne.index(' at ') + 4
                    partie_mac = ligne[debut_mac:].split()[0]

                    self.cache_arp.append({
                        "ip": ip,
                        "mac": partie_mac,
                        "etat": "ACCESSIBLE"
                    })

                    logger.debug(f"  ARP: {ip} -> {partie_mac}")

            except ValueError:
                continue

    def obtenir_serveurs_dns(self) -> List[str]:
        logger.debug("[ReconnaissanceLocale] Lecture configuration DNS")

        try:
            with open("/etc/resolv.conf", "r") as f:
                for ligne in f:
                    ligne = ligne.strip()
                    if ligne.startswith("nameserver"):
                        parties = ligne.split()
                        if len(parties) >= 2:
                            ip_dns = parties[1]
                            self.serveurs_dns.append(ip_dns)
                            logger.debug(f"  DNS: {ip_dns}")

        except FileNotFoundError:
            logger.warning("[ReconnaissanceLocale] /etc/resolv.conf introuvable")
        except Exception as e:
            logger.error(f"[ReconnaissanceLocale] Erreur lecture /etc/resolv.conf: {e}")

        return self.serveurs_dns

    def obtenir_cibles_initiales(self) -> List[str]:
        cibles = set()

        for interface in self.interfaces:
            reseau = interface.get("reseau")
            if reseau:
                try:
                    net = ipaddress.ip_network(reseau)
                    if net.version == 4 and net.is_private and not net.is_loopback:
                        cibles.add(reseau)
                        logger.info(f"[ReconnaissanceLocale] Reseau cible depuis interface: {reseau}")
                except ValueError:
                    continue

        for route in self.routes:
            destination = route.get("destination")
            if destination and destination != "0.0.0.0/0":
                try:
                    net = ipaddress.ip_network(destination)
                    if (net.version == 4 and
                        net.prefixlen >= 16 and
                        net.prefixlen < 32 and
                        net.is_private and
                        not net.is_loopback and
                        not net.is_multicast):
                        cibles.add(destination)
                        logger.info(f"[ReconnaissanceLocale] Reseau cible depuis route: {destination}")
                except ValueError:
                    continue

        return list(cibles)
