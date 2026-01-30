import subprocess
import xml.etree.ElementTree as ET
import logging
import os
import tempfile
from typing import List, Dict, Optional
import ipaddress

from config import (
    TIMING_NMAP,
    PORTS_TOP_NMAP,
    TIMEOUT_HOTE_NMAP,
    ACTIVER_DETECTION_OS,
    ACTIVER_SCRIPTS_NSE,
    SCRIPTS_NSE
)

logger = logging.getLogger(__name__)


class ScannerNmap:
    def __init__(self):
        self.resultats_scan = []
        self._verifier_nmap_installe()

    def _verifier_nmap_installe(self):
        try:
            resultat = subprocess.run(
                ["nmap", "--version"],
                capture_output=True,
                text=True,
                timeout=5
            )
            if resultat.returncode == 0:
                ligne_version = resultat.stdout.split('\n')[0]
                logger.info(f"[ScannerNmap] {ligne_version}")
            else:
                raise RuntimeError("Nmap trouve mais ne repond pas correctement")

        except FileNotFoundError:
            raise RuntimeError("Nmap non installe ou absent du PATH")
        except Exception as e:
            raise RuntimeError(f"Erreur verification nmap: {e}")

    def balayage_ping(self, reseau: str) -> List[str]:
        logger.info(f"[ScannerNmap] Balayage ping sur {reseau}")

        hotes_actifs = []

        try:
            with tempfile.NamedTemporaryFile(mode='w', suffix='.xml', delete=False) as temp_file:
                chemin_temp = temp_file.name

            cmd = [
                "nmap",
                "-sn",
                "-PR",
                "-PS80,443,22",
                "-PA80,443,22",
                "-PE",
                f"-T{TIMING_NMAP}",
                "--max-retries", "2",
                "--host-timeout", f"{TIMEOUT_HOTE_NMAP}s",
                "-oX", chemin_temp,
                reseau
            ]

            logger.debug(f"  Commande: {' '.join(cmd)}")

            resultat = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=TIMEOUT_HOTE_NMAP * 2
            )

            if os.path.exists(chemin_temp):
                hotes_actifs = self._analyser_xml_balayage_ping(chemin_temp)
                os.unlink(chemin_temp)

            logger.info(f"[ScannerNmap] {len(hotes_actifs)} hotes actifs sur {reseau}")

        except subprocess.TimeoutExpired:
            logger.warning(f"[ScannerNmap] Timeout balayage ping sur {reseau}")
            if os.path.exists(chemin_temp):
                hotes_actifs = self._analyser_xml_balayage_ping(chemin_temp)
                os.unlink(chemin_temp)

        except Exception as e:
            logger.error(f"[ScannerNmap] Erreur balayage ping: {e}")
            if os.path.exists(chemin_temp):
                os.unlink(chemin_temp)

        return hotes_actifs

    def _analyser_xml_balayage_ping(self, chemin_xml: str) -> List[str]:
        hotes_actifs = []

        try:
            arbre = ET.parse(chemin_xml)
            racine = arbre.getroot()

            for hote in racine.findall("host"):
                statut = hote.find("status")
                if statut is not None and statut.get("state") == "up":
                    adresse = hote.find("address")
                    if adresse is not None:
                        ip = adresse.get("addr")
                        if ip:
                            hotes_actifs.append(ip)
                            logger.debug(f"    Hote actif: {ip}")

        except ET.ParseError as e:
            logger.error(f"  Erreur parsing XML: {e}")
        except Exception as e:
            logger.error(f"  Erreur lecture XML: {e}")

        return hotes_actifs

    def scanner_hote(self, ip: str, approfondi: bool = True) -> Optional[Dict]:
        logger.info(f"[ScannerNmap] Scan detaille de {ip} (approfondi={approfondi})")

        try:
            with tempfile.NamedTemporaryFile(mode='w', suffix='.xml', delete=False) as temp_file:
                chemin_temp = temp_file.name

            cmd = [
                "nmap",
                "-sV",
                "--version-all",
                f"-T{TIMING_NMAP}",
                f"--top-ports", str(PORTS_TOP_NMAP),
                "--host-timeout", f"{TIMEOUT_HOTE_NMAP}s",
            ]

            if approfondi and ACTIVER_DETECTION_OS:
                cmd.extend(["-O", "--osscan-guess"])

            if approfondi and ACTIVER_SCRIPTS_NSE:
                cmd.extend(["-sC", "--script", SCRIPTS_NSE])

            cmd.extend(["-oX", chemin_temp, ip])

            logger.debug(f"  Commande: {' '.join(cmd)}")

            resultat = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=TIMEOUT_HOTE_NMAP * 3
            )

            if os.path.exists(chemin_temp):
                donnees_hote = self._analyser_xml_scan_hote(chemin_temp)
                os.unlink(chemin_temp)
                return donnees_hote

        except subprocess.TimeoutExpired:
            logger.warning(f"[ScannerNmap] Timeout scan de {ip}")
            if os.path.exists(chemin_temp):
                donnees_hote = self._analyser_xml_scan_hote(chemin_temp)
                os.unlink(chemin_temp)
                return donnees_hote

        except Exception as e:
            logger.error(f"[ScannerNmap] Erreur scan de {ip}: {e}")
            if os.path.exists(chemin_temp):
                os.unlink(chemin_temp)

        return None

    def _analyser_xml_scan_hote(self, chemin_xml: str) -> Optional[Dict]:
        try:
            arbre = ET.parse(chemin_xml)
            racine = arbre.getroot()

            hote = racine.find("host")
            if hote is None:
                return None

            statut = hote.find("status")
            if statut is None or statut.get("state") != "up":
                return None

            donnees_hote = {
                "ip": None,
                "mac": None,
                "nom_hote": None,
                "os": None,
                "precision_os": None,
                "ports": [],
                "services": [],
                "sortie_scripts": {}
            }

            for adresse in hote.findall("address"):
                type_addr = adresse.get("addrtype")
                valeur_addr = adresse.get("addr")

                if type_addr == "ipv4":
                    donnees_hote["ip"] = valeur_addr
                elif type_addr == "mac":
                    donnees_hote["mac"] = valeur_addr
                    fabricant = adresse.get("vendor")
                    if fabricant:
                        donnees_hote["fabricant_mac"] = fabricant

            noms_hotes = hote.find("hostnames")
            if noms_hotes is not None:
                elem_nom_hote = noms_hotes.find("hostname")
                if elem_nom_hote is not None:
                    donnees_hote["nom_hote"] = elem_nom_hote.get("name")

            elem_os = hote.find("os")
            if elem_os is not None:
                correspondance_os = elem_os.find("osmatch")
                if correspondance_os is not None:
                    donnees_hote["os"] = correspondance_os.get("name")
                    donnees_hote["precision_os"] = correspondance_os.get("accuracy")

            elem_ports = hote.find("ports")
            if elem_ports is not None:
                for port in elem_ports.findall("port"):
                    id_port = port.get("portid")
                    protocole = port.get("protocol")

                    elem_etat = port.find("state")
                    if elem_etat is None:
                        continue

                    etat_port = elem_etat.get("state")

                    elem_service = port.find("service")
                    nom_service = None
                    produit_service = None
                    version_service = None
                    info_service = None

                    if elem_service is not None:
                        nom_service = elem_service.get("name")
                        produit_service = elem_service.get("product")
                        version_service = elem_service.get("version")
                        info_service = elem_service.get("extrainfo")

                    donnees_port = {
                        "port": int(id_port),
                        "protocole": protocole,
                        "etat": etat_port,
                        "service": nom_service,
                        "produit": produit_service,
                        "version": version_service,
                        "info": info_service
                    }

                    donnees_hote["ports"].append(donnees_port)

                    chaine_service = nom_service or "inconnu"
                    if produit_service:
                        chaine_service += f" ({produit_service}"
                        if version_service:
                            chaine_service += f" {version_service}"
                        chaine_service += ")"

                    donnees_hote["services"].append({
                        "port": int(id_port),
                        "nom": nom_service,
                        "description": chaine_service
                    })

                    logger.debug(f"    Port {id_port}/{protocole}: {chaine_service} [{etat_port}]")

            script_hote = hote.find("hostscript")
            if script_hote is not None:
                for script in script_hote.findall("script"):
                    id_script = script.get("id")
                    sortie_script = script.get("output")
                    if id_script and sortie_script:
                        donnees_hote["sortie_scripts"][id_script] = sortie_script

            logger.info(f"  {len(donnees_hote['ports'])} ports detectes, OS: {donnees_hote.get('os', 'inconnu')}")

            return donnees_hote

        except ET.ParseError as e:
            logger.error(f"  Erreur parsing XML: {e}")
        except Exception as e:
            logger.error(f"  Erreur lecture XML: {e}")

        return None

    def scanner_reseau(self, reseau: str, approfondi: bool = False) -> List[Dict]:
        logger.info(f"[ScannerNmap] Scan reseau complet: {reseau} (approfondi={approfondi})")

        hotes_actifs = self.balayage_ping(reseau)

        if not hotes_actifs:
            logger.warning(f"[ScannerNmap] Aucun hote actif sur {reseau}")
            return []

        resultats = []
        for ip in hotes_actifs:
            donnees_hote = self.scanner_hote(ip, approfondi=approfondi)
            if donnees_hote:
                resultats.append(donnees_hote)

        logger.info(f"[ScannerNmap] Scan de {reseau} termine: "
                   f"{len(resultats)}/{len(hotes_actifs)} hotes scannes avec succes")

        return resultats

    def traceroute(self, cible: str) -> List[Dict]:
        logger.info(f"[ScannerNmap] Traceroute vers {cible}")

        sauts = []

        try:
            with tempfile.NamedTemporaryFile(mode='w', suffix='.xml', delete=False) as temp_file:
                chemin_temp = temp_file.name

            cmd = [
                "nmap",
                "-sn",
                "--traceroute",
                "--max-retries", "1",
                "-oX", chemin_temp,
                cible
            ]

            resultat = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=60
            )

            if os.path.exists(chemin_temp):
                sauts = self._analyser_xml_traceroute(chemin_temp)
                os.unlink(chemin_temp)

        except Exception as e:
            logger.error(f"[ScannerNmap] Erreur traceroute: {e}")
            if os.path.exists(chemin_temp):
                os.unlink(chemin_temp)

        return sauts

    def _analyser_xml_traceroute(self, chemin_xml: str) -> List[Dict]:
        sauts = []

        try:
            arbre = ET.parse(chemin_xml)
            racine = arbre.getroot()

            hote = racine.find("host")
            if hote is not None:
                trace = hote.find("trace")
                if trace is not None:
                    for saut in trace.findall("hop"):
                        ttl = saut.get("ttl")
                        ip = saut.get("ipaddr")
                        rtt = saut.get("rtt")
                        nom_hote = saut.get("host")

                        sauts.append({
                            "ttl": int(ttl) if ttl else 0,
                            "ip": ip,
                            "rtt": float(rtt) if rtt else None,
                            "nom_hote": nom_hote
                        })

                        logger.debug(f"  Saut {ttl}: {ip} ({rtt}ms)")

        except Exception as e:
            logger.error(f"  Erreur parsing traceroute: {e}")

        return sauts
