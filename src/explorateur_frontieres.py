import subprocess
import ipaddress
import logging
from typing import List, Dict, Optional, Set
import re

from config import (
    NB_TENTATIVES_BLOCAGE,
    TIMEOUT_TRACEROUTE,
    MAX_SAUTS_TRACEROUTE,
    PLAGES_PRIVEES,
    PLAGE_EXPLORATION_OCTET,
    MAX_RESEAUX_SANS_CONFIRMATION
)

logger = logging.getLogger(__name__)


class ExplorateurFrontieres:
    def __init__(self, scanner_nmap):
        self.scanner_nmap = scanner_nmap
        self.reseaux_bloques = []
        self.equipements_frontieres = []

    def explorer_au_dela_connu(self, reseaux_connus: List[str], hotes_decouverts: List[Dict],
                               limite: int = 10) -> Dict:
        logger.info("[ExplorateurFrontieres] Exploration frontieres reseau")

        reseaux_candidats = set()
        reseaux_bloques = []

        passerelles = self._identifier_passerelles(hotes_decouverts)
        logger.info(f"[ExplorateurFrontieres] {len(passerelles)} passerelles identifiees")

        if not passerelles:
            passerelles = self._identifier_passerelles_par_ip(hotes_decouverts)
            if passerelles:
                logger.info(f"[ExplorateurFrontieres] {len(passerelles)} passerelles potentielles (par IP)")

        for passerelle in passerelles:
            ip_passerelle = passerelle["ip"]
            logger.debug(f"  Analyse passerelle {ip_passerelle}")

            reseaux_test = self._generer_reseaux_candidats(ip_passerelle, reseaux_connus)
            reseaux_test = self._filtrer_reseaux_virtuels(reseaux_test)

            compteur = 0
            for reseau in reseaux_test:
                if compteur >= limite:
                    logger.debug(f"    Limite atteinte ({limite} reseaux)")
                    break

                if reseau in reseaux_candidats:
                    continue

                logger.debug(f"    Test reseau {reseau}")

                est_accessible, info_blocage = self._tester_accessibilite_reseau(
                    reseau, ip_passerelle
                )

                if est_accessible:
                    reseaux_candidats.add(reseau)
                    logger.info(f"  Reseau {reseau} accessible via {ip_passerelle}")
                    compteur += 1
                elif info_blocage:
                    reseaux_bloques.append({
                        "reseau": reseau,
                        "passerelle": ip_passerelle,
                        "raison": info_blocage["raison"],
                        "dernier_saut": info_blocage.get("dernier_saut")
                    })

        resultats = {
            "reseaux_candidats": list(reseaux_candidats),
            "reseaux_bloques": reseaux_bloques,
            "passerelles": passerelles
        }

        logger.info(f"[ExplorateurFrontieres] Exploration terminee: "
                   f"{len(reseaux_candidats)} nouveaux reseaux candidats, "
                   f"{len(reseaux_bloques)} reseaux bloques")

        return resultats

    def _identifier_passerelles_par_ip(self, hotes: List[Dict]) -> List[Dict]:
        passerelles = []
        for hote in hotes:
            ip = hote.get("ip", "")
            try:
                octets = ip.split('.')
                if len(octets) == 4:
                    dernier_octet = int(octets[3])
                    if dernier_octet in [1, 254]:
                        passerelles.append(hote)
                        logger.debug(f"  Passerelle potentielle: {ip} (IP typique)")
            except (ValueError, IndexError):
                pass
        return passerelles

    def _filtrer_reseaux_virtuels(self, reseaux: List[str]) -> List[str]:
        filtres = []
        for reseau in reseaux:
            if self._est_reseau_virtuel(reseau):
                logger.debug(f"    Exclus reseau virtuel: {reseau}")
                continue
            filtres.append(reseau)
        return filtres

    def _est_reseau_virtuel(self, reseau: str) -> bool:
        try:
            net = ipaddress.ip_network(reseau, strict=False)
            addr_str = str(net.network_address)

            if addr_str.startswith('169.254.'):
                return True

            if addr_str.startswith('172.17.') or addr_str.startswith('172.18.'):
                return True

            if addr_str.startswith('100.64.'):
                return True

        except ValueError:
            pass
        return False

    def _identifier_passerelles(self, hotes: List[Dict]) -> List[Dict]:
        passerelles = []

        for hote in hotes:
            type_fonctionnel = hote.get("type_fonctionnel", "UNKNOWN")

            if type_fonctionnel in ["ROUTER", "FIREWALL", "NAT", "FORWARDER"]:
                passerelles.append(hote)
                logger.debug(f"  Passerelle: {hote['ip']} ({type_fonctionnel})")

        return passerelles

    def _generer_reseaux_candidats(self, ip_passerelle: str, reseaux_connus: List[str]) -> List[str]:
        candidats = []

        try:
            addr_passerelle = ipaddress.ip_address(ip_passerelle)

            if isinstance(addr_passerelle, ipaddress.IPv4Address):
                octets = ip_passerelle.split('.')

                octets_base = octets[:2]
                troisieme_octet = int(octets[2])

                for decalage in range(-PLAGE_EXPLORATION_OCTET, PLAGE_EXPLORATION_OCTET + 1):
                    nouveau_troisieme = troisieme_octet + decalage
                    if 0 <= nouveau_troisieme <= 255:
                        reseau_candidat = f"{octets_base[0]}.{octets_base[1]}.{nouveau_troisieme}.0/24"

                        if reseau_candidat not in reseaux_connus:
                            candidats.append(reseau_candidat)

                premier_octet = int(octets[0])
                deuxieme_octet = int(octets[1])

                if premier_octet == 192 and deuxieme_octet == 168:
                    for reseau_test in ["10.0.0.0/24", "172.16.0.0/24"]:
                        if reseau_test not in reseaux_connus:
                            candidats.append(reseau_test)

                elif premier_octet == 10:
                    for decalage in range(-PLAGE_EXPLORATION_OCTET, PLAGE_EXPLORATION_OCTET + 1):
                        nouveau_deuxieme = deuxieme_octet + decalage
                        if 0 <= nouveau_deuxieme <= 255:
                            reseau_candidat = f"10.{nouveau_deuxieme}.0.0/24"
                            if reseau_candidat not in reseaux_connus:
                                candidats.append(reseau_candidat)
                    for decalage in range(-PLAGE_EXPLORATION_OCTET, PLAGE_EXPLORATION_OCTET + 1):
                        nouveau_troisieme = troisieme_octet + decalage
                        if 0 <= nouveau_troisieme <= 255:
                            reseau_candidat = f"10.{deuxieme_octet}.{nouveau_troisieme}.0/24"
                            if reseau_candidat not in reseaux_connus and reseau_candidat not in candidats:
                                candidats.append(reseau_candidat)

                elif premier_octet == 172 and 16 <= deuxieme_octet <= 31:
                    for decalage in range(-PLAGE_EXPLORATION_OCTET, PLAGE_EXPLORATION_OCTET + 1):
                        nouveau_deuxieme = deuxieme_octet + decalage
                        if 16 <= nouveau_deuxieme <= 31:
                            reseau_candidat = f"172.{nouveau_deuxieme}.0.0/24"
                            if reseau_candidat not in reseaux_connus:
                                candidats.append(reseau_candidat)

        except ValueError as e:
            logger.error(f"  Erreur parsing IP passerelle {ip_passerelle}: {e}")

        return candidats

    def _generer_sous_reseaux_depuis_plage(self, plage_ip: str, reseaux_connus: List[str]) -> List[str]:
        sous_reseaux = []

        try:
            reseau = ipaddress.ip_network(plage_ip)

            if reseau.prefixlen <= 16:
                pas = (reseau.num_addresses // (5 * 256))
                if pas < 1:
                    pas = 1

                compte = 0
                for addr in reseau.hosts():
                    if compte >= 5:
                        break

                    sous_reseau = ipaddress.ip_network(f"{addr}/24", strict=False)
                    chaine_sous_reseau = str(sous_reseau)

                    if chaine_sous_reseau not in reseaux_connus and chaine_sous_reseau not in sous_reseaux:
                        sous_reseaux.append(chaine_sous_reseau)
                        compte += 1

                    for _ in range(pas):
                        try:
                            addr = next(reseau.hosts())
                        except StopIteration:
                            break

        except ValueError as e:
            logger.error(f"  Erreur generation sous-reseaux pour {plage_ip}: {e}")

        return sous_reseaux

    def _tester_accessibilite_reseau(self, reseau: str, via_passerelle: Optional[str] = None) -> tuple:
        try:
            net = ipaddress.ip_network(reseau)
            ips_test = [
                str(net.network_address + 1),
                str(net.network_address + 254) if net.num_addresses > 254 else str(net.network_address + 1)
            ]

            for ip_test in ips_test:
                logger.debug(f"      Test de {ip_test}")

                succes_ping = self._ping_hote(ip_test)
                if succes_ping:
                    return (True, None)

                sauts = self.scanner_nmap.traceroute(ip_test)

                if sauts:
                    dernier_saut = sauts[-1] if sauts else None

                    if dernier_saut and dernier_saut["ip"] == ip_test:
                        return (True, None)

                    elif dernier_saut:
                        info_blocage = {
                            "raison": "Traceroute arrete avant destination",
                            "dernier_saut": dernier_saut["ip"]
                        }
                        return (False, info_blocage)

            info_blocage = {
                "raison": "Pas de reponse (timeout ou filtre)",
                "dernier_saut": via_passerelle
            }
            return (False, info_blocage)

        except Exception as e:
            logger.error(f"      Erreur test {reseau}: {e}")
            return (False, {"raison": f"Erreur: {str(e)}"})

    def _ping_hote(self, ip: str, timeout: int = 2) -> bool:
        try:
            resultat = subprocess.run(
                ["ping", "-c", "1", "-W", str(timeout), ip],
                capture_output=True,
                text=True,
                timeout=timeout + 1
            )

            return resultat.returncode == 0

        except subprocess.TimeoutExpired:
            return False
        except Exception as e:
            logger.debug(f"        Erreur ping: {e}")
            return False

    def analyser_blocages(self, reseaux_bloques: List[Dict]) -> List[Dict]:
        logger.info(f"[ExplorateurFrontieres] Analyse de {len(reseaux_bloques)} blocages")

        analyses = []

        for bloque in reseaux_bloques:
            reseau = bloque["reseau"]
            passerelle = bloque.get("passerelle")
            raison = bloque.get("raison", "inconnu")

            logger.debug(f"  Analyse blocage de {reseau}")

            type_blocage = self._categoriser_blocage(raison)

            bloque["type_blocage"] = type_blocage
            bloque["severite"] = self._evaluer_severite_blocage(type_blocage)
            bloque["recommandation"] = self._generer_recommandation(type_blocage, passerelle)

            analyses.append(bloque)

        return analyses

    def _categoriser_blocage(self, raison: str) -> str:
        raison_minuscule = raison.lower()

        if "admin" in raison_minuscule or "prohibited" in raison_minuscule:
            return "FIREWALL_FILTERED"
        elif "no route" in raison_minuscule or "unreachable" in raison_minuscule:
            return "NO_ROUTE"
        elif "timeout" in raison_minuscule:
            return "TIMEOUT"
        elif "stopped" in raison_minuscule or "arrete" in raison_minuscule:
            return "ROUTING_STOPPED"
        else:
            return "UNKNOWN"

    def _evaluer_severite_blocage(self, type_blocage: str) -> str:
        if type_blocage == "FIREWALL_FILTERED":
            return "HIGH"
        elif type_blocage == "NO_ROUTE":
            return "MEDIUM"
        elif type_blocage in ["TIMEOUT", "ROUTING_STOPPED"]:
            return "MEDIUM"
        else:
            return "LOW"

    def _generer_recommandation(self, type_blocage: str, passerelle: Optional[str]) -> str:
        if type_blocage == "FIREWALL_FILTERED":
            if passerelle:
                return f"Firewall actif. Relancer scan depuis {passerelle} pour explorer au-dela."
            else:
                return "Firewall actif. Identifier passerelle pour continuer exploration."

        elif type_blocage == "NO_ROUTE":
            return "Aucune route configuree vers ce reseau. Verifier configuration reseau."

        elif type_blocage in ["TIMEOUT", "ROUTING_STOPPED"]:
            if passerelle:
                return f"Reseau potentiellement accessible depuis {passerelle}."
            else:
                return "Reseau peut-etre isole ou eteint."

        else:
            return "Cause blocage indeterminee. Investigation manuelle recommandee."
