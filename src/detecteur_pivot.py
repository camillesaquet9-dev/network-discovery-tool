import logging
from typing import List, Dict, Optional

logger = logging.getLogger(__name__)


class DetecteurPivot:
    def __init__(self):
        self.candidats_pivot = []

    def identifier_pivots(self, hotes_decouverts: List[Dict], reseaux_bloques: List[Dict]) -> List[Dict]:
        logger.info(f"[DetecteurPivot] Identification pivots pour {len(reseaux_bloques)} reseaux bloques")

        pivots = []

        for bloque in reseaux_bloques:
            reseau = bloque["reseau"]
            dernier_saut = bloque.get("dernier_saut")
            passerelle = bloque.get("passerelle")

            logger.debug(f"  Recherche pivot pour {reseau}")

            ip_pivot = dernier_saut or passerelle

            if ip_pivot:
                hote_pivot = self._trouver_hote_par_ip(hotes_decouverts, ip_pivot)

                if hote_pivot:
                    info_pivot = self._creer_suggestion_pivot(
                        hote_pivot, reseau, bloque
                    )
                    pivots.append(info_pivot)
                    logger.info(f"  Pivot suggere: {ip_pivot} pour {reseau}")
                else:
                    info_pivot = {
                        "ip_pivot": ip_pivot,
                        "reseau_cible": reseau,
                        "methode_acces": "inconnu",
                        "confiance": "low",
                        "raison": "Passerelle identifiee mais non scannee en detail",
                        "commande": f"./network_discovery.py --from {ip_pivot}"
                    }
                    pivots.append(info_pivot)
                    logger.info(f"  Pivot suggere (non verifie): {ip_pivot} pour {reseau}")

        pivots_dedupliques = self._dedupliquer_pivots(pivots)

        logger.info(f"[DetecteurPivot] {len(pivots_dedupliques)} pivots uniques identifies")

        return pivots_dedupliques

    def _trouver_hote_par_ip(self, hotes: List[Dict], ip: str) -> Optional[Dict]:
        for hote in hotes:
            if hote.get("ip") == ip:
                return hote
        return None

    def _creer_suggestion_pivot(self, hote_pivot: Dict, reseau_cible: str, info_bloque: Dict) -> Dict:
        ip_pivot = hote_pivot["ip"]
        type_fonctionnel = hote_pivot.get("type_fonctionnel", "UNKNOWN")
        ports = hote_pivot.get("ports", [])

        methode_acces, commande_acces = self._determiner_methode_acces(hote_pivot)

        confiance = self._evaluer_confiance_pivot(hote_pivot, info_bloque)

        commande_scan = self._generer_commande_scan(reseau_cible)

        suggestion_pivot = {
            "ip_pivot": ip_pivot,
            "nom_hote_pivot": hote_pivot.get("nom_hote"),
            "type_pivot": type_fonctionnel,
            "reseau_cible": reseau_cible,
            "methode_acces": methode_acces,
            "commande_acces": commande_acces,
            "commande_scan": commande_scan,
            "commande_complete": f"{commande_acces} '{commande_scan}'",
            "confiance": confiance,
            "raison": self._expliquer_choix_pivot(hote_pivot, info_bloque),
            "ports_ouverts": [p["port"] for p in ports if p.get("etat") == "open"]
        }

        return suggestion_pivot

    def _determiner_methode_acces(self, hote: Dict) -> tuple:
        ip = hote["ip"]
        ports = hote.get("ports", [])
        ports_ouverts = [p["port"] for p in ports if p.get("etat") == "open"]

        if 22 in ports_ouverts:
            return ("ssh", f"ssh root@{ip}")

        if 23 in ports_ouverts:
            return ("telnet", f"telnet {ip}")

        if 3389 in ports_ouverts:
            return ("rdp", f"xfreerdp /v:{ip}")

        if 5900 in ports_ouverts or 5901 in ports_ouverts:
            port_vnc = 5900 if 5900 in ports_ouverts else 5901
            return ("vnc", f"vncviewer {ip}:{port_vnc}")

        return ("inconnu", f"# Aucun port acces distant detecte sur {ip}")

    def _evaluer_confiance_pivot(self, hote_pivot: Dict, info_bloque: Dict) -> str:
        score = 0

        type_fonctionnel = hote_pivot.get("type_fonctionnel", "UNKNOWN")
        if type_fonctionnel in ["ROUTER", "FIREWALL", "NAT"]:
            score += 3

        ports = hote_pivot.get("ports", [])
        ports_ouverts = [p["port"] for p in ports if p.get("etat") == "open"]
        if 22 in ports_ouverts:
            score += 2

        if info_bloque.get("dernier_saut") == hote_pivot["ip"]:
            score += 2

        if hote_pivot.get("os"):
            score += 1

        if score >= 5:
            return "high"
        elif score >= 3:
            return "medium"
        else:
            return "low"

    def _expliquer_choix_pivot(self, hote_pivot: Dict, info_bloque: Dict) -> str:
        raisons = []

        type_fonctionnel = hote_pivot.get("type_fonctionnel", "UNKNOWN")
        if type_fonctionnel in ["ROUTER", "FIREWALL", "NAT"]:
            raisons.append(f"identifie comme {type_fonctionnel}")

        if info_bloque.get("dernier_saut") == hote_pivot["ip"]:
            raisons.append("dernier saut repondant avant blocage")

        if info_bloque.get("passerelle") == hote_pivot["ip"]:
            raisons.append("passerelle vers reseau bloque")

        ports = hote_pivot.get("ports", [])
        ports_ouverts = [p["port"] for p in ports if p.get("etat") == "open"]
        if 22 in ports_ouverts:
            raisons.append("acces SSH disponible")

        if not raisons:
            raisons.append("positionne entre point de scan et reseau bloque")

        return ", ".join(raisons).capitalize()

    def _generer_commande_scan(self, reseau: str) -> str:
        return f"python3 /tmp/network_discovery.py --target {reseau} --output /tmp/scan_results.json"

    def _dedupliquer_pivots(self, pivots: List[Dict]) -> List[Dict]:
        map_pivot = {}

        for pivot in pivots:
            ip_pivot = pivot["ip_pivot"]

            if ip_pivot not in map_pivot:
                pivot["reseaux_cibles"] = [pivot["reseau_cible"]]
                map_pivot[ip_pivot] = pivot
            else:
                map_pivot[ip_pivot]["reseaux_cibles"].append(pivot["reseau_cible"])
                if self._score_confiance(pivot["confiance"]) > \
                   self._score_confiance(map_pivot[ip_pivot]["confiance"]):
                    map_pivot[ip_pivot]["confiance"] = pivot["confiance"]

        dedupliques = []
        for ip_pivot, donnees_pivot in map_pivot.items():
            if "reseau_cible" in donnees_pivot:
                del donnees_pivot["reseau_cible"]

            dedupliques.append(donnees_pivot)

        dedupliques.sort(
            key=lambda p: self._score_confiance(p["confiance"]),
            reverse=True
        )

        return dedupliques

    def _score_confiance(self, confiance: str) -> int:
        scores = {"high": 3, "medium": 2, "low": 1}
        return scores.get(confiance, 0)

    def generer_rapport_pivot(self, pivots: List[Dict]) -> str:
        if not pivots:
            return "Aucun pivot suggere."

        lignes = []
        lignes.append("=" * 80)
        lignes.append("PIVOTS SUGGERES POUR CONTINUER L'EXPLORATION")
        lignes.append("=" * 80)
        lignes.append("")

        for i, pivot in enumerate(pivots, 1):
            lignes.append(f"PIVOT #{i} : {pivot['ip_pivot']} ({pivot.get('type_pivot', 'UNKNOWN')})")
            lignes.append("-" * 80)

            if pivot.get("nom_hote_pivot"):
                lignes.append(f"  Hostname      : {pivot['nom_hote_pivot']}")

            lignes.append(f"  Confiance     : {pivot['confiance'].upper()}")
            lignes.append(f"  Raison        : {pivot['raison']}")

            reseaux_cibles = pivot.get("reseaux_cibles", [])
            if len(reseaux_cibles) == 1:
                lignes.append(f"  Reseau cible  : {reseaux_cibles[0]}")
            else:
                lignes.append(f"  Reseaux cibles: {', '.join(reseaux_cibles)}")

            lignes.append(f"  Acces         : {pivot['methode_acces']}")
            lignes.append(f"  Commande      : {pivot['commande_acces']}")

            if pivot.get("ports_ouverts"):
                chaine_ports = ", ".join(map(str, pivot["ports_ouverts"][:10]))
                lignes.append(f"  Ports ouverts : {chaine_ports}")

            lignes.append("")
            lignes.append("  Pour continuer l'exploration :")
            lignes.append(f"     1. Accedez au pivot : {pivot['commande_acces']}")
            lignes.append(f"     2. Deployez l'outil de scan")
            lignes.append(f"     3. Executez le scan sur les reseaux cibles")
            lignes.append("")

        return "\n".join(lignes)
