import xml.etree.ElementTree as ET
from xml.dom import minidom
import logging
from typing import List, Dict, Optional
import networkx as nx

logger = logging.getLogger(__name__)


class ExporteurVerefoo:
    def __init__(self):
        pass

    def exporter(self, graphe: nx.Graph, hotes_decouverts: List[Dict], chemin_sortie: str):
        logger.info(f"[ExporteurVerefoo] Export vers {chemin_sortie}")

        racine = self._creer_racine_nfv()

        elem_graphes = ET.SubElement(racine, "graphs")
        elem_graphe = ET.SubElement(elem_graphes, "graph", id="0")

        for hote in hotes_decouverts:
            self._ajouter_noeud(elem_graphe, hote, graphe)

        self._ajouter_contraintes(racine)
        self._ajouter_definitions_proprietes(racine, hotes_decouverts, graphe)

        ET.SubElement(racine, "ParsingString")

        self._ecrire_xml_formate(racine, chemin_sortie)

        logger.info("[ExporteurVerefoo] Export termine")

    def _creer_racine_nfv(self) -> ET.Element:
        racine = ET.Element("NFV")
        racine.set("xmlns:xsi", "http://www.w3.org/2001/XMLSchema-instance")
        return racine

    def _ajouter_noeud(self, elem_graphe: ET.Element, hote: Dict, topologie: nx.Graph):
        ip = hote["ip"]
        type_fonctionnel = hote.get("type_fonctionnel", "")

        if type_fonctionnel and type_fonctionnel != "UNKNOWN":
            elem_noeud = ET.SubElement(elem_graphe, "node", functional_type=type_fonctionnel, name=ip)
        else:
            elem_noeud = ET.SubElement(elem_graphe, "node", name=ip)

        if ip in topologie:
            voisins = list(topologie.neighbors(ip))
            for ip_voisin in voisins:
                ET.SubElement(elem_noeud, "neighbour", name=ip_voisin)

        if type_fonctionnel and type_fonctionnel != "UNKNOWN":
            self._ajouter_configuration_noeud(elem_noeud, hote, type_fonctionnel)

    def _ajouter_configuration_noeud(self, elem_noeud: ET.Element, hote: Dict, type_fonctionnel: str):
        ip = hote["ip"]
        nom_hote = hote.get("nom_hote", ip)

        elem_conf = ET.SubElement(
            elem_noeud,
            "configuration",
            description=f"Configuration auto-generee pour {nom_hote}",
            name=f"conf_{ip.replace('.', '_')}"
        )

        if type_fonctionnel == "WEBSERVER":
            elem_webserver = ET.SubElement(elem_conf, "webserver")
            elem_nom = ET.SubElement(elem_webserver, "name")
            elem_nom.text = ip

        elif type_fonctionnel == "WEBCLIENT":
            elem_webclient = ET.SubElement(elem_conf, "webclient")
            elem_webclient.set("nameWebServer", "unknown")

        elif type_fonctionnel == "FIREWALL":
            elem_firewall = ET.SubElement(elem_conf, "firewall")
            elem_firewall.set("defaultAction", "DENY")

        elif type_fonctionnel == "NAT":
            ET.SubElement(elem_conf, "nat")

        elif type_fonctionnel == "MAILSERVER":
            elem_mailserver = ET.SubElement(elem_conf, "mailserver")
            elem_nom = ET.SubElement(elem_mailserver, "name")
            elem_nom.text = ip

    def _ajouter_contraintes(self, racine: ET.Element):
        elem_contraintes = ET.SubElement(racine, "Constraints")
        ET.SubElement(elem_contraintes, "NodeConstraints")
        ET.SubElement(elem_contraintes, "LinkConstraints")

    def _ajouter_definitions_proprietes(self, racine: ET.Element, hotes: List[Dict], topologie: nx.Graph):
        elem_def_prop = ET.SubElement(racine, "PropertyDefinition")

        clients = [h for h in hotes if h.get("type_fonctionnel") == "WEBCLIENT"]
        serveurs = [h for h in hotes if h.get("type_fonctionnel") == "WEBSERVER"]

        for client in clients:
            for serveur in serveurs:
                if client["ip"] in topologie and serveur["ip"] in topologie:
                    try:
                        if nx.has_path(topologie, client["ip"], serveur["ip"]):
                            ET.SubElement(
                                elem_def_prop,
                                "Property",
                                graph="0",
                                name="ReachabilityProperty",
                                src=client["ip"],
                                dst=serveur["ip"]
                            )
                            logger.debug(f"  Propriete Reachability: {client['ip']} -> {serveur['ip']}")
                    except nx.NodeNotFound:
                        pass

    def _ecrire_xml_formate(self, racine: ET.Element, chemin_sortie: str):
        chaine_brute = ET.tostring(racine, encoding='utf-8')

        reparse = minidom.parseString(chaine_brute)
        xml_formate = reparse.toprettyxml(indent="    ", encoding='utf-8')

        with open(chemin_sortie, 'wb') as f:
            f.write(xml_formate)

        logger.info(f"[ExporteurVerefoo] Fichier XML ecrit: {chemin_sortie}")

    def exporter_json(self, hotes_decouverts: List[Dict], reseaux: List[str],
                    reseaux_bloques: List[Dict], pivots: List[Dict],
                    chemin_sortie: str):
        import json

        logger.info(f"[ExporteurVerefoo] Export JSON vers {chemin_sortie}")

        donnees = {
            "metadonnees_scan": {
                "outil": "Network Discovery Tool",
                "version": "1.0",
                "horodatage": None
            },
            "reseaux_decouverts": reseaux,
            "hotes_decouverts": hotes_decouverts,
            "reseaux_bloques": reseaux_bloques,
            "pivots_suggeres": pivots,
            "statistiques": {
                "total_hotes": len(hotes_decouverts),
                "total_reseaux": len(reseaux),
                "reseaux_bloques": len(reseaux_bloques),
                "pivots": len(pivots)
            }
        }

        with open(chemin_sortie, 'w', encoding='utf-8') as f:
            json.dump(donnees, f, indent=2, ensure_ascii=False)

        logger.info("[ExporteurVerefoo] Export JSON termine")
