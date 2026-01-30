import networkx as nx
import matplotlib.pyplot as plt
import ipaddress
import logging
from typing import List, Dict, Optional
import os

from config import (
    TAILLE_FIGURE_GRAPHE,
    TAILLE_NOEUD_GRAPHE,
    TAILLE_POLICE_GRAPHE,
    COULEURS_TYPE_FONCTIONNEL
)

logger = logging.getLogger(__name__)


class ConstructeurTopologie:
    def __init__(self):
        self.graphe = nx.Graph()
        self.reseaux = {}

    def construire_topologie(self, hotes_decouverts: List[Dict], reseaux: List[str]) -> nx.Graph:
        logger.info(f"[ConstructeurTopologie] Construction topologie: "
                   f"{len(hotes_decouverts)} hotes, {len(reseaux)} reseaux")

        self.graphe = nx.Graph()
        self.reseaux = {}

        for hote in hotes_decouverts:
            self._ajouter_noeud_hote(hote)

        for reseau in reseaux:
            self._identifier_hotes_reseau(reseau, hotes_decouverts)

        self._ajouter_aretes_reseau()
        self._ajouter_aretes_inter_reseaux(hotes_decouverts)

        logger.info(f"[ConstructeurTopologie] Topologie construite: "
                   f"{self.graphe.number_of_nodes()} noeuds, {self.graphe.number_of_edges()} aretes")

        return self.graphe

    def _ajouter_noeud_hote(self, hote: Dict):
        ip = hote["ip"]
        nom_hote = hote.get("nom_hote")
        type_fonctionnel = hote.get("type_fonctionnel", "UNKNOWN")

        if nom_hote:
            label = f"{nom_hote}\n({ip})"
        else:
            label = ip

        self.graphe.add_node(
            ip,
            label=label,
            ip=ip,
            nom_hote=nom_hote,
            type_fonctionnel=type_fonctionnel,
            os=hote.get("os"),
            ports=len(hote.get("ports", [])),
            services=hote.get("services", []),
            type="hote"
        )

        logger.debug(f"  Noeud ajoute: {ip} ({type_fonctionnel})")

    def _identifier_hotes_reseau(self, reseau: str, hotes: List[Dict]):
        try:
            net = ipaddress.ip_network(reseau)
            hotes_reseau = []

            for hote in hotes:
                ip_hote = ipaddress.ip_address(hote["ip"])
                if ip_hote in net:
                    hotes_reseau.append(hote["ip"])

            self.reseaux[reseau] = hotes_reseau
            logger.debug(f"  Reseau {reseau}: {len(hotes_reseau)} hotes")

        except ValueError as e:
            logger.error(f"  Erreur parsing reseau {reseau}: {e}")

    def _ajouter_aretes_reseau(self):
        logger.debug("[ConstructeurTopologie] Ajout aretes reseau")

        for reseau, ips_hotes in self.reseaux.items():
            for i, ip1 in enumerate(ips_hotes):
                for ip2 in ips_hotes[i + 1:]:
                    if not self.graphe.has_edge(ip1, ip2):
                        self.graphe.add_edge(
                            ip1,
                            ip2,
                            type="meme_reseau",
                            reseau=reseau
                        )

        logger.debug(f"  {self.graphe.number_of_edges()} aretes reseau ajoutees")

    def _ajouter_aretes_inter_reseaux(self, hotes: List[Dict]):
        logger.debug("[ConstructeurTopologie] Ajout aretes inter-reseaux")

        passerelles = []
        for hote in hotes:
            type_fonctionnel = hote.get("type_fonctionnel", "UNKNOWN")
            if type_fonctionnel in ["ROUTER", "FIREWALL", "NAT", "FORWARDER"]:
                passerelles.append(hote)

        for passerelle in passerelles:
            ip_passerelle = passerelle["ip"]

            reseaux_passerelle = []
            for reseau, ips_hotes in self.reseaux.items():
                if ip_passerelle in ips_hotes:
                    reseaux_passerelle.append(reseau)

            if len(reseaux_passerelle) > 1:
                logger.debug(f"  Passerelle {ip_passerelle} connecte {len(reseaux_passerelle)} reseaux")

                for i, net1 in enumerate(reseaux_passerelle):
                    for net2 in reseaux_passerelle[i + 1:]:
                        for ip_hote1 in self.reseaux[net1][:3]:
                            for ip_hote2 in self.reseaux[net2][:3]:
                                if ip_hote1 != ip_passerelle and ip_hote2 != ip_passerelle:
                                    if not self.graphe.has_edge(ip_hote1, ip_hote2):
                                        self.graphe.add_edge(
                                            ip_hote1,
                                            ip_hote2,
                                            type="inter_reseau",
                                            via_passerelle=ip_passerelle
                                        )

    def visualiser_topologie(self, chemin_sortie: str = None, afficher: bool = False):
        logger.info("[ConstructeurTopologie] Generation visualisation")

        if self.graphe.number_of_nodes() == 0:
            logger.warning("[ConstructeurTopologie] Graphe vide")
            return

        plt.figure(figsize=TAILLE_FIGURE_GRAPHE)

        pos = nx.spring_layout(self.graphe, k=2, iterations=50, seed=42)

        couleurs_noeuds = []
        for noeud in self.graphe.nodes():
            type_fonctionnel = self.graphe.nodes[noeud].get("type_fonctionnel", "UNKNOWN")
            couleur = COULEURS_TYPE_FONCTIONNEL.get(type_fonctionnel, COULEURS_TYPE_FONCTIONNEL["UNKNOWN"])
            couleurs_noeuds.append(couleur)

        aretes_meme_reseau = [(u, v) for u, v, d in self.graphe.edges(data=True)
                               if d.get("type") == "meme_reseau"]
        nx.draw_networkx_edges(
            self.graphe, pos,
            edgelist=aretes_meme_reseau,
            edge_color="lightgray",
            width=1,
            style="solid"
        )

        aretes_inter_reseaux = [(u, v) for u, v, d in self.graphe.edges(data=True)
                                if d.get("type") == "inter_reseau"]
        nx.draw_networkx_edges(
            self.graphe, pos,
            edgelist=aretes_inter_reseaux,
            edge_color="black",
            width=3,
            style="dashed"
        )

        nx.draw_networkx_nodes(
            self.graphe, pos,
            node_color=couleurs_noeuds,
            node_size=TAILLE_NOEUD_GRAPHE,
            edgecolors="black",
            linewidths=2
        )

        labels = nx.get_node_attributes(self.graphe, "label")
        nx.draw_networkx_labels(
            self.graphe, pos,
            labels=labels,
            font_size=TAILLE_POLICE_GRAPHE,
            font_weight="bold"
        )

        self._ajouter_legende()

        plt.title("Topologie Reseau Decouverte", fontsize=16, fontweight="bold")
        plt.axis("off")
        plt.tight_layout()

        if chemin_sortie:
            plt.savefig(chemin_sortie, dpi=150, bbox_inches="tight")
            logger.info(f"[ConstructeurTopologie] Visualisation sauvegardee: {chemin_sortie}")

        if afficher:
            plt.show()

        plt.close()

    def _ajouter_legende(self):
        types_dans_graphe = set()
        for noeud in self.graphe.nodes():
            ftype = self.graphe.nodes[noeud].get("type_fonctionnel", "UNKNOWN")
            types_dans_graphe.add(ftype)

        elements_legende = []
        for ftype in sorted(types_dans_graphe):
            couleur = COULEURS_TYPE_FONCTIONNEL.get(ftype, COULEURS_TYPE_FONCTIONNEL["UNKNOWN"])
            patch = plt.Line2D([0], [0], marker='o', color='w',
                             markerfacecolor=couleur, markersize=10,
                             label=ftype, markeredgecolor='black', markeredgewidth=1)
            elements_legende.append(patch)

        plt.legend(handles=elements_legende, loc="upper left", fontsize=10, frameon=True)

    def obtenir_stats_graphe(self) -> Dict:
        stats = {
            "noeuds": self.graphe.number_of_nodes(),
            "aretes": self.graphe.number_of_edges(),
            "reseaux": len(self.reseaux),
            "densite": nx.density(self.graphe),
            "composantes_connexes": len(list(nx.connected_components(self.graphe)))
        }

        compteurs_types = {}
        for noeud in self.graphe.nodes():
            ftype = self.graphe.nodes[noeud].get("type_fonctionnel", "UNKNOWN")
            compteurs_types[ftype] = compteurs_types.get(ftype, 0) + 1

        stats["types"] = compteurs_types

        return stats

    def exporter_graphml(self, chemin_sortie: str):
        logger.info(f"[ConstructeurTopologie] Export GraphML: {chemin_sortie}")

        try:
            nx.write_graphml(self.graphe, chemin_sortie)
            logger.info("[ConstructeurTopologie] Export GraphML reussi")
        except Exception as e:
            logger.error(f"[ConstructeurTopologie] Erreur export GraphML: {e}")

    def trouver_chemins_entre(self, ip_source: str, ip_dest: str) -> List[List[str]]:
        if ip_source not in self.graphe or ip_dest not in self.graphe:
            logger.warning(f"[ConstructeurTopologie] Source ou destination introuvable")
            return []

        try:
            chemins = list(nx.all_simple_paths(self.graphe, ip_source, ip_dest))
            logger.info(f"[ConstructeurTopologie] {len(chemins)} chemins trouves")
            return chemins

        except nx.NetworkXNoPath:
            logger.warning(f"[ConstructeurTopologie] Aucun chemin entre {ip_source} et {ip_dest}")
            return []

    def identifier_noeuds_critiques(self) -> List[str]:
        logger.info("[ConstructeurTopologie] Identification noeuds critiques")

        intermediaire = nx.betweenness_centrality(self.graphe)

        noeuds_tries = sorted(intermediaire.items(), key=lambda x: x[1], reverse=True)

        nb_critiques = min(5, len(noeuds_tries))
        noeuds_critiques = [noeud for noeud, centralite in noeuds_tries[:nb_critiques] if centralite > 0]

        for ip in noeuds_critiques:
            centralite = intermediaire[ip]
            ftype = self.graphe.nodes[ip].get("type_fonctionnel", "UNKNOWN")
            logger.info(f"  Noeud critique: {ip} ({ftype}) - centralite: {centralite:.3f}")

        return noeuds_critiques
