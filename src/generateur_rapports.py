import logging
from typing import List, Dict
from datetime import datetime
from tabulate import tabulate

logger = logging.getLogger(__name__)


class GenerateurRapports:
    def __init__(self):
        pass

    def generer_rapport_complet(self, donnees_scan: Dict, chemin_sortie: str):
        logger.info(f"[GenerateurRapports] Generation rapport: {chemin_sortie}")

        lignes = []

        lignes.extend(self._generer_entete(donnees_scan))
        lignes.append("")

        lignes.extend(self._generer_resume_executif(donnees_scan))
        lignes.append("")

        lignes.extend(self._generer_section_reseaux(donnees_scan))
        lignes.append("")

        lignes.extend(self._generer_section_hotes(donnees_scan))
        lignes.append("")

        if donnees_scan.get("reseaux_bloques"):
            lignes.extend(self._generer_section_reseaux_bloques(donnees_scan))
            lignes.append("")

        if donnees_scan.get("pivots"):
            lignes.extend(self._generer_section_pivots(donnees_scan))
            lignes.append("")

        lignes.extend(self._generer_section_statistiques(donnees_scan))
        lignes.append("")

        lignes.extend(self._generer_recommandations(donnees_scan))

        contenu_rapport = "\n".join(lignes)
        with open(chemin_sortie, 'w', encoding='utf-8') as f:
            f.write(contenu_rapport)

        logger.info("[GenerateurRapports] Rapport genere")

    def _generer_entete(self, donnees_scan: Dict) -> List[str]:
        lignes = []
        lignes.append("=" * 80)
        lignes.append("RAPPORT DE DECOUVERTE ET EXPLORATION RESEAU")
        lignes.append("=" * 80)
        lignes.append(f"Date du scan    : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        lignes.append(f"Point de depart : {donnees_scan.get('ip_locale', 'N/A')}")
        lignes.append(f"Outil           : Network Discovery Tool v1.0")
        lignes.append("=" * 80)

        return lignes

    def _generer_resume_executif(self, donnees_scan: Dict) -> List[str]:
        lignes = []
        lignes.append("RESUME EXECUTIF")
        lignes.append("-" * 80)

        hotes_decouverts = donnees_scan.get("hotes_decouverts", [])
        reseaux = donnees_scan.get("reseaux", [])
        reseaux_bloques = donnees_scan.get("reseaux_bloques", [])

        lignes.append(f"{len(reseaux)} reseaux decouverts et cartographies")
        lignes.append(f"{len(hotes_decouverts)} equipements actifs identifies")

        if reseaux_bloques:
            lignes.append(f"{len(reseaux_bloques)} reseaux detectes mais inaccessibles")

        compteurs_types = {}
        for hote in hotes_decouverts:
            ftype = hote.get("type_fonctionnel", "UNKNOWN")
            compteurs_types[ftype] = compteurs_types.get(ftype, 0) + 1

        if compteurs_types:
            lignes.append("")
            lignes.append("Repartition par type d'equipement:")
            for ftype, compte in sorted(compteurs_types.items(), key=lambda x: x[1], reverse=True):
                lignes.append(f"  - {ftype}: {compte}")

        return lignes

    def _generer_section_reseaux(self, donnees_scan: Dict) -> List[str]:
        lignes = []
        lignes.append("RESEAUX CARTOGRAPHIES")
        lignes.append("-" * 80)

        reseaux = donnees_scan.get("reseaux", [])
        hotes_decouverts = donnees_scan.get("hotes_decouverts", [])

        if not reseaux:
            lignes.append("Aucun reseau decouvert.")
            return lignes

        for reseau in reseaux:
            import ipaddress
            try:
                net = ipaddress.ip_network(reseau)
                hotes_dans_reseau = [h for h in hotes_decouverts
                                    if ipaddress.ip_address(h["ip"]) in net]

                lignes.append(f"[OK] {reseau}")
                lignes.append(f"    Hotes actifs: {len(hotes_dans_reseau)}")

                types_importants = ["ROUTER", "FIREWALL", "NAT", "WEBSERVER", "MAILSERVER"]
                hotes_importants = [h for h in hotes_dans_reseau
                                   if h.get("type_fonctionnel") in types_importants]

                if hotes_importants:
                    lignes.append("    Equipements cles:")
                    for hote in hotes_importants[:5]:
                        ftype = hote.get("type_fonctionnel", "UNKNOWN")
                        nom_hote = hote.get("nom_hote", "")
                        label = f"{hote['ip']}"
                        if nom_hote:
                            label += f" ({nom_hote})"
                        lignes.append(f"      - {label} - {ftype}")

                lignes.append("")

            except ValueError:
                lignes.append(f"[ERR] {reseau} - Erreur parsing")
                lignes.append("")

        return lignes

    def _generer_section_hotes(self, donnees_scan: Dict) -> List[str]:
        lignes = []
        lignes.append("INVENTAIRE DES EQUIPEMENTS")
        lignes.append("-" * 80)

        hotes_decouverts = donnees_scan.get("hotes_decouverts", [])

        if not hotes_decouverts:
            lignes.append("Aucun equipement decouvert.")
            return lignes

        donnees_tableau = []
        for hote in hotes_decouverts:
            ip = hote["ip"]
            nom_hote = hote.get("nom_hote", "N/A")
            ftype = hote.get("type_fonctionnel", "UNKNOWN")
            info_os = hote.get("os", "N/A")
            nb_ports = len(hote.get("ports", []))

            services = hote.get("services", [])
            chaine_services = ", ".join([s["nom"] or "inconnu" for s in services[:3]])
            if len(services) > 3:
                chaine_services += f", ... (+{len(services) - 3})"

            donnees_tableau.append([
                ip,
                nom_hote or "N/A",
                ftype,
                (info_os or "N/A")[:30],
                nb_ports,
                (chaine_services or "N/A")[:40]
            ])

        entetes = ["IP", "Hostname", "Type", "OS", "Ports", "Services"]
        lignes.append(tabulate(donnees_tableau, headers=entetes, tablefmt="grid"))

        return lignes

    def _generer_section_reseaux_bloques(self, donnees_scan: Dict) -> List[str]:
        lignes = []
        lignes.append("RESEAUX DETECTES MAIS INACCESSIBLES")
        lignes.append("-" * 80)

        reseaux_bloques = donnees_scan.get("reseaux_bloques", [])

        if not reseaux_bloques:
            lignes.append("Aucun reseau bloque detecte.")
            return lignes

        for bloque in reseaux_bloques:
            reseau = bloque["reseau"]
            raison = bloque.get("raison", "inconnu")
            type_blocage = bloque.get("type_blocage", "UNKNOWN")
            severite = bloque.get("severite", "UNKNOWN")
            passerelle = bloque.get("passerelle")
            dernier_saut = bloque.get("dernier_saut")

            lignes.append(f"[X] {reseau}")
            lignes.append(f"    Raison         : {raison}")
            lignes.append(f"    Type blocage   : {type_blocage} (severite: {severite})")

            if dernier_saut:
                lignes.append(f"    Dernier saut   : {dernier_saut}")
            if passerelle:
                lignes.append(f"    Via passerelle : {passerelle}")

            recommandation = bloque.get("recommandation", "")
            if recommandation:
                lignes.append(f"    Recommandation : {recommandation}")

            lignes.append("")

        return lignes

    def _generer_section_pivots(self, donnees_scan: Dict) -> List[str]:
        lignes = []
        lignes.append("PIVOTS SUGGERES POUR CONTINUER L'EXPLORATION")
        lignes.append("-" * 80)

        pivots = donnees_scan.get("pivots", [])

        if not pivots:
            lignes.append("Aucun pivot suggere.")
            return lignes

        for i, pivot in enumerate(pivots, 1):
            ip_pivot = pivot["ip_pivot"]
            type_pivot = pivot.get("type_pivot", "UNKNOWN")
            confiance = pivot["confiance"].upper()
            reseaux_cibles = pivot.get("reseaux_cibles", [])
            methode_acces = pivot["methode_acces"]
            commande_acces = pivot.get("commande_acces", "N/A")

            lignes.append(f"PIVOT #{i}: {ip_pivot} ({type_pivot})")
            lignes.append("-" * 80)
            lignes.append(f"  Confiance      : {confiance}")
            lignes.append(f"  Raison         : {pivot.get('raison', 'N/A')}")

            if len(reseaux_cibles) == 1:
                lignes.append(f"  Reseau cible   : {reseaux_cibles[0]}")
            else:
                lignes.append(f"  Reseaux cibles : {', '.join(reseaux_cibles)}")

            lignes.append(f"  Methode acces  : {methode_acces}")
            lignes.append(f"  Commande       : {commande_acces}")

            if pivot.get("ports_ouverts"):
                chaine_ports = ", ".join(map(str, pivot["ports_ouverts"][:10]))
                lignes.append(f"  Ports ouverts  : {chaine_ports}")

            lignes.append("")
            lignes.append("  Pour continuer l'exploration:")
            lignes.append(f"     1. Connectez-vous au pivot: {commande_acces}")
            lignes.append("     2. Deployez l'outil de scan sur le pivot")
            lignes.append(f"     3. Relancez le scan ciblant les reseaux bloques")
            lignes.append("")

        return lignes

    def _generer_section_statistiques(self, donnees_scan: Dict) -> List[str]:
        lignes = []
        lignes.append("STATISTIQUES DETAILLEES")
        lignes.append("-" * 80)

        stats_graphe = donnees_scan.get("stats_graphe", {})

        lignes.append(f"Noeuds dans le graphe    : {stats_graphe.get('noeuds', 0)}")
        lignes.append(f"Aretes dans le graphe    : {stats_graphe.get('aretes', 0)}")
        lignes.append(f"Densite du graphe        : {stats_graphe.get('densite', 0):.3f}")
        lignes.append(f"Composantes connexes     : {stats_graphe.get('composantes_connexes', 0)}")

        noeuds_critiques = donnees_scan.get("noeuds_critiques", [])
        if noeuds_critiques:
            lignes.append("")
            lignes.append("Noeuds critiques (points de passage obliges):")
            for ip_noeud in noeuds_critiques:
                hote = next((h for h in donnees_scan.get("hotes_decouverts", [])
                            if h["ip"] == ip_noeud), None)
                if hote:
                    ftype = hote.get("type_fonctionnel", "UNKNOWN")
                    lignes.append(f"  - {ip_noeud} ({ftype})")

        return lignes

    def _generer_recommandations(self, donnees_scan: Dict) -> List[str]:
        lignes = []
        lignes.append("RECOMMANDATIONS")
        lignes.append("-" * 80)

        reseaux_bloques = donnees_scan.get("reseaux_bloques", [])
        pivots = donnees_scan.get("pivots", [])
        hotes_decouverts = donnees_scan.get("hotes_decouverts", [])

        recommandations = []

        if reseaux_bloques:
            severite_haute = [b for b in reseaux_bloques if b.get("severite") == "HIGH"]
            if severite_haute:
                recommandations.append(
                    f"- {len(severite_haute)} reseau(x) bloque(s) par firewall. "
                    "Verifier politiques de securite et regles de filtrage."
                )

        if pivots:
            confiance_haute = [p for p in pivots if p["confiance"] == "high"]
            if confiance_haute:
                recommandations.append(
                    f"- {len(confiance_haute)} pivot(s) a haute confiance identifie(s). "
                    "Relancer scan depuis ces points pour completer cartographie."
                )

        firewalls = [h for h in hotes_decouverts if h.get("type_fonctionnel") == "FIREWALL"]
        if firewalls:
            recommandations.append(
                f"- {len(firewalls)} firewall(s) detecte(s). "
                "Verifier configurations pour assurer coherence politiques securite."
            )

        webservers = [h for h in hotes_decouverts if h.get("type_fonctionnel") == "WEBSERVER"]
        if webservers:
            recommandations.append(
                f"- {len(webservers)} serveur(s) web detecte(s). "
                "Auditer configurations et s'assurer qu'ils sont a jour."
            )

        recommandations.append(
            "- Exporter resultats au format Verefoo pour analyse politiques reseau."
        )
        recommandations.append(
            "- Utiliser visualisation graphique pour identifier rapidement chemins critiques."
        )

        if not recommandations:
            recommandations.append("- Aucune recommandation particuliere. Reseau bien cartographie.")

        for rec in recommandations:
            lignes.append(rec)

        lignes.append("")
        lignes.append("=" * 80)
        lignes.append("FIN DU RAPPORT")
        lignes.append("=" * 80)

        return lignes

    def generer_resume_console(self, donnees_scan: Dict) -> str:
        hotes_decouverts = donnees_scan.get("hotes_decouverts", [])
        reseaux = donnees_scan.get("reseaux", [])
        reseaux_bloques = donnees_scan.get("reseaux_bloques", [])
        pivots = donnees_scan.get("pivots", [])

        lignes = []
        lignes.append("=" * 60)
        lignes.append("RESUME DE LA DECOUVERTE RESEAU")
        lignes.append("=" * 60)
        lignes.append(f"Reseaux decouverts       : {len(reseaux)}")
        lignes.append(f"Equipements actifs       : {len(hotes_decouverts)}")
        lignes.append(f"Reseaux bloques          : {len(reseaux_bloques)}")
        lignes.append(f"Pivots suggeres          : {len(pivots)}")
        lignes.append("=" * 60)

        return "\n".join(lignes)
