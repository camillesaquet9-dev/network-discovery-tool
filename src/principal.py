#!/usr/bin/env python3

import sys
import os
import argparse
import logging
from datetime import datetime
from typing import List, Dict

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import config
from utilitaires_reseau import ReconnaissanceLocale
from enveloppe_nmap import ScannerNmap
from inference_type import MoteurInferenceType
from explorateur_frontieres import ExplorateurFrontieres
from detecteur_pivot import DetecteurPivot
from constructeur_topologie import ConstructeurTopologie
from exporteur_verefoo import ExporteurVerefoo
from generateur_rapports import GenerateurRapports
from mouvement_lateral import GestionnaireMouvementLateral

def configurer_logging(niveau=logging.INFO):
    config.creer_repertoires()

    fichier_log = config.obtenir_chemin_log(f"decouverte_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log")

    logging.basicConfig(
        level=niveau,
        format=config.FORMAT_LOG,
        handlers=[
            logging.FileHandler(fichier_log, encoding='utf-8'),
            logging.StreamHandler(sys.stdout)
        ]
    )

    logger = logging.getLogger(__name__)
    logger.info("=" * 80)
    logger.info("Outil de Decouverte et Exploration Reseau Automatisee")
    logger.info("=" * 80)
    logger.info(f"Fichier log: {fichier_log}")

    return logger


class OrchestrateurDecouverteReseau:
    def __init__(self, args):
        self.args = args
        self.logger = logging.getLogger(__name__)

        self.recon_locale = ReconnaissanceLocale()
        self.scanner_nmap = ScannerNmap()
        self.inference_type = MoteurInferenceType()
        self.explorateur_frontieres = ExplorateurFrontieres(self.scanner_nmap)
        self.detecteur_pivot = DetecteurPivot()
        self.constructeur_topologie = ConstructeurTopologie()
        self.exporteur_verefoo = ExporteurVerefoo()
        self.generateur_rapports = GenerateurRapports()
        self.mouvement_lateral = GestionnaireMouvementLateral()

        self.hotes_decouverts = []
        self.reseaux = []
        self.reseaux_bloques = []
        self.pivots = []
        self.graphe = None

    def executer(self):
        self.logger.info("")
        self.logger.info("DEMARRAGE DE LA DECOUVERTE RESEAU")
        self.logger.info("")

        try:
            self.logger.info("PHASE 1: Reconnaissance locale")
            info_locale = self.phase1_reconnaissance_locale()

            self.logger.info("")
            self.logger.info("PHASE 2: Decouverte des reseaux et hotes")
            self.phase2_decouverte_reseau(info_locale)

            self.logger.info("")
            self.logger.info("PHASE 3: Fingerprinting et inference de type")
            self.phase3_fingerprinting()

            if not self.args.no_pivot:
                self.logger.info("")
                self.logger.info("PHASE 4: Exploration des frontieres")
                self.phase4_exploration_frontieres()

            self.logger.info("")
            self.logger.info("PHASE 5: Construction de la topologie")
            self.phase5_construire_topologie()

            self.logger.info("")
            self.logger.info("PHASE 6: Export des resultats")
            self.phase6_exporter_resultats()

            self.logger.info("")
            self.logger.info("PHASE 7: Generation des rapports")
            self.phase7_generer_rapports()

            self.logger.info("")
            self.logger.info("DECOUVERTE TERMINEE AVEC SUCCES")
            self.afficher_resume_final()

        except KeyboardInterrupt:
            self.logger.warning("\nInterruption par l'utilisateur")
            sys.exit(1)

        except Exception as e:
            self.logger.error(f"\nErreur fatale: {e}", exc_info=True)
            sys.exit(1)

    def phase1_reconnaissance_locale(self) -> Dict:
        info_locale = self.recon_locale.executer_reconnaissance_complete()

        self.logger.info(f"  IP locale        : {info_locale['ip_locale']}")
        self.logger.info(f"  Interfaces       : {len(info_locale['interfaces'])}")
        self.logger.info(f"  Routes           : {len(info_locale['routes'])}")
        self.logger.info(f"  Passerelle       : {info_locale['passerelle_defaut']}")

        return info_locale

    def phase2_decouverte_reseau(self, info_locale: Dict):
        if self.args.target:
            reseaux_cibles = [self.args.target]
            self.logger.info(f"  Reseau cible (manuel): {self.args.target}")
        else:
            reseaux_cibles = self.recon_locale.obtenir_cibles_initiales()
            self.logger.info(f"  Reseaux detectes: {len(reseaux_cibles)}")
            for reseau in reseaux_cibles:
                self.logger.info(f"    - {reseau}")

        reseaux_scannes = set()
        iteration = 0

        while reseaux_cibles and iteration < config.MAX_ITERATIONS_DECOUVERTE:
            iteration += 1
            self.logger.info(f"  --- Iteration {iteration} ---")

            reseau = reseaux_cibles.pop(0)

            if reseau in reseaux_scannes:
                continue

            self.logger.info(f"  Scan du reseau {reseau}")

            hotes = self.scanner_nmap.scanner_reseau(reseau, approfondi=self.args.deep)

            if hotes:
                self.hotes_decouverts.extend(hotes)
                self.reseaux.append(reseau)
                reseaux_scannes.add(reseau)

                self.logger.info(f"  OK {len(hotes)} hotes decouverts sur {reseau}")
            else:
                self.logger.warning(f"  ERR Aucun hote actif sur {reseau}")

        self.logger.info(f"  TOTAL: {len(self.hotes_decouverts)} hotes sur {len(self.reseaux)} reseaux")

    def phase3_fingerprinting(self):
        self.hotes_decouverts = self.inference_type.annoter_plusieurs_hotes(self.hotes_decouverts)

        self.logger.info(f"  {len(self.hotes_decouverts)} hotes annotes")

    def phase4_exploration_frontieres(self):
        resultats_exploration = self.explorateur_frontieres.explorer_au_dela_connu(
            self.reseaux,
            self.hotes_decouverts
        )

        reseaux_candidats = resultats_exploration.get("reseaux_candidats", [])
        self.reseaux_bloques = resultats_exploration.get("reseaux_bloques", [])

        if self.reseaux_bloques:
            self.reseaux_bloques = self.explorateur_frontieres.analyser_blocages(self.reseaux_bloques)
            self.logger.info(f"  {len(self.reseaux_bloques)} reseaux bloques detectes")

            self.pivots = self.detecteur_pivot.identifier_pivots(
                self.hotes_decouverts,
                self.reseaux_bloques
            )

            if self.pivots:
                self.logger.info(f"  {len(self.pivots)} pivots suggeres")

                if self.args.pas_de_cote:
                    self.logger.info("")
                    self.logger.info("  Execution automatique des pas de cote...")
                    self._executer_pas_de_cote()
        else:
            self.logger.info("  Aucun reseau bloque detecte")

    def _executer_pas_de_cote(self):
        """
        Execute les pas de cote sur les pivots detectes
        """
        utilisateur_ssh = self.args.ssh_user or "root"
        cle_ssh = self.args.ssh_key
        mot_de_passe = self.args.ssh_password

        for pivot in self.pivots:
            if pivot.get("confiance") in ["high", "medium", "low"]:
                reseaux_cibles = pivot.get("reseaux_cibles", [])

                self.logger.info(f"  Pas de cote vers {pivot['ip_pivot']} "
                               f"pour {len(reseaux_cibles)} reseau(x)")

                resultat = self.mouvement_lateral.executer_pas_de_cote(
                    pivot, reseaux_cibles, utilisateur_ssh, cle_ssh, mot_de_passe
                )

                if resultat.get("succes"):
                    methode = resultat.get("methode", "inconnu")
                    self.logger.info(f"  OK Pas de cote reussi sur {pivot['ip_pivot']} via {methode}")
                else:
                    self.logger.warning(f"  ERR Pas de cote echoue: {resultat.get('raison')}")

        donnees_fusionnees = self.mouvement_lateral.fusionner_resultats({
            "hotes_decouverts": self.hotes_decouverts,
            "reseaux": self.reseaux
        })

        self.hotes_decouverts = donnees_fusionnees["hotes_decouverts"]
        self.reseaux = donnees_fusionnees["reseaux"]

        self.logger.info(f"  Resultats fusionnes: {len(self.hotes_decouverts)} hotes totaux")

    def phase5_construire_topologie(self):
        self.graphe = self.constructeur_topologie.construire_topologie(
            self.hotes_decouverts,
            self.reseaux
        )

        stats = self.constructeur_topologie.obtenir_stats_graphe()
        self.logger.info(f"  Noeuds: {stats['noeuds']}, Aretes: {stats['aretes']}")

        noeuds_critiques = self.constructeur_topologie.identifier_noeuds_critiques()
        self.logger.info(f"  {len(noeuds_critiques)} noeuds critiques identifies")

        self.stats_graphe = stats
        self.noeuds_critiques = noeuds_critiques

    def phase6_exporter_resultats(self):
        horodatage = datetime.now().strftime("%Y%m%d_%H%M%S")

        chemin_xml = config.obtenir_chemin_sortie(f"{config.PREFIXE_SORTIE}_{horodatage}_verefoo.xml")
        self.exporteur_verefoo.exporter(
            self.graphe,
            self.hotes_decouverts,
            chemin_xml
        )
        self.logger.info(f"  OK XML Verefoo: {chemin_xml}")

        chemin_json = config.obtenir_chemin_sortie(f"{config.PREFIXE_SORTIE}_{horodatage}_data.json")
        self.exporteur_verefoo.exporter_json(
            self.hotes_decouverts,
            self.reseaux,
            self.reseaux_bloques,
            self.pivots,
            chemin_json
        )
        self.logger.info(f"  OK JSON: {chemin_json}")

        chemin_graphml = config.obtenir_chemin_sortie(f"{config.PREFIXE_SORTIE}_{horodatage}_topology.graphml")
        self.constructeur_topologie.exporter_graphml(chemin_graphml)
        self.logger.info(f"  OK GraphML: {chemin_graphml}")

        chemin_viz = config.obtenir_chemin_sortie(f"{config.PREFIXE_SORTIE}_{horodatage}_topology.png")
        self.constructeur_topologie.visualiser_topologie(chemin_sortie=chemin_viz, afficher=False)
        self.logger.info(f"  OK Visualisation: {chemin_viz}")

    def phase7_generer_rapports(self):
        horodatage = datetime.now().strftime("%Y%m%d_%H%M%S")

        donnees_scan = {
            "ip_locale": self.recon_locale.ip_locale,
            "hotes_decouverts": self.hotes_decouverts,
            "reseaux": self.reseaux,
            "reseaux_bloques": self.reseaux_bloques,
            "pivots": self.pivots,
            "stats_graphe": self.stats_graphe,
            "noeuds_critiques": self.noeuds_critiques
        }

        chemin_rapport = config.obtenir_chemin_sortie(f"{config.PREFIXE_SORTIE}_{horodatage}_rapport.txt")
        self.generateur_rapports.generer_rapport_complet(donnees_scan, chemin_rapport)
        self.logger.info(f"  OK Rapport complet: {chemin_rapport}")

        if self.pivots:
            rapport_pivot = self.detecteur_pivot.generer_rapport_pivot(self.pivots)
            chemin_rapport_pivot = config.obtenir_chemin_sortie(f"{config.PREFIXE_SORTIE}_{horodatage}_pivots.txt")
            with open(chemin_rapport_pivot, 'w', encoding='utf-8') as f:
                f.write(rapport_pivot)
            self.logger.info(f"  OK Rapport pivots: {chemin_rapport_pivot}")

    def afficher_resume_final(self):
        donnees_scan = {
            "hotes_decouverts": self.hotes_decouverts,
            "reseaux": self.reseaux,
            "reseaux_bloques": self.reseaux_bloques,
            "pivots": self.pivots
        }

        resume = self.generateur_rapports.generer_resume_console(donnees_scan)
        print("\n" + resume)


def analyser_arguments():
    parser = argparse.ArgumentParser(
        description="Outil de decouverte et exploration reseau automatisee"
    )

    parser.add_argument(
        "--target",
        type=str,
        help="Reseau cible specifique au format CIDR (ex: 192.168.1.0/24)"
    )

    parser.add_argument(
        "--deep",
        action="store_true",
        help="Active le scan approfondi (detection OS, scripts NSE)"
    )

    parser.add_argument(
        "--no-pivot",
        action="store_true",
        help="Desactive la detection de pivots et l'exploration des frontieres"
    )

    parser.add_argument(
        "--output-dir",
        type=str,
        help=f"Repertoire de sortie personnalise (defaut: {config.REPERTOIRE_SORTIE})"
    )

    parser.add_argument(
        "--quiet",
        action="store_true",
        help="Mode silencieux (logs WARNING et au-dessus uniquement)"
    )

    parser.add_argument(
        "--pas-de-cote",
        action="store_true",
        help="Active l'execution automatique des pas de cote sur les pivots detectes"
    )

    parser.add_argument(
        "--ssh-user",
        type=str,
        default="root",
        help="Utilisateur SSH pour connexion aux pivots (defaut: root)"
    )

    parser.add_argument(
        "--ssh-key",
        type=str,
        help="Chemin vers la cle SSH privee pour connexion aux pivots"
    )

    parser.add_argument(
        "--ssh-password",
        type=str,
        help="Mot de passe pour connexion SSH/Telnet/WinRM aux pivots"
    )

    return parser.parse_args()


def main():
    args = analyser_arguments()

    if args.output_dir:
        config.REPERTOIRE_SORTIE = args.output_dir
        config.creer_repertoires()

    niveau_log = logging.WARNING if args.quiet else logging.INFO
    logger = configurer_logging(niveau_log)

    if os.geteuid() != 0:
        logger.warning("Attention: Ce script necessite les privileges root pour:")
        logger.warning("   - Scan ARP")
        logger.warning("   - Detection OS")
        logger.warning("   - Certains scripts NSE")
        logger.warning("")
        logger.warning("   Relancez avec: sudo python3 principal.py")
        logger.warning("")

        reponse = input("Continuer sans privileges root ? [o/N] ")
        if reponse.lower() not in ['o', 'oui', 'y', 'yes']:
            logger.info("Arret du script.")
            sys.exit(0)

    orchestrateur = OrchestrateurDecouverteReseau(args)
    orchestrateur.executer()


if __name__ == "__main__":
    main()
