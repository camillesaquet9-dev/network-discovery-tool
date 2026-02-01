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
from menu_interactif import MenuInteractif, AnalyseurMachineLocale

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
        self.menu = MenuInteractif()
        self.analyseur = AnalyseurMachineLocale()

        self.hotes_decouverts = []
        self.reseaux = []
        self.reseaux_bloques = []
        self.pivots = []
        self.graphe = None
        self.profondeur_scan = config.PROFONDEUR_NORMAL
        self.mode_interactif = config.MODE_INTERACTIF and not args.quiet

        if not hasattr(self.args, 'explorer_voisins'):
            self.args.explorer_voisins = False

    def executer(self):
        try:
            if self.mode_interactif:
                self.menu.effacer_ecran()
                self.menu.afficher_banniere()

            self.logger.info("")
            self.logger.info("DEMARRAGE DE LA DECOUVERTE RESEAU")
            self.logger.info("")

            self.logger.info("PHASE 1: Reconnaissance locale")
            info_locale = self.phase1_reconnaissance_locale()

            if self.mode_interactif:
                self.menu.afficher_info_machine(info_locale)
                contexte = self.analyseur.analyser_contexte(info_locale)

                choix = self.afficher_menu_et_obtenir_choix(info_locale, contexte)
                if choix is None:
                    self.logger.info("Arret demande par l'utilisateur")
                    sys.exit(0)

            self.logger.info("")
            self.logger.info("PHASE 2: Decouverte des reseaux et hotes")
            self.phase2_decouverte_reseau(info_locale)

            self.logger.info("")
            self.logger.info("PHASE 3: Fingerprinting et inference de type")
            self.phase3_fingerprinting()

            if not self.args.no_pivot and self.args.explorer_voisins:
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

    def afficher_menu_et_obtenir_choix(self, info_locale: Dict, contexte: Dict):
        choix = self.menu.afficher_menu_principal()

        if choix == 5:
            return None

        if choix == 1:
            self.profondeur_scan = config.PROFONDEUR_LEGER
            self.args.explorer_voisins = False

        elif choix == 2:
            self.profondeur_scan = config.PROFONDEUR_COMPLET
            self.args.explorer_voisins = False

        elif choix == 3:
            profondeur = self.menu.afficher_menu_profondeur()
            if profondeur:
                self.profondeur_scan = profondeur
            self.args.explorer_voisins = True

        elif choix == 4:
            reseau = self.menu.demander_reseau_manuel()
            if reseau:
                self.args.target = reseau
            profondeur = self.menu.afficher_menu_profondeur()
            if profondeur:
                self.profondeur_scan = profondeur
            self.args.explorer_voisins = False

        return choix

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

        if self.mode_interactif and len(reseaux_cibles) > config.MAX_RESEAUX_SANS_CONFIRMATION:
            self.menu.afficher_reseaux_detectes(reseaux_cibles)
            reseaux_cibles = self.menu.selectionner_reseaux(reseaux_cibles, "SELECTION DES RESEAUX")
            if not reseaux_cibles:
                self.logger.info("  Aucun reseau selectionne")
                return

        profondeur = self.profondeur_scan
        if self.args.deep:
            profondeur = config.PROFONDEUR_COMPLET

        reseaux_scannes = set()
        iteration = 0

        while reseaux_cibles and iteration < config.MAX_ITERATIONS_DECOUVERTE:
            iteration += 1
            self.logger.info(f"  --- Iteration {iteration} ---")

            reseau = reseaux_cibles.pop(0)

            if reseau in reseaux_scannes:
                continue

            self.logger.info(f"  Scan du reseau {reseau}")

            hotes = self.scanner_nmap.scanner_reseau(reseau, profondeur=profondeur)

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
            self.hotes_decouverts,
            limite=10
        )

        reseaux_candidats = resultats_exploration.get("reseaux_candidats", [])
        self.reseaux_bloques = resultats_exploration.get("reseaux_bloques", [])

        if reseaux_candidats:
            self.logger.info(f"  {len(reseaux_candidats)} nouveaux reseaux accessibles detectes")

            if self.mode_interactif:
                self.menu.afficher_reseaux_detectes(reseaux_candidats, "RESEAUX VOISINS DETECTES")
                reseaux_candidats = self.menu.selectionner_reseaux(
                    reseaux_candidats,
                    "SELECTION DES RESEAUX A EXPLORER"
                )
                if not reseaux_candidats:
                    self.logger.info("  Aucun reseau selectionne pour exploration")
                    return

            self.logger.info("  Scan des nouveaux reseaux...")

            profondeur = self.profondeur_scan
            if self.args.deep:
                profondeur = config.PROFONDEUR_COMPLET

            for reseau in reseaux_candidats:
                if reseau not in self.reseaux:
                    self.logger.info(f"    Scan de {reseau}")
                    hotes = self.scanner_nmap.scanner_reseau(reseau, profondeur=profondeur)

                    if hotes:
                        hotes = self.inference_type.annoter_plusieurs_hotes(hotes)
                        self.hotes_decouverts.extend(hotes)
                        self.reseaux.append(reseau)
                        self.logger.info(f"    {len(hotes)} hotes trouves sur {reseau}")

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

        if self.mode_interactif:
            nb_ports = sum(len(h.get("ports", [])) for h in self.hotes_decouverts)
            types = {}
            for h in self.hotes_decouverts:
                t = h.get("type_fonctionnel", "UNKNOWN")
                types[t] = types.get(t, 0) + 1

            stats = {
                "nb_reseaux": len(self.reseaux),
                "nb_hotes": len(self.hotes_decouverts),
                "nb_ports": nb_ports,
                "types": types
            }
            self.menu.afficher_resume_decouverte(stats)
        else:
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
        "--explorer-voisins",
        action="store_true",
        default=False,
        help="Active l'exploration des reseaux voisins"
    )

    parser.add_argument(
        "--no-menu",
        action="store_true",
        help="Desactive le menu interactif"
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
        "--no-root",
        action="store_true",
        help="Mode sans privileges root (scan TCP connect, pas de detection OS)"
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

    if args.no_menu:
        config.MODE_INTERACTIF = False

    niveau_log = logging.WARNING if args.quiet else logging.INFO
    logger = configurer_logging(niveau_log)

    if os.geteuid() != 0:
        if args.no_root:
            logger.info("Mode sans privileges root active")
            logger.info("  - Utilisation scan TCP connect (-sT)")
            logger.info("  - Detection OS desactivee")
            logger.info("  - Certains scripts NSE desactives")
            config.MODE_SANS_ROOT = True
            config.ACTIVER_DETECTION_OS = False
        else:
            logger.warning("Attention: Ce script necessite les privileges root pour:")
            logger.warning("   - Scan ARP")
            logger.warning("   - Detection OS")
            logger.warning("   - Certains scripts NSE")
            logger.warning("")
            logger.warning("   Relancez avec: sudo python3 principal.py")
            logger.warning("   Ou utilisez: python3 principal.py --no-root")
            logger.warning("")

            reponse = input("Continuer sans privileges root ? [o/N] ")
            if reponse.lower() not in ['o', 'oui', 'y', 'yes']:
                logger.info("Arret du script.")
                sys.exit(0)
            config.MODE_SANS_ROOT = True
            config.ACTIVER_DETECTION_OS = False

    orchestrateur = OrchestrateurDecouverteReseau(args)
    orchestrateur.executer()


if __name__ == "__main__":
    main()
