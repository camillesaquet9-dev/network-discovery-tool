import os
import sys
import ipaddress
import logging
from typing import List, Dict, Optional, Tuple

logger = logging.getLogger(__name__)


class MenuInteractif:
    def __init__(self):
        self.largeur_terminal = 70

    def effacer_ecran(self):
        os.system('clear' if os.name != 'nt' else 'cls')

    def afficher_banniere(self):
        print("=" * self.largeur_terminal)
        print("   OUTIL DE DECOUVERTE ET EXPLORATION RESEAU")
        print("=" * self.largeur_terminal)
        print()

    def afficher_separateur(self, titre: str = ""):
        if titre:
            longueur_tirets = (self.largeur_terminal - len(titre) - 2) // 2
            print("-" * longueur_tirets + " " + titre + " " + "-" * longueur_tirets)
        else:
            print("-" * self.largeur_terminal)

    def afficher_info_machine(self, info_locale: Dict):
        self.afficher_separateur("MACHINE ATTAQUANTE")
        print()

        print(f"  IP locale       : {info_locale.get('ip_locale', 'Non detectee')}")
        print(f"  Passerelle      : {info_locale.get('passerelle_defaut', 'Non detectee')}")
        print()

        interfaces = info_locale.get('interfaces', [])
        if interfaces:
            print("  Interfaces actives:")
            for iface in interfaces:
                nom = iface.get('nom', '?')
                ip = iface.get('ip', '?')
                reseau = iface.get('reseau', '?')
                print(f"    - {nom}: {ip} (reseau: {reseau})")
        print()

        serveurs_dns = info_locale.get('serveurs_dns', [])
        if serveurs_dns:
            print(f"  Serveurs DNS    : {', '.join(serveurs_dns)}")

        cache_arp = info_locale.get('cache_arp', [])
        print(f"  Entrees ARP     : {len(cache_arp)} machines connues")

        routes = info_locale.get('routes', [])
        routes_privees = [r for r in routes if r.get('type') != 'defaut']
        print(f"  Routes          : {len(routes_privees)} reseaux accessibles")

        print()

    def afficher_reseaux_detectes(self, reseaux: List[str], titre: str = "RESEAUX DETECTES"):
        self.afficher_separateur(titre)
        print()

        if not reseaux:
            print("  Aucun reseau detecte.")
        else:
            for i, reseau in enumerate(reseaux, 1):
                print(f"  [{i}] {reseau}")

        print()

    def demander_confirmation(self, message: str, defaut: bool = False) -> bool:
        suffixe = "[O/n]" if defaut else "[o/N]"
        try:
            reponse = input(f"  {message} {suffixe} ").strip().lower()
            if not reponse:
                return defaut
            return reponse in ['o', 'oui', 'y', 'yes']
        except (EOFError, KeyboardInterrupt):
            print()
            return False

    def demander_choix_numero(self, message: str, min_val: int, max_val: int,
                              defaut: Optional[int] = None) -> Optional[int]:
        try:
            prompt = f"  {message}"
            if defaut is not None:
                prompt += f" [{defaut}]"
            prompt += ": "

            reponse = input(prompt).strip()

            if not reponse and defaut is not None:
                return defaut

            valeur = int(reponse)
            if min_val <= valeur <= max_val:
                return valeur
            else:
                print(f"  Erreur: Entrez un nombre entre {min_val} et {max_val}")
                return None

        except ValueError:
            print("  Erreur: Entrez un nombre valide")
            return None
        except (EOFError, KeyboardInterrupt):
            print()
            return None

    def afficher_menu_principal(self) -> Optional[int]:
        self.afficher_separateur("MENU PRINCIPAL")
        print()
        print("  [1] Scan rapide (reseau local uniquement)")
        print("  [2] Scan approfondi (avec detection OS et services)")
        print("  [3] Explorer les reseaux voisins")
        print("  [4] Scan manuel (choisir le reseau)")
        print("  [5] Quitter")
        print()

        return self.demander_choix_numero("Votre choix", 1, 5, 1)

    def afficher_menu_profondeur(self) -> Optional[int]:
        self.afficher_separateur("PROFONDEUR DU SCAN")
        print()
        print("  [1] Leger   - Ping + ports principaux (rapide)")
        print("  [2] Normal  - Detection services (recommande)")
        print("  [3] Complet - Services + OS + scripts NSE (lent)")
        print()

        return self.demander_choix_numero("Votre choix", 1, 3, 2)

    def demander_reseau_manuel(self) -> Optional[str]:
        print()
        try:
            reseau = input("  Entrez le reseau a scanner (ex: 192.168.1.0/24): ").strip()

            if not reseau:
                return None

            try:
                net = ipaddress.ip_network(reseau, strict=False)
                return str(net)
            except ValueError:
                print("  Erreur: Format de reseau invalide")
                return None

        except (EOFError, KeyboardInterrupt):
            print()
            return None

    def selectionner_reseaux(self, reseaux: List[str], message: str = "Reseaux a scanner") -> List[str]:
        if not reseaux:
            return []

        self.afficher_separateur(message)
        print()

        for i, reseau in enumerate(reseaux, 1):
            print(f"  [{i}] {reseau}")

        print()
        print("  [A] Tous les reseaux")
        print("  [0] Aucun (annuler)")
        print()

        try:
            reponse = input("  Entrez les numeros separes par des virgules (ex: 1,3,5): ").strip()

            if not reponse or reponse == '0':
                return []

            if reponse.lower() == 'a':
                return reseaux

            indices = []
            for partie in reponse.split(','):
                partie = partie.strip()
                if partie.isdigit():
                    idx = int(partie)
                    if 1 <= idx <= len(reseaux):
                        indices.append(idx - 1)

            return [reseaux[i] for i in indices]

        except (EOFError, KeyboardInterrupt):
            print()
            return []

    def confirmer_scan_reseaux(self, reseaux: List[str], nb_hotes_estime: int = 0) -> bool:
        print()
        self.afficher_separateur("CONFIRMATION")
        print()
        print(f"  Reseaux a scanner : {len(reseaux)}")

        for reseau in reseaux[:5]:
            print(f"    - {reseau}")
        if len(reseaux) > 5:
            print(f"    ... et {len(reseaux) - 5} autres")

        print()

        if len(reseaux) > 10:
            print("  ATTENTION: Scanner beaucoup de reseaux peut prendre du temps.")
            print()

        return self.demander_confirmation("Lancer le scan?", defaut=True)

    def afficher_progression(self, etape: str, detail: str = ""):
        if detail:
            print(f"  [{etape}] {detail}")
        else:
            print(f"  [{etape}]")

    def afficher_resultat_scan(self, reseau: str, nb_hotes: int, temps: float = 0):
        if nb_hotes > 0:
            print(f"  OK  {reseau}: {nb_hotes} hotes trouves")
        else:
            print(f"  --  {reseau}: aucun hote actif")

    def afficher_resume_decouverte(self, stats: Dict):
        print()
        self.afficher_separateur("RESUME")
        print()
        print(f"  Reseaux scannes     : {stats.get('nb_reseaux', 0)}")
        print(f"  Hotes decouverts    : {stats.get('nb_hotes', 0)}")
        print(f"  Ports ouverts       : {stats.get('nb_ports', 0)}")
        print()

        types = stats.get('types', {})
        if types:
            print("  Types detectes:")
            for type_nom, count in sorted(types.items(), key=lambda x: -x[1]):
                print(f"    - {type_nom}: {count}")

        print()

    def pause(self, message: str = "Appuyez sur Entree pour continuer..."):
        try:
            input(f"  {message}")
        except (EOFError, KeyboardInterrupt):
            pass


class AnalyseurMachineLocale:
    def __init__(self):
        pass

    def analyser_contexte(self, info_locale: Dict) -> Dict:
        contexte = {
            "est_vm": False,
            "est_container": False,
            "interfaces_physiques": [],
            "interfaces_virtuelles": [],
            "reseaux_locaux": [],
            "reseaux_routes": [],
            "passerelles": []
        }

        interfaces = info_locale.get('interfaces', [])
        for iface in interfaces:
            nom = iface.get('nom', '')

            if self._est_interface_virtuelle(nom):
                contexte["interfaces_virtuelles"].append(iface)
                if nom.startswith('veth') or nom.startswith('docker'):
                    contexte["est_container"] = True
            else:
                contexte["interfaces_physiques"].append(iface)

            reseau = iface.get('reseau')
            if reseau:
                contexte["reseaux_locaux"].append(reseau)

        routes = info_locale.get('routes', [])
        for route in routes:
            dest = route.get('destination', '')
            passerelle = route.get('passerelle')

            if dest != '0.0.0.0/0' and passerelle:
                contexte["reseaux_routes"].append(dest)
                if passerelle not in contexte["passerelles"]:
                    contexte["passerelles"].append(passerelle)

        passerelle_defaut = info_locale.get('passerelle_defaut')
        if passerelle_defaut and passerelle_defaut not in contexte["passerelles"]:
            contexte["passerelles"].insert(0, passerelle_defaut)

        return contexte

    def _est_interface_virtuelle(self, nom: str) -> bool:
        prefixes_virtuels = [
            'veth', 'docker', 'br-', 'virbr', 'vbox', 'vmnet',
            'tun', 'tap', 'utun', 'awdl', 'llw', 'bridge'
        ]

        nom_lower = nom.lower()
        for prefixe in prefixes_virtuels:
            if nom_lower.startswith(prefixe):
                return True

        return False

    def filtrer_reseaux_pertinents(self, reseaux: List[str], contexte: Dict) -> Tuple[List[str], List[str]]:
        pertinents = []
        exclus = []

        for reseau in reseaux:
            try:
                net = ipaddress.ip_network(reseau, strict=False)

                if net.is_loopback or net.is_multicast or net.is_link_local:
                    exclus.append(reseau)
                    continue

                if not net.is_private:
                    exclus.append(reseau)
                    continue

                if self._est_reseau_virtuel(reseau):
                    exclus.append(reseau)
                    continue

                pertinents.append(reseau)

            except ValueError:
                exclus.append(reseau)

        return pertinents, exclus

    def _est_reseau_virtuel(self, reseau: str) -> bool:
        try:
            net = ipaddress.ip_network(reseau, strict=False)
            premier_octet = int(str(net.network_address).split('.')[0])

            if premier_octet == 169:
                return True

            if reseau.startswith('172.17.') or reseau.startswith('172.18.'):
                return True

        except ValueError:
            pass

        return False

    def suggerer_cibles(self, info_locale: Dict, contexte: Dict) -> List[str]:
        suggestions = []

        for reseau in contexte.get('reseaux_locaux', []):
            if reseau not in suggestions:
                suggestions.append(reseau)

        return suggestions
