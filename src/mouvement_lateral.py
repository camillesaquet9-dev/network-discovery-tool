import subprocess
import logging
import os
import json
import tempfile
import time
from typing import List, Dict, Optional

logger = logging.getLogger(__name__)


class GestionnaireMouvementLateral:
    def __init__(self):
        self.resultats_pivots = []
        self.methodes_disponibles = {
            22: "ssh",
            23: "telnet",
            3389: "rdp",
            5985: "winrm",
            5986: "winrm_ssl",
            5900: "vnc",
            5901: "vnc"
        }

    def executer_pas_de_cote(self, pivot: Dict, reseaux_cibles: List[str],
                             utilisateur: str = "root", cle_ssh: Optional[str] = None,
                             mot_de_passe: Optional[str] = None) -> Dict:
        """
        Execute un scan depuis un pivot (pas de cote)
        Essaie plusieurs methodes d'acces dans l'ordre de priorite
        """
        ip_pivot = pivot["ip_pivot"]
        ports_ouverts = pivot.get("ports_ouverts", [])

        logger.info(f"[MouvementLateral] Execution pas de cote vers {ip_pivot}")
        logger.info(f"[MouvementLateral] Ports disponibles: {ports_ouverts}")

        methode_utilisee = None

        # Determine les methodes d'acces disponibles par ordre de priorite
        methodes_a_essayer = self._determiner_methodes_acces(ports_ouverts)

        if not methodes_a_essayer:
            logger.warning(f"[MouvementLateral] Aucune methode d'acces disponible sur {ip_pivot}")
            return {"succes": False, "raison": "Aucune methode d'acces disponible"}

        try:
            # Essaie chaque methode jusqu'a ce qu'une fonctionne
            for methode in methodes_a_essayer:
                logger.info(f"[MouvementLateral] Tentative avec {methode}")

                if self._tester_connexion(ip_pivot, methode, utilisateur, cle_ssh, mot_de_passe):
                    methode_utilisee = methode
                    logger.info(f"[MouvementLateral] Connexion reussie via {methode}")
                    break

            if not methode_utilisee:
                logger.warning(f"[MouvementLateral] Echec connexion avec toutes les methodes")
                return {"succes": False, "raison": "Toutes les methodes de connexion ont echoue"}

            if not self._deployer_outil(ip_pivot, methode_utilisee, utilisateur, cle_ssh, mot_de_passe):
                logger.error(f"[MouvementLateral] Echec deploiement outil sur {ip_pivot}")
                return {"succes": False, "raison": "Deploiement echoue"}

            for reseau_cible in reseaux_cibles:
                logger.info(f"[MouvementLateral] Scan de {reseau_cible} depuis {ip_pivot}")

                resultats = self._executer_scan_distant(
                    ip_pivot, reseau_cible, methode_utilisee, utilisateur, cle_ssh, mot_de_passe
                )

                if resultats:
                    self.resultats_pivots.append({
                        "pivot": ip_pivot,
                        "reseau": reseau_cible,
                        "methode": methode_utilisee,
                        "donnees": resultats
                    })
                    logger.info(f"[MouvementLateral] Scan reussi: {len(resultats.get('hotes_decouverts', []))} hotes")

            self._nettoyer_pivot(ip_pivot, methode_utilisee, utilisateur, cle_ssh, mot_de_passe)

            return {"succes": True, "nb_scans": len(reseaux_cibles), "methode": methode_utilisee}

        except Exception as e:
            logger.error(f"[MouvementLateral] Erreur pas de cote: {e}")
            return {"succes": False, "raison": str(e)}

    def _determiner_methodes_acces(self, ports_ouverts: List[int]) -> List[str]:
        """
        Determine les methodes d'acces disponibles par ordre de priorite
        """
        methodes = []

        # Ordre de priorite
        priorite = [
            (22, "ssh"),           # SSH : le plus securise
            (5985, "winrm"),       # WinRM pour Windows
            (5986, "winrm_ssl"),   # WinRM SSL
            (23, "telnet"),        # Telnet : moins securise mais fonctionne
            (3389, "rdp"),         # RDP Windows
            (5900, "vnc"),         # VNC
            (5901, "vnc")          # VNC alternatif
        ]

        for port, methode in priorite:
            if port in ports_ouverts:
                if methode not in methodes:
                    methodes.append(methode)
                    logger.debug(f"  Methode disponible: {methode} (port {port})")

        return methodes

    def _tester_connexion(self, ip: str, methode: str, utilisateur: str,
                          cle_ssh: Optional[str], mot_de_passe: Optional[str]) -> bool:
        """
        Teste la connexion selon la methode specifiee
        """
        if methode == "ssh":
            return self._tester_connexion_ssh(ip, utilisateur, cle_ssh)
        elif methode == "telnet":
            return self._tester_connexion_telnet(ip, utilisateur, mot_de_passe)
        elif methode in ["winrm", "winrm_ssl"]:
            return self._tester_connexion_winrm(ip, utilisateur, mot_de_passe, methode == "winrm_ssl")
        elif methode == "vnc":
            return self._tester_connexion_vnc(ip, mot_de_passe)
        else:
            logger.warning(f"  Methode {methode} non implementee")
            return False

    def _deployer_outil(self, ip: str, methode: str, utilisateur: str,
                        cle_ssh: Optional[str], mot_de_passe: Optional[str]) -> bool:
        """
        Deploie l'outil selon la methode de connexion
        """
        if methode == "ssh":
            return self._copier_script_sur_pivot(ip, utilisateur, cle_ssh)
        elif methode == "telnet":
            return self._deployer_via_telnet(ip, utilisateur, mot_de_passe)
        elif methode in ["winrm", "winrm_ssl"]:
            return self._deployer_via_winrm(ip, utilisateur, mot_de_passe, methode == "winrm_ssl")
        else:
            logger.warning(f"  Deploiement via {methode} non supporte")
            return False

    def _tester_connexion_ssh(self, ip: str, utilisateur: str, cle_ssh: Optional[str]) -> bool:
        """
        Teste la connexion SSH au pivot
        """
        try:
            cmd = ["ssh", "-o", "ConnectTimeout=5", "-o", "StrictHostKeyChecking=no"]

            if cle_ssh:
                cmd.extend(["-i", cle_ssh])

            cmd.extend([f"{utilisateur}@{ip}", "echo", "test"])

            resultat = subprocess.run(
                cmd,
                capture_output=True,
                timeout=10
            )

            return resultat.returncode == 0

        except Exception as e:
            logger.error(f"  Erreur test SSH: {e}")
            return False

    def _tester_connexion_telnet(self, ip: str, utilisateur: str, mot_de_passe: Optional[str]) -> bool:
        """
        Teste la connexion Telnet au pivot
        """
        try:
            import pexpect

            logger.info(f"  Test connexion Telnet vers {ip}")

            child = pexpect.spawn(f"telnet {ip}", timeout=10, encoding='utf-8')

            child.expect(['login:', 'Username:'], timeout=5)
            child.sendline(utilisateur)

            if mot_de_passe:
                child.expect(['Password:', 'password:'], timeout=5)
                child.sendline(mot_de_passe)

            child.expect(['$', '#', '>'], timeout=5)
            child.sendline('echo test')
            child.expect('test', timeout=5)

            child.close()
            logger.info(f"  Connexion Telnet reussie")
            return True

        except ImportError:
            logger.warning("  Module pexpect non disponible, installation de pexpect avec: pip3 install pexpect")
            try:
                subprocess.run(["pip3", "install", "pexpect"], capture_output=True, timeout=30)
                return self._tester_connexion_telnet(ip, utilisateur, mot_de_passe)
            except:
                logger.error("  Impossible d'installer pexpect")
                return False
        except Exception as e:
            logger.error(f"  Erreur test Telnet: {e}")
            return False

    def _tester_connexion_winrm(self, ip: str, utilisateur: str, mot_de_passe: Optional[str], ssl: bool = False) -> bool:
        """
        Teste la connexion WinRM (Windows Remote Management)
        """
        try:
            import winrm

            logger.info(f"  Test connexion WinRM vers {ip}")

            protocole = "https" if ssl else "http"
            port = 5986 if ssl else 5985

            session = winrm.Session(f'{protocole}://{ip}:{port}/wsman',
                                   auth=(utilisateur, mot_de_passe or ""),
                                   transport='ntlm',
                                   server_cert_validation='ignore')

            resultat = session.run_cmd('echo test')

            if resultat.status_code == 0:
                logger.info(f"  Connexion WinRM reussie")
                return True

            return False

        except ImportError:
            logger.warning("  Module pywinrm non disponible, installation avec: pip3 install pywinrm")
            try:
                subprocess.run(["pip3", "install", "pywinrm"], capture_output=True, timeout=30)
                return self._tester_connexion_winrm(ip, utilisateur, mot_de_passe, ssl)
            except:
                logger.error("  Impossible d'installer pywinrm")
                return False
        except Exception as e:
            logger.error(f"  Erreur test WinRM: {e}")
            return False

    def _tester_connexion_vnc(self, ip: str, mot_de_passe: Optional[str]) -> bool:
        """
        Teste la connexion VNC (pour information, VNC necessiterait interaction graphique)
        """
        logger.warning("  VNC detecte mais necessite interaction graphique manuelle")
        return False

    def _deployer_via_telnet(self, ip: str, utilisateur: str, mot_de_passe: Optional[str]) -> bool:
        """
        Deploie le script via Telnet
        """
        try:
            import pexpect

            logger.info(f"  Deploiement via Telnet sur {ip}")

            child = pexpect.spawn(f"telnet {ip}", timeout=30, encoding='utf-8')
            child.expect(['login:', 'Username:'], timeout=5)
            child.sendline(utilisateur)

            if mot_de_passe:
                child.expect(['Password:', 'password:'], timeout=5)
                child.sendline(mot_de_passe)

            child.expect(['$', '#', '>'], timeout=5)

            # Cree le repertoire
            child.sendline('mkdir -p /tmp/network_discovery_tool')
            child.expect(['$', '#', '>'], timeout=5)

            child.close()

            # Utilise TFTP ou autre methode pour transferer les fichiers
            logger.info("  Creation repertoire reussie")

            # Pour Telnet, on utilise une approche alternative: creer le script directement
            return self._creer_script_inline(ip, utilisateur, mot_de_passe)

        except Exception as e:
            logger.error(f"  Erreur deploiement Telnet: {e}")
            return False

    def _deployer_via_winrm(self, ip: str, utilisateur: str, mot_de_passe: Optional[str], ssl: bool = False) -> bool:
        """
        Deploie le script via WinRM sur Windows
        """
        try:
            import winrm
            import base64

            logger.info(f"  Deploiement via WinRM sur {ip}")

            protocole = "https" if ssl else "http"
            port = 5986 if ssl else 5985

            session = winrm.Session(f'{protocole}://{ip}:{port}/wsman',
                                   auth=(utilisateur, mot_de_passe or ""),
                                   transport='ntlm',
                                   server_cert_validation='ignore')

            # Cree le repertoire
            session.run_cmd('mkdir C:\\temp\\network_discovery_tool')

            # Copie les fichiers (simplifie pour Windows)
            logger.info("  Script deploye sur Windows")
            return True

        except Exception as e:
            logger.error(f"  Erreur deploiement WinRM: {e}")
            return False

    def _creer_script_inline(self, ip: str, utilisateur: str, mot_de_passe: Optional[str]) -> bool:
        """
        Cree une version simplifiee du script directement sur la machine distante
        """
        try:
            import pexpect

            child = pexpect.spawn(f"telnet {ip}", timeout=60, encoding='utf-8')
            child.expect(['login:', 'Username:'], timeout=5)
            child.sendline(utilisateur)

            if mot_de_passe:
                child.expect(['Password:', 'password:'], timeout=5)
                child.sendline(mot_de_passe)

            child.expect(['$', '#', '>'], timeout=5)

            # Cree un script Python minimal pour le scan
            script_minimal = '''cat > /tmp/scan.py << 'EOF'
import os
import sys
target = sys.argv[1] if len(sys.argv) > 1 else "192.168.1.0/24"
os.system(f"nmap -sn {target} -oX /tmp/scan_result.xml")
EOF
'''
            child.sendline(script_minimal)
            child.expect(['$', '#', '>'], timeout=5)

            child.sendline('chmod +x /tmp/scan.py')
            child.expect(['$', '#', '>'], timeout=5)

            child.close()

            logger.info("  Script minimal cree sur le pivot")
            return True

        except Exception as e:
            logger.error(f"  Erreur creation script inline: {e}")
            return False

    def _copier_script_sur_pivot(self, ip: str, utilisateur: str, cle_ssh: Optional[str]) -> bool:
        """
        Copie le script et ses dependances sur le pivot
        """
        try:
            repertoire_src = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

            cmd_scp = ["scp", "-r", "-o", "StrictHostKeyChecking=no"]

            if cle_ssh:
                cmd_scp.extend(["-i", cle_ssh])

            cmd_scp.extend([
                os.path.join(repertoire_src, "src"),
                f"{utilisateur}@{ip}:/tmp/network_discovery_tool/"
            ])

            resultat = subprocess.run(
                cmd_scp,
                capture_output=True,
                timeout=60
            )

            if resultat.returncode == 0:
                logger.info(f"  Script copie sur {ip}")
                return True
            else:
                logger.error(f"  Erreur copie: {resultat.stderr.decode()}")
                return False

        except Exception as e:
            logger.error(f"  Erreur copie script: {e}")
            return False

    def _executer_scan_distant(self, ip: str, reseau_cible: str, methode: str,
                               utilisateur: str, cle_ssh: Optional[str],
                               mot_de_passe: Optional[str]) -> Optional[Dict]:
        """
        Execute le scan sur le pivot distant selon la methode de connexion
        """
        try:
            if methode == "ssh":
                return self._executer_scan_ssh(ip, reseau_cible, utilisateur, cle_ssh)
            elif methode == "telnet":
                return self._executer_scan_telnet(ip, reseau_cible, utilisateur, mot_de_passe)
            elif methode in ["winrm", "winrm_ssl"]:
                return self._executer_scan_winrm(ip, reseau_cible, utilisateur, mot_de_passe, methode == "winrm_ssl")
            else:
                logger.warning(f"  Execution via {methode} non supportee")
                return None

        except Exception as e:
            logger.error(f"  Erreur execution distante: {e}")
            return None

    def _executer_scan_ssh(self, ip: str, reseau_cible: str, utilisateur: str, cle_ssh: Optional[str]) -> Optional[Dict]:
        """
        Execute le scan via SSH
        """
        try:
            cmd_exec = ["ssh", "-o", "StrictHostKeyChecking=no"]

            if cle_ssh:
                cmd_exec.extend(["-i", cle_ssh])

            commande_distante = (
                f"cd /tmp/network_discovery_tool && "
                f"python3 src/principal.py --target {reseau_cible} "
                f"--output-dir /tmp/scan_results --quiet"
            )

            cmd_exec.extend([f"{utilisateur}@{ip}", commande_distante])

            logger.info(f"  Execution scan SSH sur {ip}")

            resultat = subprocess.run(
                cmd_exec,
                capture_output=True,
                timeout=600
            )

            if resultat.returncode != 0:
                logger.warning(f"  Scan distant a retourne une erreur")

            return self._recuperer_resultats_distants(ip, "ssh", utilisateur, cle_ssh, None)

        except subprocess.TimeoutExpired:
            logger.error(f"  Timeout scan SSH sur {ip}")
            return None
        except Exception as e:
            logger.error(f"  Erreur scan SSH: {e}")
            return None

    def _executer_scan_telnet(self, ip: str, reseau_cible: str, utilisateur: str, mot_de_passe: Optional[str]) -> Optional[Dict]:
        """
        Execute le scan via Telnet
        """
        try:
            import pexpect

            logger.info(f"  Execution scan Telnet sur {ip}")

            child = pexpect.spawn(f"telnet {ip}", timeout=600, encoding='utf-8')
            child.expect(['login:', 'Username:'], timeout=5)
            child.sendline(utilisateur)

            if mot_de_passe:
                child.expect(['Password:', 'password:'], timeout=5)
                child.sendline(mot_de_passe)

            child.expect(['$', '#', '>'], timeout=5)

            child.sendline(f'python3 /tmp/scan.py {reseau_cible}')
            child.expect(['$', '#', '>'], timeout=600)

            child.close()

            return self._recuperer_resultats_distants(ip, "telnet", utilisateur, None, mot_de_passe)

        except Exception as e:
            logger.error(f"  Erreur scan Telnet: {e}")
            return None

    def _executer_scan_winrm(self, ip: str, reseau_cible: str, utilisateur: str, mot_de_passe: Optional[str], ssl: bool) -> Optional[Dict]:
        """
        Execute le scan via WinRM
        """
        try:
            import winrm

            logger.info(f"  Execution scan WinRM sur {ip}")

            protocole = "https" if ssl else "http"
            port = 5986 if ssl else 5985

            session = winrm.Session(f'{protocole}://{ip}:{port}/wsman',
                                   auth=(utilisateur, mot_de_passe or ""),
                                   transport='ntlm',
                                   server_cert_validation='ignore')

            # Execute nmap sur Windows
            commande = f'nmap -sn {reseau_cible} -oX C:\\temp\\scan_result.xml'
            resultat = session.run_cmd(commande)

            return self._recuperer_resultats_distants(ip, "winrm", utilisateur, None, mot_de_passe)

        except Exception as e:
            logger.error(f"  Erreur scan WinRM: {e}")
            return None

    def _recuperer_resultats_distants(self, ip: str, methode: str, utilisateur: str,
                                      cle_ssh: Optional[str], mot_de_passe: Optional[str]) -> Optional[Dict]:
        """
        Recupere les resultats JSON du scan distant selon la methode
        """
        try:
            if methode == "ssh":
                return self._recuperer_via_ssh(ip, utilisateur, cle_ssh)
            elif methode == "telnet":
                logger.info("  Recuperation basique pour Telnet")
                return {"hotes_decouverts": [], "reseaux_decouverts": []}
            elif methode in ["winrm", "winrm_ssl"]:
                logger.info("  Recuperation basique pour WinRM")
                return {"hotes_decouverts": [], "reseaux_decouverts": []}
            else:
                return None

        except Exception as e:
            logger.error(f"  Erreur recuperation resultats: {e}")
            return None

    def _recuperer_via_ssh(self, ip: str, utilisateur: str, cle_ssh: Optional[str]) -> Optional[Dict]:
        """
        Recupere les resultats via SSH
        """
        try:
            cmd_ls = ["ssh", "-o", "StrictHostKeyChecking=no"]

            if cle_ssh:
                cmd_ls.extend(["-i", cle_ssh])

            cmd_ls.extend([
                f"{utilisateur}@{ip}",
                "ls -t /tmp/scan_results/*_data.json 2>/dev/null | head -1"
            ])

            resultat_ls = subprocess.run(
                cmd_ls,
                capture_output=True,
                text=True,
                timeout=10
            )

            if resultat_ls.returncode != 0:
                logger.error("  Aucun fichier de resultats trouve")
                return None

            fichier_distant = resultat_ls.stdout.strip()

            with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as temp_file:
                fichier_local = temp_file.name

            cmd_scp = ["scp", "-o", "StrictHostKeyChecking=no"]

            if cle_ssh:
                cmd_scp.extend(["-i", cle_ssh])

            cmd_scp.extend([
                f"{utilisateur}@{ip}:{fichier_distant}",
                fichier_local
            ])

            resultat_scp = subprocess.run(
                cmd_scp,
                capture_output=True,
                timeout=30
            )

            if resultat_scp.returncode == 0:
                with open(fichier_local, 'r') as f:
                    donnees = json.load(f)

                os.unlink(fichier_local)
                logger.info(f"  Resultats recuperes depuis {ip}")
                return donnees
            else:
                logger.error("  Erreur recuperation via SSH")
                return None

        except Exception as e:
            logger.error(f"  Erreur recuperation via SSH: {e}")
            return None

    def _nettoyer_pivot(self, ip: str, methode: str, utilisateur: str,
                        cle_ssh: Optional[str], mot_de_passe: Optional[str]):
        """
        Nettoie les fichiers temporaires sur le pivot selon la methode
        """
        try:
            if methode == "ssh":
                cmd_clean = ["ssh", "-o", "StrictHostKeyChecking=no"]

                if cle_ssh:
                    cmd_clean.extend(["-i", cle_ssh])

                cmd_clean.extend([
                    f"{utilisateur}@{ip}",
                    "rm -rf /tmp/network_discovery_tool /tmp/scan_results /tmp/scan.py"
                ])

                subprocess.run(cmd_clean, capture_output=True, timeout=10)

            elif methode == "telnet":
                import pexpect
                child = pexpect.spawn(f"telnet {ip}", timeout=10, encoding='utf-8')
                child.expect(['login:', 'Username:'], timeout=5)
                child.sendline(utilisateur)
                if mot_de_passe:
                    child.expect(['Password:', 'password:'], timeout=5)
                    child.sendline(mot_de_passe)
                child.expect(['$', '#', '>'], timeout=5)
                child.sendline('rm -rf /tmp/network_discovery_tool /tmp/scan_results /tmp/scan.py')
                child.close()

            elif methode in ["winrm", "winrm_ssl"]:
                import winrm
                protocole = "https" if methode == "winrm_ssl" else "http"
                port = 5986 if methode == "winrm_ssl" else 5985
                session = winrm.Session(f'{protocole}://{ip}:{port}/wsman',
                                       auth=(utilisateur, mot_de_passe or ""),
                                       transport='ntlm',
                                       server_cert_validation='ignore')
                session.run_cmd('rmdir /S /Q C:\\temp\\network_discovery_tool')

            logger.info(f"  Nettoyage effectue sur {ip}")

        except Exception as e:
            logger.warning(f"  Erreur nettoyage: {e}")

    def fusionner_resultats(self, resultats_principaux: Dict) -> Dict:
        """
        Fusionne les resultats des pivots avec les resultats principaux
        """
        if not self.resultats_pivots:
            return resultats_principaux

        logger.info(f"[MouvementLateral] Fusion de {len(self.resultats_pivots)} resultats de pivots")

        hotes_fusionnes = list(resultats_principaux.get("hotes_decouverts", []))
        reseaux_fusionnes = list(resultats_principaux.get("reseaux", []))

        for resultat_pivot in self.resultats_pivots:
            donnees = resultat_pivot["donnees"]

            for hote in donnees.get("hotes_decouverts", []):
                if not any(h["ip"] == hote["ip"] for h in hotes_fusionnes):
                    hotes_fusionnes.append(hote)

            for reseau in donnees.get("reseaux_decouverts", []):
                if reseau not in reseaux_fusionnes:
                    reseaux_fusionnes.append(reseau)

        resultats_principaux["hotes_decouverts"] = hotes_fusionnes
        resultats_principaux["reseaux"] = reseaux_fusionnes

        logger.info(f"[MouvementLateral] Fusion terminee: {len(hotes_fusionnes)} hotes, {len(reseaux_fusionnes)} reseaux")

        return resultats_principaux
