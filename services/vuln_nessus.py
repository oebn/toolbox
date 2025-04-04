import subprocess
import time
import os
import logging
import json
from dotenv import load_dotenv

# Configuration du logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("nessus_client")

# Chargement des variables d'environnement
load_dotenv()

# Classe pour l'indicateur de connexion
class ConnectionIndicator:
    """Classe pour gérer l'indicateur de connexion (LED virtuelle)."""
    
    STATUS_OK = "✅"
    STATUS_ERROR = "❌"
    STATUS_WARNING = "⚠️"
    STATUS_CONNECTING = "🔄"
    
    def __init__(self):
        self.status = self.STATUS_CONNECTING
        self.message = "Initialisation..."
        
    def set_ok(self, message="Connexion à l'API réussie"):
        """Définit l'indicateur sur OK"""
        self.status = self.STATUS_OK
        self.message = message
        self._display()
        
    def set_error(self, message="Échec de connexion à l'API"):
        """Définit l'indicateur sur ERREUR"""
        self.status = self.STATUS_ERROR
        self.message = message
        self._display()
        
    def set_warning(self, message="Connexion à l'API avec avertissements"):
        """Définit l'indicateur sur AVERTISSEMENT"""
        self.status = self.STATUS_WARNING
        self.message = message
        self._display()
        
    def set_connecting(self, message="Tentative de connexion..."):
        """Définit l'indicateur sur EN COURS DE CONNEXION"""
        self.status = self.STATUS_CONNECTING
        self.message = message
        self._display()
        
    def _display(self):
        """Affiche l'état actuel de l'indicateur"""
        logger.info(f"Indicateur de connexion: {self.status} {self.message}")

class NessusClient:
    """
    Client pour Nessus utilisant la ligne de commande Nessus.
    Cette approche contourne les problèmes potentiels avec l'API REST.
    """
    
    def __init__(self):
        """Initialise le client Nessus avec les paramètres provenant des variables d'environnement."""
        # Création de l'indicateur de connexion
        self.indicator = ConnectionIndicator()
        self.indicator.set_connecting()
        
        # Récupération des paramètres depuis les variables d'environnement
        self.nessus_url = os.getenv("NESSUS_URL", "https://localhost:8834")
        self.access_key = os.getenv("NESSUS_ACCESS_KEY", "ff38dca85826b0a3929bd520cdd2555bd5f996abf07abebd80e27e36553bf215")
        self.secret_key = os.getenv("NESSUS_SECRET_KEY", "b9c933236629b4ef63104d9209ba1c62e68d4efdef214006e85c466287db6c54")
        
        if not all([self.access_key, self.secret_key]):
            self.indicator.set_error("Clés d'API manquantes")
            raise ValueError("Les clés d'API Nessus sont manquantes. Vérifiez vos variables d'environnement.")
            
        # Test de connexion initial
        if self._test_connection():
            self.indicator.set_ok("Nessus est accessible")
        else:
            self.indicator.set_error("Impossible de se connecter à Nessus")
    
    def _test_connection(self):
        """Teste si Nessus est accessible."""
        try:
            # Utilisation de curl pour tester la connexion
            cmd = [
                "curl", "-s", "-k",
                f"{self.nessus_url}/server/status",
                "-H", f"X-ApiKeys: accessKey={self.access_key}; secretKey={self.secret_key}"
            ]
            
            logger.info("Test de connexion à Nessus...")
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            print("=" * 80)
            print("RÉPONSE DU TEST DE CONNEXION:")
            print(result.stdout)
            print("=" * 80)
            
            if result.returncode == 0 and "status" in result.stdout:
                logger.info("Connexion à Nessus réussie")
                return True
            else:
                logger.error(f"Échec de la connexion à Nessus: {result.stderr}")
                return False
        except Exception as e:
            logger.error(f"Erreur lors du test de connexion: {str(e)}")
            return False
    
    def get_scan_templates(self):
        """Récupère les templates de scan disponibles."""
        try:
            cmd = [
                "curl", "-s", "-k",
                f"{self.nessus_url}/editor/scan/templates",
                "-H", f"X-ApiKeys: accessKey={self.access_key}; secretKey={self.secret_key}"
            ]
            
            logger.info("Récupération des templates de scan...")
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if result.returncode == 0:
                data = json.loads(result.stdout)
                templates = data.get('templates', [])
                logger.info(f"Récupération de {len(templates)} templates de scan")
                return templates
            else:
                logger.error(f"Échec de la récupération des templates: {result.stderr}")
                self.indicator.set_error("Échec de récupération des templates")
                return []
        except Exception as e:
            logger.error(f"Erreur lors de la récupération des templates: {str(e)}")
            self.indicator.set_error(f"Erreur: {str(e)[:50]}...")
            return []
    
    def create_and_launch_scan(self, targets, name=None, template_name="731a8e52-3ea6-a291-ec0a-d2ff0619c19d7bd788d6be818b65"):
        """
        Crée et lance un scan Nessus depuis la ligne de commande.
        
        Args:
            targets (str): Liste de cibles séparées par des virgules
            name (str, optional): Nom du scan. Par défaut "Scan automatique"
            template_name (str, optional): Nom ou UUID du template à utiliser
            
        Returns:
            int or None: ID du scan créé ou None en cas d'erreur
        """
        if not targets:
            logger.error("Aucune cible spécifiée pour le scan")
            self.indicator.set_error("Cible non spécifiée")
            return None
        
        # Générer un nom par défaut si non spécifié
        scan_name = name or f"Scan automatique - {time.strftime('%Y-%m-%d %H:%M')}"
        
        try:
            # Construire la configuration du scan
            scan_config = {
                "uuid": template_name,
                "settings": {
                    "name": scan_name,
                    "text_targets": targets,
                    "enabled": True,
                    "scanner_id": "1"
                }
            }
            
            # Créer le scan via curl directement (sans fichier temporaire)
            create_cmd = [
                "curl", "-s", "-k",
                "-X", "POST",
                f"{self.nessus_url}/scans",
                "-H", f"X-ApiKeys: accessKey={self.access_key}; secretKey={self.secret_key}",
                "-H", "Content-Type: application/json",
                "-d", json.dumps(scan_config)
            ]
            
            logger.info(f"Création d'un scan pour la cible: {targets}")
            logger.debug(f"Commande exécutée: {' '.join(create_cmd)}")
            create_result = subprocess.run(create_cmd, capture_output=True, text=True)
            
            # Afficher la réponse brute pour le débogage
            print("=" * 80)
            print("RÉPONSE BRUTE DE CRÉATION DE SCAN:")
            print(create_result.stdout)
            print("ERREUR ÉVENTUELLE:")
            print(create_result.stderr)
            print("=" * 80)
            
            # Vérifier le code de retour
            if create_result.returncode != 0:
                logger.error(f"Échec de la création du scan via curl: {create_result.stderr}")
                self.indicator.set_error("Échec de la création du scan")
                return None
            
            # Extraire l'ID du scan si possible
            try:
                if not create_result.stdout.strip():
                    logger.error("Réponse vide reçue de l'API Nessus")
                    self.indicator.set_error("Réponse vide de l'API")
                    return None
                
                create_data = json.loads(create_result.stdout)
                
                # Vérifier différentes structures possibles de la réponse
                scan_id = None
                
                if "scan" in create_data and "id" in create_data["scan"]:
                    scan_id = create_data["scan"]["id"]
                elif "id" in create_data:
                    scan_id = create_data["id"]
                elif "scanId" in create_data:
                    scan_id = create_data["scanId"]
                
                if not scan_id:
                    logger.error("Impossible d'extraire l'ID du scan de la réponse")
                    logger.debug(f"Structure de la réponse: {json.dumps(create_data, indent=2)}")
                    self.indicator.set_error("ID de scan non trouvé")
                    return None
                
                logger.info(f"Scan créé avec ID: {scan_id}")
                
                # Lancer le scan
                launch_result = self.launch_existing_scan(scan_id)
                
                if launch_result:
                    return scan_id
                else:
                    return None
                
            except json.JSONDecodeError:
                logger.error(f"Réponse invalide (pas un JSON): {create_result.stdout}")
                self.indicator.set_error("Réponse invalide")
                return None
            
        except Exception as e:
            logger.error(f"Exception lors de la création/lancement du scan: {str(e)}")
            self.indicator.set_error(f"Erreur: {str(e)[:50]}...")
            return None
            
    def launch_existing_scan(self, scan_id):
        """
        Lance un scan Nessus existant.
        
        Args:
            scan_id (int): ID du scan à lancer
            
        Returns:
            bool: True si le scan a été lancé avec succès, False sinon
        """
        try:
            launch_cmd = [
                "curl", "-s", "-k",
                "-X", "POST",
                f"{self.nessus_url}/scans/{scan_id}/launch",
                "-H", f"X-ApiKeys: accessKey={self.access_key}; secretKey={self.secret_key}"
            ]
            
            logger.info(f"Lancement du scan existant {scan_id}")
            launch_result = subprocess.run(launch_cmd, capture_output=True, text=True)
            
            print("=" * 80)
            print("RÉPONSE DE LANCEMENT:")
            print(launch_result.stdout)
            print("ERREUR ÉVENTUELLE:")
            print(launch_result.stderr)
            print("=" * 80)
            
            if launch_result.returncode == 0:
                logger.info(f"Scan {scan_id} lancé avec succès")
                self.indicator.set_ok(f"Scan {scan_id} lancé")
                return True
            else:
                logger.error(f"Échec du lancement du scan: {launch_result.stderr}")
                self.indicator.set_error("Échec du lancement du scan")
                return False
        except Exception as e:
            logger.error(f"Erreur lors du lancement du scan: {str(e)}")
            self.indicator.set_error(f"Erreur: {str(e)[:50]}...")
            return False
    
    def check_scan_status(self, scan_id):
        """
        Vérifie le statut d'un scan en cours.
        
        Args:
            scan_id (int): ID du scan à vérifier
            
        Returns:
            str or None: Statut du scan ou None en cas d'erreur
        """
        if not scan_id:
            logger.error("ID de scan invalide")
            self.indicator.set_error("ID de scan invalide")
            return None
        
        try:
            cmd = [
                "curl", "-s", "-k",
                f"{self.nessus_url}/scans/{scan_id}",
                "-H", f"X-ApiKeys: accessKey={self.access_key}; secretKey={self.secret_key}"
            ]
            
            logger.info(f"Vérification du statut du scan {scan_id}")
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if result.returncode == 0:
                try:
                    data = json.loads(result.stdout)
                    status = data.get("info", {}).get("status")
                    
                    if status:
                        logger.info(f"Statut du scan {scan_id}: {status}")
                        
                        if status == "completed":
                            self.indicator.set_ok(f"Scan {scan_id} terminé")
                        else:
                            self.indicator.set_warning(f"Scan {scan_id}: {status}")
                            
                        return status
                    else:
                        logger.warning(f"Statut non trouvé dans la réponse: {data}")
                        return None
                        
                except json.JSONDecodeError:
                    logger.error(f"Réponse invalide: {result.stdout}")
                    return None
            else:
                logger.error(f"Échec de la vérification du statut: {result.stderr}")
                return None
                
        except Exception as e:
            logger.error(f"Erreur lors de la vérification du statut: {str(e)}")
            self.indicator.set_error(f"Erreur: {str(e)[:50]}...")
            return None
    
    def get_scan_results(self, scan_id):
        """
        Récupère les résultats d'un scan terminé.
        
        Args:
            scan_id (int): ID du scan dont on veut récupérer les résultats
            
        Returns:
            dict or None: Résultats du scan ou None en cas d'erreur
        """
        if not scan_id:
            logger.error("ID de scan invalide")
            self.indicator.set_error("ID de scan invalide")
            return None
        
        try:
            cmd = [
                "curl", "-s", "-k",
                f"{self.nessus_url}/scans/{scan_id}",
                "-H", f"X-ApiKeys: accessKey={self.access_key}; secretKey={self.secret_key}"
            ]
            
            logger.info(f"Récupération des résultats du scan {scan_id}")
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if result.returncode == 0:
                try:
                    data = json.loads(result.stdout)
                    
                    if "vulnerabilities" in data:
                        vulnerabilities = data["vulnerabilities"]
                        count = len(vulnerabilities)
                        logger.info(f"Récupération de {count} vulnérabilités pour le scan {scan_id}")
                        self.indicator.set_ok(f"{count} vulnérabilités trouvées")
                        return vulnerabilities
                    else:
                        logger.warning(f"Aucune vulnérabilité trouvée dans la réponse pour le scan {scan_id}")
                        self.indicator.set_warning("Aucune vulnérabilité trouvée")
                        return []
                        
                except json.JSONDecodeError:
                    logger.error(f"Réponse invalide: {result.stdout}")
                    return None
            else:
                logger.error(f"Échec de la récupération des résultats: {result.stderr}")
                return None
                
        except Exception as e:
            logger.error(f"Erreur lors de la récupération des résultats: {str(e)}")
            self.indicator.set_error(f"Erreur: {str(e)[:50]}...")
            return None

# Exemple d'utilisation
if __name__ == "__main__":
    try:
        client = NessusClient()
        
        print("📡 Test de connexion à Nessus...")
        if client._test_connection():
            print("✅ Connexion réussie")
            
            # Option 1: Créer et lancer un nouveau scan
            print("\n🎯 Création et lancement d'un scan...")
            scan_id = client.create_and_launch_scan("192.168.36.129", template_name="731a8e52-3ea6-a291-ec0a-d2ff0619c19d7bd788d6be818b65")
            
            # Option 2: Lancer un scan existant (utiliser cette option si la création échoue)
            # scan_id = 22  # Remplacer par un ID de scan connu et fonctionnel
            # print("\n🚀 Lancement d'un scan existant...")
            # if client.launch_existing_scan(scan_id):
            #     print(f"✅ Scan {scan_id} lancé avec succès")
            
            if scan_id:
                print(f"✅ Scan {scan_id} créé et lancé avec succès")
                
                print("\n⌛ Vérification du statut...")
                status = client.check_scan_status(scan_id)
                print(f"📊 Statut actuel: {status}")
                
                if status == "completed":
                    print("\n📊 Récupération des résultats...")
                    results = client.get_scan_results(scan_id)
                    print(f"Nombre de vulnérabilités trouvées: {len(results) if results else 0}")
            else:
                print("❌ Échec de la création/lancement du scan")
        else:
            print("❌ Échec de la connexion à Nessus")
            
    except Exception as e:
        print(f"❌ Erreur critique: {e}")
