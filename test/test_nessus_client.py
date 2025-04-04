# test_nessus_client.py
import unittest
from unittest.mock import patch, MagicMock
import os
import sys
from services.vuln_nessus import NessusClient

class TestNessusClient(unittest.TestCase):
    """Tests unitaires pour la classe NessusClient"""
    
    def setUp(self):
        """Configuration avant chaque test"""
        # Mock des variables d'environnement
        self.env_patcher = patch.dict(os.environ, {
            "NESSUS_URL": "https://nessus-test.local:8834",
            "NESSUS_ACCESS_KEY": "test_access_key",
            "NESSUS_SECRET_KEY": "test_secret_key",
            "VERIFY_SSL": "False"
        })
        self.env_patcher.start()
        self.client = NessusClient()
        
    def tearDown(self):
        """Nettoyage après chaque test"""
        self.env_patcher.stop()
        
    @patch('requests.get')
    def test_get_folders(self, mock_get):
        """Test de la méthode get_folders"""
        # Configuration du mock
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"folders": [{"id": 1, "name": "Test"}]}
        mock_get.return_value = mock_response
        
        # Appel de la méthode
        result = self.client.get_folders()
        
        # Vérifications
        self.assertIsNotNone(result)
        mock_get.assert_called_once()
        self.assertEqual(result, {"folders": [{"id": 1, "name": "Test"}]})
        
    @patch('requests.get')
    def test_get_folders_error(self, mock_get):
        """Test de la méthode get_folders avec erreur"""
        # Configuration du mock pour simuler une erreur
        mock_get.side_effect = Exception("Erreur de connexion")
        
        # Appel de la méthode
        result = self.client.get_folders()
        
        # Vérifications
        self.assertIsNone(result)
        mock_get.assert_called_once()
        
    @patch('requests.post')
    def test_create_scan(self, mock_post):
        """Test de la méthode create_scan"""
        # Configuration du mock
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"scan": {"id": 123}}
        mock_post.return_value = mock_response
        
        # Appel de la méthode
        result = self.client.create_scan("192.168.1.1", "Test Scan")
        
        # Vérifications
        self.assertEqual(result, 123)
        mock_post.assert_called_once()
        
    @patch('requests.post')
    def test_launch_scan(self, mock_post):
        """Test de la méthode launch_scan"""
        # Configuration du mock
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_post.return_value = mock_response
        
        # Appel de la méthode
        result = self.client.launch_scan(123)
        
        # Vérifications
        self.assertTrue(result)
        mock_post.assert_called_once()
        
    @patch('requests.get')
    @patch('time.sleep')
    def test_check_scan_status(self, mock_sleep, mock_get):
        """Test de la méthode check_scan_status"""
        # Configuration du mock
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"info": {"status": "completed"}}
        mock_get.return_value = mock_response
        
        # Appel de la méthode
        result = self.client.check_scan_status(123, polling_interval=1, max_attempts=1)
        
        # Vérifications
        self.assertEqual(result, "completed")
        mock_get.assert_called_once()
        mock_sleep.assert_not_called()  # Le scan est déjà terminé, pas d'attente
        
    @patch('requests.get')
    def test_get_scan_results(self, mock_get):
        """Test de la méthode get_scan_results"""
        # Configuration du mock
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"vulnerabilities": [{"id": 1, "name": "Test Vuln"}]}
        mock_get.return_value = mock_response
        
        # Appel de la méthode
        result = self.client.get_scan_results(123)
        
        # Vérifications
        self.assertEqual(result, [{"id": 1, "name": "Test Vuln"}])
        mock_get.assert_called_once()

if __name__ == '__main__':
    unittest.main()
