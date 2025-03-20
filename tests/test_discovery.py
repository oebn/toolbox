import sys
import os

# Ajouter le chemin du dossier parent pour trouver "modules"
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from modules.network_discovery import discover_network

network_range = input("Entrez la plage d'IP à scanner (ex: 192.168.1.0/24) : ")
results = discover_network(network_range)

print("\n🔍 Résultats du scan :")
for host in results:
    print(f"IP : {host['ip']}, Hostname : {host['hostname']}, État : {host['state']}")
