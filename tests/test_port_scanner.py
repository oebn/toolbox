import sys
import os

# Ajouter le chemin du dossier parent pour trouver "modules"
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from modules.port_scanner import scan_ports

target = input("Entrez l'IP ou le domaine à scanner : ")
ports = input("Entrez la plage de ports (ex: 22,80,443 ou 1-65535) : ") or "22,80,443"

results = scan_ports(target, ports)

print("\n🔍 Résultats du scan :")
for res in results:
    print(f"IP: {res['ip']} | Port: {res['port']} | État: {res['state']} | Service: {res['service']}")
