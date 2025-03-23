import requests
import time

NESSUS_URL = "https://localhost:8834"
ACCESS_KEY = "c2c21e5be016d7ecaead7b1ff0e35fc81c80e3ec466482521a67aa872f9a7655"
SECRET_KEY = "d6eccd8a831df62e4dc7e299f8cf408936797c8e1d5d8b6e3baafdf3482939b4"

def nessus_scan(target):
    headers = {
        "X-ApiKeys": f"accessKey={ACCESS_KEY}; secretKey={SECRET_KEY}",
        "Content-Type": "application/json"
    }

    # 1. Créer un scan
    scan_data = {
        "uuid": "ab4bacd2-5257-11e4-926b-406186ea4fc5",  # ID du template (basic scan)
        "settings": {
            "name": f"Scan {target}",
            "text_targets": target
        }
    }
    scan_response = requests.post(f"{NESSUS_URL}/scans", json=scan_data, headers=headers, verify=False)
    scan_id = scan_response.json()["scan"]["id"]
    print(f"🚀 Scan lancé : {scan_id}")

    # 2. Lancer le scan
    requests.post(f"{NESSUS_URL}/scans/{scan_id}/launch", headers=headers, verify=False)

    # 3. Attendre la fin du scan
    while True:
        status = requests.get(f"{NESSUS_URL}/scans/{scan_id}", headers=headers, verify=False).json()["info"]["status"]
        print(f"⏳ Scan en cours : {status}")
        if status == "completed":
            break
        time.sleep(30)

    # 4. Récupérer les résultats
    result = requests.get(f"{NESSUS_URL}/scans/{scan_id}", headers=headers, verify=False).json()
    return result
