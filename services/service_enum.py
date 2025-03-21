import nmap

def enumerate_services(target: str, ports: str = "22,80,443"):
    """
    Enumère les services actifs sur une machine cible avec Nmap.

    :param target: IP ou domaine cible
    :param ports: Plage de ports à analyser
    :return: Liste des services détectés avec version
    """
    nm = nmap.PortScanner()
    print(f"🔍 Énumération des services sur {target}, ports : {ports}...")
    
    nm.scan(hosts=target, ports=ports, arguments="-sV")  # Scan avec détection des versions
    
    services = []
    for host in nm.all_hosts():
        for proto in nm[host].all_protocols():
            for port in nm[host][proto]:
                service_name = nm[host][proto][port].get("name", "Unknown")
                version = nm[host][proto][port].get("version", "Unknown")
                product = nm[host][proto][port].get("product", "Unknown")
                
                services.append({
                    "ip": host,
                    "port": port,
                    "service": service_name,
                    "version": version,
                    "product": product
                })

    return services

# Test rapide si exécuté directement
if __name__ == "__main__":
    target_ip = input("Entrez l'adresse IP cible : ")
    results = enumerate_services(target_ip)
    for res in results:
        print(f"IP: {res['ip']} | Port: {res['port']} | Service: {res['service']} | Version: {res['version']} | Produit: {res['product']}")
