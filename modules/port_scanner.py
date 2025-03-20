import nmap

def scan_ports(target: str, ports: str = "1-1024", scan_type: str = "-sT"):
    """
    Scan des ports ouverts sur une cible avec Nmap.

    :param target: IP ou domaine cible
    :param ports: Plage de ports à scanner (ex: "22,80,443" ou "1-65535")
    :param scan_type: Type de scan (ex: "-sS" pour SYN scan, "-sV" pour détection des services)
    :return: Dictionnaire avec les résultats du scan
    """
    nm = nmap.PortScanner()
    print(f"🔍 Scan en cours sur {target}, ports : {ports} ({scan_type})...")

    nm.scan(hosts=target, ports=ports, arguments=scan_type)

    results = []
    for host in nm.all_hosts():
        for proto in nm[host].all_protocols():
            for port in nm[host][proto]:
                state = nm[host][proto][port]["state"]
                service = nm[host][proto][port].get("name", "Unknown")
                results.append({
                    "ip": host,
                    "port": port,
                    "state": state,
                    "service": service
                })

    return results

# Test rapide si le script est exécuté directement
if __name__ == "__main__":
    target_ip = input("Entrez l'adresse IP cible : ")
    scan_results = scan_ports(target_ip)
    for r in scan_results:
        print(f"IP: {r['ip']} | Port: {r['port']} | État: {r['state']} | Service: {r['service']}")
