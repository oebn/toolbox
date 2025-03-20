import nmap

def discover_network(network_range: str):
    """
    Scanne un réseau donné et retourne la liste des machines actives.
    """
    nm = nmap.PortScanner()
    print(f"🔍 Scanning network {network_range}...")
    nm.scan(hosts=network_range, arguments="-sn")  # Scan sans port (découverte simple)
    
    active_hosts = []
    for host in nm.all_hosts():
        active_hosts.append({
            "ip": host,
            "state": nm[host].state(),
            "hostname": nm[host].hostname()
        })
    
    return active_hosts

# Test rapide si le script est exécuté directement
if __name__ == "__main__":
    test_network = "192.168.1.0/24"
    results = discover_network(test_network)
    for r in results:
        print(f"IP: {r['ip']}, Hostname: {r['hostname']}, État: {r['state']}")
