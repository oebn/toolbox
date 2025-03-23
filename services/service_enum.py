import nmap

def enumerate_services(target, ports):
    """
    Enumère les services et affiche toutes les informations récupérées par Nmap.
    """
    nm = nmap.PortScanner()
    print(f"🔍 Scan d'énumération sur {target} (ports : {ports})")

    # Ajout de l'option -sV pour la détection des versions
    nm.scan(hosts=target, ports=ports, arguments="-sV")

    services = []

    for host in nm.all_hosts():
        for proto in nm[host].all_protocols():
            for port in nm[host][proto]:
                port_data = nm[host][proto][port]
                print(f"📊 Données Nmap brutes : {port_data}")

                service = port_data.get("name", "Unknown")
                version = port_data.get("version", "Non détectée")
                product = port_data.get("product", "Inconnu")
                extrainfo = port_data.get("extrainfo", "")

                services.append(f"Port {port} : {service} (Produit : {product}, Version : {version}) {extrainfo}")

    return services
