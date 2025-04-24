import nmap
import logging
import datetime
import os
import json

# Configuration du logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("nmap_vulnscan")

# Répertoire pour stocker les rapports
CAPTURE_DIR = "vuln_reports"
os.makedirs(CAPTURE_DIR, exist_ok=True)

def vuln_scan(target, ports="21,22,23,25,80,110,139,143,443,445,3389"):
    """
    Lance un scan de vulnérabilités avec les scripts NSE "vuln" de Nmap.
    
    Args:
        target (str): Cible IP ou hostname
        ports (str): Ports à scanner (par défaut les ports communs)
    
    Returns:
        dict: Résultats du scan avec informations détaillées
    """
    scanner = nmap.PortScanner()
    arguments = f"--script vuln -p {ports}"
    
    try:
        logger.info(f"Lancement du scan de vulnérabilités sur {target} avec les ports {ports}")
        scanner.scan(hosts=target, arguments=arguments)
        
        if target in scanner.all_hosts():
            result = {
                "target": target,
                "scan_time": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "scan_stats": scanner.scanstats(),
                "command_line": scanner.command_line(),
                "host_status": "up" if scanner[target].state() == "up" else "down",
                "vulnerabilities": []
            }
            
            # Extraction des vulnérabilités par port
            for proto in scanner[target].all_protocols():
                ports_list = scanner[target][proto].keys()
                for port in ports_list:
                    port_info = scanner[target][proto][port]
                    service = port_info.get('name', 'unknown')
                    state = port_info.get('state', 'unknown')
                    
                    # Analyse des scripts pour trouver les vulnérabilités
                    if 'script' in port_info:
                        for script_name, script_output in port_info['script'].items():
                            if "vuln" in script_name or "VULNERABLE" in str(script_output).upper():
                                vuln_data = {
                                    "port": port,
                                    "protocol": proto,
                                    "service": service,
                                    "state": state,
                                    "vulnerability": script_name,
                                    "details": script_output
                                }
                                result["vulnerabilities"].append(vuln_data)
            
            # Sauvegarder le rapport
            timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            report_file = os.path.join(CAPTURE_DIR, f"vuln_scan_{timestamp}.json")
            with open(report_file, 'w') as f:
                json.dump(result, f, indent=4)
            
            result["report_file"] = report_file
            return result
        else:
            return {"error": "Hôte non scanné ou hors ligne."}
    except Exception as e:
        logger.error(f"Erreur lors du scan: {str(e)}")
        return {"error": str(e)}

def get_common_ports_by_category():
    """Retourne des listes de ports communs par catégorie"""
    return {
        "web": "80,443,8080,8443,8000,8888",
        "database": "1433,1521,3306,5432,27017",
        "mail": "25,110,143,465,587,993,995",
        "file_transfer": "20,21,22,69,115,445",
        "remote_access": "22,23,3389,5900",
        "common": "21,22,23,25,80,110,139,143,443,445,3389",
        "top100": "1,3,4,6,7,9,13,17,19,20,21,22,23,24,25,26,30,32,33,37,42,43,49,53,70,79,80,81,82,83,84,85,88,89,90,99,100,106,109,110,111,113,119,125,135,139,143,144,146,161,163,179,199,211,212,222,254,255,256,259,264,280,301,306,311,340,366,389,406,407,416,417,425,427,443,444,445,458,464,465,481,497,500,512,513,514,515,524,541,543,544,545,548,554,555,563,587,593,616,617,625,631,636,646,648,666,667,668,683,687,691,700,705,711,714,720,722,726,749,765,777,783,787,800,801,808,843,873,880,888,898,900,901,902,903,911,912,981,987,990,992,993,995,999,1000"
    }
