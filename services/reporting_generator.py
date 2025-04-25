import os
import datetime
import json
from jinja2 import Environment, FileSystemLoader

# Configuration des chemins
TEMPLATES_DIR = "templates"
REPORTS_DIR = "generated_reports"

# Préparer le dossier si pas existant
os.makedirs(REPORTS_DIR, exist_ok=True)

def generate_report(module_name, scan_results, template_name="report_template.html"):
    """
    Génère un rapport HTML basé sur un template Jinja2.
    
    Args:
        module_name (str): Nom du module (ex: "vuln_scan", "network_discovery")
        scan_results (dict or list): Résultats du scan
        template_name (str): Nom du template à utiliser
    
    Returns:
        str: Chemin vers le rapport généré
    """
    env = Environment(loader=FileSystemLoader(TEMPLATES_DIR))
    
    # Choisir le bon template en fonction du module
    if module_name == "vuln_scan":
        template_name = "vuln_report_template.html"
    elif module_name == "sniffer":
        template_name = "sniffer_report_template.html"
    
    template = env.get_template(template_name)
    
    now = datetime.datetime.now().strftime("%d/%m/%Y %H:%M:%S")
    
    # Préparation des données pour le template
    data = {
        "module_name": module_name,
        "generated_on": now,
        "results": scan_results,
        "module_title": get_module_title(module_name),
        "stats": get_scan_stats(scan_results)
    }
    
    rendered = template.render(**data)
    
    filename = f"report_{module_name}_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
    filepath = os.path.join(REPORTS_DIR, filename)
    
    with open(filepath, "w", encoding="utf-8") as f:
        f.write(rendered)
    
    return filepath

def get_module_title(module_name):
    """Retourne un titre lisible pour chaque module"""
    titles = {
        "vuln_scan": "Scan de Vulnérabilités Nmap",
        "network_discovery": "Découverte Réseau",
        "port_scan": "Scan de Ports",
        "service_enumeration": "Énumération des Services",
        "sniffer": "Capture Réseau"
    }
    return titles.get(module_name, module_name)

def get_scan_stats(scan_results):
    """Génère des statistiques à partir des résultats du scan"""
    stats = {}
    
    if isinstance(scan_results, dict):
        if "vulnerabilities" in scan_results:
            stats["total_vulnerabilities"] = len(scan_results["vulnerabilities"])
            stats["by_severity"] = count_vulnerabilities_by_severity(scan_results["vulnerabilities"])
        
        if "scan_time" in scan_results:
            stats["scan_time"] = scan_results["scan_time"]
        
        if "target" in scan_results:
            stats["target"] = scan_results["target"]
            
        # Pour les captures réseau
        if "total_packets" in scan_results:
            stats["total_packets"] = scan_results["total_packets"]
            stats["protocols"] = scan_results.get("protocols", {})
            stats["conversations"] = scan_results.get("conversations", [])
    
    return stats

def count_vulnerabilities_by_severity(vulnerabilities):
    """Compte les vulnérabilités par niveau de sévérité"""
    severity_count = {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "info": 0
    }
    
    for vuln in vulnerabilities:
        if "severity" in vuln:
            severity = vuln["severity"].lower()
            if severity in severity_count:
                severity_count[severity] += 1
        else:
            # Si pas de sévérité spécifiée, considérer comme info
            severity_count["info"] += 1
    
    return severity_count
    
def generate_vuln_report(scan_results):
    """Fonction spécifique pour générer un rapport de vulnérabilités"""
    # Assurez-vous que le dossier existe
    os.makedirs(REPORTS_DIR, exist_ok=True)
    
    # Générer le rapport
    return generate_report("vuln_scan", scan_results)

def generate_sniffer_report(scan_results):
    """Fonction spécifique pour générer un rapport de capture réseau"""
    # Assurez-vous que le dossier existe
    os.makedirs(REPORTS_DIR, exist_ok=True)
    
    # Générer le rapport
    return generate_report("sniffer", scan_results)
