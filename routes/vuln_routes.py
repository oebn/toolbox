from flask import Blueprint, request, jsonify, render_template, send_file
from markupsafe import Markup
from services.nmap_vulnscan import vuln_scan, get_common_ports_by_category
import os
import json
import logging

# Configuration du logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("vuln_routes")

vuln_bp = Blueprint("vuln", __name__)

@vuln_bp.route("/nmap", methods=["POST"])
def launch_vuln_scan():
    """Lance un scan de vulnérabilités Nmap"""
    if request.is_json:
        data = request.get_json()
        target = data.get("target")
        ports = data.get("ports", "21,22,23,25,80,110,139,143,443,445,3389")
    else:
        target = request.form.get("target")
        ports = request.form.get("ports", "21,22,23,25,80,110,139,143,443,445,3389")
    
    if not target:
        return jsonify({"error": "Le paramètre 'target' est requis."}), 400
    
    results = vuln_scan(target, ports)
    
    # Si la requête vient de l'API
    if request.headers.get('Accept') == 'application/json' or request.is_json:
        return jsonify(results)
    
    # Si la requête vient du formulaire web
    if "error" in results:
        return render_template("results.html", 
                             title="Erreur de scan", 
                             result=[f"Erreur: {results['error']}"],
                             module="vuln")
    
    # Format HTML
    html_result = []
    html_result.append("<h2>Résultats du scan de vulnérabilités Nmap</h2>")
    html_result.append(f"<p><strong>Cible:</strong> {target}</p>")
    html_result.append(f"<p><strong>Heure du scan:</strong> {results['scan_time']}</p>")
    html_result.append(f"<p><strong>État de l'hôte:</strong> {results['host_status']}</p>")
    
    if results["vulnerabilities"]:
        html_result.append(f"<h3>Vulnérabilités détectées ({len(results['vulnerabilities'])})</h3>")
        
        # Regrouper par port
        vuln_by_port = {}
        for vuln in results["vulnerabilities"]:
            port = vuln["port"]
            if port not in vuln_by_port:
                vuln_by_port[port] = []
            vuln_by_port[port].append(vuln)
        
        for port in sorted(vuln_by_port.keys()):
            html_result.append(f"<div style='margin-bottom: 20px; border: 1px solid #ddd; padding: 10px;'>")
            html_result.append(f"<h4>Port {port}</h4>")
            
            for vuln in vuln_by_port[port]:
                html_result.append(f"<p><strong>Service:</strong> {vuln['service']} ({vuln['state']})</p>")
                html_result.append(f"<p><strong>Vulnérabilité:</strong> {vuln['vulnerability']}</p>")
                html_result.append(f"<pre style='background-color: #f5f5f5; padding: 10px; overflow-x: auto;'>{vuln['details']}</pre>")
            
            html_result.append("</div>")
    else:
        html_result.append("<p>Aucune vulnérabilité détectée sur les ports scannés.</p>")
    
    html_result.append(f"<h4>Commande exécutée</h4>")
    html_result.append(f"<pre>{results['command_line']}</pre>")
    
    return render_template("results.html", 
                         title=f"Scan de vulnérabilités - {target}", 
                         result=[Markup(item) for item in html_result],
                         module="vuln")

@vuln_bp.route("/api/vuln/ports", methods=["GET"])
def get_port_categories():
    """Retourne les catégories de ports disponibles"""
    return jsonify(get_common_ports_by_category())
