from flask import Blueprint, request, jsonify, render_template, send_file
from markupsafe import Markup
from services.nmap_vulnscan import vuln_scan, get_common_ports_by_category
from services.reporting_generator import generate_vuln_report
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
    
    # Lancer le scan
    results = vuln_scan(target, ports)
    
    # Variable pour stocker le chemin du rapport
    html_report = None
    report_filename = None
    
    # Générer le rapport si le scan a réussi
    if "error" not in results:
        try:
            html_report = generate_vuln_report(results)
            # Extraire juste le nom du fichier
            report_filename = os.path.basename(html_report)
            logger.info(f"Rapport généré avec succès: {html_report}")
        except Exception as e:
            logger.error(f"Erreur lors de la génération du rapport: {str(e)}")
            # Continuer même si la génération du rapport échoue
    
    # Si c'est une requête API JSON
    if request.headers.get('Accept') == 'application/json' or request.is_json:
        if html_report:
            results["html_report"] = html_report
        return jsonify(results)
    
    # Si c'est depuis l'interface web
    if "error" in results:
        return render_template("results.html", 
                             title="Erreur de scan", 
                             result=[f"Erreur: {results['error']}"],
                             module="vuln")
    
    # Format HTML pour l'affichage
    html_result = []
    html_result.append("<h2>Résultats du scan de vulnérabilités Nmap</h2>")
    html_result.append(f"<p><strong>Cible:</strong> {target}</p>")
    html_result.append(f"<p><strong>Heure du scan:</strong> {results.get('scan_time', 'N/A')}</p>")
    html_result.append(f"<p><strong>État de l'hôte:</strong> {results.get('host_status', 'N/A')}</p>")
    
    if results.get("vulnerabilities"):
        html_result.append(f"<h3>Vulnérabilités détectées ({len(results['vulnerabilities'])})</h3>")
        
        for vuln in results["vulnerabilities"]:
            html_result.append(f"<div style='margin-bottom: 20px; border: 1px solid #ddd; padding: 10px;'>")
            html_result.append(f"<h4>Port {vuln.get('port', 'unknown')}</h4>")
            html_result.append(f"<p><strong>Service:</strong> {vuln.get('service', 'unknown')} ({vuln.get('state', 'unknown')})</p>")
            html_result.append(f"<p><strong>Vulnérabilité:</strong> {vuln.get('vulnerability', 'unknown')}</p>")
            html_result.append(f"<pre style='background-color: #f5f5f5; padding: 10px; overflow-x: auto;'>{vuln.get('details', '')}</pre>")
            html_result.append("</div>")
    else:
        html_result.append("<p>Aucune vulnérabilité détectée sur les ports scannés.</p>")
    
    html_result.append(f"<h4>Commande exécutée</h4>")
    html_result.append(f"<pre>{results.get('command_line', '')}</pre>")
    
    # Passer le nom du fichier au lieu du chemin complet
    return render_template("results.html", 
                         title=f"Scan de vulnérabilités - {target}", 
                         result=[Markup(item) for item in html_result],
                         html_report=report_filename,
                         module="vuln")

@vuln_bp.route("/api/vuln/ports", methods=["GET"])
def get_port_categories():
    """Retourne les catégories de ports disponibles"""
    return jsonify(get_common_ports_by_category())
