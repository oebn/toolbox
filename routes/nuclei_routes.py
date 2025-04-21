from flask import Blueprint, request, jsonify, render_template, send_file, redirect
from markupsafe import Markup
from services.vuln_nuclei import run_nuclei_scan, get_report, list_reports
import os
import logging

# Configuration du logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("nuclei_routes")

nuclei_bp = Blueprint('nuclei', __name__)

# Répertoire pour stocker les rapports
CAPTURE_DIR = "nuclei_reports"

# Créer le dossier pour stocker les rapports si inexistant
os.makedirs(CAPTURE_DIR, exist_ok=True)

@nuclei_bp.route('/scan', methods=['POST'])
def launch_nuclei_scan():
    """Lance un scan Nuclei et renvoie les résultats"""
    try:
        # Récupérer les données
        if request.is_json:
            data = request.get_json()
            target = data.get("target")
            template = data.get("template", "vulnerabilities/")
            severity = data.get("severity", "")
            tags = data.get("tags", "")
            options = data.get("options", {})
        else:
            target = request.form.get("target")
            template = request.form.get("template", "vulnerabilities/")
            severity = request.form.get("severity", "")
            tags = request.form.get("tags", "")
            options = {}
            if request.form.get("rate_limit"):
                options["rate_limit"] = request.form.get("rate_limit")
            if request.form.get("timeout"):
                options["timeout"] = request.form.get("timeout")
            if request.form.get("retries"):
                options["retries"] = request.form.get("retries")
                
        # Validation
        if not target:
            return jsonify({"error": "Cible manquante"}), 400
            
        # Exécuter Nuclei
        result = run_nuclei_scan(target, template, severity, tags, options)
        
        # Réponse JSON
        if request.headers.get('Accept') == 'application/json' or request.is_json:
            return jsonify(result)
            
        # Redirection vers le rapport HTML
        if result.get("success", False) and "html_report" in result:
            html_report = result["html_report"]
            report_id = os.path.basename(html_report).replace("nuclei_scan_", "").replace(".html", "")
            return redirect(f"/api/vuln/nuclei/html-report/{report_id}")
            
        # Format HTML
        html_result = []
        
        if result.get("success", False):
            html_result.append("<div style='color: green; font-weight: bold;'>Scan terminé avec succès</div>")
            
            # Vulnérabilités
            if "vulnerabilities" in result:
                html_result.append("<h3>Vulnérabilités détectées</h3>")
                html_result.append("<table border='1' style='border-collapse: collapse; width: 100%;'>")
                html_result.append("<tr><th>Sévérité</th><th>Nombre</th></tr>")
                
                for sev, count in result["vulnerabilities"].items():
                    if sev != "total":
                        color = "#000"
                        if sev == "critical": color = "#cc0000"
                        elif sev == "high": color = "#ff6600"
                        elif sev == "medium": color = "#ffcc00"
                        elif sev == "low": color = "#999900"
                        
                        html_result.append(f"<tr><td style='color:{color};'>{sev.upper()}</td><td>{count}</td></tr>")
                
                html_result.append(f"<tr><td><strong>TOTAL</strong></td><td><strong>{result['vulnerabilities'].get('total', 0)}</strong></td></tr>")
                html_result.append("</table>")
            
            # Lien rapport
            if "report_path" in result:
                report_id = os.path.basename(result["report_path"]).replace("nuclei_scan_", "").replace(".json", "")
                html_result.append(f"<p><a href='/api/vuln/nuclei/report/{report_id}' target='_blank'>Voir le rapport détaillé</a></p>")
                
            # Commande
            html_result.append("<h3>Commande</h3>")
            html_result.append(f"<pre>{result.get('command', '')}</pre>")
            
            # Sortie
            if result.get("stdout"):
                html_result.append("<h3>Sortie</h3>")
                html_result.append(f"<pre>{result.get('stdout', '')}</pre>")
        else:
            html_result.append(f"<div style='color: red; font-weight: bold;'>Erreur: {result.get('error', 'Erreur inconnue')}</div>")
            
            if "command" in result:
                html_result.append("<h3>Commande</h3>")
                html_result.append(f"<pre>{result.get('command', '')}</pre>")
                
            if "stderr" in result:
                html_result.append("<h3>Erreur</h3>")
                html_result.append(f"<pre>{result.get('stderr', '')}</pre>")
                
        return render_template(
            "results.html", 
            title=f"Résultats du scan Nuclei sur {target}", 
            result=[Markup(item) for item in html_result]
        )
    except Exception as e:
        logger.error(f"Erreur lors du lancement du scan: {e}")
        return jsonify({"error": str(e)}), 500

@nuclei_bp.route('/templates', methods=['GET'])
def get_nuclei_templates():
    """Récupère la liste des templates disponibles pour Nuclei"""
    try:
        templates = [
            {"tag": "default", "name": "cves", "path": "cves/"},
            {"tag": "default", "name": "vulnerabilities", "path": "vulnerabilities/"},
            {"tag": "default", "name": "misconfiguration", "path": "misconfiguration/"},
            {"tag": "default", "name": "technologies", "path": "technologies/"},
            {"tag": "default", "name": "exposures", "path": "exposures/"}
        ]
        
        if request.headers.get('Accept') == 'application/json':
            return jsonify({"templates": templates})
            
        return render_template(
            "results.html", 
            title="Templates Nuclei disponibles", 
            result=[
                "<h3>Templates disponibles</h3>",
                "<table border='1' style='border-collapse: collapse; width: 100%;'>",
                "<tr><th>Tag</th><th>Nom</th><th>Chemin</th></tr>",
                "".join([f"<tr><td>{tpl['tag']}</td><td>{tpl['name']}</td><td>{tpl['path']}</td></tr>" for tpl in templates]),
                "</table>"
            ]
        )
    except Exception as e:
        logger.error(f"Erreur lors de la récupération des templates: {e}")
        if request.headers.get('Accept') == 'application/json':
            return jsonify({"error": str(e)}), 500
        else:
            return render_template("results.html", title="Erreur", result=[f"Erreur: {str(e)}"])

@nuclei_bp.route('/reports', methods=['GET'])
def list_nuclei_reports():
    """Liste tous les rapports disponibles"""
    try:
        reports = list_reports()
        
        if request.headers.get('Accept') == 'application/json':
            return jsonify({"reports": reports})
            
        return render_template(
            "results.html", 
            title="Rapports Nuclei disponibles", 
            result=[
                "<h3>Rapports disponibles</h3>",
                "<table border='1' style='border-collapse: collapse; width: 100%;'>",
                "<tr><th>Date</th><th>Fichier</th><th>Vulnérabilités</th><th>Taille</th><th>Action</th></tr>",
                "".join([
                    f"<tr><td>{report['date']}</td><td>{report['file_name']}</td><td>{report['finding_count']}</td><td>{report['size']} octets</td><td><a href='/api/vuln/nuclei/report/{report['timestamp']}' target='_blank'>Voir</a></td></tr>" 
                    for report in reports
                ]),
                "</table>"
            ]
        )
    except Exception as e:
        logger.error(f"Erreur lors de la récupération des rapports: {e}")
        if request.headers.get('Accept') == 'application/json':
            return jsonify({"error": str(e)}), 500
        else:
            return render_template("results.html", title="Erreur", result=[f"Erreur: {str(e)}"])

@nuclei_bp.route('/report/<timestamp>', methods=['GET'])
def get_nuclei_report(timestamp):
    """Récupère un rapport spécifique par son timestamp"""
    try:
        file_path = f"{CAPTURE_DIR}/nuclei_scan_{timestamp}.json"
        
        if not os.path.exists(file_path):
            if request.headers.get('Accept') == 'application/json':
                return jsonify({"error": "Rapport introuvable"}), 404
            else:
                return render_template("results.html", title="Erreur", result=["Rapport introuvable"])
        
        # Vérifier s'il existe un rapport HTML
        html_path = file_path.replace(".json", ".html")
        if os.path.exists(html_path):
            return redirect(f"/api/vuln/nuclei/html-report/{timestamp}")
        
        # Format JSON ou téléchargement
        if request.headers.get('Accept') == 'application/json' or request.args.get('download') == 'true':
            return send_file(file_path, as_attachment=request.args.get('download') == 'true')
            
        # Format HTML
        report_data = get_report(file_path)
        
        if not report_data.get("success", False):
            return render_template("results.html", title="Erreur", result=[f"Erreur: {report_data.get('error', 'Erreur inconnue')}"])
            
        findings = report_data.get("findings", [])
        
        html_result = [
            f"<h3>Rapport Nuclei - {timestamp}</h3>",
            f"<p>Nombre de vulnérabilités trouvées: {len(findings)}</p>",
            "<p><a href='?download=true'>Télécharger le rapport JSON</a></p>"
        ]
        
        # Afficher chaque vulnérabilité
        for i, finding in enumerate(findings):
            severity = "unknown"
            if "info" in finding and "severity" in finding["info"]:
                severity = finding["info"]["severity"].lower()
                
            name = "Vulnérabilité inconnue"
            if "info" in finding and "name" in finding["info"]:
                name = finding["info"]["name"]
                
            html_result.append(f"""
                <div style='margin-bottom: 15px; padding: 10px; border: 1px solid #ddd; border-radius: 5px;'>
                    <h4>{i+1}. {name}</h4>
                    <p><strong>Sévérité:</strong> {severity.upper()}</p>
            """)
            
            if "matched" in finding:
                html_result.append(f"<p><strong>URL touchée:</strong> {finding['matched']}</p>")
                
            if "info" in finding and "description" in finding["info"]:
                html_result.append(f"<p><strong>Description:</strong> {finding['info']['description']}</p>")
                
            html_result.append("</div>")
        
        return render_template(
            "results.html", 
            title=f"Rapport Nuclei - {timestamp}", 
            result=[Markup(item) for item in html_result]
        )
    except Exception as e:
        logger.error(f"Erreur lors de la récupération du rapport: {e}")
        if request.headers.get('Accept') == 'application/json':
            return jsonify({"error": str(e)}), 500
        else:
            return render_template("results.html", title="Erreur", result=[f"Erreur: {str(e)}"])

@nuclei_bp.route('/html-report/<timestamp>', methods=['GET'])
def get_nuclei_html_report(timestamp):
    """Affiche un rapport HTML généré"""
    try:
        file_path = f"{CAPTURE_DIR}/nuclei_scan_{timestamp}.html"
        
        if not os.path.exists(file_path):
            return render_template("results.html", title="Erreur", result=["Rapport HTML introuvable"])
        
        with open(file_path, 'r') as f:
            html_content = f.read()
            
        return html_content
    except Exception as e:
        logger.error(f"Erreur lors de la récupération du rapport HTML: {e}")
        return render_template("results.html", title="Erreur", result=[f"Erreur: {str(e)}"])
