from flask import Blueprint, request, jsonify, render_template
from services.vuln_nessus import NessusClient
import logging

logger = logging.getLogger("nessus_routes")
nessus_bp = Blueprint("nessus", __name__)

@nessus_bp.route("/scan", methods=["POST"])
def start_scan():
    """
    Démarre un scan Nessus sur une cible spécifiée.
    """
    try:
        # Gestion des données selon le type de contenu
        if request.is_json:
            # Pour les requêtes API JSON
            data = request.get_json()
            targets = data.get("targets")
            name = data.get("name")
            template = data.get("template", "731a8e52-3ea6-a291-ec0a-d2ff0619c19d7bd788d6be818b65")
        else:
            # Pour les formulaires HTML
            targets = request.form.get("targets")
            name = request.form.get("name")
            template = request.form.get("template", "731a8e52-3ea6-a291-ec0a-d2ff0619c19d7bd788d6be818b65")

        logger.info(f"Démarrage d'un scan pour la cible: {targets} (template: {template})")

        if not targets:
            if request.is_json:
                return jsonify({"error": "Le paramètre 'targets' est requis"}), 400
            else:
                return render_template("results.html", title="Erreur", result=["Le paramètre 'targets' est requis"])

        # Initialisation du client
        client = NessusClient()
        
        # Vérifier l'état de l'indicateur
        if client.indicator.status == client.indicator.STATUS_ERROR:
            error_message = f"Erreur de connexion à Nessus: {client.indicator.message}"
            if request.is_json:
                return jsonify({"error": error_message}), 500
            else:
                return render_template("results.html", title="Erreur de connexion", result=[error_message])
        
        # Créer et lancer le scan
        scan_id = client.create_and_launch_scan(targets, name, template)
        
        if not scan_id:
            error_message = "Échec de la création/lancement du scan"
            if request.is_json:
                return jsonify({"error": error_message}), 500
            else:
                return render_template("results.html", title="Erreur", result=[error_message, f"Statut: {client.indicator.message}"])
        
        # Retourne une réponse selon le type de requête
        if request.is_json:
            return jsonify({
                "message": "Scan lancé avec succès", 
                "scan_id": scan_id,
                "status": client.indicator.status,
                "status_message": client.indicator.message
            }), 200
        else:
            return render_template(
                "results.html", 
                title="Scan Nessus", 
                result=[
                    f"Statut: {client.indicator.status} {client.indicator.message}",
                    f"Scan ID: {scan_id}", 
                    "Scan lancé avec succès", 
                    "Vérifiez les résultats ultérieurement via l'API /api/nessus/scan/{scan_id}/results"
                ]
            )
            
    except Exception as e:
        logger.error(f"Erreur lors du démarrage du scan: {e}")
        if request.is_json:
            return jsonify({"error": f"Erreur serveur: {str(e)}"}), 500
        else:
            return render_template("results.html", title="Erreur", result=[f"Erreur: {str(e)}"])

@nessus_bp.route("/status", methods=["GET"])
def check_api_status():
    """
    Vérifie le statut de la connexion à Nessus.
    """
    try:
        client = NessusClient()
        connection_ok = client._test_connection()
        
        if request.headers.get('Accept') == 'application/json':
            return jsonify({
                "status": client.indicator.status,
                "message": client.indicator.message,
                "connected": connection_ok
            })
        else:
            return render_template(
                "results.html", 
                title="Statut de Nessus", 
                result=[
                    f"Statut: {client.indicator.status}",
                    f"Message: {client.indicator.message}",
                    f"Connexion: {'Établie' if connection_ok else 'Échouée'}"
                ]
            )
            
    except Exception as e:
        logger.error(f"Erreur lors de la vérification du statut de Nessus: {e}")
        if request.headers.get('Accept') == 'application/json':
            return jsonify({"error": f"Erreur serveur: {str(e)}"}), 500
        else:
            return render_template("results.html", title="Erreur", result=[f"Erreur: {str(e)}"])

@nessus_bp.route("/templates", methods=["GET"])
def get_templates():
    """
    Récupère la liste des templates de scan disponibles.
    """
    try:
        client = NessusClient()
        templates = client.get_scan_templates()
        
        template_list = []
        for template in templates:
            template_list.append({
                "name": template.get("name", "Inconnu"),
                "uuid": template.get("uuid", ""),
                "description": template.get("description", "")
            })
        
        if request.headers.get('Accept') == 'application/json':
            return jsonify({
                "templates": template_list,
                "count": len(template_list)
            })
        else:
            result = [f"Nombre de templates disponibles: {len(template_list)}"]
            for i, template in enumerate(template_list):
                result.append(f"{i+1}. {template['name']} (UUID: {template['uuid'][:8] if template['uuid'] else 'N/A'}...)")
            
            return render_template(
                "results.html", 
                title="Templates de scan Nessus", 
                result=result
            )
            
    except Exception as e:
        logger.error(f"Erreur lors de la récupération des templates: {e}")
        if request.headers.get('Accept') == 'application/json':
            return jsonify({"error": f"Erreur serveur: {str(e)}"}), 500
        else:
            return render_template("results.html", title="Erreur", result=[f"Erreur: {str(e)}"])

@nessus_bp.route("/scan/<int:scan_id>/status", methods=["GET"])
def scan_status(scan_id):
    """
    Vérifie le statut d'un scan Nessus.
    """
    try:
        client = NessusClient()
        status = client.check_scan_status(scan_id)
        
        if status is None:
            if request.headers.get('Accept') == 'application/json':
                return jsonify({
                    "error": "Impossible de récupérer le statut",
                    "indicator_status": client.indicator.status,
                    "indicator_message": client.indicator.message
                }), 500
            else:
                return render_template("results.html", title="Erreur", result=[
                    "Impossible de récupérer le statut",
                    f"Indicateur: {client.indicator.status} {client.indicator.message}"
                ])
        
        if request.headers.get('Accept') == 'application/json':
            return jsonify({
                "scan_id": scan_id, 
                "status": status, 
                "completed": status == "completed",
                "indicator_status": client.indicator.status,
                "indicator_message": client.indicator.message
            })
        else:
            return render_template(
                "results.html", 
                title=f"Statut du scan {scan_id}", 
                result=[
                    f"Indicateur: {client.indicator.status} {client.indicator.message}",
                    f"Statut: {status}", 
                    f"Terminé: {'Oui' if status == 'completed' else 'Non'}"
                ]
            )
        
    except Exception as e:
        logger.error(f"Erreur lors de la vérification du statut: {e}")
        if request.headers.get('Accept') == 'application/json':
            return jsonify({"error": f"Erreur serveur: {str(e)}"}), 500
        else:
            return render_template("results.html", title="Erreur", result=[f"Erreur: {str(e)}"])

@nessus_bp.route("/scan/<int:scan_id>/results", methods=["GET"])
def scan_results(scan_id):
    """
    Récupère les résultats d'un scan Nessus.
    """
    try:
        client = NessusClient()
        results = client.get_scan_results(scan_id)
        
        if results is None:
            if request.headers.get('Accept') == 'application/json':
                return jsonify({
                    "error": "Impossible de récupérer les résultats",
                    "indicator_status": client.indicator.status,
                    "indicator_message": client.indicator.message
                }), 500
            else:
                return render_template("results.html", title="Erreur", result=[
                    "Impossible de récupérer les résultats",
                    f"Indicateur: {client.indicator.status} {client.indicator.message}"
                ])
        
        if request.headers.get('Accept') == 'application/json':
            return jsonify({
                "scan_id": scan_id, 
                "vulnerabilities": results,
                "count": len(results),
                "indicator_status": client.indicator.status,
                "indicator_message": client.indicator.message
            })
        else:
            # Formatage des résultats pour l'affichage HTML
            formatted_results = [
                f"Indicateur: {client.indicator.status} {client.indicator.message}",
                f"Nombre de vulnérabilités trouvées: {len(results)}"
            ]
            
            for vuln in results:
                formatted_results.append(f"- {vuln.get('plugin_name', 'Vulnérabilité inconnue')} (Sévérité: {vuln.get('severity', 'N/A')})")
            
            return render_template(
                "results.html", 
                title=f"Résultats du scan {scan_id}", 
                result=formatted_results
            )
        
    except Exception as e:
        logger.error(f"Erreur lors de la récupération des résultats: {e}")
        if request.headers.get('Accept') == 'application/json':
            return jsonify({"error": f"Erreur serveur: {str(e)}"}), 500
        else:
            return render_template("results.html", title="Erreur", result=[f"Erreur: {str(e)}"])
