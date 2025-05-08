# app.py - Version améliorée
from flask import Flask, render_template, redirect, send_file, request
import os
import datetime
from config import Config
from dotenv import load_dotenv
from utils.logger import get_logger

# Chargement des variables d'environnement
load_dotenv()

# Configuration du logger
logger = get_logger('app')

def create_app():
    """Crée et configure l'application Flask"""
    logger.info("Création de l'application Flask")
    app = Flask(__name__)
    app.config.from_object(Config)
    
    # Ajout du filtre personnalisé basename
    @app.template_filter('basename')
    def basename_filter(path):
        """Extrait le nom de fichier d'un chemin complet"""
        return os.path.basename(path)
    
    # Import des blueprints ici pour éviter les imports circulaires
    from routes.scan_routes import scan_bp
    from routes.discovery_routes import discovery_bp
    from routes.enumeration_routes import enumeration_bp
    from routes.sniffer_routes import sniffer_bp
    from routes.hydra_routes import hydra_bp
    from routes.vuln_routes import vuln_bp
    from routes.exploit_routes import exploit_bp
    
    # Enregistrer les routes API
    app.register_blueprint(scan_bp, url_prefix="/api/scan")
    app.register_blueprint(discovery_bp, url_prefix="/api/discover")
    app.register_blueprint(enumeration_bp, url_prefix="/api/enumerate")
    app.register_blueprint(sniffer_bp, url_prefix="/api/sniffer")
    app.register_blueprint(hydra_bp, url_prefix="/api/hydra")
    app.register_blueprint(vuln_bp, url_prefix='/api/vuln')
    app.register_blueprint(exploit_bp, url_prefix='/api/exploit')
    
    logger.debug("Blueprints enregistrés")
    
    # Routes pour l'interface web
    @app.route("/")
    def home():
        logger.debug("Accès à la page d'accueil")
        return render_template("index.html")
        
    @app.route("/network")
    def network_page():
        logger.debug("Accès à la page de découverte réseau")
        return render_template("network.html")
        
    @app.route("/portscan")
    def portscan_page():
        logger.debug("Accès à la page de scan de ports")
        return render_template("portscan.html")
        
    @app.route("/enumerate")
    def enumerate_page():
        logger.debug("Accès à la page d'énumération")
        return render_template("enumerate.html")
        
    @app.route("/sniffer")
    def sniffer_page():
        logger.debug("Accès à la page de capture réseau")
        return render_template("sniffer.html")
        
    @app.route("/hydra")
    def hydra_page():
        logger.debug("Accès à la page de brute force")
        return render_template("hydra.html")
        
    @app.route("/vuln")
    def vuln_page():
        logger.debug("Accès à la page de scan de vulnérabilités")
        return render_template("vuln.html")
        
    @app.route("/exploit")
    def exploit_page():
        """Affiche la page d'exploitation avec les paramètres fournis"""
        logger.info("Accès à la page d'exploitation")
        
        # Récupérer les paramètres de la requête
        vuln_id = request.args.get("vuln_id")
        ip = request.args.get("ip")
        port = request.args.get("port")
        
        # Vérifier si les paramètres sont présents
        if not vuln_id or not ip or not port:
            logger.warning("Paramètres manquants pour la page d'exploitation")
            return redirect("/")
        
        # Trouver le module Metasploit correspondant
        from services.metasploit_auto import EXPLOIT_MAP
        module = "Unknown"
        for key, value in EXPLOIT_MAP.items():
            if key.lower() in vuln_id.lower() or vuln_id.lower() in key.lower():
                module = value
                break
        
        logger.info(f"Préparation de l'exploitation de {vuln_id} sur {ip}:{port}")
        
        # Rendre le template avec les informations
        return render_template(
            "exploit_form.html", 
            vuln={
                "id": vuln_id,
                "target": ip,
                "port": port
            },
            module=module
        )
    
    @app.route("/exploits")
    def exploits_list_page():
        """Affiche la liste des rapports d'exploitation"""
        logger.debug("Accès à la page des rapports d'exploitation")
        
        # Rediriger vers la route API correspondante
        return redirect("/api/exploit/reports")
        
    @app.route("/results")
    def results_page():
        logger.debug("Redirection de /results vers /")
        return redirect("/")
    
    @app.route("/reports")
    def reports_page():
        """Affiche la liste des rapports générés"""
        logger.info("Accès à la page des rapports")
        reports = []
        reports_dir = "generated_reports"
        
        if os.path.exists(reports_dir):
            for filename in os.listdir(reports_dir):
                if filename.endswith('.html'):
                    file_path = os.path.join(reports_dir, filename)
                    stats = os.stat(file_path)
                    reports.append({
                        "name": filename,
                        "date": datetime.datetime.fromtimestamp(stats.st_mtime).strftime("%Y-%m-%d %H:%M:%S"),
                        "size": f"{stats.st_size / 1024:.1f} KB"
                    })
        
        # Trier par date décroissante
        reports.sort(key=lambda x: x["date"], reverse=True)
        
        logger.debug(f"Trouvé {len(reports)} rapports")
        return render_template("reports.html", reports=reports)
        
    @app.route("/api/report/download/<path:filename>")
    def download_report(filename):
        """Télécharge un rapport généré"""
        logger.info(f"Téléchargement du rapport: {filename}")
        
        # Vérifier que le fichier existe
        report_path = os.path.join("generated_reports", filename)
        if not os.path.exists(report_path):
            logger.warning(f"Rapport introuvable: {filename}")
            return "Fichier non trouvé", 404
            
        return send_file(report_path, as_attachment=True)
    
    @app.route("/api/report/view/<path:filename>")
    def view_report(filename):
        """Affiche un rapport dans le navigateur"""
        logger.info(f"Affichage du rapport: {filename}")
        
        # Vérifier que le fichier existe
        report_path = os.path.join("generated_reports", filename)
        if not os.path.exists(report_path):
            logger.warning(f"Rapport introuvable: {filename}")
            return "Fichier non trouvé", 404
            
        return send_file(report_path)
        
    # Gestion des erreurs
    @app.errorhandler(404)
    def page_not_found(e):
        logger.warning(f"Page non trouvée: {request.path}")
        return render_template('404.html'), 404
        
    @app.errorhandler(500)
    def server_error(e):
        logger.error(f"Erreur serveur: {str(e)}")
        return render_template('500.html'), 500
    
    logger.info("Application Flask configurée avec succès")
    return app

if __name__ == "__main__":
    app = create_app()
    
    # Configuration du serveur
    host = os.getenv("HOST", "0.0.0.0")
    port = int(os.getenv("PORT", 5000))
    debug = os.getenv("FLASK_ENV", "production") == "development"
    
    logger.info(f"Démarrage de l'application sur {host}:{port} (debug: {debug})")
    app.run(host=host, port=port, debug=debug)
