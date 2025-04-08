# app.py - Version améliorée
from flask import Flask, render_template
import os
from config import Config
from routes.scan_routes import scan_bp
from routes.discovery_routes import discovery_bp
from routes.enumeration_routes import enumeration_bp
from routes.sniffer_routes import sniffer_bp
from dotenv import load_dotenv
import logging

# Chargement des variables d'environnement
load_dotenv()

# Configuration du logging
log_level = os.getenv("LOG_LEVEL", "INFO")
numeric_level = getattr(logging, log_level.upper(), logging.INFO)
logging.basicConfig(
    level=numeric_level,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("app")

def create_app():
    """Crée et configure l'application Flask"""
    app = Flask(__name__)
    app.config.from_object(Config)
    
    # Enregistrer les routes API
    app.register_blueprint(scan_bp, url_prefix="/api/scan")
    app.register_blueprint(discovery_bp, url_prefix="/api/discover")
    app.register_blueprint(enumeration_bp, url_prefix="/api/enumerate")
    app.register_blueprint(sniffer_bp, url_prefix="/api/sniffer")
    
    # Route pour afficher l'interface web
    @app.route("/")
    def home():
        return render_template("index.html")
        
    return app

if __name__ == "__main__":
    app = create_app()
    
    # Configuration du serveur
    host = os.getenv("HOST", "0.0.0.0")
    port = int(os.getenv("PORT", 5000))
    debug = os.getenv("FLASK_ENV", "production") == "development"
    
    logger.info(f"Démarrage de l'application sur {host}:{port} (debug: {debug})")
    app.run(host=host, port=port, debug=debug)
