from flask import Flask, render_template
from config import Config
from routes.scan_routes import scan_bp
from routes.discovery_routes import discovery_bp
from routes.enumeration_routes import enumeration_bp

app = Flask(__name__)
app.config.from_object(Config)


# Enregistrer les routes API
app.register_blueprint(scan_bp, url_prefix="/api/scan")
app.register_blueprint(discovery_bp, url_prefix="/api/discover")
app.register_blueprint(enumeration_bp, url_prefix="/api/enumerate")

# Route pour afficher l’interface web
@app.route("/")
def home():
	return render_template("index.html")

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
