from flask import Blueprint, request, render_template
from services.vuln_nessus import nessus_scan

nessus_bp = Blueprint("nessus", __name__)

@nessus_bp.route("/", methods=["GET", "POST"])
def nessus_route():
    if request.method == "POST":
        target = request.form.get("target")
        print(f"🔍 Scan Nessus sur {target}")
        
        result = nessus_scan(target)
        
        return render_template("results.html", title="Scan de Vulnérabilités (Nessus)", result=result)
    return render_template("index.html")
