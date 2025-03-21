from flask import Blueprint, request, jsonify, render_template
from services.service_enum import enumerate_services

enumeration_bp = Blueprint("enumerate", __name__)

@enumeration_bp.route("/", methods=["GET", "POST"])
def enumerate_services():
    if request.method == "POST":
        target = request.form["target"]
        ports = request.form["ports"]
        result = enumerate_services(target, ports)
        return render_template("results.html", title="Énumération des Services", result=result)
    return render_template("index.html")
