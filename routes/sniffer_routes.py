from flask import Blueprint, jsonify, request, send_file, render_template
from markupsafe import Markup
from services.packet_sniffer import capture_packets, get_interfaces, analyze_pcap
import os

sniffer_bp = Blueprint('sniffer', __name__)

@sniffer_bp.route('/start', methods=['POST'])
def start_sniffer():
    """Lance une capture réseau et retourne le chemin du fichier pcap"""
    try:
        if request.is_json:
            data = request.get_json()
            interface = data.get("interface", "eth0")
            count = int(data.get("count", 100))
        else:
            interface = request.form.get("interface", "eth0")
            count = int(request.form.get("count", 100))

        pcap_file = capture_packets(interface, count)
        filename = os.path.basename(pcap_file)
        
        # Analyser le fichier pcap pour extraire les informations importantes
        try:
            analysis_results = analyze_pcap(pcap_file)
        except Exception as e:
            analysis_results = {
                "error": str(e),
                "note": "L'analyse n'a pas pu être complétée. Vous pouvez toujours télécharger le fichier."
            }
        
        if request.is_json:
            return jsonify({
                "message": "Capture terminée", 
                "file": pcap_file,
                "download_url": f"/api/sniffer/download?file={filename}",
                "analysis": analysis_results
            }), 200
        else:
            # Créer un lien HTML sécurisé avec Markup pour éviter l'échappement
            download_link = Markup(f'<a href="/api/sniffer/download?file={filename}" class="btn btn-primary">Télécharger le fichier PCAP</a>')
            
            # Préparer les informations d'analyse pour l'affichage
            analysis_html = []
            
            # Informations générales
            analysis_html.append(f"Fichier: {filename}")
            analysis_html.append(f"Interface: {interface}")
            analysis_html.append(f"Nombre de paquets demandés: {count}")
            analysis_html.append(download_link)
            
            # Si une erreur s'est produite pendant l'analyse
            if 'error' in analysis_results:
                analysis_html.append(f"Note: {analysis_results.get('note', '')}")
            else:
                # Ajouter des informations d'analyse si disponibles
                analysis_html.append(f"Nombre de paquets capturés: {analysis_results.get('packet_count', 0)}")
                if 'unique_ips' in analysis_results:
                    analysis_html.append(f"Adresses IP uniques: {analysis_results.get('unique_ips', 0)}")
            
            # Utiliser le template standard results.html pour éviter les problèmes
            return render_template(
                "results.html", 
                title="Capture réseau terminée", 
                result=analysis_html
            )
    except Exception as e:
        if request.is_json:
            return jsonify({"error": str(e)}), 500
        else:
            return render_template("results.html", title="Erreur", result=[f"Erreur: {str(e)}"])

@sniffer_bp.route('/download', methods=['GET'])
def download_capture():
    """Télécharge un fichier de capture"""
    try:
        filename = request.args.get('file')
        if not filename:
            return jsonify({"error": "Nom de fichier manquant"}), 400
            
        capture_dir = os.path.join(os.getcwd(), "captures")
        file_path = os.path.join(capture_dir, filename)
        
        # Vérifier que le fichier existe et qu'il est dans le bon répertoire
        if not os.path.exists(file_path) or not os.path.isfile(file_path):
            return jsonify({"error": "Fichier introuvable"}), 404
            
        # Vérifier que le fichier est bien dans le répertoire de captures
        if not os.path.abspath(file_path).startswith(os.path.abspath(capture_dir)):
            return jsonify({"error": "Accès non autorisé"}), 403
            
        return send_file(file_path, as_attachment=True)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@sniffer_bp.route('/interfaces', methods=['GET'])
def list_interfaces():
    """Liste les interfaces réseau disponibles"""
    try:
        interfaces = get_interfaces()
        return jsonify({"interfaces": interfaces})
    except Exception as e:
        return jsonify({"error": str(e)}), 500
