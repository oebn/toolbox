from flask import Blueprint, jsonify, request, send_file, render_template
from markupsafe import Markup
from services.packet_sniffer import capture_packets, get_interfaces, analyze_pcap
from services.sniffer_report_generator import SnifferReportGenerator
import os
import logging

# Configuration du logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("sniffer_routes")

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
        analysis_results = {}
        report_path = None
        
        try:
            analysis_results = analyze_pcap(pcap_file)
            
            # Générer le rapport HTML
            generator = SnifferReportGenerator()
            report_path = generator.generate_report(pcap_file)
            
            if report_path:
                report_filename = os.path.basename(report_path)
                logger.info(f"Rapport généré: {report_path}")
                
        except Exception as e:
            logger.error(f"Erreur lors de l'analyse ou de la génération du rapport: {str(e)}")
            analysis_results = {
                "error": str(e),
                "note": "L'analyse n'a pas pu être complétée. Vous pouvez toujours télécharger le fichier."
            }
        
        if request.is_json:
            response_data = {
                "message": "Capture terminée", 
                "file": pcap_file,
                "download_url": f"/api/sniffer/download?file={filename}",
                "analysis": analysis_results
            }
            if report_path:
                response_data["report_url"] = f"/api/report/download/{report_filename}"
            return jsonify(response_data), 200
        else:
            # Préparer l'affichage HTML
            analysis_html = []
            
            # Informations générales
            analysis_html.append("<h2>Capture réseau terminée</h2>")
            analysis_html.append(f"<p><strong>Fichier:</strong> {filename}</p>")
            analysis_html.append(f"<p><strong>Interface:</strong> {interface}</p>")
            analysis_html.append(f"<p><strong>Nombre de paquets demandés:</strong> {count}</p>")
            
            # Boutons d'action
            buttons_html = '<div class="mb-3">'
            buttons_html += f'<a href="/api/sniffer/download?file={filename}" class="btn btn-primary me-2">Télécharger le fichier PCAP</a>'
            
            if report_path:
                buttons_html += f'<a href="/api/report/download/{report_filename}" class="btn btn-success me-2">Voir le rapport HTML</a>'
            
            buttons_html += '</div>'
            analysis_html.append(Markup(buttons_html))
            
            # Si une erreur s'est produite pendant l'analyse
            if 'error' in analysis_results:
                analysis_html.append(f"<div class='alert alert-warning'>Note: {analysis_results.get('note', '')}</div>")
            else:
                # Résumé de l'analyse
                analysis_html.append("<h3>Résumé de l'analyse</h3>")
                analysis_html.append(f"<p><strong>Nombre de paquets capturés:</strong> {analysis_results.get('packet_count', 0)}</p>")
                
                if 'unique_ips' in analysis_results:
                    analysis_html.append(f"<p><strong>Adresses IP uniques:</strong> {analysis_results.get('unique_ips', 0)}</p>")
                
                if 'top_protocols' in analysis_results:
                    analysis_html.append("<h4>Protocoles les plus utilisés</h4>")
                    analysis_html.append("<ul>")
                    for proto, count in analysis_results['top_protocols']:
                        analysis_html.append(f"<li>{proto}: {count} paquets</li>")
                    analysis_html.append("</ul>")
                
                if 'tcp_ports' in analysis_results and analysis_results['tcp_ports']:
                    analysis_html.append(f"<p><strong>Ports TCP détectés:</strong> {', '.join(map(str, analysis_results['tcp_ports'][:10]))}{' ...' if len(analysis_results['tcp_ports']) > 10 else ''}</p>")
                
                if 'udp_ports' in analysis_results and analysis_results['udp_ports']:
                    analysis_html.append(f"<p><strong>Ports UDP détectés:</strong> {', '.join(map(str, analysis_results['udp_ports'][:10]))}{' ...' if len(analysis_results['udp_ports']) > 10 else ''}</p>")
                
                # Premiers paquets
                if 'first_packets' in analysis_results and analysis_results['first_packets']:
                    analysis_html.append("<h4>Premiers paquets capturés</h4>")
                    analysis_html.append('<div class="table-responsive">')
                    analysis_html.append('<table class="table table-striped table-sm">')
                    analysis_html.append('<thead><tr><th>#</th><th>Temps</th><th>Source</th><th>Destination</th><th>Protocole</th><th>Taille</th></tr></thead>')
                    analysis_html.append('<tbody>')
                    
                    for packet in analysis_results['first_packets']:
                        analysis_html.append('<tr>')
                        analysis_html.append(f"<td>{packet.get('number', '')}</td>")
                        analysis_html.append(f"<td>{packet.get('time', '')}</td>")
                        analysis_html.append(f"<td>{packet.get('src', '')}</td>")
                        analysis_html.append(f"<td>{packet.get('dst', '')}</td>")
                        analysis_html.append(f"<td>{packet.get('protocol', '')}</td>")
                        analysis_html.append(f"<td>{packet.get('length', '')} bytes</td>")
                        analysis_html.append('</tr>')
                    
                    analysis_html.append('</tbody></table></div>')
            
            # Retourner le template avec le contenu
            return render_template(
                "results.html", 
                title="Capture réseau terminée", 
                result=[Markup(item) if isinstance(item, str) else item for item in analysis_html],
                module="sniffer"
            )
            
    except Exception as e:
        if request.is_json:
            return jsonify({"error": str(e)}), 500
        else:
            return render_template(
                "results.html", 
                title="Erreur", 
                result=[f"Erreur: {str(e)}"],
                module="sniffer"
            )

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

@sniffer_bp.route('/report/<filename>', methods=['POST'])
def generate_report(filename):
    """Génère un rapport pour un fichier PCAP existant"""
    pcap_path = os.path.join("captures", filename)
    
    if not os.path.exists(pcap_path):
        return jsonify({"error": "Fichier PCAP non trouvé"}), 404
    
    try:
        generator = SnifferReportGenerator()
        report_path = generator.generate_report(pcap_path)
        
        if report_path:
            report_filename = os.path.basename(report_path)
            return jsonify({
                "message": "Rapport généré avec succès",
                "report_file": report_filename,
                "download_url": f"/api/report/download/{report_filename}"
            })
        else:
            return jsonify({"error": "Échec de la génération du rapport"}), 500
    except Exception as e:
        return jsonify({"error": str(e)}), 500
