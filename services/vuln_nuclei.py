import subprocess
import datetime
import os
import json
import logging

# Configuration du logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger("vuln_nuclei")

# Répertoire pour stocker les rapports
CAPTURE_DIR = "nuclei_reports"

# S'assurer que le répertoire existe
os.makedirs(CAPTURE_DIR, exist_ok=True)

def run_nuclei_scan(target, template_path="vulnerabilities/", severity="", tags="", options=None):
    """Lance un scan nuclei sur la cible spécifiée."""
    try:
        # Nettoyer l'URL cible
        if target.startswith("https://http://"):
            target = target.replace("https://http://", "http://")
        elif target.startswith("http://https://"):
            target = target.replace("http://https://", "https://")
            
        # Créer un nom de fichier avec timestamp
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        output_file = os.path.join(CAPTURE_DIR, f"nuclei_scan_{timestamp}.json")
        
        # Construire la commande
        command = [
            "nuclei",
            "-u", target,
            "-t", template_path,
            "-json",
            "-o", output_file,
            "-c", "25"  # 25 connexions en parallèle
        ]
        
        # Ajouter les options
        if severity:
            command.extend(["-severity", severity])
        if tags:
            command.extend(["-tags", tags])
        if options:
            if options.get("rate_limit"):
                command.extend(["-rate-limit", str(options["rate_limit"])])
            if options.get("timeout"):
                command.extend(["-timeout", str(options["timeout"])])
            if options.get("retries"):
                command.extend(["-retries", str(options["retries"])])
        
        logger.info(f"Exécution de la commande: {' '.join(command)}")
        
        # Exécuter la commande
        process = subprocess.run(command, capture_output=True, text=True, timeout=300)
        
        # Vérifier si le fichier a été créé
        if os.path.exists(output_file):
            logger.info(f"Fichier de rapport créé: {output_file}")
            
            # Générer le rapport HTML
            html_file = output_file.replace(".json", ".html")
            create_html_report(output_file, html_file)
            
            # Analyser les vulnérabilités
            vulnerabilities = {
                "critical": 0,
                "high": 0,
                "medium": 0,
                "low": 0,
                "info": 0,
                "unknown": 0,
                "total": 0
            }
            
            try:
                with open(output_file, 'r') as f:
                    lines = f.readlines()
                    vulnerabilities["total"] = len(lines)
                    
                    for line in lines:
                        try:
                            finding = json.loads(line)
                            if "info" in finding and "severity" in finding["info"]:
                                severity_level = finding["info"]["severity"].lower()
                                if severity_level in vulnerabilities:
                                    vulnerabilities[severity_level] += 1
                                else:
                                    vulnerabilities["unknown"] += 1
                            else:
                                vulnerabilities["unknown"] += 1
                        except:
                            pass
            except Exception as e:
                logger.error(f"Erreur lors de l'analyse du fichier: {e}")
            
            return {
                "success": True,
                "report_path": output_file,
                "html_report": html_file,
                "command": " ".join(command),
                "stdout": process.stdout,
                "stderr": process.stderr,
                "vulnerabilities": vulnerabilities
            }
        else:
            logger.error(f"Le fichier de rapport n'a pas été créé: {output_file}")
            return {
                "success": False,
                "error": "Le fichier de rapport n'a pas été créé",
                "command": " ".join(command),
                "stdout": process.stdout,
                "stderr": process.stderr
            }
    except Exception as e:
        logger.error(f"Erreur lors de l'exécution de nuclei: {e}")
        return {
            "success": False,
            "error": str(e),
            "command": " ".join(command) if 'command' in locals() else "Command not built"
        }

def get_report(report_path):
    """Récupère le contenu d'un rapport Nuclei"""
    try:
        if not os.path.exists(report_path):
            return {"success": False, "error": "Rapport introuvable"}
            
        findings = []
        with open(report_path, 'r') as f:
            for line in f:
                try:
                    finding = json.loads(line)
                    findings.append(finding)
                except:
                    pass
                    
        return {
            "success": True,
            "findings": findings,
            "count": len(findings)
        }
    except Exception as e:
        logger.error(f"Erreur lors de la lecture du rapport: {e}")
        return {
            "success": False,
            "error": str(e)
        }

def list_reports():
    """Liste tous les rapports disponibles"""
    reports = []
    
    try:
        for file in os.listdir(CAPTURE_DIR):
            if file.startswith("nuclei_scan_") and file.endswith(".json"):
                file_path = os.path.join(CAPTURE_DIR, file)
                
                # Extraire la date
                try:
                    timestamp_str = file.replace("nuclei_scan_", "").replace(".json", "")
                    timestamp = datetime.datetime.strptime(timestamp_str, "%Y%m%d_%H%M%S")
                    formatted_date = timestamp.strftime("%d/%m/%Y %H:%M:%S")
                except:
                    formatted_date = "Date inconnue"
                    timestamp_str = ""
                
                # Taille du fichier
                file_size = os.path.getsize(file_path)
                
                # Nombre de vulnérabilités
                vuln_count = 0
                try:
                    with open(file_path, 'r') as f:
                        vuln_count = sum(1 for _ in f)
                except:
                    pass
                
                reports.append({
                    "file_name": file,
                    "path": file_path,
                    "date": formatted_date,
                    "timestamp": timestamp_str,
                    "size": file_size,
                    "finding_count": vuln_count
                })
        
        # Trier par date
        reports.sort(key=lambda x: x.get("timestamp", ""), reverse=True)
        
        return reports
    except Exception as e:
        logger.error(f"Erreur lors de la liste des rapports: {e}")
        return []

def create_html_report(json_file, html_file):
    """Crée un rapport HTML à partir du rapport JSON"""
    try:
        if not os.path.exists(json_file):
            return False
            
        vulns = []
        with open(json_file, 'r') as f:
            for line in f:
                try:
                    vulns.append(json.loads(line))
                except:
                    pass
                    
        # Créer un HTML basique
        with open(html_file, 'w') as f:
            f.write(f'''
            <!DOCTYPE html>
            <html>
            <head>
                <title>Rapport Nuclei</title>
                <style>
                    body {{ font-family: Arial, sans-serif; margin: 20px; }}
                    h1 {{ color: #333; }}
                    .vuln {{ margin-bottom: 20px; padding: 10px; border: 1px solid #ddd; border-radius: 5px; }}
                    .critical {{ border-left: 5px solid #cc0000; }}
                    .high {{ border-left: 5px solid #ff6600; }}
                    .medium {{ border-left: 5px solid #ffcc00; }}
                    .low {{ border-left: 5px solid #999900; }}
                    .info {{ border-left: 5px solid #0099cc; }}
                    .unknown {{ border-left: 5px solid #666666; }}
                    .severity {{ display: inline-block; padding: 3px 8px; border-radius: 3px; color: white; font-weight: bold; }}
                    .severity-critical {{ background-color: #cc0000; }}
                    .severity-high {{ background-color: #ff6600; }}
                    .severity-medium {{ background-color: #ffcc00; color: #333; }}
                    .severity-low {{ background-color: #999900; }}
                    .severity-info {{ background-color: #0099cc; }}
                    .severity-unknown {{ background-color: #666666; }}
                    table {{ width: 100%; border-collapse: collapse; }}
                    th, td {{ padding: 8px; text-align: left; border-bottom: 1px solid #ddd; }}
                    pre {{ background-color: #f5f5f5; padding: 10px; overflow-x: auto; }}
                </style>
            </head>
            <body>
                <h1>Rapport de Vulnérabilités Nuclei</h1>
                <p>Date du scan: {datetime.datetime.now().strftime("%d/%m/%Y %H:%M:%S")}</p>
                <p>Nombre de vulnérabilités trouvées: {len(vulns)}</p>
            ''')
            
            # Ajouter chaque vulnérabilité
            for i, vuln in enumerate(vulns):
                severity = "unknown"
                if "info" in vuln and "severity" in vuln["info"]:
                    severity = vuln["info"]["severity"].lower()
                    
                name = "Vulnérabilité inconnue"
                if "info" in vuln and "name" in vuln["info"]:
                    name = vuln["info"]["name"]
                    
                f.write(f'''
                <div class="vuln {severity}">
                    <h2>{i+1}. {name} <span class="severity severity-{severity}">{severity.upper()}</span></h2>
                ''')
                
                # Description
                if "info" in vuln and "description" in vuln["info"]:
                    f.write(f'<p><strong>Description:</strong> {vuln["info"]["description"]}</p>')
                
                # URL
                if "matched" in vuln:
                    f.write(f'<p><strong>URL:</strong> {vuln["matched"]}</p>')
                
                # Détails techniques
                f.write('<details><summary>Détails techniques</summary>')
                
                if "request" in vuln:
                    f.write(f'<h3>Requête</h3><pre>{vuln["request"]}</pre>')
                
                if "response" in vuln:
                    f.write(f'<h3>Réponse</h3><pre>{vuln["response"]}</pre>')
                
                f.write('</details>')
                f.write('</div>')
            
            f.write('''
            <script>
                document.addEventListener('DOMContentLoaded', function() {
                    var details = document.querySelectorAll('details');
                    details.forEach(function(detail) {
                        detail.addEventListener('toggle', function() {
                            if (this.open) {
                                details.forEach(function(d) {
                                    if (d !== detail) d.open = false;
                                });
                            }
                        });
                    });
                });
            </script>
            </body>
            </html>
            ''')
            
        return True
    except Exception as e:
        logger.error(f"Erreur lors de la création du rapport HTML: {e}")
        return False
