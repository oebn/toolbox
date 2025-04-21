// Fonction pour charger les templates de Nuclei
function loadTemplates() {
    const selectElement = document.getElementById('nuclei-template');
    if (!selectElement) return;
    
    // Afficher un message de chargement
    selectElement.innerHTML = '<option value="">Chargement des templates...</option>';
    
    // Récupérer la liste des templates via l'API
    fetch('/api/vuln/nuclei/templates', {
        headers: { 'Accept': 'application/json' }
    })
    .then(response => {
        if (!response.ok) {
            throw new Error('Réponse réseau non valide');
        }
        return response.json();
    })
    .then(data => {
        // Vider la liste
        selectElement.innerHTML = '';
        
        // Option par défaut
        const defaultOption = document.createElement('option');
        defaultOption.value = "vulnerabilities/";
        defaultOption.textContent = "Vulnérabilités (défaut)";
        selectElement.appendChild(defaultOption);
        
        // Ajouter les templates par catégories
        const categories = {
            'cves': 'CVEs',
            'vulnerabilities': 'Vulnérabilités',
            'misconfiguration': 'Mauvaises configurations',
            'technologies': 'Technologies',
            'exposures': 'Expositions',
            'default': 'Autres'
        };
        
        // Option pour tous les templates
        const allOption = document.createElement('option');
        allOption.value = "";
        allOption.textContent = "Tous les templates";
        selectElement.appendChild(allOption);
        
        if (data.templates && data.templates.length > 0) {
            // Créer des groupes pour chaque catégorie
            for (const category in categories) {
                const templatesInCategory = data.templates.filter(tpl => 
                    tpl.path.startsWith(category) || 
                    (category === 'default' && !Object.keys(categories).some(cat => tpl.path.startsWith(cat) && cat !== 'default'))
                );
                
                if (templatesInCategory.length > 0) {
                    const optgroup = document.createElement('optgroup');
                    optgroup.label = categories[category];
                    
                    // Ajouter une option pour toute la catégorie
                    const categoryOption = document.createElement('option');
                    categoryOption.value = category + "/";
                    categoryOption.textContent = "Tous les " + categories[category].toLowerCase();
                    optgroup.appendChild(categoryOption);
                    
                    // Ajouter les templates individuels
                    templatesInCategory.forEach(template => {
                        const option = document.createElement('option');
                        option.value = template.path;
                        option.textContent = template.name;
                        optgroup.appendChild(option);
                    });
                    
                    selectElement.appendChild(optgroup);
                }
            }
        } else {
            // Aucun template trouvé ou erreur
            const option = document.createElement('option');
            option.value = "";
            option.textContent = "Aucun template disponible";
            selectElement.appendChild(option);
        }
    })
    .catch(error => {
        console.error('Erreur lors du chargement des templates:', error);
        selectElement.innerHTML = '<option value="">Erreur de chargement</option>';
    });
}

// Fonction pour charger la liste des rapports
function loadReports() {
    const reportsContainer = document.getElementById('reports-container');
    if (!reportsContainer) return;
    
    // Afficher un message de chargement
    reportsContainer.innerHTML = '<p>Chargement des rapports...</p>';
    
    // Récupérer la liste des rapports
    fetch('/api/vuln/nuclei/reports', {
        headers: { 'Accept': 'application/json' }
    })
    .then(response => {
        if (!response.ok) {
            throw new Error('Réponse réseau non valide');
        }
        return response.json();
    })
    .then(data => {
        if (data.reports && data.reports.length > 0) {
            let html = '<table class="reports-table">';
            html += '<tr><th>Date</th><th>Fichier</th><th>Vulnérabilités</th><th>Actions</th></tr>';
            
            data.reports.forEach(report => {
                html += `<tr>
                    <td>${report.date}</td>
                    <td>${report.file_name}</td>
                    <td>${report.finding_count}</td>
                    <td>
                        <a href="/api/vuln/nuclei/report/${report.timestamp}" target="_blank" class="btn-view">Voir</a>
                        <a href="/api/vuln/nuclei/report/${report.timestamp}?download=true" class="btn-download">Télécharger</a>
                    </td>
                </tr>`;
            });
            
            html += '</table>';
            reportsContainer.innerHTML = html;
        } else {
            reportsContainer.innerHTML = '<p>Aucun rapport disponible</p>';
        }
    })
    .catch(error => {
        console.error('Erreur lors du chargement des rapports:', error);
        reportsContainer.innerHTML = `<p>Erreur: ${error.message}</p>`;
    });
}

// Gestionnaire pour les options avancées
function toggleAdvancedOptions() {
    const advancedOptions = document.getElementById('nuclei-advanced-options');
    const toggleLink = document.getElementById('toggle-nuclei-options');
    
    if (advancedOptions.style.display === 'none') {
        advancedOptions.style.display = 'block';
        toggleLink.textContent = 'Masquer les options avancées';
    } else {
        advancedOptions.style.display = 'none';
        toggleLink.textContent = 'Options avancées';
    }
    
    return false; // Empêcher le comportement par défaut du lien
}

// Initialisation
document.addEventListener('DOMContentLoaded', function() {
    // Charger les templates
    loadTemplates();
    
    // Charger les rapports si on est sur la page des rapports
    if (document.getElementById('reports-container')) {
        loadReports();
    }
    
    // Gestionnaire pour les options avancées
    const toggleLink = document.getElementById('toggle-nuclei-options');
    if (toggleLink) {
        toggleLink.addEventListener('click', function(e) {
            e.preventDefault();
            toggleAdvancedOptions();
        });
    }
    
    // Gestionnaire de soumission du formulaire
    const nucleiForm = document.getElementById('nuclei-form');
    if (nucleiForm) {
        nucleiForm.addEventListener('submit', function() {
            const startBtn = document.getElementById('start-nuclei-btn');
            startBtn.disabled = true;
            startBtn.textContent = 'Scan en cours...';
            
            // Afficher un message de chargement
            const resultContainer = document.getElementById('scan-result');
            if (resultContainer) {
                resultContainer.innerHTML = '<p>Scan en cours, veuillez patienter...</p>';
            }
        });
    }
});
