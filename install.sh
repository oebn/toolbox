#!/bin/bash

echo "📦 Installation des dépendances..."

# Vérifier si Nmap est installé
if ! command -v nmap &> /dev/null; then
    echo "🔍 Nmap non trouvé. Installation en cours..."
    sudo apt update && sudo apt install -y nmap
else
    echo "✅ Nmap est déjà installé."
fi

# Installer Python et pip s'ils ne sont pas présents
if ! command -v python3 &> /dev/null; then
    echo "🐍 Python3 non trouvé. Installation en cours..."
    sudo apt install -y python3 python3-pip
else
    echo "✅ Python3 est déjà installé."
fi

# Créer un environnement virtuel (optionnel mais recommandé)
if [ ! -d "venv" ]; then
    echo "📦 Création de l'environnement virtuel..."
    python3 -m venv venv
    source venv/bin/activate
else
    echo "✅ Environnement virtuel déjà existant."
    source venv/bin/activate
fi

# Installer les dépendances systèmes nécessaires à Scapy

echo "📦 Installation des dépendances système pour le sniffing réseau avec Scapy..."
sudo apt install -y tcpdump libpcap-dev
sudo apt-get install tshark
sudo setcap cap_net_raw,cap_net_admin=eip $(which python3)

# Installation Hydra

echo "📦 Installation d'Hydra pour brute-force..."
sudo apt install -y hydra

# Installation Nuclei

echo "🔍 Vérification de la présence de Nuclei..."

if ! command -v nuclei &> /dev/null
then
    echo "💡 Nuclei non trouvé, installation en cours..."
    
    sudo apt install -y unzip wget
    
    # Téléchargement du binaire
    wget https://github.com/projectdiscovery/nuclei/releases/download/v3.4.2/nuclei_3.4.2_linux_amd64.zip -O nuclei.zip
    
    # Décompression
    unzip nuclei.zip
    
    # Déplacement vers /usr/local/bin
    sudo mv nuclei /usr/local/bin/
    sudo chmod +x /usr/local/bin/nuclei
    
    # Nettoyage
    rm nuclei.zip
    rm LICENSE.md README_CN.md README_ID.md README_KR.md README.md README_JP.md README_ES.md README_PT-BR.md
    
    echo "✅ Nuclei installé avec succès."
else
    echo "✅ Nuclei est déjà installé."
fi


# Installer les dépendances Python
echo "📜 Installation des paquets Python..."
pip install -r requirements.txt

echo "🚀 Installation terminée ! Pour lancer l'API :"
echo "1. Active l'environnement : source venv/bin/activate"
echo "2. Lance : python3 app.py"
