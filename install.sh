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
sudo apt update
sudo apt install -y tcpdump libpcap-dev
sudo apt-get install tshark

# Installation Hydra

echo "📦 Installation d'Hydra pour brute-force..."
sudo apt update
sudo apt install -y hydra


# Installer les dépendances Python
echo "📜 Installation des paquets Python..."
pip install -r requirements.txt

echo "🚀 Installation terminée ! Pour lancer l'API :"
echo "1. Active l'environnement : source venv/bin/activate"
echo "2. Lance : python3 app.py"
