#!/bin/bash
# Lanceur de la webapp Network Discovery Viewer

echo ""
echo "============================================"
echo "   Network Discovery Viewer"
echo "============================================"
echo ""

# Vérifie si Flask est installé
if ! python3 -c "import flask" 2>/dev/null; then
    echo "Flask n'est pas installé. Installation..."
    pip3 install flask werkzeug
fi

# Lance la webapp
echo "Démarrage du serveur..."
echo "Ouvrez http://localhost:5000 dans votre navigateur"
echo ""

cd "$(dirname "$0")/webapp"
python3 app.py
