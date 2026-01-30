#!/usr/bin/env python3

import os
import json
from flask import Flask, render_template, request, jsonify
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024
app.config['UPLOAD_FOLDER'] = os.path.join(os.path.dirname(__file__), 'uploads')

os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

donnees_chargees = {}


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/upload', methods=['POST'])
def telecharger_fichier():
    if 'file' not in request.files:
        return jsonify({'erreur': 'Aucun fichier fourni'}), 400

    fichier = request.files['file']

    if fichier.filename == '':
        return jsonify({'erreur': 'Aucun fichier selectionne'}), 400

    if not fichier.filename.endswith('.json'):
        return jsonify({'erreur': 'Seuls les fichiers JSON sont acceptes'}), 400

    try:
        contenu = fichier.read().decode('utf-8')
        donnees = json.loads(contenu)

        global donnees_chargees
        donnees_chargees = donnees

        resume = {
            'succes': True,
            'nom_fichier': secure_filename(fichier.filename),
            'nb_reseaux': len(donnees.get('reseaux_decouverts', [])),
            'nb_hotes': len(donnees.get('hotes_decouverts', [])),
            'nb_bloques': len(donnees.get('reseaux_bloques', [])),
            'nb_pivots': len(donnees.get('pivots_suggeres', []))
        }

        return jsonify(resume)

    except json.JSONDecodeError as e:
        return jsonify({'erreur': f'JSON invalide: {str(e)}'}), 400
    except Exception as e:
        return jsonify({'erreur': f'Erreur: {str(e)}'}), 500


@app.route('/api/donnees')
def obtenir_donnees():
    if not donnees_chargees:
        return jsonify({'erreur': 'Aucune donnee chargee'}), 404
    return jsonify(donnees_chargees)


@app.route('/api/hotes')
def obtenir_hotes():
    if not donnees_chargees:
        return jsonify({'erreur': 'Aucune donnee chargee'}), 404
    return jsonify(donnees_chargees.get('hotes_decouverts', []))


@app.route('/api/reseaux')
def obtenir_reseaux():
    if not donnees_chargees:
        return jsonify({'erreur': 'Aucune donnee chargee'}), 404
    return jsonify(donnees_chargees.get('reseaux_decouverts', []))


@app.route('/api/hote/<ip>')
def obtenir_details_hote(ip):
    if not donnees_chargees:
        return jsonify({'erreur': 'Aucune donnee chargee'}), 404

    hotes = donnees_chargees.get('hotes_decouverts', [])
    hote = next((h for h in hotes if h.get('ip') == ip), None)

    if not hote:
        return jsonify({'erreur': 'Hote non trouve'}), 404

    return jsonify(hote)


@app.route('/api/statistiques')
def obtenir_statistiques():
    if not donnees_chargees:
        return jsonify({'erreur': 'Aucune donnee chargee'}), 404

    hotes = donnees_chargees.get('hotes_decouverts', [])

    compteurs_types = {}
    for hote in hotes:
        ftype = hote.get('type_fonctionnel', 'UNKNOWN')
        compteurs_types[ftype] = compteurs_types.get(ftype, 0) + 1

    total_ports = sum(len(h.get('ports', [])) for h in hotes)
    ports_ouverts = sum(
        len([p for p in h.get('ports', []) if p.get('etat') == 'open'])
        for h in hotes
    )

    services = set()
    for hote in hotes:
        for port in hote.get('ports', []):
            if port.get('service'):
                services.add(port['service'])

    fabricants = set()
    for hote in hotes:
        if hote.get('fabricant_mac'):
            fabricants.add(hote['fabricant_mac'])

    statistiques = {
        'total_hotes': len(hotes),
        'total_reseaux': len(donnees_chargees.get('reseaux_decouverts', [])),
        'distribution_types': compteurs_types,
        'total_ports_scannes': total_ports,
        'ports_ouverts': ports_ouverts,
        'services_uniques': list(services),
        'fabricants_uniques': list(fabricants),
        'reseaux_bloques': len(donnees_chargees.get('reseaux_bloques', [])),
        'pivots_suggeres': len(donnees_chargees.get('pivots_suggeres', []))
    }

    return jsonify(statistiques)


if __name__ == '__main__':
    print("\n" + "="*60)
    print("  Network Discovery Viewer")
    print("  http://localhost:5001")
    print("="*60 + "\n")
    app.run(debug=True, host='0.0.0.0', port=5001)
