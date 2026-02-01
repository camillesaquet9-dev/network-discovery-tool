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


def convertir_hote(hote):
    """Convertit les cles francaises en anglais pour le frontend"""
    return {
        'ip': hote.get('ip'),
        'hostname': hote.get('nom_hote'),
        'mac': hote.get('mac'),
        'mac_vendor': hote.get('fabricant_mac'),
        'os': hote.get('os'),
        'os_accuracy': hote.get('precision_os'),
        'functional_type': hote.get('type_fonctionnel', 'UNKNOWN'),
        'ports': [
            {
                'port': p.get('port'),
                'protocol': p.get('protocole'),
                'state': p.get('etat'),
                'service': p.get('service'),
                'product': p.get('produit'),
                'version': p.get('version'),
                'info': p.get('info')
            }
            for p in hote.get('ports', [])
        ],
        'services': hote.get('services', []),
        'scripts_output': hote.get('sortie_scripts', {})
    }


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/upload', methods=['POST'])
def telecharger_fichier():
    if 'file' not in request.files:
        return jsonify({'error': 'Aucun fichier fourni'}), 400

    fichier = request.files['file']

    if fichier.filename == '':
        return jsonify({'error': 'Aucun fichier selectionne'}), 400

    if not fichier.filename.endswith('.json'):
        return jsonify({'error': 'Seuls les fichiers JSON sont acceptes'}), 400

    try:
        contenu = fichier.read().decode('utf-8')
        donnees = json.loads(contenu)

        global donnees_chargees
        donnees_chargees = donnees

        resume = {
            'success': True,
            'filename': secure_filename(fichier.filename),
            'networks_count': len(donnees.get('reseaux_decouverts', [])),
            'hosts_count': len(donnees.get('hotes_decouverts', [])),
            'blocked_count': len(donnees.get('reseaux_bloques', [])),
            'pivots_count': len(donnees.get('pivots_suggeres', []))
        }

        return jsonify(resume)

    except json.JSONDecodeError as e:
        return jsonify({'error': f'JSON invalide: {str(e)}'}), 400
    except Exception as e:
        return jsonify({'error': f'Erreur: {str(e)}'}), 500


@app.route('/api/data')
def obtenir_donnees():
    if not donnees_chargees:
        return jsonify({'error': 'Aucune donnee chargee'}), 404

    hotes_convertis = [convertir_hote(h) for h in donnees_chargees.get('hotes_decouverts', [])]

    return jsonify({
        'discovered_networks': donnees_chargees.get('reseaux_decouverts', []),
        'discovered_hosts': hotes_convertis,
        'blocked_networks': donnees_chargees.get('reseaux_bloques', []),
        'suggested_pivots': donnees_chargees.get('pivots_suggeres', [])
    })


@app.route('/api/hosts')
def obtenir_hotes():
    if not donnees_chargees:
        return jsonify({'error': 'Aucune donnee chargee'}), 404

    hotes_convertis = [convertir_hote(h) for h in donnees_chargees.get('hotes_decouverts', [])]
    return jsonify(hotes_convertis)


@app.route('/api/networks')
def obtenir_reseaux():
    if not donnees_chargees:
        return jsonify({'error': 'Aucune donnee chargee'}), 404
    return jsonify(donnees_chargees.get('reseaux_decouverts', []))


@app.route('/api/host/<ip>')
def obtenir_details_hote(ip):
    if not donnees_chargees:
        return jsonify({'error': 'Aucune donnee chargee'}), 404

    hotes = donnees_chargees.get('hotes_decouverts', [])
    hote = next((h for h in hotes if h.get('ip') == ip), None)

    if not hote:
        return jsonify({'error': 'Hote non trouve'}), 404

    return jsonify(convertir_hote(hote))


@app.route('/api/stats')
def obtenir_statistiques():
    if not donnees_chargees:
        return jsonify({'error': 'Aucune donnee chargee'}), 404

    hotes = donnees_chargees.get('hotes_decouverts', [])

    compteurs_types = {}
    for hote in hotes:
        ftype = hote.get('type_fonctionnel', 'UNKNOWN')
        compteurs_types[ftype] = compteurs_types.get(ftype, 0) + 1

    total_ports = sum(len(h.get('ports', [])) for h in hotes)
    ports_ouverts = sum(
        len([p for p in h.get('ports', []) if p.get('etat') in ['open', 'open|filtered']])
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
        'total_hosts': len(hotes),
        'total_networks': len(donnees_chargees.get('reseaux_decouverts', [])),
        'type_distribution': compteurs_types,
        'total_ports_scanned': total_ports,
        'open_ports': ports_ouverts,
        'unique_services': list(services),
        'unique_vendors': list(fabricants),
        'blocked_networks': len(donnees_chargees.get('reseaux_bloques', [])),
        'suggested_pivots': len(donnees_chargees.get('pivots_suggeres', []))
    }

    return jsonify(statistiques)


if __name__ == '__main__':
    print("\n" + "="*60)
    print("  Network Discovery Viewer")
    print("  http://localhost:5001")
    print("="*60 + "\n")
    app.run(debug=True, host='0.0.0.0', port=5001)
