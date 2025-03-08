from flask import Flask, request, jsonify
from flask_cors import CORS
import sys
import os
import ssl

# Ana dizini Python path'ine ekle
current_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.dirname(current_dir)
sys.path.append(parent_dir)

import rsz_solve
import rsz_rdiff_scan
import LLL_nonce_leakage
import getz_input

app = Flask(__name__)

# CORS ayarları
FRONTEND_ORIGIN = os.getenv('FRONTEND_ORIGIN', 'https://rsz-frontend.vercel.app')
NGROK_URL = "https://517a-38-41-53-133.ngrok-free.app"  # Yeni ngrok URL'i

CORS(app, resources={
    r"/api/*": {
        "origins": [FRONTEND_ORIGIN, NGROK_URL],
        "methods": ["GET", "POST", "OPTIONS"],
        "allow_headers": ["Content-Type"]
    }
})

@app.route('/api/solve-rsz', methods=['POST'])
def solve_rsz():
    try:
        result = rsz_solve.generate_and_solve()
        return jsonify(result)
    except Exception as e:
        return jsonify({'error': str(e)}), 400

@app.route('/api/scan-address', methods=['POST'])
def scan_address():
    try:
        data = request.json
        address = data.get('address')
        if not address:
            return jsonify({'error': 'Address is required'}), 400
            
        result = rsz_rdiff_scan.scan_address(address)
        return jsonify(result)
    except Exception as e:
        return jsonify({'error': str(e)}), 400

@app.route('/api/nonce-leakage', methods=['POST'])
def analyze_nonce_leakage():
    try:
        data = request.json
        fix_bits = data.get('fix_bits', 56)
        result = LLL_nonce_leakage.analyze(fix_bits)
        return jsonify(result)
    except Exception as e:
        return jsonify({'error': str(e)}), 400

@app.route('/api/get-tx-info', methods=['POST'])
def get_tx_info():
    try:
        data = request.json
        txid = data.get('txid')
        rawtx = data.get('rawtx')
        
        if txid:
            result = getz_input.process_txid(txid)
        elif rawtx:
            result = getz_input.process_rawtx(rawtx)
        else:
            return jsonify({'error': 'Either txid or rawtx is required'}), 400
            
        return jsonify(result)
    except Exception as e:
        return jsonify({'error': str(e)}), 400

if __name__ == '__main__':
    context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
    context.load_cert_chain('domain.crt', 'domain.key')
    app.run(host='0.0.0.0', port=5000, ssl_context=context, debug=True) 