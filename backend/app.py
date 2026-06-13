"""
MythosShield — Backend with Firebase Integration
"""

import os, json, subprocess, tempfile, datetime, requests, zipfile, shutil
from flask import Flask, request, jsonify
from flask_cors import CORS
import firebase_admin
from firebase_admin import credentials, firestore, auth
import bcrypt

app = Flask(__name__)
CORS(app)

# ─── Firebase Initialization ────────────────────────────────────────────────
# Check if running on Render (production) or local
if os.environ.get('RENDER'):
    # On Render: use environment variable for credentials
    cred_json = os.environ.get('FIREBASE_CREDENTIALS')
    if cred_json:
        cred_dict = json.loads(cred_json)
        cred = credentials.Certificate(cred_dict)
    else:
        cred = credentials.ApplicationDefault()
else:
    # Local development
    cred = credentials.Certificate('serviceAccountKey.json')

firebase_admin.initialize_app(cred)
db = firestore.client()

# ─── Helper Functions ────────────────────────────────────────────────────────

def get_user_from_token():
    """Extract and verify Firebase ID token from Authorization header"""
    auth_header = request.headers.get('Authorization')
    if not auth_header or not auth_header.startswith('Bearer '):
        return None, jsonify({'error': 'Missing or invalid auth token'}), 401
    
    id_token = auth_header.split(' ')[1]
    try:
        decoded_token = auth.verify_id_token(id_token)
        return decoded_token, None, None
    except Exception as e:
        return None, jsonify({'error': f'Invalid token: {str(e)}'}), 401

# ─── Auth Endpoints (Firebase) ──────────────────────────────────────────────

@app.post("/auth/register")
def register():
    """Register a new bank using Firebase Authentication"""
    data = request.json or {}
    email = data.get('email')
    password = data.get('password')
    bank_name = data.get('bank_name')
    gst_number = data.get('gst_number', '')
    
    if not email or not password or not bank_name:
        return jsonify({'error': 'Email, password, and bank name required'}), 400
    
    try:
        # Create user in Firebase Auth
        user = auth.create_user(
            email=email,
            password=password,
            display_name=bank_name
        )
        
        # Store additional bank info in Firestore
        bank_data = {
            'bank_name': bank_name,
            'email': email,
            'gst_number': gst_number,
            'created_at': datetime.datetime.now().isoformat(),
            'user_id': user.uid
        }
        db.collection('banks').document(user.uid).set(bank_data)
        
        return jsonify({'message': 'Registered successfully', 'user_id': user.uid}), 201
        
    except auth.EmailAlreadyExistsError:
        return jsonify({'error': 'Email already registered'}), 409
    except Exception as e:
        return jsonify({'error': str(e)}), 400

@app.post("/auth/login")
def login():
    """Login endpoint - returns Firebase ID token (client handles actual auth)"""
    # Client-side Firebase Auth handles the actual login
    # This endpoint just validates the token from client
    user, error_response, status = get_user_from_token()
    if error_response:
        return error_response, status
    
    # Get bank data from Firestore
    bank_doc = db.collection('banks').document(user['uid']).get()
    bank_data = bank_doc.to_dict() if bank_doc.exists else {}
    
    return jsonify({
        'access_token': request.headers.get('Authorization').split(' ')[1],
        'bank_name': bank_data.get('bank_name', ''),
        'user_id': user['uid']
    }), 200

# ─── SBOM Generation ─────────────────────────────────────────────────────────

AI_EXTENSIONS = {".pt", ".h5", ".onnx", ".pkl", ".joblib", ".pb", ".tflite", ".bin", ".safetensors"}

def generate_sbom_from_path(path):
    """Generate SBOM from local path"""
    components = []
    for root, dirs, files in os.walk(path):
        for fname in files:
            fpath = os.path.join(root, fname)
            if fname == "package.json":
                try:
                    with open(fpath, 'r', encoding='utf-8') as f:
                        pkg = json.load(f)
                    for dep, ver in {**pkg.get("dependencies", {}), **pkg.get("devDependencies", {})}.items():
                        components.append({
                            "name": dep,
                            "version": ver.lstrip("^~"),
                            "type": "npm-package",
                            "source": fname
                        })
                except Exception:
                    pass
            elif fname == "requirements.txt":
                try:
                    with open(fpath, 'r', encoding='utf-8') as f:
                        for line in f:
                            line = line.strip()
                            if line and not line.startswith("#"):
                                parts = line.replace("==", "@").replace(">=", "@").split("@")
                                components.append({
                                    "name": parts[0].strip(),
                                    "version": parts[1].strip() if len(parts) > 1 else "unknown",
                                    "type": "python-package",
                                    "source": fname
                                })
                except Exception:
                    pass
    return {"schema": "mythosshield-1.0", "artifacts": components}

def generate_aibom(path):
    """Scan for AI model files"""
    models = []
    for root, dirs, files in os.walk(path):
        for fname in files:
            ext = os.path.splitext(fname)[1].lower()
            if ext in AI_EXTENSIONS:
                fpath = os.path.join(root, fname)
                size = os.path.getsize(fpath)
                models.append({
                    "name": fname,
                    "path": os.path.relpath(fpath, path),
                    "format": ext.lstrip("."),
                    "size_bytes": size
                })
    return {"schema": "mythosshield-aibom-1.0", "model_count": len(models), "models": models}

# ─── Scan Endpoints ──────────────────────────────────────────────────────────

@app.post("/scan/upload")
def scan_upload():
    """Upload and scan a ZIP file"""
    user, error_response, status = get_user_from_token()
    if error_response:
        return error_response, status
    
    if 'file' not in request.files:
        return jsonify({'error': 'No file uploaded'}), 400
    
    file = request.files['file']
    if not file.filename.endswith('.zip'):
        return jsonify({'error': 'Only ZIP files are accepted'}), 400
    
    temp_dir = tempfile.mkdtemp()
    zip_path = os.path.join(temp_dir, 'upload.zip')
    extract_path = os.path.join(temp_dir, 'extracted')
    
    try:
        file.save(zip_path)
        os.makedirs(extract_path, exist_ok=True)
        
        with zipfile.ZipFile(zip_path, 'r') as zip_ref:
            zip_ref.extractall(extract_path)
        
        sbom = generate_sbom_from_path(extract_path)
        aibom = generate_aibom(extract_path)
        
        # Save to Firestore
        scan_data = {
            'user_id': user['uid'],
            'source': file.filename,
            'sbom': sbom,
            'aibom': aibom,
            'vulnerabilities': [],
            'compliance_score': 0,
            'created_at': datetime.datetime.now().isoformat()
        }
        doc_ref = db.collection('scans').add(scan_data)
        scan_id = doc_ref[1].id
        
        # Trigger vulnerability scan
        # This would run async in production
        
        return jsonify({'scan_id': scan_id, 'sbom': sbom, 'aibom': aibom}), 200
        
    except zipfile.BadZipFile:
        return jsonify({'error': 'Invalid ZIP file'}), 400
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)

@app.get("/scans")
def list_scans():
    """Get all scans for authenticated user"""
    user, error_response, status = get_user_from_token()
    if error_response:
        return error_response, status
    
    scans_ref = db.collection('scans').where('user_id', '==', user['uid']).order_by('created_at', direction=firestore.Query.DESCENDING).limit(20)
    scans = []
    for doc in scans_ref.stream():
        data = doc.to_dict()
        data['id'] = doc.id
        scans.append(data)
    
    return jsonify({'scans': scans}), 200

@app.get("/scan/<scan_id>")
def get_scan(scan_id):
    """Get a specific scan by ID"""
    user, error_response, status = get_user_from_token()
    if error_response:
        return error_response, status
    
    doc_ref = db.collection('scans').document(scan_id).get()
    if not doc_ref.exists:
        return jsonify({'error': 'Scan not found'}), 404
    
    data = doc_ref.to_dict()
    if data.get('user_id') != user['uid']:
        return jsonify({'error': 'Unauthorized'}), 403
    
    data['id'] = doc_ref.id
    return jsonify(data), 200

@app.get("/health")
def health():
    return jsonify({'status': 'ok', 'product': 'MythosShield', 'version': '2.0.0'}), 200

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    print(f"MythosShield with Firebase running on port {port}")
    app.run(host="0.0.0.0", port=port, debug=False)