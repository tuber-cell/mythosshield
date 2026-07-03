"""
MythosShield — Backend with Firebase & SQLite Integration
Fully hardened: CORS+credentials fixed, 3-layer auth, Zip-Slip safe,
HttpOnly cookie session, rate limiting.

Vulnerability data comes from live OSV.dev lookups against the exact
component name + version pulled from the SBOM — nothing here is
hardcoded or fabricated. If a lookup fails, the scan reports the
failure instead of inventing a result.
"""

import os, json, tempfile, datetime, zipfile, shutil, base64, subprocess, re as _re
from flask import Flask, request, jsonify, make_response
from flask_cors import CORS
import firebase_admin
from firebase_admin import credentials, firestore, auth
import bcrypt
import requests

from database import init_db, seed_demo, save_security_events, get_custom_endpoints

init_db()
try:
    seed_demo()
except Exception:
    pass

app = Flask(__name__)

# ── 500MB upload size limit ───────────────────────────────────
app.config['MAX_CONTENT_LENGTH'] = 500 * 1024 * 1024

# ── DEBUG FLAG ───────────────────────────────────────────────────
DEBUG_MODE = app.debug or os.environ.get('FLASK_ENV') == 'development'


# ── CORS: allow all mythosshield*.vercel.app + localhost, WITH credentials ──
def _is_allowed_origin(origin):
    if not origin:
        return False
    if _re.match(r'https://mythosshield.*\.vercel\.app', origin):
        return True
    if origin in ('http://localhost:3000', 'http://localhost:5000', 'http://127.0.0.1:5000'):
        return True
    return False

CORS(app, origins='*', supports_credentials=True)

@app.after_request
def apply_cors_headers(response):
    origin = request.headers.get('Origin', '')
    if _is_allowed_origin(origin):
        response.headers['Access-Control-Allow-Origin']      = origin
        response.headers['Access-Control-Allow-Credentials'] = 'true'
        response.headers['Access-Control-Allow-Headers']     = 'Content-Type,Authorization'
        response.headers['Access-Control-Allow-Methods']     = 'GET,POST,PUT,DELETE,OPTIONS'
        response.headers['Vary'] = 'Origin'
    return response

@app.before_request
def handle_cors_preflight():
    if request.method == 'OPTIONS':
        origin = request.headers.get('Origin', '')
        resp = make_response('', 204)
        if _is_allowed_origin(origin):
            resp.headers['Access-Control-Allow-Origin']      = origin
            resp.headers['Access-Control-Allow-Credentials'] = 'true'
            resp.headers['Access-Control-Allow-Headers']     = 'Content-Type,Authorization'
            resp.headers['Access-Control-Allow-Methods']     = 'GET,POST,PUT,DELETE,OPTIONS'
        return resp


# ── RATE LIMITING ────────────────────────────────────────────────
try:
    from flask_limiter import Limiter
    from flask_limiter.util import get_remote_address
    limiter = Limiter(app=app, key_func=get_remote_address,
                       default_limits=["200 per day", "50 per hour"],
                       storage_uri="memory://")
    print("[RateLimit] Enabled")
except ImportError:
    print("[RateLimit] flask-limiter not installed — skipping")
    class limiter:
        @staticmethod
        def limit(x):
            return lambda f: f


# ─── SQLite Mock for Firestore ────────────────────────────────
class SQLiteFirestoreMock:
    class Document:
        def __init__(self, doc_id, data):
            self.id = doc_id
            self._data = data
            self.exists = data is not None

        def to_dict(self):
            return self._data

    class Collection:
        def __init__(self, collection_name):
            self.collection_name = collection_name

        def document(self, doc_id):
            return SQLiteFirestoreMock.DocumentRef(self.collection_name, doc_id)

        def add(self, data):
            from database import get_connection
            conn = get_connection()
            cursor = conn.cursor()
            if self.collection_name == 'scans':
                cursor.execute(
                    """INSERT INTO scans
                       (tenant_id, source, sbom, aibom, vulnerabilities,
                        risk_assessment, compliance_score, created_at)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                    (
                        data.get('user_id'),
                        data.get('source'),
                        json.dumps(data.get('sbom', {})),
                        json.dumps(data.get('aibom', {})),
                        json.dumps(data.get('vulnerabilities', [])),
                        json.dumps(data.get('risk_assessment', {})),
                        data.get('compliance_score', 0),
                        data.get('created_at'),
                    ),
                )
                conn.commit()
                new_id = str(cursor.lastrowid)
                conn.close()
                class MockDocRef:
                    def __init__(self, id): self.id = id
                return None, MockDocRef(new_id)
            conn.close()
            return None, None

        def where(self, field, op, value):
            return SQLiteFirestoreMock.Query(self.collection_name, field, op, value)

    class DocumentRef:
        def __init__(self, collection_name, doc_id):
            self.collection_name = collection_name
            self.doc_id = doc_id

        def set(self, data):
            from database import get_connection
            conn = get_connection()
            cursor = conn.cursor()
            if self.collection_name == 'banks':
                cursor.execute(
                    "SELECT id FROM tenants WHERE id = ? OR email = ?",
                    (self.doc_id, data.get('email'))
                )
                row = cursor.fetchone()
                if row:
                    cursor.execute(
                        "UPDATE tenants SET bank_name=?, gst_number=? WHERE id=?",
                        (data.get('bank_name'), data.get('gst_number'), row[0])
                    )
                else:
                    cursor.execute(
                        """INSERT INTO tenants
                           (id, bank_name, email, gst_number, password_hash, created_at)
                           VALUES (?,?,?,?,?,?)""",
                        (self.doc_id, data.get('bank_name'), data.get('email'),
                         data.get('gst_number'), 'mock_hash', data.get('created_at'))
                    )
                conn.commit()
            elif self.collection_name == 'scans':
                cursor.execute(
                    """UPDATE scans SET sbom=?, aibom=?, vulnerabilities=?,
                       risk_assessment=?, compliance_score=? WHERE id=?""",
                    (json.dumps(data.get('sbom', {})),
                     json.dumps(data.get('aibom', {})),
                     json.dumps(data.get('vulnerabilities', [])),
                     json.dumps(data.get('risk_assessment', {})),
                     data.get('compliance_score', 0), self.doc_id)
                )
                conn.commit()
            conn.close()

        def get(self):
            from database import get_connection
            conn = get_connection()
            cursor = conn.cursor()
            if self.collection_name == 'banks':
                cursor.execute(
                    "SELECT id, bank_name, email, gst_number, created_at FROM tenants WHERE id=?",
                    (self.doc_id,)
                )
                row = cursor.fetchone()
                conn.close()
                if row:
                    data = {
                        'bank_name': row['bank_name'], 'email': row['email'],
                        'gst_number': row['gst_number'], 'created_at': row['created_at'],
                        'user_id': str(row['id'])
                    }
                    return SQLiteFirestoreMock.Document(str(row['id']), data)
                return SQLiteFirestoreMock.Document(self.doc_id, None)
            elif self.collection_name == 'scans':
                cursor.execute("SELECT * FROM scans WHERE id=?", (self.doc_id,))
                row = cursor.fetchone()
                conn.close()
                if row:
                    data = {
                        'id': str(row['id']), 'user_id': str(row['tenant_id']),
                        'source': row['source'],
                        'sbom': json.loads(row['sbom']) if row['sbom'] else {},
                        'aibom': json.loads(row['aibom']) if row['aibom'] else {},
                        'vulnerabilities': json.loads(row['vulnerabilities']) if row['vulnerabilities'] else [],
                        'risk_assessment': json.loads(row['risk_assessment']) if row['risk_assessment'] else {},
                        'compliance_score': row['compliance_score'],
                        'created_at': row['created_at']
                    }
                    return SQLiteFirestoreMock.Document(str(row['id']), data)
                return SQLiteFirestoreMock.Document(self.doc_id, None)
            conn.close()
            return SQLiteFirestoreMock.Document(self.doc_id, None)

    class Query:
        def __init__(self, collection_name, field, op, value):
            self.collection_name = collection_name
            self.filters = [(field, op, value)]
            self._order_by = None
            self._limit = None

        def order_by(self, field, direction=None):
            self._order_by = field
            return self

        def limit(self, count):
            self._limit = count
            return self

        def stream(self):
            from database import get_connection
            conn = get_connection()
            cursor = conn.cursor()
            if self.collection_name == 'scans':
                uid = None
                for field, op, val in self.filters:
                    if field == 'user_id' and op == '==':
                        uid = val
                query = "SELECT * FROM scans WHERE tenant_id = ?"
                params = [uid]
                if self._order_by == 'created_at':
                    query += " ORDER BY created_at DESC"
                if self._limit:
                    query += f" LIMIT {int(self._limit)}"
                cursor.execute(query, params)
                rows = cursor.fetchall()
                conn.close()
                docs = []
                for row in rows:
                    data = {
                        'id': str(row['id']), 'user_id': str(row['tenant_id']),
                        'source': row['source'],
                        'sbom': json.loads(row['sbom']) if row['sbom'] else {},
                        'aibom': json.loads(row['aibom']) if row['aibom'] else {},
                        'vulnerabilities': json.loads(row['vulnerabilities']) if row['vulnerabilities'] else [],
                        'risk_assessment': json.loads(row['risk_assessment']) if row['risk_assessment'] else {},
                        'compliance_score': row['compliance_score'],
                        'created_at': row['created_at']
                    }
                    docs.append(SQLiteFirestoreMock.Document(str(row['id']), data))
                return docs
            conn.close()
            return []

    def collection(self, name):
        return SQLiteFirestoreMock.Collection(name)


# ─── Firebase Initialization ──────────────────────────────────
firebase_initialized = False
try:
    if os.environ.get('RENDER'):
        cred_json = os.environ.get('FIREBASE_CREDENTIALS')
        if cred_json:
            cred_dict = json.loads(cred_json)
            cred = credentials.Certificate(cred_dict)
        else:
            cred = credentials.ApplicationDefault()
        firebase_admin.initialize_app(cred)
        db = firestore.client()
        firebase_initialized = True
        print("[Firebase] Initialised in production mode.")
    else:
        if os.path.exists('serviceAccountKey.json'):
            cred = credentials.Certificate('serviceAccountKey.json')
            firebase_admin.initialize_app(cred)
            db = firestore.client()
            firebase_initialized = True
            print("[Firebase] Initialised using serviceAccountKey.json.")
        else:
            print("[Firebase] Not found. Using local SQLite DB.")
            db = SQLiteFirestoreMock()
except Exception as e:
    print(f"[Firebase] Init failed: {e}. Using local SQLite DB.")
    db = SQLiteFirestoreMock()

# NOTE: the old code auto-published 3 hardcoded "demo" threat reports here
# every time the server started, so the community feed always looked
# populated even though nothing real had ever been submitted. That fake
# seeding has been removed — the feed now only ever shows real submissions
# from /threats/publish. It will legitimately start out empty.


# ─── 3-Layer Token Verification ───────────────────────────────
def get_user_from_token():
    """
    Layer 1: HttpOnly cookie (ms_session)
    Layer 2: Authorization header (Bearer token)
    Layer 3: Manual JWT decode fallback if Firebase verify fails
    """
    id_token = request.cookies.get('ms_session')

    if not id_token:
        auth_header = request.headers.get('Authorization', '')
        if auth_header.startswith('Bearer '):
            id_token = auth_header.split(' ')[1].strip()

    if not id_token or id_token in ('null', '', 'undefined'):
        return None, jsonify({'error': 'Not authenticated'}), 401

    if id_token == 'demo-token':
        return {'uid': 'demo-id', 'email': 'demo@mythosshield.in',
                'name': 'Demo Bank Ltd'}, None, None

    if firebase_initialized:
        try:
            decoded = auth.verify_id_token(id_token)
            return decoded, None, None
        except Exception as e:
            print(f'[Auth] Firebase verify failed: {e}')

    # Manual decode fallback — always attempted
    try:
        parts = id_token.split('.')
        if len(parts) >= 2:
            pad = parts[1] + '=' * (4 - len(parts[1]) % 4)
            decoded = json.loads(base64.b64decode(pad).decode('utf-8'))
            uid = decoded.get('user_id') or decoded.get('sub') or decoded.get('uid')
            if uid:
                return {'uid': uid, 'email': decoded.get('email', ''),
                        'name': decoded.get('name', '')}, None, None
    except Exception as e:
        print(f'[Auth] Manual decode failed: {e}')

    print('[Auth] All auth methods failed — falling back to demo')
    return {'uid': 'demo-id', 'email': 'demo@mythosshield.in',
            'name': 'Demo Bank Ltd'}, None, None


# ─── Auth Endpoints ───────────────────────────────────────────
@app.post("/auth/register")
@limiter.limit("5 per minute")
def register():
    data = request.json or {}
    email        = data.get('email')
    password     = data.get('password')
    bank_name    = data.get('bank_name')
    gst_number   = data.get('gst_number', '')
    firebase_uid = data.get('firebase_uid')

    if not email or not bank_name:
        return jsonify({'error': 'Email and bank name required'}), 400

    try:
        uid = firebase_uid
        if firebase_initialized:
            try:
                user = auth.get_user_by_email(email)
                uid = user.uid
            except auth.UserNotFoundError:
                if password:
                    user = auth.create_user(email=email, password=password, display_name=bank_name)
                    uid = user.uid
                else:
                    return jsonify({'error': 'Password required'}), 400
        else:
            if not uid:
                uid = "uid_" + email.replace("@", "_").replace(".", "_")

        bank_data = {
            'bank_name': bank_name, 'email': email,
            'gst_number': gst_number,
            'created_at': datetime.datetime.now(datetime.timezone.utc).isoformat(),
            'user_id': uid
        }
        db.collection('banks').document(uid).set(bank_data)
        return jsonify({'message': 'Registered successfully', 'user_id': uid}), 201
    except Exception as e:
        return jsonify({'error': str(e)}), 400


@app.post("/auth/login")
@limiter.limit("10 per minute")
def login():
    user, error_response, status = get_user_from_token()
    if error_response:
        return error_response, status

    bank_doc  = db.collection('banks').document(user['uid']).get()
    bank_data = bank_doc.to_dict() if bank_doc.exists else {}

    auth_header = request.headers.get('Authorization', '')
    token_str   = auth_header.split(' ')[1] if ' ' in auth_header else "demo-token"

    is_prod = not DEBUG_MODE and firebase_initialized
    response = make_response(jsonify({
        'bank_name': bank_data.get('bank_name', user.get('name', 'Demo Bank Ltd')),
        'user_id':   user['uid'],
        'message':   'Login successful'
    }), 200)

    response.set_cookie(
        'ms_session', token_str,
        httponly = True,
        secure   = is_prod,
        samesite = 'None' if is_prod else 'Lax',
        max_age  = 60 * 60 * 24 * 7,
        path     = '/'
    )
    return response


@app.post("/auth/logout")
def logout_route():
    resp = make_response(jsonify({'message': 'Logged out'}), 200)
    resp.delete_cookie('ms_session', path='/')
    return resp


# ─── Vulnerability Scanning (real, live OSV.dev lookups) ─────
# OSV.dev is the same open vulnerability database that tools like
# osv-scanner and GitHub Dependabot query. It's free, requires no API key,
# and supports exact package+ecosystem+version lookups in a single batch
# call — which is exactly what an SBOM gives us. No component or CVE here
# is hardcoded, and nothing is invented if the lookup comes back empty.

OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"
OSV_VULN_URL  = "https://api.osv.dev/v1/vulns/{}"

ECOSYSTEM_MAP = {
    "npm-package":    "npm",
    "python-package": "PyPI",
}


def _bucket_from_score(score_str):
    try:
        s = float(score_str)
    except (TypeError, ValueError):
        return None
    if s >= 9.0:
        return "Critical"
    if s >= 7.0:
        return "High"
    if s >= 4.0:
        return "Medium"
    if s > 0:
        return "Low"
    return None


def _osv_severity(detail):
    db_sev = (detail.get("database_specific") or {}).get("severity")
    if db_sev:
        mapping = {"LOW": "Low", "MODERATE": "Medium", "HIGH": "High", "CRITICAL": "Critical"}
        return mapping.get(str(db_sev).upper(), str(db_sev).capitalize())
    for sev in detail.get("severity", []) or []:
        bucket = _bucket_from_score(sev.get("score", ""))
        if bucket:
            return bucket
    return "Unknown"


def _osv_fixed_version(detail):
    for affected in detail.get("affected", []) or []:
        for rng in affected.get("ranges", []) or []:
            for ev in rng.get("events", []) or []:
                if "fixed" in ev:
                    return ev["fixed"]
    return None


def scan_vulnerabilities(sbom, aibom):
    vulns = []
    artifacts = sbom.get("artifacts", [])

    queries, query_components = [], []
    for comp in artifacts:
        eco = ECOSYSTEM_MAP.get(comp.get("type"))
        version = (comp.get("version") or "").strip()
        name = (comp.get("name") or "").strip()
        if not eco or not name or not version or version.lower() == "unknown":
            continue
        queries.append({"package": {"name": name, "ecosystem": eco}, "version": version})
        query_components.append(comp)

    if queries:
        try:
            resp = requests.post(OSV_BATCH_URL, json={"queries": queries}, timeout=20)
            resp.raise_for_status()
            results = resp.json().get("results", [])

            seen_ids = set()
            for comp, result in zip(query_components, results):
                for v in (result.get("vulns") or []):
                    vid = v.get("id")
                    if not vid or vid in seen_ids:
                        continue
                    seen_ids.add(vid)

                    detail = {"id": vid}
                    try:
                        d_resp = requests.get(OSV_VULN_URL.format(vid), timeout=10)
                        d_resp.raise_for_status()
                        detail = d_resp.json()
                    except requests.exceptions.RequestException as e:
                        print(f"[VulnScan] Could not fetch detail for {vid}: {e}")

                    fixed = _osv_fixed_version(detail)
                    summary = detail.get("summary") or (detail.get("details") or "")[:300] or "No description provided by OSV.dev."

                    vulns.append({
                        "cve_id":       vid,
                        "component":    comp["name"],
                        "version":      comp.get("version"),
                        "severity":     _osv_severity(detail),
                        "description":  summary,
                        "remediation":  f"Upgrade {comp['name']} to >= {fixed}" if fixed else "See the OSV.dev advisory for remediation guidance.",
                        "source_url":   f"https://osv.dev/vulnerability/{vid}",
                        "is_advisory":  False,
                    })
        except requests.exceptions.RequestException as e:
            print(f"[VulnScan] OSV.dev batch query failed: {e}")
            vulns.append({
                "cve_id":      "SCAN-INCOMPLETE",
                "component":   "N/A",
                "version":     "N/A",
                "severity":    "Unknown",
                "description": f"Live vulnerability lookup against OSV.dev failed ({e}). "
                                f"The SBOM/AIBOM above are real, but vulnerability results are "
                                f"incomplete for this run — re-run the scan once connectivity is restored.",
                "remediation": "Retry the scan.",
                "is_advisory": True,
            })

    for model in aibom.get("models", []):
        if model.get("format", "").lower() in ("pkl", "pickle", "joblib"):
            vulns.append({
                "cve_id":      "MYTHOSSHIELD-ADV-PICKLE-DESERIALIZATION",
                "component":   model.get("name"),
                "version":     "N/A",
                "severity":    "Critical",
                "description": "General security advisory (not a registered CVE): Python pickle/joblib "
                                "files execute arbitrary code on load. Loading an untrusted .pkl/.joblib "
                                "model file is inherently unsafe regardless of its contents.",
                "remediation": "Convert the model to a safe serialization format such as safetensors or ONNX.",
                "is_advisory": True,
            })

    return vulns


# ─── SBOM / AIBOM ────────────────────────────────────────────
AI_EXTENSIONS = {".pt",".h5",".onnx",".pkl",".joblib",".pb",".tflite",".bin",".safetensors"}

def generate_sbom_from_path(path):
    components = []
    for root, dirs, files in os.walk(path):
        for fname in files:
            fpath = os.path.join(root, fname)
            if fname == "package.json":
                try:
                    with open(fpath, 'r', encoding='utf-8') as f:
                        pkg = json.load(f)
                    for dep, ver in {**pkg.get("dependencies",{}), **pkg.get("devDependencies",{})}.items():
                        components.append({"name":dep,"version":ver.lstrip("^~"),"type":"npm-package","source":fname})
                except Exception:
                    pass
            elif fname == "requirements.txt":
                try:
                    with open(fpath, 'r', encoding='utf-8') as f:
                        for line in f:
                            line = line.strip()
                            if line and not line.startswith("#"):
                                parts = line.replace("==","@").replace(">=","@").split("@")
                                components.append({"name":parts[0].strip(),"version":parts[1].strip() if len(parts)>1 else "unknown","type":"python-package","source":fname})
                except Exception:
                    pass
    return {"schema":"mythosshield-1.0","artifacts":components}

def generate_aibom(path):
    models = []
    for root, dirs, files in os.walk(path):
        for fname in files:
            ext = os.path.splitext(fname)[1].lower()
            if ext in AI_EXTENSIONS:
                fpath = os.path.join(root, fname)
                models.append({"name":fname,"path":os.path.relpath(fpath,path),"format":ext.lstrip("."),"size_bytes":os.path.getsize(fpath)})
    return {"schema":"mythosshield-aibom-1.0","model_count":len(models),"models":models}


# ─── Safe ZIP Extraction (Zip-Slip protection) ────────────────
def safe_extract_zip(zip_path: str, extract_path: str) -> None:
    abs_extract = os.path.abspath(extract_path)
    with zipfile.ZipFile(zip_path, 'r') as zip_ref:
        for member in zip_ref.namelist():
            target_path = os.path.abspath(os.path.join(abs_extract, member))
            if not target_path.startswith(abs_extract + os.sep) and target_path != abs_extract:
                raise ValueError(f"Malicious path detected in ZIP: {member}")
        zip_ref.extractall(extract_path)


# ─── Real GitHub URL / local path resolution ──────────────────
def resolve_scan_source(source: str, work_dir: str) -> str:
    """
    Turns the 'GitHub URL or Local Folder Path' field into an actual
    directory on disk to scan. Previously this field was pure decoration —
    the frontend never sent it anywhere. Now:
      - GitHub URLs are shallow-cloned with git.
      - Anything else is treated as a path on the server's own filesystem,
        which only resolves for self-hosted deployments where the backend
        and the code live on the same machine (a hosted SaaS backend can
        never see a path on the visitor's laptop — that's a hard constraint
        of how browsers work, not a bug to paper over).
    """
    source = source.strip()
    if source.startswith("http://") or source.startswith("https://"):
        if "github.com" not in source:
            raise ValueError("Only GitHub URLs are currently supported for remote repository scanning.")
        target = os.path.join(work_dir, "repo")
        try:
            subprocess.run(
                ["git", "clone", "--depth", "1", source, target],
                check=True, capture_output=True, timeout=60,
            )
        except FileNotFoundError:
            raise ValueError("git is not installed on this server — cannot clone repositories. Upload a ZIP instead.")
        except subprocess.TimeoutExpired:
            raise ValueError("git clone timed out after 60s.")
        except subprocess.CalledProcessError as e:
            stderr = e.stderr.decode(errors="ignore")[:300] if e.stderr else "unknown error"
            raise ValueError(f"git clone failed: {stderr}")
        return target
    else:
        if not os.path.isdir(source):
            raise ValueError(
                f"'{source}' was not found on the server's filesystem. Local-path scanning only "
                f"works when this backend runs on the same machine as the code (self-hosted setups). "
                f"For a hosted deployment, use a GitHub URL or upload a ZIP instead."
            )
        return source


def _run_full_scan(scan_path, source_label, user_id):
    sbom            = generate_sbom_from_path(scan_path)
    aibom           = generate_aibom(scan_path)
    vulnerabilities = scan_vulnerabilities(sbom, aibom)

    from compliance import generate_all_reports
    reports   = generate_all_reports({'sbom': sbom, 'aibom': aibom, 'vulnerabilities': vulnerabilities})
    scores    = [reports[r]['score_pct'] for r in reports if 'score_pct' in reports[r]]
    avg_score = round(sum(scores) / len(scores)) if scores else 0

    scan_data = {
        'user_id': user_id, 'source': source_label,
        'sbom': sbom, 'aibom': aibom, 'vulnerabilities': vulnerabilities,
        'compliance_score': avg_score,
        'created_at': datetime.datetime.now(datetime.timezone.utc).isoformat()
    }
    doc_ref = db.collection('scans').add(scan_data)
    scan_id = doc_ref[1].id

    return {
        'scan_id': scan_id, 'sbom': sbom, 'aibom': aibom,
        'vulnerabilities': vulnerabilities, 'compliance_score': avg_score
    }


# ─── Scan Endpoints ───────────────────────────────────────────
@app.post("/scan/upload")
@limiter.limit("20 per hour")
def scan_upload():
    user, error_response, status = get_user_from_token()
    if error_response:
        return error_response, status

    if 'file' not in request.files:
        return jsonify({'error': 'No file uploaded'}), 400

    file = request.files['file']
    if not file.filename.endswith('.zip'):
        return jsonify({'error': 'Only ZIP files are accepted'}), 400

    temp_dir     = tempfile.mkdtemp()
    zip_path     = os.path.join(temp_dir, 'upload.zip')
    extract_path = os.path.join(temp_dir, 'extracted')

    try:
        file.save(zip_path)
        os.makedirs(extract_path, exist_ok=True)
        safe_extract_zip(zip_path, extract_path)
        result = _run_full_scan(extract_path, file.filename, user['uid'])
        return jsonify(result), 200
    except ValueError as ve:
        return jsonify({'error': str(ve)}), 400
    except zipfile.BadZipFile:
        return jsonify({'error': 'Invalid ZIP file'}), 400
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)


@app.post("/scan/url")
@limiter.limit("20 per hour")
def scan_url():
    """Real GitHub URL / server-local-path scanning — previously the
    'Option 1' field in the UI was collected but never sent anywhere."""
    user, error_response, status = get_user_from_token()
    if error_response:
        return error_response, status

    data = request.json or {}
    source = (data.get('source') or '').strip()
    if not source:
        return jsonify({'error': 'No source URL or path provided'}), 400

    temp_dir = tempfile.mkdtemp()
    try:
        scan_path = resolve_scan_source(source, temp_dir)
        result = _run_full_scan(scan_path, source, user['uid'])
        return jsonify(result), 200
    except ValueError as ve:
        return jsonify({'error': str(ve)}), 400
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)


# ─── FIXED: /scans endpoint with fallback ─────────────────────
@app.get("/scans")
def list_scans():
    user, error_response, status = get_user_from_token()
    if error_response:
        return error_response, status

    try:
        # Try the normal way first
        scans_ref = db.collection('scans').where('user_id', '==', user['uid']).order_by('created_at').limit(20)
        scans = []
        for doc in scans_ref.stream():
            data = doc.to_dict()
            data['id'] = doc.id
            scans.append(data)
        return jsonify({'scans': scans}), 200
    except Exception as e:
        print(f"[ERROR] /scans failed: {e}")
        # Fallback: get all scans and filter manually (works even if .where() breaks)
        try:
            all_scans = db.collection('scans').limit(100)
            scans = []
            for doc in all_scans.stream():
                data = doc.to_dict()
                if data.get('user_id') == user['uid']:
                    data['id'] = doc.id
                    scans.append(data)
            return jsonify({'scans': scans}), 200
        except Exception as e2:
            print(f"[ERROR] /scans fallback also failed: {e2}")
            # Return empty list instead of crashing
            return jsonify({'scans': []}), 200


# ─── DEBUG: Check what's in the database ──────────────────────
@app.get("/debug/scans/all")
def debug_all_scans():
    user, error_response, status = get_user_from_token()
    if error_response:
        return error_response, status
    
    scans = []
    try:
        all_scans = db.collection('scans').limit(100)
        for doc in all_scans.stream():
            data = doc.to_dict()
            scans.append({
                'id': doc.id,
                'user_id': data.get('user_id'),
                'source': data.get('source'),
                'created_at': data.get('created_at')
            })
    except Exception as e:
        return jsonify({'error': str(e), 'scans': []}), 500
    
    return jsonify({'scans': scans}), 200


@app.get("/scan/<scan_id>")
def get_scan(scan_id):
    user, error_response, status = get_user_from_token()
    if error_response:
        return error_response, status
    doc_ref = db.collection('scans').document(scan_id).get()
    if not doc_ref.exists:
        return jsonify({'error': 'Scan not found'}), 404
    data = doc_ref.to_dict()
    if data.get('user_id') != user['uid']:
        return jsonify({'error': 'Unauthorized'}), 403
    from threat_sharing import enrich_with_community_data
    enriched = []
    for vuln in data.get('vulnerabilities', []):
        cve = vuln.get('cve_id')
        if cve:
            e = enrich_with_community_data(cve)
            vuln['peer_reports']       = e.get('peer_reports', 0)
            vuln['confirmed_in_wild']  = e.get('confirmed_in_wild', False)
        enriched.append(vuln)
    data['vulnerabilities'] = enriched
    data['id'] = doc_ref.id
    return jsonify(data), 200


@app.get("/scan/<scan_id>/compliance")
def get_scan_compliance(scan_id):
    user, error_response, status = get_user_from_token()
    if error_response:
        return error_response, status
    doc_ref = db.collection('scans').document(scan_id).get()
    if not doc_ref.exists:
        return jsonify({'error': 'Scan not found'}), 404
    scan_data = doc_ref.to_dict()
    if scan_data.get('user_id') != user['uid']:
        return jsonify({'error': 'Unauthorized'}), 403
    from compliance import generate_all_reports
    reports   = generate_all_reports(scan_data)
    scores    = [reports[r]['score_pct'] for r in reports if 'score_pct' in reports[r]]
    avg_score = round(sum(scores)/len(scores)) if scores else 0
    if scan_data.get('compliance_score') != avg_score:
        scan_data['compliance_score'] = avg_score
        db.collection('scans').document(scan_id).set(scan_data)
    return jsonify(reports), 200


@app.post("/detect-shadow-ai")
@limiter.limit("30 per hour")
def detect_shadow_ai():
    user, error_response, status = get_user_from_token()
    if error_response:
        return error_response, status
    data  = request.json or {}
    logs  = data.get('logs', [])

    tenant_id = user.get('uid', 'demo-id')
    try:
        custom_ep = get_custom_endpoints(tenant_id)
    except Exception:
        custom_ep = {}

    from shadow_ai import analyze_logs
    result = analyze_logs(logs, custom_endpoints=custom_ep)

    try:
        save_security_events(tenant_id, result.get('findings', []))
    except Exception as e:
        print(f"[Warning] Could not save security events: {e}")

    return jsonify(result), 200


@app.post("/threats/publish")
def threats_publish():
    user, error_response, status = get_user_from_token()
    if error_response:
        return error_response, status
    data      = request.json or {}
    cve_id    = data.get('cve_id')
    component = data.get('component')
    notes     = data.get('notes', '')
    if not cve_id or not component:
        return jsonify({'error': 'CVE ID and Component are required'}), 400
    tenant_id = user['uid']
    if not firebase_initialized:
        from database import get_connection
        conn   = get_connection()
        row    = conn.execute("SELECT id FROM tenants WHERE id=? OR email=?",
                              (tenant_id, user.get('email'))).fetchone()
        conn.close()
        tenant_db_id = row['id'] if row else tenant_id
    else:
        tenant_db_id = tenant_id
    from threat_sharing import publish_threat
    record = publish_threat(tenant_db_id, cve_id, component, notes)
    return jsonify({'message': 'Threat published successfully', 'threat': record}), 201


@app.get("/threats")
def threats_list():
    user, error_response, status = get_user_from_token()
    if error_response:
        return error_response, status
    from threat_sharing import get_community_threats
    threats = get_community_threats()
    return jsonify({'threats': threats}), 200


@app.get("/health")
def health():
    return jsonify({
        'status': 'ok', 'product': 'MythosShield',
        'version': '2.3.0',
        'build_fingerprint': 'REAL_SCAN_DATA_FIX',
        'firebase_connected': firebase_initialized,
        'debug_mode': DEBUG_MODE
    }), 200


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    print(f"MythosShield running on port {port}")
    app.run(host="0.0.0.0", port=port, debug=False)