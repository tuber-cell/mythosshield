"""
MythosShield — main backend
Covers: SBOM/AIBOM generation, vulnerability scanning, risk scoring, auth, multi-tenancy, ZIP upload
"""

import os, json, sqlite3, hashlib, subprocess, tempfile, datetime, requests, zipfile, shutil
from flask import Flask, request, jsonify, g
from flask_cors import CORS
from flask_jwt_extended import (
    JWTManager, create_access_token, jwt_required, get_jwt_identity
)
import bcrypt

app = Flask(__name__)
app.config["JWT_SECRET_KEY"] = os.environ.get("JWT_SECRET", "mythos-dev-secret-change-in-prod")
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = datetime.timedelta(hours=12)
CORS(app)
jwt = JWTManager(app)

DB_PATH = os.environ.get("DB_PATH", "mythosshield.db")

# ─── Database ────────────────────────────────────────────────────────────────

def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db

@app.teardown_appcontext
def close_db(e=None):
    db = g.pop("db", None)
    if db:
        db.close()

def init_db():
    db = sqlite3.connect(DB_PATH)
    db.executescript("""
        CREATE TABLE IF NOT EXISTS tenants (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            bank_name TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            gst_number TEXT,
            password_hash TEXT NOT NULL,
            created_at TEXT DEFAULT (datetime('now'))
        );
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            tenant_id INTEGER NOT NULL,
            source TEXT NOT NULL,
            sbom JSON,
            aibom JSON,
            vulnerabilities JSON,
            risk_assessment JSON,
            compliance_score REAL DEFAULT 0,
            created_at TEXT DEFAULT (datetime('now')),
            FOREIGN KEY (tenant_id) REFERENCES tenants(id)
        );
        CREATE TABLE IF NOT EXISTS webhooks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            tenant_id INTEGER NOT NULL,
            url TEXT NOT NULL,
            active INTEGER DEFAULT 1,
            created_at TEXT DEFAULT (datetime('now'))
        );
    """)
    db.commit()
    db.close()

# ─── Auth ────────────────────────────────────────────────────────────────────

import re

def validate_password(pw):
    if len(pw) < 8:
        return False, "Password must be at least 8 characters"
    if not re.search(r"\d", pw):
        return False, "Password must contain at least one number"
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", pw):
        return False, "Password must contain at least one special character"
    return True, "ok"

@app.post("/auth/register")
def register():
    data = request.json or {}
    for field in ("email", "bank_name", "password"):
        if not data.get(field):
            return jsonify(error=f"{field} is required"), 400
    ok, msg = validate_password(data["password"])
    if not ok:
        return jsonify(error=msg), 400
    pw_hash = bcrypt.hashpw(data["password"].encode(), bcrypt.gensalt()).decode()
    db = get_db()
    try:
        db.execute(
            "INSERT INTO tenants (bank_name, email, gst_number, password_hash) VALUES (?,?,?,?)",
            (data["bank_name"], data["email"], data.get("gst_number",""), pw_hash)
        )
        db.commit()
    except sqlite3.IntegrityError:
        return jsonify(error="Email already registered"), 409
    return jsonify(message="Registered successfully"), 201

@app.post("/auth/login")
def login():
    data = request.json or {}
    db = get_db()
    row = db.execute("SELECT * FROM tenants WHERE email=?", (data.get("email",""),)).fetchone()
    if not row or not bcrypt.checkpw(data.get("password","").encode(), row["password_hash"].encode()):
        return jsonify(error="Invalid credentials"), 401
    token = create_access_token(identity=str(row["id"]))
    return jsonify(access_token=token, bank_name=row["bank_name"])

# ─── SBOM / AIBOM ────────────────────────────────────────────────────────────

AI_EXTENSIONS = {".pt", ".h5", ".onnx", ".pkl", ".joblib", ".pb", ".tflite", ".bin", ".safetensors"}
AI_DIR_HINTS  = {"models", "checkpoints", "weights", "saved_model"}

def generate_sbom_from_path(path):
    """Use syft if available, else fall back to dependency file scanning."""
    try:
        result = subprocess.run(
            ["syft", path, "-o", "json"],
            capture_output=True, text=True, timeout=120
        )
        if result.returncode == 0:
            return json.loads(result.stdout)
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass
    # Fallback: parse requirements.txt / package.json
    components = []
    for root, dirs, files in os.walk(path):
        for fname in files:
            fpath = os.path.join(root, fname)
            if fname == "requirements.txt":
                try:
                    with open(fpath, 'r', encoding='utf-8') as f:
                        for line in f:
                            line = line.strip()
                            if line and not line.startswith("#"):
                                parts = line.replace("==","@").replace(">=","@").split("@")
                                components.append({
                                    "name": parts[0].strip(),
                                    "version": parts[1].strip() if len(parts)>1 else "unknown",
                                    "type": "python-package",
                                    "source": fname
                                })
                except Exception:
                    pass
            elif fname == "package.json":
                try:
                    with open(fpath, 'r', encoding='utf-8') as f:
                        pkg = json.load(f)
                    for dep, ver in {**pkg.get("dependencies",{}), **pkg.get("devDependencies",{})}.items():
                        components.append({"name": dep, "version": ver.lstrip("^~"), "type": "npm-package", "source": fname})
                except Exception:
                    pass
    return {"schema": "mythosshield-fallback-1.0", "artifacts": components}

def generate_aibom(path):
    """Walk directory and collect AI model files."""
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
                    "size_bytes": size,
                    "sha256": _sha256(fpath)
                })
    return {
        "schema": "mythosshield-aibom-1.0",
        "model_count": len(models),
        "models": models
    }

def _sha256(fpath):
    h = hashlib.sha256()
    try:
        with open(fpath, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return "error"

@app.post("/scan/sbom")
@jwt_required()
def scan_sbom():
    tenant_id = int(get_jwt_identity())
    data = request.json or {}
    source = data.get("source", "")
    if not source:
        return jsonify(error="source (repo URL or folder path) is required"), 400

    work_dir = source
    tmp_dir = None

    if source.startswith("http"):
        try:
            import git
            tmp_dir = tempfile.mkdtemp()
            git.Repo.clone_from(source, tmp_dir, depth=1)
            work_dir = tmp_dir
        except Exception as e:
            return jsonify(error=f"Could not clone repo: {e}"), 400

    sbom  = generate_sbom_from_path(work_dir)
    aibom = generate_aibom(work_dir)

    if tmp_dir:
        shutil.rmtree(tmp_dir, ignore_errors=True)

    db = get_db()
    cur = db.execute(
        "INSERT INTO scans (tenant_id, source, sbom, aibom) VALUES (?,?,?,?)",
        (tenant_id, source, json.dumps(sbom), json.dumps(aibom))
    )
    db.commit()
    scan_id = cur.lastrowid

    return jsonify(scan_id=scan_id, sbom=sbom, aibom=aibom)

# ─── ZIP Upload Endpoint ─────────────────────────────────────────────────────

@app.post("/scan/upload")
@jwt_required()
def scan_upload():
    tenant_id = int(get_jwt_identity())
    
    if 'file' not in request.files:
        return jsonify(error="No file uploaded"), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify(error="Empty filename"), 400
    
    if not file.filename.endswith('.zip'):
        return jsonify(error="Only ZIP files are accepted"), 400
    
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
        
        db = get_db()
        cur = db.execute(
            "INSERT INTO scans (tenant_id, source, sbom, aibom) VALUES (?,?,?,?)",
            (tenant_id, file.filename, json.dumps(sbom), json.dumps(aibom))
        )
        db.commit()
        scan_id = cur.lastrowid
        
        return jsonify(scan_id=scan_id, sbom=sbom, aibom=aibom)
        
    except zipfile.BadZipFile:
        return jsonify(error="Invalid ZIP file"), 400
    except Exception as e:
        return jsonify(error=f"Error processing ZIP: {str(e)}"), 500
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)

# ─── Vulnerability Scanner ───────────────────────────────────────────────────

NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"

def query_nvd(keyword, results_per_page=5):
    try:
        r = requests.get(NVD_API, params={"keywordSearch": keyword, "resultsPerPage": results_per_page}, timeout=10)
        if r.status_code == 200:
            return r.json().get("vulnerabilities", [])
    except Exception:
        pass
    return []

def assess_risk(vulns):
    """Score and prioritise vulnerabilities using simple heuristics."""
    PRIORITY = {"RCE": 10, "privilege escalation": 9, "code execution": 8,
                "command injection": 8, "sql injection": 7, "xss": 6,
                "denial of service": 5, "dos": 5, "information disclosure": 4}
    scored = []
    for v in vulns:
        desc = (v.get("description") or "").lower()
        cvss  = v.get("cvss_score", 0) or 0
        bonus = max((w for k, w in PRIORITY.items() if k in desc), default=0)
        v["priority_score"] = round(cvss + bonus, 1)
        scored.append(v)
    scored.sort(key=lambda x: x["priority_score"], reverse=True)
    return scored

@app.post("/scan/vulnerabilities")
@jwt_required()
def scan_vulnerabilities():
    tenant_id = int(get_jwt_identity())
    data = request.json or {}
    scan_id = data.get("scan_id")
    if not scan_id:
        return jsonify(error="scan_id required"), 400

    db = get_db()
    row = db.execute("SELECT * FROM scans WHERE id=? AND tenant_id=?", (scan_id, tenant_id)).fetchone()
    if not row:
        return jsonify(error="Scan not found"), 404

    sbom = json.loads(row["sbom"] or "{}")
    components = sbom.get("artifacts", [])

    vulns = []
    for comp in components[:30]:  # limit to avoid rate limiting
        name = comp.get("name","")
        ver  = comp.get("version","")
        cves = query_nvd(f"{name} {ver}")
        for item in cves:
            cve_data = item.get("cve", {})
            cve_id   = cve_data.get("id","")
            descs    = cve_data.get("descriptions",[])
            desc     = next((d["value"] for d in descs if d.get("lang")=="en"), "")
            metrics  = cve_data.get("metrics",{})
            cvss     = 0.0
            severity = "UNKNOWN"
            for key in ("cvssMetricV31","cvssMetricV30","cvssMetricV2"):
                if key in metrics and metrics[key]:
                    m = metrics[key][0].get("cvssData",{})
                    cvss = m.get("baseScore", 0.0)
                    severity = m.get("baseSeverity", "UNKNOWN")
                    break
            vulns.append({
                "component": name,
                "version": ver,
                "cve_id": cve_id,
                "description": desc[:300],
                "cvss_score": cvss,
                "severity": severity
            })

    counts = {"critical":0,"high":0,"medium":0,"low":0,"unknown":0}
    for v in vulns:
        s = v["severity"].lower()
        if s in counts:
            counts[s] += 1
        else:
            counts["unknown"] += 1

    prioritised = assess_risk(vulns)

    db.execute(
        "UPDATE scans SET vulnerabilities=?, risk_assessment=? WHERE id=?",
        (json.dumps(prioritised), json.dumps(counts), scan_id)
    )
    db.commit()

    return jsonify(
        scan_id=scan_id,
        total_vulnerabilities=len(vulns),
        **counts,
        risk_assessment=prioritised[:20]
    )

# ─── Compliance Score ─────────────────────────────────────────────────────────

def calc_compliance_score(sbom, aibom, vulns):
    score = 100.0
    if not sbom.get("artifacts"):
        score -= 20
    if not aibom.get("models") and aibom.get("model_count", 0) == 0:
        score -= 10
    critical = sum(1 for v in vulns if v.get("severity","").lower() == "critical")
    high     = sum(1 for v in vulns if v.get("severity","").lower() == "high")
    score -= min(critical * 15, 40)
    score -= min(high * 5, 20)
    return max(round(score, 1), 0)

@app.get("/scan/<int:scan_id>")
@jwt_required()
def get_scan(scan_id):
    tenant_id = int(get_jwt_identity())
    db = get_db()
    row = db.execute("SELECT * FROM scans WHERE id=? AND tenant_id=?", (scan_id, tenant_id)).fetchone()
    if not row:
        return jsonify(error="Not found"), 404
    sbom  = json.loads(row["sbom"]  or "{}")
    aibom = json.loads(row["aibom"] or "{}")
    vulns = json.loads(row["vulnerabilities"] or "[]")
    score = calc_compliance_score(sbom, aibom, vulns)
    return jsonify(
        id=row["id"], source=row["source"], created_at=row["created_at"],
        sbom=sbom, aibom=aibom, vulnerabilities=vulns,
        compliance_score=score
    )

@app.get("/scans")
@jwt_required()
def list_scans():
    tenant_id = int(get_jwt_identity())
    db = get_db()
    rows = db.execute(
        "SELECT id, source, compliance_score, created_at FROM scans WHERE tenant_id=? ORDER BY id DESC LIMIT 20",
        (tenant_id,)
    ).fetchall()
    return jsonify(scans=[dict(r) for r in rows])

# ─── Shadow AI ───────────────────────────────────────────────────────────────

from shadow_ai import analyze_logs as _analyze_logs

@app.post("/detect-shadow-ai")
@jwt_required()
def detect_shadow_ai():
    data = request.json or {}
    logs = data.get("logs", [])
    if not isinstance(logs, list):
        return jsonify(error="logs must be a JSON array"), 400
    result = _analyze_logs(logs)
    return jsonify(result)

# ─── Compliance Reports ───────────────────────────────────────────────────────

from compliance import generate_all_reports, generate_dpdpa_report, generate_sebi_report, generate_bis_report, generate_rbi_dpip_report

def _get_scan_data(scan_id, tenant_id):
    db = get_db()
    row = db.execute("SELECT * FROM scans WHERE id=? AND tenant_id=?", (scan_id, tenant_id)).fetchone()
    if not row:
        return None
    return {
        "sbom":            json.loads(row["sbom"]  or "{}"),
        "aibom":           json.loads(row["aibom"] or "{}"),
        "vulnerabilities": json.loads(row["vulnerabilities"] or "[]"),
    }

@app.get("/scan/<int:scan_id>/compliance")
@jwt_required()
def compliance_reports(scan_id):
    sd = _get_scan_data(scan_id, int(get_jwt_identity()))
    if sd is None:
        return jsonify(error="Scan not found"), 404
    return jsonify(generate_all_reports(sd))

@app.get("/scan/<int:scan_id>/compliance/dpdpa")
@jwt_required()
def compliance_dpdpa(scan_id):
    sd = _get_scan_data(scan_id, int(get_jwt_identity()))
    if sd is None: return jsonify(error="Not found"), 404
    return jsonify(generate_dpdpa_report(sd))

@app.get("/scan/<int:scan_id>/compliance/sebi")
@jwt_required()
def compliance_sebi(scan_id):
    sd = _get_scan_data(scan_id, int(get_jwt_identity()))
    if sd is None: return jsonify(error="Not found"), 404
    return jsonify(generate_sebi_report(sd))

@app.get("/scan/<int:scan_id>/compliance/bis")
@jwt_required()
def compliance_bis(scan_id):
    sd = _get_scan_data(scan_id, int(get_jwt_identity()))
    if sd is None: return jsonify(error="Not found"), 404
    return jsonify(generate_bis_report(sd))

@app.get("/scan/<int:scan_id>/compliance/rbi")
@jwt_required()
def compliance_rbi(scan_id):
    sd = _get_scan_data(scan_id, int(get_jwt_identity()))
    if sd is None: return jsonify(error="Not found"), 404
    return jsonify(generate_rbi_dpip_report(sd))

# ─── Webhooks ─────────────────────────────────────────────────────────────────

@app.post("/register-webhook")
@jwt_required()
def register_webhook():
    tenant_id = int(get_jwt_identity())
    url = (request.json or {}).get("url","")
    if not url.startswith("http"):
        return jsonify(error="Valid URL required"), 400
    db = get_db()
    db.execute("INSERT INTO webhooks (tenant_id, url) VALUES (?,?)", (tenant_id, url))
    db.commit()
    return jsonify(message="Webhook registered"), 201

# ─── Health ───────────────────────────────────────────────────────────────────

@app.get("/health")
def health():
    return jsonify(status="ok", product="MythosShield", version="1.0.0")

# ─── Boot ─────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    init_db()
    port = int(os.environ.get("PORT", 5000))
    print(f"MythosShield backend running on port {port}")
    app.run(host="0.0.0.0", port=port, debug=os.environ.get("DEBUG","false").lower()=="true")