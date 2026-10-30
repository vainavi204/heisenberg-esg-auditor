import os, re, io, json, sqlite3, secrets, hashlib, hmac
from datetime import date, datetime, timedelta
from pathlib import Path
from typing import Optional

from dotenv import load_dotenv
from fastapi import FastAPI, UploadFile, File, HTTPException, Header
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

BASE_DIR = Path(__file__).resolve().parent
load_dotenv(BASE_DIR / ".env")
DB_PATH = BASE_DIR / "data" / "verda.db"
DB_PATH.parent.mkdir(parents=True, exist_ok=True)

ADMIN_USERNAME = os.getenv("ESG_ADMIN_USERNAME", "")
ADMIN_PASSWORD = os.getenv("ESG_ADMIN_PASSWORD", "")
SESSION_SECRET = os.getenv("ESG_SESSION_SECRET", "")

app = FastAPI(title="HEISENBERG ESG Auditor API", version="1.0.0", description="Demo API for certificate extraction, verification, and ESG scoring.")
app.add_middleware(
    CORSMiddleware,
    allow_origins=[x.strip() for x in os.getenv("CORS_ORIGINS", "http://localhost:5173,http://127.0.0.1:5173").split(",") if x.strip()],
    allow_credentials=True, allow_methods=["*"], allow_headers=["*"],
)

class LoginRequest(BaseModel):
    username: str
    password: str


def db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    with db() as conn:
        conn.execute("""CREATE TABLE IF NOT EXISTS audits (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            filename TEXT NOT NULL, certificate_number TEXT, issuer TEXT, standard TEXT,
            scope TEXT, issue_date TEXT, expiry_date TEXT, status TEXT NOT NULL,
            score INTEGER NOT NULL, risk_level TEXT NOT NULL, pillar TEXT,
            extracted_text TEXT, created_at TEXT NOT NULL
        )""")
        count = conn.execute("SELECT COUNT(*) FROM audits").fetchone()[0]
        if count == 0:
            samples = [
                ("GreenLeaf_ESG_Certificate.pdf", "ESG-2026-1042", "GreenLeaf Certification", "ISO 14001:2015", "Environmental management", "2025-01-12", "2027-01-12", "Valid", 92, "Low Risk", "E", "Environmental management system certificate. ISO 14001:2015. Certificate No ESG-2026-1042.", "2026-10-24 10:30"),
                ("EcoBuild_Vendor_Certificate.pdf", "ECO-2026-2085", "EcoBuild Standards", "ISO 45001:2018", "Occupational health and safety", "2024-06-01", "2026-12-15", "Expiring Soon", 68, "Medium Risk", "S", "ISO 45001:2018 occupational health and safety management certificate.", "2026-10-23 14:15"),
                ("UrbanTex_ESG_Report.pdf", "Not detected", "Not detected", "Not detected", "Not detected", "", "", "Needs Review", 42, "High Risk", "G", "Vendor ESG report. Fields require manual review.", "2026-10-22 11:45"),
                ("Sunrise_Packaging_ESG.pdf", "SP-2026-3310", "Sunrise Assurance", "ISO 14001:2015", "Packaging operations", "2025-02-01", "2027-02-01", "Valid", 88, "Low Risk", "E", "ISO 14001:2015 certificate for packaging operations.", "2026-10-21 09:20"),
                ("PrimeChem_Compliance.pdf", "PC-2026-4412", "PrimeChem Audit", "ISO 37001:2016", "Anti-bribery management", "2024-03-10", "2026-09-30", "Expired", 24, "High Risk", "G", "ISO 37001:2016 anti-bribery management certificate.", "2026-10-20 16:40"),
            ]
            conn.executemany("INSERT INTO audits (filename,certificate_number,issuer,standard,scope,issue_date,expiry_date,status,score,risk_level,pillar,extracted_text,created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)", samples)

init_db()


def check_auth_config():
    if not ADMIN_USERNAME or not ADMIN_PASSWORD or len(SESSION_SECRET) < 32:
        raise HTTPException(status_code=503, detail="Authentication is not configured. Set ESG_ADMIN_USERNAME, ESG_ADMIN_PASSWORD, and an ESG_SESSION_SECRET of at least 32 characters in backend/.env, then restart the backend.")


def make_token(username: str) -> str:
    stamp = str(int(datetime.utcnow().timestamp()))
    body = f"{username}:{stamp}"
    sig = hmac.new(SESSION_SECRET.encode(), body.encode(), hashlib.sha256).hexdigest()
    return f"{body}:{sig}"


def require_auth(authorization: Optional[str]):
    check_auth_config()
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Please sign in to continue.")
    token = authorization[7:]
    try:
        username, stamp, sig = token.rsplit(":", 2)
        body = f"{username}:{stamp}"
        expected = hmac.new(SESSION_SECRET.encode(), body.encode(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(sig, expected) or username != ADMIN_USERNAME or datetime.utcnow().timestamp() - int(stamp) > 12 * 3600:
            raise ValueError()
    except Exception:
        raise HTTPException(status_code=401, detail="Your session is invalid or expired. Please sign in again.")


def rows_to_dict(rows):
    return [dict(r) for r in rows]


def determine_pillar(standard: str) -> str:
    s = (standard or "").upper()
    if any(x in s for x in ["14001", "14064", "50001"]): return "E"
    if any(x in s for x in ["45001", "SA8000"]): return "S"
    if any(x in s for x in ["37001", "27001", "9001"]): return "G"
    return "E"


def extract_pdf_text(data: bytes) -> str:
    try:
        from pypdf import PdfReader
        reader = PdfReader(io.BytesIO(data))
        return "\n".join(page.extract_text() or "" for page in reader.pages).strip()
    except Exception:
        return ""


def extract_image_text(data: bytes) -> str:
    try:
        from PIL import Image, ImageOps, ImageFilter
        import pytesseract
        image = Image.open(io.BytesIO(data)).convert("L")
        image = ImageOps.autocontrast(image).filter(ImageFilter.SHARPEN)
        return pytesseract.image_to_string(image).strip()
    except Exception:
        return ""


def parse_fields(text: str):
    def find(patterns, default="Not detected"):
        for pattern in patterns:
            m = re.search(pattern, text, re.I | re.M)
            if m: return m.group(1).strip(" :#-\t")
        return default
    number = find([r"(?:certificate\s*(?:no\.?|number|#))\s*[:#-]?\s*([A-Z0-9][A-Z0-9\-/]{3,})", r"\b([A-Z]{2,5}-20\d{2}-\d{3,})\b"])
    standard = find([r"\b(ISO\s*\d{4,5}(?::\s*\d{4})?)\b", r"\b(SA\s*8000(?::\s*\d{4})?)\b"])
    issuer = find([r"(?:issued\s+by|certification\s+body|issuing\s+body)\s*[:\-]?\s*([^\n,;]{3,80})"])
    scope = find([r"(?:scope(?:\s+of\s+certification)?)\s*[:\-]?\s*([^\n]{3,160})"])
    issue = find([r"(?:issue\s+date|issued\s+on|date\s+of\s+issue)\s*[:\-]?\s*([0-9]{1,2}[./-][0-9]{1,2}[./-][0-9]{2,4}|20\d{2}-\d{2}-\d{2})", r"(?:issue\s+date|issued\s+on)\s*[:\-]?\s*(\w+\s+\d{1,2},?\s+20\d{2})"])
    expiry = find([r"(?:expiry\s+date|expiration\s+date|valid\s+until|valid\s+through)\s*[:\-]?\s*([0-9]{1,2}[./-][0-9]{1,2}[./-][0-9]{2,4}|20\d{2}-\d{2}-\d{2})", r"(?:expiry\s+date|expiration\s+date|valid\s+until)\s*[:\-]?\s*(\w+\s+\d{1,2},?\s+20\d{2})"])
    return {"certificate_number": number, "issuer": issuer, "standard": standard, "scope": scope, "issue_date": issue, "expiry_date": expiry}


def parse_date(value: str):
    if not value or value == "Not detected": return None
    value = value.strip().replace(".", "/")
    for fmt in ("%Y-%m-%d", "%d/%m/%Y", "%m/%d/%Y", "%d-%m-%Y", "%m-%d-%Y", "%B %d, %Y", "%B %d %Y", "%b %d, %Y"):
        try: return datetime.strptime(value, fmt).date()
        except ValueError: pass
    return None


def assess(fields, text):
    today = date.today()
    expiry = parse_date(fields.get("expiry_date", ""))
    standard = fields.get("standard", "Not detected")
    if not text.strip() or standard == "Not detected":
        status = "Needs Review"; score = 42
    elif expiry and expiry < today:
        status = "Expired"; score = 24
    elif expiry and expiry <= today + timedelta(days=90):
        status = "Expiring Soon"; score = 68
    elif fields.get("certificate_number") != "Not detected" and fields.get("issuer") != "Not detected":
        status = "Valid (text checks)"; score = 88
    else:
        status = "Needs Review"; score = 55
    risk = "Low Risk" if score >= 75 else "Medium Risk" if score >= 50 else "High Risk"
    return status, score, risk

@app.get("/")
def root():
    return {"message": "HEISENBERG ESG Auditor API", "docs": "/docs", "health": "/api/health"}

@app.get("/api/health")
def health():
    return {"status": "ok", "app": "HEISENBERG ESG Auditor", "auth_configured": bool(ADMIN_USERNAME and ADMIN_PASSWORD and len(SESSION_SECRET) >= 32)}

@app.post("/api/auth/login")
def login(payload: LoginRequest):
    check_auth_config()
    username_ok = hmac.compare_digest(payload.username.strip(), ADMIN_USERNAME)
    password_ok = hmac.compare_digest(payload.password, ADMIN_PASSWORD)
    if not (username_ok and password_ok):
        raise HTTPException(status_code=401, detail="The username or password is incorrect.")
    return {"access_token": make_token(ADMIN_USERNAME), "token_type": "bearer", "user": {"username": ADMIN_USERNAME, "role": "Procurement Officer"}}

@app.get("/api/dashboard")
def dashboard(authorization: Optional[str] = Header(default=None)):
    require_auth(authorization)
    with db() as conn:
        audits = rows_to_dict(conn.execute("SELECT * FROM audits ORDER BY id DESC").fetchall())
    total = len(audits)
    avg = round(sum(x["score"] for x in audits) / total) if total else 0
    return {"total_screened": total, "high_risk": sum(x["risk_level"] == "High Risk" for x in audits), "medium_risk": sum(x["risk_level"] == "Medium Risk" for x in audits), "low_risk": sum(x["risk_level"] == "Low Risk" for x in audits), "average_score": avg, "audits": audits}

@app.get("/api/audits")
def get_audits(authorization: Optional[str] = Header(default=None)):
    require_auth(authorization)
    with db() as conn:
        return rows_to_dict(conn.execute("SELECT * FROM audits ORDER BY id DESC").fetchall())

@app.post("/api/certificates/analyze")
async def analyze_certificate(file: UploadFile = File(...), authorization: Optional[str] = Header(default=None)):
    require_auth(authorization)
    filename = file.filename or "certificate"
    ext = Path(filename).suffix.lower()
    if ext not in {".pdf", ".png", ".jpg", ".jpeg"}:
        raise HTTPException(status_code=400, detail="Please upload a PDF, JPG, or PNG file.")
    data = await file.read()
    if len(data) > 15 * 1024 * 1024:
        raise HTTPException(status_code=400, detail="File is too large. Maximum size is 15 MB.")
    text = extract_pdf_text(data) if ext == ".pdf" else extract_image_text(data)
    extraction_note = None
    if not text:
        extraction_note = "No text could be extracted. For scanned PDFs, install Tesseract and Poppler or try a clearer PDF/image. Fields may need manual review."
    fields = parse_fields(text)
    status, score, risk = assess(fields, text)
    pillar = determine_pillar(fields["standard"])
    created = datetime.now().strftime("%Y-%m-%d %H:%M")
    with db() as conn:
        cur = conn.execute("INSERT INTO audits (filename,certificate_number,issuer,standard,scope,issue_date,expiry_date,status,score,risk_level,pillar,extracted_text,created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)", (filename, fields["certificate_number"], fields["issuer"], fields["standard"], fields["scope"], fields["issue_date"], fields["expiry_date"], status, score, risk, pillar, text, created))
        audit_id = cur.lastrowid
    return {"id": audit_id, "filename": filename, "fields": fields, "verification_status": status, "score": score, "risk_level": risk, "pillar": pillar, "extracted_text": text, "note": extraction_note, "created_at": created, "disclaimer": "Text/date checks only. This demo does not contact certification bodies to prove authenticity."}

@app.get("/api/reports/summary")
def report_summary(authorization: Optional[str] = Header(default=None)):
    require_auth(authorization)
    with db() as conn:
        audits = rows_to_dict(conn.execute("SELECT * FROM audits ORDER BY id DESC").fetchall())
    return {"generated_at": datetime.now().isoformat(timespec="minutes"), "total_certificates": len(audits), "audits": audits, "risk_counts": {k: sum(a['risk_level'] == k for a in audits) for k in ["Low Risk", "Medium Risk", "High Risk"]}}
