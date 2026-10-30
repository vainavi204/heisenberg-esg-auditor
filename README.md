# HEISENBERG — Corporate Sustainable Procurement Vendor ESG Auditor

Local development starter with a dark navy/teal dashboard inspired by the screenshot supplied by the project team.

## Stack
- Frontend: React + Vite + Recharts
- Backend: FastAPI
- Local database: SQLite (easy to run on a laptop)
- Certificate text extraction: pypdf for text PDFs; Tesseract OCR for scanned PDFs/images when installed

## Requirements
- Python 3.10+
- Node.js 20+ (or current LTS)
- Optional: Tesseract OCR installed and available on PATH for scanned certificates

## Run on Windows / VS Code
Open this folder in VS Code.

### Terminal 1 — backend
```powershell
cd backend
py -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
Copy-Item .env.example .env
```
Edit `backend/.env` and set a private local password and a random session secret. Generate a secret using:
```powershell
py -c "import secrets; print(secrets.token_hex(32))"
```
Paste the output into `ESG_SESSION_SECRET` in `.env`, save, then start:
```powershell
py -m uvicorn main:app --reload --port 8000
```
Check `http://127.0.0.1:8000/api/health` and API docs at `http://127.0.0.1:8000/docs`.

### Terminal 2 — frontend
```powershell
cd frontend
npm install
Copy-Item .env.example .env
npm run dev
```
Open the Vite Local address shown in the terminal, normally `http://localhost:5173`.

Sign in with the username and password configured in `backend/.env`.

## Notes and limitations
- SQLite data is stored in `backend/data/` and remains local to this computer.
- Sample audit rows are seeded for dashboard demonstration. They are illustrative, not real supplier assessments.
- Scoring is a transparent demo heuristic, not a formal ESG certification or legal determination.
- Text extraction is not certificate authenticity verification. Authenticity must be checked with the issuer/registry and a human reviewer.
- PostgreSQL, production user management/roles, issuer integrations, and deployment hardening are follow-on work.
- Never commit `.env` files or publish real credentials.
