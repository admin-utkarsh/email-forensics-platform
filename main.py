"""
main.py -- AI-Powered Email Threat Detection, Geolocation and Forensic
Intelligence Platform (backend)

Run locally:
    pip install -r requirements.txt
    uvicorn main:app --reload --port 8000

Then open frontend/index.html (or serve it) and point it at
http://localhost:8000
"""
import uuid
import time
from datetime import datetime, timezone
from email.utils import parseaddr
from typing import Optional

from fastapi import FastAPI, UploadFile, File, Form, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from header_analysis import (
    parse_email, extract_relay_chain, probable_origin_ip,
    parse_auth_results, check_alignment,
)
from nlp_model import classify_text, suspicious_url_signals
from intel import domain_report, geolocate_ip
from risk_engine import compute_risk

app = FastAPI(title="Email Threat Detection & Forensic Intelligence Platform")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# In-memory case store (swap for a real DB e.g. SQLite/Postgres in production)
CASES = {}


class RawEmailIn(BaseModel):
    raw_email: str


def _run_pipeline(raw_bytes: bytes) -> dict:
    parsed = parse_email(raw_bytes)

    relay_chain = extract_relay_chain(parsed["received"])
    origin_ip = probable_origin_ip(relay_chain)

    auth = parse_auth_results(parsed["auth_results"])
    alignment = check_alignment(parsed)

    nlp = classify_text(parsed["subject"], parsed["body"])
    url_signals = suspicious_url_signals(parsed["urls"])

    from_domain = alignment.get("from_domain")
    dom_report = domain_report(from_domain)

    geo = geolocate_ip(origin_ip) if origin_ip else None

    risk = compute_risk(parsed, auth, alignment, nlp, url_signals, dom_report, geo)

    case_id = str(uuid.uuid4())[:8]
    result = {
        "case_id": case_id,
        "analyzed_at": datetime.now(timezone.utc).isoformat(),
        "subject": parsed["subject"],
        "from": parsed["from"],
        "to": parsed["to"],
        "message_id": parsed["message_id"],
        "date": parsed["date"],
        "attachments": parsed["attachments"],
        "urls_found": parsed["urls"],
        "relay_chain": relay_chain,
        "origin_ip": origin_ip,
        "geolocation": geo,
        "auth_results": auth,
        "alignment": alignment,
        "nlp_analysis": nlp,
        "url_signals": url_signals,
        "domain_report": dom_report,
        "risk_assessment": risk,
    }
    CASES[case_id] = result
    return result


@app.get("/api/health")
def health():
    return {"status": "ok", "cases_analyzed": len(CASES)}


@app.post("/api/analyze/text")
def analyze_text(payload: RawEmailIn):
    if not payload.raw_email.strip():
        raise HTTPException(400, "raw_email is empty")
    return _run_pipeline(payload.raw_email.encode("utf-8", errors="ignore"))


@app.post("/api/analyze/file")
async def analyze_file(file: UploadFile = File(...)):
    content = await file.read()
    if not content:
        raise HTTPException(400, "Uploaded file is empty")
    return _run_pipeline(content)


@app.get("/api/cases")
def list_cases():
    return [
        {
            "case_id": c["case_id"],
            "subject": c["subject"],
            "from": c["from"],
            "analyzed_at": c["analyzed_at"],
            "fraud_score": c["risk_assessment"]["fraud_score"],
            "verdict": c["risk_assessment"]["verdict"],
        }
        for c in sorted(CASES.values(), key=lambda x: x["analyzed_at"], reverse=True)
    ]


@app.get("/api/cases/{case_id}")
def get_case(case_id: str):
    if case_id not in CASES:
        raise HTTPException(404, "Case not found")
    return CASES[case_id]
