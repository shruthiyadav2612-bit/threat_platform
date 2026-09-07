import os
import json
from datetime import datetime

from fastapi import FastAPI, UploadFile, File, Form, Depends, HTTPException
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session

from . import models
from .database import engine, get_db, Base
from .parser import parse_email, extract_iocs, sha256_of
from .classifier import (
    PhishingClassifier, detect_language, build_explainable_reasons,
    compute_subscores, extract_scam_phrases,
)
from .geolocation import geolocate_ip
from .campaign import (
    seen_before, link_campaigns, campaign_graph_data, all_campaigns,
    ioc_intelligence, campaign_detail,
)
from .bec import domain_similarity, display_name_check, financial_intent, additive_risk_score
from .report import build_forensic_report, build_complaint_draft

Base.metadata.create_all(bind=engine)

app = FastAPI(title="AI Email Threat Detection, Geolocation & Forensic Intelligence")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

classifier = PhishingClassifier()

REPORTS_DIR = os.path.join(os.path.dirname(__file__), "..", "generated_reports")
os.makedirs(REPORTS_DIR, exist_ok=True)

STATIC_DIR = os.path.join(os.path.dirname(__file__), "static")
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


@app.get("/")
def index():
    return FileResponse(os.path.join(STATIC_DIR, "index.html"))


@app.post("/api/analyze")
async def analyze(file: UploadFile = File(None), raw_email: str = Form(None), db: Session = Depends(get_db)):
    if file is not None:
        content = (await file.read()).decode("utf-8", errors="ignore")
        filename = file.filename
    elif raw_email:
        content = raw_email
        filename = "pasted_email.eml"
    else:
        raise HTTPException(400, "No email content provided")

    if not content.strip():
        raise HTTPException(400, "Empty email content")

    parsed = parse_email(content)
    iocs = extract_iocs(content, parsed)
    email_hash = sha256_of(content)
    language = detect_language(parsed.get("subject", "") + " " + parsed.get("body", ""))
    classification = classifier.analyze(parsed.get("subject", "") + " " + parsed.get("body", ""))

    # "Seen before" check runs BEFORE we insert this case's own IOCs
    seen_ips = [seen_before(db, "ip", ip) for ip in iocs["ips"]]
    known_before = next((s for s in seen_ips if s["known"]), {"known": False, "times_seen": 0, "case_ids": []})

    reasons = build_explainable_reasons(classification, parsed, iocs, language)
    scam_phrases = extract_scam_phrases(parsed.get("body", "") + " " + parsed.get("subject", ""))
    subscores = compute_subscores(classification, parsed, iocs, language)
    subscores["ioc"] = 85 if known_before["known"] else 0

    # BEC / CEO-impersonation layer
    domain_sim = domain_similarity(parsed.get("from_domain", ""))
    name_check = display_name_check(parsed.get("from", ""))
    intent = financial_intent(parsed.get("subject", "") + " " + parsed.get("body", ""))
    bec_score = additive_risk_score(parsed, domain_sim, name_check, intent)

    # Persist case
    case = models.Case(
        filename=filename,
        subject=parsed["subject"][:500],
        sender=parsed["from"][:255],
        from_domain=parsed["from_domain"][:255],
        upload_date=datetime.utcnow(),
        threat_score=classification["threat_score"],
        verdict=classification["verdict"],
        language=language,
        email_hash=email_hash,
        raw_email=content,
    )
    db.add(case)
    db.flush()

    header_row = models.EmailHeader(
        case_id=case.id,
        raw_headers=parsed["raw_headers"],
        spf=parsed["spf"], dkim=parsed["dkim"], dmarc=parsed["dmarc"],
        reply_to=parsed["reply_to"],
        anomalies=json.dumps(parsed["anomalies"]),
    )
    db.add(header_row)

    ioc_values_for_campaign = []
    for ip in iocs["ips"]:
        db.add(models.IOC(case_id=case.id, ioc_type="ip", value=ip))
        ioc_values_for_campaign.append(ip)
    for u in iocs["urls"]:
        db.add(models.IOC(case_id=case.id, ioc_type="url", value=u["url"][:500]))
        if u["domain"]:
            db.add(models.IOC(case_id=case.id, ioc_type="domain", value=u["domain"]))
            ioc_values_for_campaign.append(u["domain"])

    db.commit()

    campaigns = link_campaigns(db, case, ioc_values_for_campaign)

    geo_results = []
    for hop in parsed["hops"]:
        geo = geolocate_ip(hop["ip"], use_live_api=False)
        geo["hop"] = hop["hop"]
        geo_results.append(geo)

    return JSONResponse({
        "case_id": case.id,
        "case_ref": f"CT-2026-{case.id:05d}",
        "classification": classification,
        "subscores": subscores,
        "scam_phrases": scam_phrases,
        "language": language,
        "reasons": reasons,
        "headers": {k: v for k, v in parsed.items() if k not in ("body", "raw_headers")},
        "iocs": iocs,
        "geo_results": geo_results,
        "email_hash": email_hash,
        "seen_before": known_before,
        "campaigns": [{"id": c.id, "name": c.name, "case_count": len(c.cases)} for c in campaigns],
        "bec": {
            "domain_similarity": domain_sim,
            "display_name_check": name_check,
            "financial_intent": intent,
            "additive_score": bec_score,
        },
    })


@app.get("/api/ioc")
def get_ioc_intelligence(value: str, db: Session = Depends(get_db)):
    # query param (not a path segment) since IOC values can be full URLs with slashes
    return ioc_intelligence(db, value)


@app.get("/api/campaigns/{campaign_id}/detail")
def get_campaign_detail(campaign_id: int, db: Session = Depends(get_db)):
    return campaign_detail(db, campaign_id)


@app.get("/api/cases")
def list_cases(db: Session = Depends(get_db)):
    cases = db.query(models.Case).order_by(models.Case.upload_date.desc()).all()
    return [
        {
            "case_id": c.id, "subject": c.subject, "sender": c.sender,
            "verdict": c.verdict, "threat_score": c.threat_score,
            "language": c.language, "upload_date": c.upload_date.isoformat(),
        }
        for c in cases
    ]


@app.get("/api/campaigns")
def list_campaigns(db: Session = Depends(get_db)):
    return all_campaigns(db)


@app.get("/api/campaigns/{campaign_id}/graph")
def get_campaign_graph(campaign_id: int, db: Session = Depends(get_db)):
    return campaign_graph_data(db, campaign_id)


def _load_case_bundle(db: Session, case_id: int):
    case = db.query(models.Case).filter(models.Case.id == case_id).first()
    if not case:
        raise HTTPException(404, "Case not found")
    header_row = case.headers
    parsed = {
        "from": case.sender, "reply_to": header_row.reply_to if header_row else "",
        "subject": case.subject, "date": "", "spf": header_row.spf if header_row else "none",
        "dkim": header_row.dkim if header_row else "none", "dmarc": header_row.dmarc if header_row else "none",
        "from_domain": case.from_domain,
        "reply_domain": "",
    }
    iocs = {"ips": [], "urls": [], "domains": []}
    for ioc in case.iocs:
        if ioc.ioc_type == "ip":
            iocs["ips"].append(ioc.value)
        elif ioc.ioc_type == "url":
            iocs["urls"].append({"url": ioc.value, "domain": "", "reasons": []})
    classification = {"threat_score": case.threat_score, "verdict": case.verdict, "suspicious_words": [], "reassuring_words": []}
    geo_results = [geolocate_ip(ip) for ip in iocs["ips"]]
    for i, g in enumerate(geo_results):
        g["hop"] = i + 1
    reasons = build_explainable_reasons(classification, parsed, iocs, case.language)
    known = seen_before(db, "ip", iocs["ips"][0], exclude_case_id=case.id) if iocs["ips"] else {"known": False}
    return case, parsed, classification, iocs, geo_results, reasons, known


@app.get("/api/report/{case_id}")
def download_forensic_report(case_id: int, db: Session = Depends(get_db)):
    case, parsed, classification, iocs, geo_results, reasons, known = _load_case_bundle(db, case_id)
    path = os.path.join(REPORTS_DIR, f"forensic_{case_id}.pdf")
    build_forensic_report(path, case_id, parsed, classification, iocs, geo_results, reasons, case.email_hash, case.language, known)
    return FileResponse(path, filename=f"forensic_report_case_{case_id}.pdf")


@app.get("/api/complaint/{case_id}")
def download_complaint_draft(case_id: int, db: Session = Depends(get_db)):
    case, parsed, classification, iocs, geo_results, reasons, known = _load_case_bundle(db, case_id)
    path = os.path.join(REPORTS_DIR, f"complaint_{case_id}.pdf")
    build_complaint_draft(path, case_id, parsed, classification, iocs, geo_results, case.email_hash)
    return FileResponse(path, filename=f"complaint_draft_case_{case_id}.pdf")
