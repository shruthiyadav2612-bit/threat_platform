"""
Generates two PDF documents:
  1. Forensic Threat Report — full technical evidence
  2. Cybercrime Complaint Draft — structured for filing at cybercrime.gov.in
     style portals. NOT an official submission — a pre-filled draft the
     user reviews and files themselves.
"""

from datetime import datetime
from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.units import mm
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle


def _base_doc(path):
    doc = SimpleDocTemplate(path, pagesize=A4, topMargin=20 * mm, bottomMargin=20 * mm)
    styles = getSampleStyleSheet()
    return doc, styles


def build_forensic_report(path: str, case_id: int, headers: dict, classification: dict,
                           iocs: dict, geo_results: list, reasons: list, email_hash: str,
                           language: str, seen_before_info: dict):
    doc, styles = _base_doc(path)
    h2 = styles["Heading2"]
    normal = styles["Normal"]
    small = ParagraphStyle("small", parent=normal, fontSize=8, textColor=colors.grey)
    title_style = ParagraphStyle("TitleX", parent=styles["Title"], fontSize=18)

    story = []
    story.append(Paragraph("Cyber Forensic Threat Report", title_style))
    story.append(Paragraph(f"Case ID: CT-2026-{case_id:05d} &nbsp;&nbsp;|&nbsp;&nbsp; Generated: {datetime.utcnow().isoformat()}Z", small))
    story.append(Spacer(1, 10))

    verdict_color = {
        "High Risk": "#c0392b", "Medium Risk": "#e67e22", "Low Risk": "#27ae60",
    }.get(classification["verdict"], "#000000")
    story.append(Paragraph(
        f'<font color="{verdict_color}"><b>Verdict: {classification["verdict"]} ({classification["threat_score"]}%)</b></font>',
        h2))
    story.append(Paragraph(f"Detected language: {language}", normal))
    story.append(Spacer(1, 8))

    story.append(Paragraph("Explainable Evidence Checklist", h2))
    for r in reasons:
        mark = "✗" if r["flag"] == "fail" else ("ℹ" if r["flag"] == "info" else "✓")
        story.append(Paragraph(f"{mark} {r['text']}", normal))
    story.append(Spacer(1, 10))

    if seen_before_info and seen_before_info.get("known"):
        story.append(Paragraph("Threat Intelligence — Known IOC", h2))
        story.append(Paragraph(
            f"One or more indicators in this email were seen in {seen_before_info['times_seen']} "
            f"prior case(s): {seen_before_info['case_ids']}. This may be part of a coordinated campaign.",
            normal))
        story.append(Spacer(1, 10))

    story.append(Paragraph("Header Forensics", h2))
    header_data = [
        ["Field", "Value"],
        ["From", headers.get("from", "")],
        ["Reply-To", headers.get("reply_to", "") or "-"],
        ["Subject", headers.get("subject", "")],
        ["Date", headers.get("date", "")],
        ["SPF", headers.get("spf", "")],
        ["DKIM", headers.get("dkim", "")],
        ["DMARC", headers.get("dmarc", "")],
    ]
    t = Table(header_data, colWidths=[80 * mm, 90 * mm])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#2c3e50")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
    ]))
    story.append(t)
    story.append(Spacer(1, 10))

    story.append(Paragraph("Indicators of Compromise (IOCs)", h2))
    ioc_rows = [["Type", "Value"]]
    for ip in iocs.get("ips", []):
        ioc_rows.append(["IP", ip])
    for u in iocs.get("urls", []):
        flag = f" ({', '.join(u['reasons'])})" if u["reasons"] else ""
        ioc_rows.append(["URL", u["url"][:65] + flag])
    if len(ioc_rows) == 1:
        ioc_rows.append(["-", "No IOCs extracted"])
    t2 = Table(ioc_rows, colWidths=[30 * mm, 140 * mm])
    t2.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#2c3e50")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
        ("FONTSIZE", (0, 0), (-1, -1), 8),
    ]))
    story.append(t2)
    story.append(Spacer(1, 10))

    story.append(Paragraph("Infrastructure Geolocation (Approximate)", h2))
    story.append(Paragraph(
        "<i>Reflects approximate infrastructure location only — VPNs, proxies, and "
        "compromised hosts can mislead attribution.</i>", small))
    geo_rows = [["Hop", "IP", "City", "Country", "Org"]]
    for g in geo_results:
        geo_rows.append([str(g.get("hop", "-")), g["ip"], g.get("city", "-"), g.get("country", "-"), (g.get("org") or "-")[:30]])
    if len(geo_rows) == 1:
        geo_rows.append(["-", "-", "-", "-", "-"])
    t3 = Table(geo_rows, colWidths=[15 * mm, 30 * mm, 35 * mm, 25 * mm, 65 * mm])
    t3.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#2c3e50")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
        ("FONTSIZE", (0, 0), (-1, -1), 8),
    ]))
    story.append(t3)
    story.append(Spacer(1, 10))

    story.append(Paragraph("Chain of Custody", h2))
    story.append(Paragraph(f"SHA-256 of original email: <font face='Courier'>{email_hash}</font>", small))

    doc.build(story)


def build_complaint_draft(path: str, case_id: int, headers: dict, classification: dict,
                           iocs: dict, geo_results: list, email_hash: str):
    doc, styles = _base_doc(path)
    h2 = styles["Heading2"]
    normal = styles["Normal"]
    small = ParagraphStyle("small", parent=normal, fontSize=8, textColor=colors.grey)
    title_style = ParagraphStyle("TitleX", parent=styles["Title"], fontSize=16)

    story = []
    story.append(Paragraph("Cybercrime Incident Report — Draft", title_style))
    story.append(Paragraph(
        "This is a pre-filled DRAFT to assist filing at your national/state cybercrime "
        "reporting portal (e.g. cybercrime.gov.in). It is not an official submission — "
        "review, add any missing details, and file it yourself through the official channel.",
        small))
    story.append(Spacer(1, 10))

    rows = [
        ["Field", "Details"],
        ["Case Reference", f"CT-2026-{case_id:05d}"],
        ["Incident Type", "Phishing / Email-based Fraud"],
        ["Date/Time Reported", datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")],
        ["Threat Assessment", f"{classification['verdict']} ({classification['threat_score']}%)"],
        ["Sender Address", headers.get("from", "")],
        ["Subject Line", headers.get("subject", "")],
        ["Suspicious URLs", "; ".join(u["url"] for u in iocs.get("urls", [])[:5]) or "-"],
        ["Source IP(s)", "; ".join(iocs.get("ips", [])[:5]) or "-"],
        ["Approx. Infrastructure Location", "; ".join(f"{g.get('city')}, {g.get('country')}" for g in geo_results) or "-"],
        ["Authentication Failures", f"SPF: {headers.get('spf')}, DKIM: {headers.get('dkim')}, DMARC: {headers.get('dmarc')}"],
        ["Financial Loss (if any)", "[ To be filled by complainant ]"],
        ["Evidence Reference", f"SHA-256: {email_hash[:32]}..."],
    ]
    t = Table(rows, colWidths=[55 * mm, 115 * mm])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#2c3e50")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
        ("FONTSIZE", (0, 0), (-1, -1), 8),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
    ]))
    story.append(t)
    story.append(Spacer(1, 12))
    story.append(Paragraph(
        "Recommended Action: Do not click any links in the original email. Change "
        "passwords for any account referenced. File this draft at your national "
        "cybercrime portal and attach the full Forensic Threat Report as evidence.",
        normal))

    doc.build(story)
