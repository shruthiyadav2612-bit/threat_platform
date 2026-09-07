"""
Email parsing: header forensics + IOC extraction.
Reused/extended from the earlier prototype's analyzer.py.
"""

import re
import hashlib
from email import message_from_string
from email.utils import parseaddr

IP_RE = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}"
    r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b"
)
URL_RE = re.compile(r"https?://[^\s\"'<>\)]+")
DOMAIN_IN_URL_RE = re.compile(r"https?://([a-zA-Z0-9.-]+)")
DOMAIN_RE = re.compile(r"@([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})")

SUSPICIOUS_TLDS = {"xyz", "top", "click", "gq", "tk", "ml", "cf"}
URL_SHORTENERS = {"bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd"}


def _domain_of(addr: str) -> str:
    _, email_addr = parseaddr(addr or "")
    m = DOMAIN_RE.search("@" + email_addr.split("@")[-1] if email_addr else "")
    return m.group(1).lower() if m else ""


def _extract_auth_status(auth_header: str, mechanism: str) -> str:
    m = re.search(rf"{mechanism}=(\w+)", auth_header, re.IGNORECASE)
    return m.group(1).lower() if m else "none"


def _get_body(msg) -> str:
    if msg.is_multipart():
        parts = []
        for part in msg.walk():
            if part.get_content_type() == "text/plain":
                try:
                    parts.append(part.get_payload(decode=True).decode(errors="ignore"))
                except Exception:
                    pass
        return "\n".join(parts) if parts else ""
    try:
        payload = msg.get_payload(decode=True)
        return payload.decode(errors="ignore") if payload else msg.get_payload()
    except Exception:
        return msg.get_payload() if isinstance(msg.get_payload(), str) else ""


def parse_email(raw_email: str) -> dict:
    msg = message_from_string(raw_email)

    from_addr = msg.get("From", "")
    reply_to = msg.get("Reply-To", "")
    return_path = msg.get("Return-Path", "")
    subject = msg.get("Subject", "(no subject)")
    date = msg.get("Date", "")
    message_id = msg.get("Message-ID", "")

    received_chain = msg.get_all("Received", []) or []
    auth_results = msg.get("Authentication-Results", "") or ""
    spf = _extract_auth_status(auth_results, "spf")
    dkim = _extract_auth_status(auth_results, "dkim")
    dmarc = _extract_auth_status(auth_results, "dmarc")

    from_domain = _domain_of(from_addr)
    reply_domain = _domain_of(reply_to) if reply_to else ""

    anomalies = []
    if reply_domain and reply_domain != from_domain:
        anomalies.append(f"Reply-To domain ({reply_domain}) does not match From domain ({from_domain})")
    if spf == "fail":
        anomalies.append("SPF check failed — sending server not authorized for this domain")
    if dkim == "fail":
        anomalies.append("DKIM signature failed — message may have been altered in transit")
    if dmarc == "fail":
        anomalies.append("DMARC policy failed — domain alignment check did not pass")
    if not received_chain:
        anomalies.append("No Received headers found — header chain may be stripped or forged")
    if not message_id:
        anomalies.append("Missing Message-ID — unusual for legitimate mail servers")

    hops = []
    for i, hop in enumerate(reversed(received_chain)):
        ips = IP_RE.findall(hop)
        if ips:
            hops.append({"hop": i + 1, "ip": ips[0], "raw": hop[:180]})

    body = _get_body(msg)

    return {
        "from": from_addr,
        "reply_to": reply_to,
        "return_path": return_path,
        "subject": subject,
        "date": date,
        "message_id": message_id,
        "spf": spf,
        "dkim": dkim,
        "dmarc": dmarc,
        "from_domain": from_domain,
        "reply_domain": reply_domain,
        "anomalies": anomalies,
        "hops": hops,
        "body": body,
        "raw_headers": "\n".join(f"{k}: {v}" for k, v in msg.items()),
    }


def extract_iocs(raw_email: str, parsed: dict) -> dict:
    body = parsed.get("body", "") + "\n" + raw_email
    ips = sorted(set(IP_RE.findall(raw_email)))
    urls = sorted(set(URL_RE.findall(body)))
    domains = sorted(set(DOMAIN_IN_URL_RE.findall(body)))

    flagged_urls = []
    for url in urls:
        reasons = []
        m = DOMAIN_IN_URL_RE.search(url)
        domain = m.group(1) if m else ""
        tld = domain.split(".")[-1].lower() if "." in domain else ""
        if IP_RE.match(domain):
            reasons.append("uses raw IP instead of domain name")
        if domain in URL_SHORTENERS:
            reasons.append("known URL shortener (hides real destination)")
        if tld in SUSPICIOUS_TLDS:
            reasons.append(f"high-risk TLD (.{tld})")
        flagged_urls.append({"url": url, "domain": domain, "reasons": reasons})

    return {"ips": ips, "domains": domains, "urls": flagged_urls}


def sha256_of(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", errors="ignore")).hexdigest()
