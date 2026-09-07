"""
Business Email Compromise / CEO-impersonation detection layer.
Adds a second, fully transparent additive risk score alongside the ML
classifier — two independent methods agreeing is a strong signal.
"""

import re
import difflib
from email.utils import parseaddr

# Known-good domains to compare against for look-alike detection.
# In production this would be the organization's own domain list;
# for the demo we detect look-alikes against a small trusted set.
TRUSTED_DOMAINS = [
    "company.com", "sbi.co.in", "paypal.com", "microsoft.com",
    "google.com", "gmail.com", "outlook.com",
]

FINANCIAL_TERMS = {
    "transfer", "payment", "wire", "bank account", "invoice",
    "urgent payment", "account number", "ifsc", "swift", "beneficiary",
    "reimbursement", "vendor payment", "gift card", "purchase order",
}
CREDENTIAL_TERMS = {
    "password", "login", "otp", "verify your account", "credentials",
    "reset your password", "confirm your identity", "pin",
}
URGENCY_TERMS = {
    "urgent", "asap", "immediately", "today", "do not delay",
    "confidential", "right away", "as soon as possible", "before eod",
}

CEO_TITLE_PATTERN = re.compile(
    r"\b(ceo|cfo|coo|director|founder|president|managing director|md)\b", re.IGNORECASE
)


def domain_similarity(observed_domain: str, trusted_domains: list = None) -> dict:
    """
    Finds the closest trusted domain to the observed one via difflib and
    flags a look-alike if it's suspiciously close but not an exact match
    (classic typosquat pattern: cornpany.com vs company.com).
    """
    trusted_domains = trusted_domains or TRUSTED_DOMAINS
    if not observed_domain:
        return {"closest_domain": None, "similarity": 0, "is_lookalike": False}

    if observed_domain in trusted_domains:
        return {"closest_domain": observed_domain, "similarity": 100, "is_lookalike": False}

    best_domain, best_score = None, 0.0
    for td in trusted_domains:
        score = difflib.SequenceMatcher(None, observed_domain, td).ratio()
        if score > best_score:
            best_score, best_domain = score, td

    similarity_pct = round(best_score * 100, 1)
    is_lookalike = 0.80 <= best_score < 1.0  # close but not identical = typosquat zone

    return {"closest_domain": best_domain, "similarity": similarity_pct, "is_lookalike": is_lookalike}


def display_name_check(from_header: str) -> dict:
    """
    Flags when the display name claims an executive title (e.g. "Rahul
    Sharma – CEO") but the underlying address domain looks unrelated /
    freemail, which is a classic CEO-impersonation pattern.
    """
    display_name, addr = parseaddr(from_header or "")
    claims_executive = bool(CEO_TITLE_PATTERN.search(display_name or ""))
    domain = addr.split("@")[-1].lower() if "@" in addr else ""
    freemail = domain in {"gmail.com", "yahoo.com", "outlook.com", "hotmail.com", "protonmail.com"}

    mismatch = claims_executive and (freemail or not domain)
    return {
        "display_name": display_name,
        "claims_executive_title": claims_executive,
        "sender_domain": domain,
        "mismatch": mismatch,
    }


def financial_intent(text: str) -> dict:
    """Classifies what the email is actually asking for, not just tone."""
    lower = (text or "").lower()

    financial_hits = [t for t in FINANCIAL_TERMS if t in lower]
    credential_hits = [t for t in CREDENTIAL_TERMS if t in lower]
    urgency_hits = [t for t in URGENCY_TERMS if t in lower]

    def level(hits, strong_threshold=2):
        if not hits:
            return "NONE"
        return "HIGH" if len(hits) >= strong_threshold else "MEDIUM"

    return {
        "financial_request": level(financial_hits),
        "credential_request": level(credential_hits, strong_threshold=1),
        "urgency": level(urgency_hits),
        "matched_financial_terms": financial_hits,
        "matched_credential_terms": credential_hits,
        "matched_urgency_terms": urgency_hits,
    }


def additive_risk_score(headers: dict, domain_sim: dict, name_check: dict, intent: dict) -> dict:
    """
    Transparent point-based score — independent of the ML model, so
    agreement between the two methods is meaningful evidence.
    """
    breakdown = []

    def add(label, points, condition):
        if condition:
            breakdown.append({"label": label, "points": points})

    add("Look-alike domain detected", 20, domain_sim["is_lookalike"])
    add("Display name claims executive title but sender domain is unrelated", 20, name_check["mismatch"])
    add("Reply-To domain differs from sender domain", 15, headers.get("reply_domain") and headers.get("reply_domain") != headers.get("from_domain"))
    add("SPF authentication failed", 10, headers.get("spf") == "fail")
    add("DKIM authentication failed", 10, headers.get("dkim") == "fail")
    add("DMARC authentication failed", 10, headers.get("dmarc") == "fail")
    add("Financial transaction request detected", 10, intent["financial_request"] in ("MEDIUM", "HIGH"))
    add("Urgency language detected", 5, intent["urgency"] in ("MEDIUM", "HIGH"))

    total = min(100, sum(b["points"] for b in breakdown))
    if total >= 60:
        verdict = "HIGH RISK — Possible CEO Impersonation / BEC"
    elif total >= 30:
        verdict = "MEDIUM RISK — Review recommended"
    else:
        verdict = "LOW RISK"

    return {"total": total, "verdict": verdict, "breakdown": breakdown}
