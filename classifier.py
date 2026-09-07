"""
Explainable phishing classifier (TF-IDF + Logistic Regression) and a
lightweight Indian-language detector (English / Hindi / Hinglish).
"""

import re
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression

from .train_data import PHISHING_SAMPLES, LEGITIMATE_SAMPLES, HINGLISH_MARKERS, SCAM_PHRASES

try:
    from langdetect import detect, DetectorFactory
    DetectorFactory.seed = 0
except ImportError:
    detect = None

DEVANAGARI_RE = re.compile(r"[\u0900-\u097F]")


class PhishingClassifier:
    def __init__(self):
        texts = PHISHING_SAMPLES + LEGITIMATE_SAMPLES
        labels = [1] * len(PHISHING_SAMPLES) + [0] * len(LEGITIMATE_SAMPLES)

        self.vectorizer = TfidfVectorizer(stop_words=None, ngram_range=(1, 1), lowercase=True)
        X = self.vectorizer.fit_transform(texts)

        self.model = LogisticRegression(max_iter=1000)
        self.model.fit(X, labels)

        self.feature_names = self.vectorizer.get_feature_names_out()
        self.coefs = self.model.coef_[0]

    def analyze(self, text: str) -> dict:
        text = text or ""
        X = self.vectorizer.transform([text])
        proba = self.model.predict_proba(X)[0][1]

        indices = X.nonzero()[1]
        contributions = []
        for idx in indices:
            word = self.feature_names[idx]
            weight = self.coefs[idx]
            tfidf_val = X[0, idx]
            contributions.append({
                "word": word,
                "weight": round(float(weight), 3),
                "impact": round(float(weight * tfidf_val), 4),
            })
        contributions.sort(key=lambda c: c["impact"], reverse=True)
        top_suspicious = [c for c in contributions if c["impact"] > 0][:8]
        top_reassuring = [c for c in contributions if c["impact"] < 0][:5]

        score_pct = round(proba * 100, 1)
        if score_pct >= 70:
            verdict = "High Risk"
        elif score_pct >= 35:
            verdict = "Medium Risk"
        else:
            verdict = "Low Risk"

        return {
            "threat_score": score_pct,
            "verdict": verdict,
            "suspicious_words": top_suspicious,
            "reassuring_words": top_reassuring,
        }


def detect_language(text: str) -> str:
    """Returns 'Hindi', 'Hinglish', or 'English'."""
    if not text or not text.strip():
        return "English"

    if DEVANAGARI_RE.search(text):
        return "Hindi"

    words = set(re.findall(r"[a-zA-Z]+", text.lower()))
    marker_hits = len(words & HINGLISH_MARKERS)

    if marker_hits >= 2:
        return "Hinglish"

    if detect is not None:
        try:
            lang = detect(text)
            if lang == "hi":
                return "Hindi"
        except Exception:
            pass

    return "English"


def extract_scam_phrases(text: str) -> list:
    """Returns the concrete scam phrases matched verbatim in the email text."""
    if not text:
        return []
    lower = text.lower()
    return [p for p in SCAM_PHRASES if p in lower]


def compute_subscores(classification: dict, headers: dict, iocs: dict, language: str) -> dict:
    """
    Breaks the single threat score into component signals for the dashboard
    bars: Email (language model), URL, Header, IOC, Language.
    Each is 0-100. Heuristic, built from signals we already computed —
    not a second model.
    """
    email_score = classification["threat_score"]

    url_score = 0
    urls = iocs.get("urls", [])
    if urls:
        flagged = sum(1 for u in urls if u["reasons"])
        url_score = min(100, round((flagged / len(urls)) * 100))
        if flagged and url_score < 40:
            url_score = 40  # any flagged URL is at least a moderate signal

    header_fail_count = sum([
        headers.get("spf") == "fail",
        headers.get("dkim") == "fail",
        headers.get("dmarc") == "fail",
        bool(headers.get("reply_domain")) and headers.get("reply_domain") != headers.get("from_domain"),
    ])
    header_score = min(100, header_fail_count * 25)

    ioc_score = 0  # filled in by caller once seen_before is known (network signal)

    language_score = 60 if language in ("Hindi", "Hinglish") else 0

    return {
        "email": round(email_score),
        "url": url_score,
        "header": header_score,
        "ioc": ioc_score,
        "language": language_score,
    }


def build_explainable_reasons(classification: dict, headers: dict, iocs: dict, language: str) -> list:
    """
    Turns raw signals into the human-readable checklist style requested:
    "Sender domain looks suspicious", "SPF failed", etc.
    """
    reasons = []
    if headers.get("spf") == "fail":
        reasons.append({"flag": "fail", "text": "SPF authentication failed"})
    if headers.get("dkim") == "fail":
        reasons.append({"flag": "fail", "text": "DKIM signature failed"})
    if headers.get("dmarc") == "fail":
        reasons.append({"flag": "fail", "text": "DMARC alignment failed"})
    if headers.get("reply_domain") and headers.get("reply_domain") != headers.get("from_domain"):
        reasons.append({"flag": "fail", "text": "Reply-To domain differs from sender domain"})
    for u in iocs.get("urls", []):
        if u["reasons"]:
            reasons.append({"flag": "fail", "text": f"Suspicious URL detected ({', '.join(u['reasons'])})"})
            break
    if classification["suspicious_words"]:
        reasons.append({"flag": "fail", "text": "Urgency/credential-harvesting language detected"})
    phrases = extract_scam_phrases(headers.get("body", "") + " " + headers.get("subject", ""))
    if phrases:
        reasons.append({
            "flag": "fail",
            "text": f'Scam phrase detected: "{phrases[0]}"' + (f" (+{len(phrases)-1} more)" if len(phrases) > 1 else ""),
        })
    if language in ("Hindi", "Hinglish"):
        reasons.append({"flag": "info", "text": f"Message language: {language} — common regional scam pattern"})
    if not reasons:
        reasons.append({"flag": "pass", "text": "No strong phishing indicators found"})
    return reasons
