# AI-Powered Email Threat Detection, Geolocation & Forensic Intelligence

FastAPI + MySQL-ready platform. Extends the earlier prototype with the
national-scale differentiators: a shared IOC threat-intelligence network,
automatic attack-campaign clustering, an interactive campaign relationship
graph, and Hinglish/Hindi phishing detection.

## Architecture

```
Upload .eml / paste raw email
        │
        ▼
   Email Parser (headers, body, hops)
        │
        ├── AI Phishing Classifier (explainable — TF-IDF + LogisticRegression)
        ├── Language Detector (English / Hindi / Hinglish)
        ├── Header Forensics (SPF / DKIM / DMARC / anomalies)
        └── IOC Extraction (IPs, domains, URLs)
        │
        ▼
      MySQL Database  ───────────────┐
        │                            │
        ▼                            ▼
   "Seen before?"              Attack Campaign
   (has this IOC                Clustering
    appeared before?)          (cases sharing an
        │                       IOC → one campaign)
        ▼                            │
   Threat Intelligence               ▼
      Banner                  Campaign Relationship
                                    Graph (vis-network)
        │                            │
        └──────────┬─────────────────┘
                    ▼
         Forensic PDF Report +
       Cybercrime Complaint Draft
```

## Project structure
```
threat_platform/
├── app/
│   ├── main.py           # FastAPI app + all routes
│   ├── database.py       # SQLAlchemy engine (MySQL or SQLite)
│   ├── models.py         # cases, headers, iocs, campaigns tables
│   ├── parser.py         # header forensics + IOC extraction
│   ├── classifier.py     # explainable phishing classifier + language detection
│   ├── train_data.py     # seed dataset (English + Hinglish)
│   ├── geolocation.py    # IP → approximate infrastructure location
│   ├── campaign.py       # seen-before + campaign clustering + graph data
│   ├── report.py         # forensic PDF + complaint-draft PDF
│   └── static/           # dashboard (index.html, style.css, script.js)
├── sample_emails/        # phishing_english.eml, phishing_hinglish.eml
│                          # (share IPs — analyze both to see campaign linking)
└── requirements.txt
```

## Run it
```bash
pip install -r requirements.txt
uvicorn app.main:app --reload
```
Open `http://localhost:8000`.

**No MySQL setup needed to try it** — by default it runs on a local SQLite
file (`threat_platform.db`), same schema, zero config.

### Switch to MySQL (for the real deployment)
```bash
export DATABASE_URL="mysql+pymysql://user:password@localhost:3306/threat_platform"
uvicorn app.main:app --reload
```
Create the database first: `CREATE DATABASE threat_platform;` — tables are
created automatically on startup from `models.py`.

## Demo flow that shows off the differentiators
1. Analyze `sample_emails/phishing_english.eml` — see explainable verdict,
   header forensics, IOCs, geolocation map.
2. Analyze `sample_emails/phishing_hinglish.eml` — same IP infrastructure,
   Hinglish text. Notice:
   - **Language detector** flags it as Hinglish
   - **"Seen before" banner** — the IP was already in case 1
   - **Campaign banner** — both cases get clustered into a shared campaign
3. Open the **Attack Campaigns** tab — click a campaign to see the
   relationship graph (cases ↔ shared IOCs).
4. Download the **Forensic Report** and **Cybercrime Complaint Draft** PDFs
   from either case.

## What's real vs. what to extend before a real submission
- **Classifier**: trained on a small seed set (`train_data.py`) — swap in a
  real corpus (Nazario phishing corpus + Enron ham; collect labeled
  Hinglish scam samples) before quoting accuracy numbers to judges.
- **Geolocation**: runs in offline demo mode by default. Set
  `use_live_api=True` + an `ipinfo.io` token in `main.py`'s `geolocate_ip()`
  calls for real lookups.
- **Language detection**: keyword-marker + langdetect hybrid — works well
  for common scam phrasing, not a full NLP language model.
- **Complaint draft**: explicitly labeled as a draft for the user to review
  and file themselves — this project does not submit anything to any
  government portal automatically, and the report says so.

## Important caveat to state in your demo
IP geolocation shows **approximate infrastructure location only**. VPNs,
proxies, cloud hosting, and compromised intermediary servers can all cause
the shown location to differ from the actual attacker — this disclaimer
appears in the UI, the PDF report, and the complaint draft.
