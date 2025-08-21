
# ScamShield Seniors — Simple Scam & URL Triage for Older Adults

**One-screen, accessible tool** that explains *why* a message/URL is risky and **what to do next**.
Built for open-ended hackathons with security-focused judges.

## 🎯 Problem
Scams via SMS/WhatsApp/email disproportionately impact older adults. Triage is confusing and time-sensitive, leading to financial loss and stress.

## ✅ Solution
Paste a message or link to get:
- A **traffic-light verdict** (Safe / Suspicious / Malicious)
- **Plain-English reasons** (e.g., urgent tone, odd domain, `@` in URL, punycode)
- **Action steps** (what to do next) and **reporting resources**
- Optional **CSV batch** triage for caregivers/analysts

All logic is **explainable heuristics** (no external feeds) to keep the MVP fast and transparent.

## 🧩 Features
- Message heuristics: urgency/pressure language, financial/credential triggers, ALL-CAPS spamminess
- URL heuristics: non-HTTPS, IP host, too many dots, `@` symbol, punycode, rare TLD, lookalike chars, long URL, params
- Accessibility-first UI: large text, high-contrast, clear labels
- Privacy-friendly: no data stored server-side

## 🖥️ Quick Start
```bash
# 1) (Recommended) Create a virtual environment
python -m venv .venv
# macOS/Linux
source .venv/bin/activate
# Windows
# .venv\Scripts\activate

# 2) Install dependencies
pip install -r requirements.txt

# 3) Run the Streamlit app
streamlit run streamlit_app.py
```

Then open the local URL Streamlit prints (usually http://localhost:8501).

## 🧪 Try It Fast
Use `sample_messages.csv` and `sample_urls.csv` to demo batch triage.

## 📁 Structure
```
scamshield-seniors/
├── scamshield/
│   ├── __init__.py
│   ├── core.py              # heuristics & scoring
│   ├── explain.py           # plain-English reason formatting
│   └── resources.py         # "what to do next" & reporting links
├── streamlit_app.py         # web UI
├── requirements.txt
├── sample_messages.csv
├── sample_urls.csv
├── LICENSE
└── README.md
```

## 🧠 How We Score (0–100)
- **Message signals**: urgency/pressure, sensitive terms, all-caps, emoji spam, suspicious numbers/shortcodes.
- **URL signals**: HTTP, IP host, many dots, `@` present, punycode/unicode, rare TLD, lookalikes (I/l/1, o/0), long length, many params.
- Verdicts:
  - **0–29** → Safe
  - **30–59** → Suspicious
  - **60+** → Malicious

> ⚠️ Prototype for triage/education. Don’t use as sole decision engine in production.

## 🗣️ Demo Script (3–5 min)
1. **Problem (20–30s):** scams target seniors; triage is hard.
2. **Solution (30–45s):** one-screen verdict + reasons + steps.
3. **Live demo (2m):** paste benign vs phishy message; paste phishy URL; run CSV batch.
4. **Under the hood (45s):** explainable heuristics; privacy-first.
5. **Impact & next (30–45s):** libraries/senior centers, browser extension, WHOIS/ML, multilingual.

## 🚀 What’s Next
- WHOIS domain age
- Lightweight ML refinement
- Browser extension (MV3) using same core
- Multilingual support

## 📄 License
MIT — see `LICENSE`.
