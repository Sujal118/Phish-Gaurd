<div align="center">
  <h1>🛡️ PhishGuard</h1>
  <p><b>Advanced, Rule-Based Phishing Email Detection System with 100% Explainability</b></p>

  [![Python](https://img.shields.io/badge/Python-3.9+-blue.svg?logo=python&logoColor=white)](https://www.python.org)
  [![React](https://img.shields.io/badge/React-18-61dafb.svg?logo=react&logoColor=black)](https://reactjs.org/)
  [![Flask](https://img.shields.io/badge/Flask-2.x-black.svg?logo=flask&logoColor=white)](https://flask.palletsprojects.com/)
  [![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](https://opensource.org/licenses/MIT)
</div>

---

## 📌 Project Overview
Traditional email filters rely heavily on blocklists and black-box machine learning models, making it difficult for users to understand *why* an email was blocked. **PhishGuard** solves this by structurally deconstructing raw emails (`.eml` files) to find deceptive tactics—providing fully explainable, deterministic risk scores.

**Built for Resonance'26 — VIT Pune | Cybersecurity Track**

## ✨ Core Features
- **Executive Summary & Diagnostics:** Analyzes emails and points directly to the deception (e.g., highlighting invisible Cyrillic characters disguised as English letters).
- **Interactive Threat Heatmap:** A Plotly.js visualization mapping specific headers and body text against our detection modules.
- **Phishing Forge Lab:** An educational "Red Team" simulation. It takes legitimate emails and auto-injects phishing tactics (homoglyphs, reply-to routing) with a side-by-side diff so users can see the attacker’s perspective.
- **Batch Processing & Threat Feed:** Simulate SOC (Security Operations Center) triaging by uploading a `.zip` of multiple emails, analyzing them concurrently, and ranking them in a live threat feed.
- **Downloadable Risk PDF:** Generates an enterprise-grade PDF report mapping risk breakdowns, authentication drops, and metadata.

---

## 🧠 The Risk Scoring Engine

The engine is completely rule-based and avoids ML hallucination, ensuring absolute explainability. The risk score (0-100) is calculated via the following weighted algorithm:

| Detection Module | Description | Weight |
|------------------|-------------|:------:|
| **SPF Validation** | Uses `dnspython` to perform live DNS TXT record lookups verifying if the sender IP is authorized. | 35 pts |
| **Domain Typosquatting** | Uses `python-Levenshtein` to mathematically calculate edit distance between the sender's domain and highly-targeted brands. | 25 pts |
| **Unicode Confusables** | Uses the `confusables` library to detect homograph attacks (e.g. Cyrillic `а` swapped for Latin `a`) hiding in text. | 20 pts |
| **Reply-To Mismatch** | Checks if the sender header doesn't match the hidden Reply-To header, a classic spoofing technique. | 10 pts |
| **Hop Count Anomaly** | Scans `Received` headers to detect messages routed through overly complex or abnormally short infrastructure. | 10 pts |

*Scores > 60 trigger a **High Risk** flag, triggering visual warnings across the dashboard.*

---

## ⚙️ Tech Stack
**Backend**:
- Python 3.9+
- Flask & Flask-CORS (REST API)
- ReportLab (PDF Generation)
- `dnspython`, `python-Levenshtein`, `confusables`

**Frontend**:
- React 18 (via CDN for local portability)
- Vanilla CSS / Bootstrap 5
- Plotly.js (Heatmap visualizations)

---

## 🚀 Quick Start Guide

### 1. Backend Setup
Clone the repository and install the Python dependencies:
```bash
git clone https://github.com/yourusername/phishguard.git
cd phishguard/backend
pip install -r requirements.txt
```

Launch the Flask server:
```bash
python app.py
```
*The API will start running on `http://127.0.0.1:5000`*

### 2. Frontend Setup
Because PhishGuard's frontend was built to be highly portable for hackathons, you do not need to install `npm` modules. You can simply serve the directory.

In a new terminal wrapper:
```bash
cd phishguard/frontend
npx serve .
# OR use Python's built-in server: python -m http.server 3000
```
Open **`http://localhost:3000`** in your browser to view the dashboard!

---

## 📂 Repository Structure
```text
phishguard/
├── backend/
│   ├── analyzer/           # Detection engine logic (SPF, Unicode, Typosquatting)
│   ├── reports/            # PDF Generation with ReportLab
│   ├── forge/              # Spoofing simulation logic
│   ├── app.py              # Main Flask server
│   └── requirements.txt    # Python dependencies
├── frontend/
│   ├── components/         # React Components (Scorecard, Heatmap, ForgeLab)
│   ├── index.html          # Entry-point
│   ├── dashboard.jsx       # Main Dashboard UI
│   └── styles.css          # Core Styling & Theming
└── datasets/               # Sample safe/phishing emails for testing
```

---

## 🎓 Learning & Testing Data
We have provided sample emails specifically designed to trigger the detection modules. To test the dashboard, you can drag & drop the `.eml` files located inside the `datasets/phishing/` or `datasets/legit/` directories, or you can copy raw text from `datasets/paste_mails/` directly into the web app!

---

<div align="center">
<i>Built for the Cybersecurity Track @ Resonance'26</i><br>
<i>Department of CSE (AI & ML), VIT Pune Bibwewadi</i>
</div>
