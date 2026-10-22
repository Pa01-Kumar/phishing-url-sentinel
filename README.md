# Spamdetection
# 🛡️ Phishing URL Sentinel

A full-stack cybersecurity application that detects phishing URLs using a hybrid approach: Machine Learning and real-time heuristic analysis.

## 🧠 How it Works
1. **Machine Learning:** Analyzes URL character patterns using a Hugging Face Transformer model.
2. **Heuristics:** 
   * **WHOIS Check:** Flags domains registered less than 30 days ago.
   * **DNS Check:** Flags domains that do not resolve to an IP.
   * **Keyword Analysis:** Flags URLs containing deceptive terms (e.g., "login", "verify", "secure").
3. **Score Fusion:** Combines the ML confidence with the heuristic penalties to output a final Risk Score and Verdict (Benign, Suspicious, Malicious).

## 🛠️ Tech Stack
* **Backend:** Python, FastAPI, Uvicorn, Transformers, PyTorch, python-whois, tldextract
* **Frontend:** HTML, Tailwind CSS, Vanilla JavaScript

## 🚀 How to Run Locally

### 1. Backend Setup
```bash
cd backend
python -m venv venv
# Windows: .\venv\Scripts\activate
# Mac/Linux: source venv/bin/activate
pip install -r requirements.txt
uvicorn main:app --reload