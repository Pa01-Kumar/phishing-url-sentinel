# 🛡️ Phishing URL Sentinel

A full-stack cybersecurity application that detects phishing URLs using a hybrid approach: Machine Learning and real-time heuristic analysis.

## 🚀 Features & How it Works
1. **Machine Learning:** Analyzes URL character patterns using a Hugging Face Transformer model (`Eason918/malicious-url-detector`).
2. **Real-Time Heuristics & Threat Intelligence:**
   * **WHOIS Verification:** Flags domains registered less than 30 days ago.
   * **DNS Resolution Check:** Flags domains that fail IP resolution.
   * **Keyword & Subdomain Inspection:** Flags deception patterns (e.g., "login", "verify", "secure", "banking").
   * **Shannon Entropy Analysis:** Detects algorithmic domain generation (DGA).
   * **VirusTotal API Integration:** Aggregates real-time threat intelligence from 70+ antivirus engines.
   * **STIX 2.1 Threat Intel Export:** Generates standardized threat intel bundles for SIEM/SOAR integration.
3. **Score Fusion:** Combines ML probability with heuristic penalties to output an actionable Risk Score and Verdict (Benign, Suspicious, Malicious).
4. **Interactive Dashboard:** Live screenshot preview, full redirect tracer, feedback mechanism, and persistent scan history.

---

## 🛠️ Tech Stack
* **Backend:** Python 3.10+, FastAPI, Uvicorn, Hugging Face Transformers, PyTorch (CPU-optimized), SQLite
* **Frontend:** Responsive HTML5, Tailwind CSS, Vanilla JS

---

## ☁️ Free Cloud Deployment Options

### Option 1: Hugging Face Spaces (Recommended for ML)
Hugging Face Spaces provides a **free 16 GB RAM CPU tier** with no credit card required—ideal for PyTorch and Transformers!

1. Go to [Hugging Face Spaces: New Space](https://huggingface.co/new-space).
2. Enter a **Space name** (e.g., `phishing-url-sentinel`).
3. Set **License** to `mit` or `apache-2.0`.
4. Select **Docker** as the Space SDK and choose **Blank**.
5. Push your repository to your Space:
   ```bash
   git remote add space https://huggingface.co/spaces/<your-username>/phishing-url-sentinel
   git push space main
   ```
6. Under **Settings -> Variables and secrets**, add `VIRUSTOTAL_API_KEY` (optional).
7. Hugging Face automatically builds the container and provides your public HTTPS URL:
   `https://<your-username>-phishing-url-sentinel.hf.space`

---

### Option 2: Render.com
1. Go to the [Render Dashboard](https://dashboard.render.com/) and click **New +** -> **Web Service**.
2. Connect your GitHub repository `Pa01-Kumar/phishing-url-sentinel`.
3. Render detects the root `Dockerfile` and `render.yaml` automatically.
4. Select the **Free** instance type.
5. In **Environment Variables**, add `VIRUSTOTAL_API_KEY`.
6. Click **Deploy Web Service** to get a live HTTPS URL (e.g., `https://phishing-url-sentinel.onrender.com`).

---

## 💻 Running Locally

### 1. Using Python
```bash
# Clone the repository
git clone https://github.com/Pa01-Kumar/phishing-url-sentinel.git
cd phishing-url-sentinel

# Create and activate virtual environment
python -m venv venv
# On Windows: .\venv\Scripts\activate
# On Mac/Linux: source venv/bin/activate

# Install dependencies
pip install torch --index-url https://download.pytorch.org/whl/cpu
pip install -r requirements.txt

# Run unified server
uvicorn backend.main:app --reload --port 8000
```
Open **http://127.0.0.1:8000** in your browser.

### 2. Using Docker
```bash
docker build -t phishing-sentinel .
docker run -p 7860:7860 -e VIRUSTOTAL_API_KEY="your_key" phishing-sentinel
```
Open **http://localhost:7860** in your browser.
