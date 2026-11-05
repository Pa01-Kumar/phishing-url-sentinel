
# Phishing URL Sentinel

A full-stack cybersecurity application that detects phishing URLs using a hybrid approach combining machine learning, real-time heuristic analysis, and threat intelligence.

**Live Demo:** [Phishing URL Sentinel](https://phishing-sentinel-two.vercel.app)

## Features

### 1. Machine Learning Detection
Analyzes URL character patterns using the Hugging Face Inference API and the `Eason918/malicious-url-detector` model.

### 2. Real-Time Heuristic Analysis

- **WHOIS Verification:** Flags domains registered less than 30 days ago.
- **DNS Resolution:** Identifies domains that fail to resolve to an IP address.
- **Keyword and Subdomain Inspection:** Detects suspicious patterns such as `login`, `verify`, `secure`, and `banking`.
- **Shannon Entropy Analysis:** Identifies high-entropy domains that may indicate algorithmically generated domain names.
- **Typosquatting and Homoglyph Detection:** Uses fuzzy matching to identify deceptive domains, such as `paypa1.com`.

### 3. Threat Intelligence Integration

- **VirusTotal and URLhaus:** Integrates external threat intelligence to identify potentially malicious URLs.
- **STIX 2.1 Export:** Generates standardized threat intelligence bundles for integration with SIEM and SOAR platforms.

### 4. Risk Scoring and Classification
Combines machine learning predictions with heuristic penalties to generate a risk score and classify URLs as:

- Benign
- Suspicious
- Malicious

### 5. Interactive Dashboard

- Live screenshot preview
- Redirect tracing
- User feedback mechanism
- Persistent scan history

## Tech Stack

| Component | Technologies |
|---|---|
| Backend | Python 3.10+, FastAPI, Uvicorn |
| Frontend | HTML5, Tailwind CSS, Vanilla JavaScript |
| Database | SQLite |
| Rate Limiting | SlowAPI |
| Machine Learning | Hugging Face Inference API |
| Threat Intelligence | VirusTotal, URLhaus |
| Deployment | Render, Vercel |

## Getting Started

Follow these instructions to run the application locally.

### Prerequisites

Ensure the following are installed or available:

1. Python 3.10 or later.
2. A VirusTotal API key. [Get a free API key](https://www.virustotal.com/).
3. A Hugging Face access token. [Generate a token](https://huggingface.co/settings/tokens).

### Step 1: Clone the Repository

Open a terminal and run:

```bash
git clone https://github.com/Pa01-Kumar/phishing-url-sentinel.git
cd phishing-url-sentinel
```

### Step 2: Set Up the Backend

Navigate to the backend directory:

```bash
cd backend
```

Create a virtual environment:

```bash
python -m venv venv
```

Activate the virtual environment.

**Windows:**

```powershell
.\venv\Scripts\activate
```

**macOS / Linux:**

```bash
source venv/bin/activate
```

Install the required dependencies:

```bash
pip install -r requirements.txt
```

#### Configure Environment Variables

Create a `.env` file inside the `backend` directory and add your API keys:

```dotenv
VIRUSTOTAL_API_KEY=your_virustotal_key_here
HF_TOKEN=hf_your_huggingface_token_here
```

Replace the placeholder values with your actual API keys.

**Security:** Never commit your `.env` file or expose API keys in your source code.

#### Start the Backend Server

Run the following command from the `backend` directory:

```bash
uvicorn main:app --reload
```

The backend API will start locally with automatic reloading enabled.

### Step 3: Set Up the Frontend

Open a new terminal window and navigate to the root directory of the project.

Start the frontend development server:

```bash
python -m http.server 8080 --directory frontend
```

Open your browser and visit:

[http://localhost:8080](http://localhost:8080)

The application is now available for local testing.

## VS Code: Selecting the Python Interpreter

If VS Code displays yellow warning lines under your Python imports, make sure the correct virtual environment is selected.

1. Press `Ctrl + Shift + P` on Windows/Linux or `Cmd + Shift + P` on macOS.
2. Search for `Python: Select Interpreter`.
3. Select the Python interpreter associated with your project's `venv` environment.

This allows VS Code to recognize the dependencies installed in your virtual environment.

## Deployment

The application uses a separate backend and frontend deployment to support free-tier hosting.

### Backend — Render

Configure the Render service with the following settings:

| Setting | Value |
|---|---|
| Root Directory | `backend` |
| Build Command | `pip install -r requirements.txt` |
| Start Command | `uvicorn main:app --host 0.0.0.0 --port $PORT` |

Add the following environment variables through the Render Dashboard:

```dotenv
VIRUSTOTAL_API_KEY=your_virustotal_key_here
HF_TOKEN=hf_your_huggingface_token_here
```

### Frontend — Vercel

Configure the Vercel project with:

| Setting | Value |
|---|---|
| Root Directory | `frontend` |

Ensure the frontend is configured to communicate with the deployed backend API.

## Security Architecture

### SSRF Protection
Blocks requests to internal IP addresses and cloud metadata endpoints to reduce the risk of Server-Side Request Forgery (SSRF).

### Rate Limiting
Limits scans to a maximum of five requests per minute per IP address to help prevent API quota exhaustion.

### Secret Management
API keys are stored in environment variables and excluded from version control.

## Project Structure

```text
phishing-url-sentinel/
├── backend/
│   ├── main.py
│   ├── requirements.txt
│   └── .env
├── frontend/
│   └── index.html
├── .gitignore
└── README.md
```

The structure above illustrates the main project components. The exact file structure may vary depending on your implementation.

## Contributing

Contributions, bug reports, and feature suggestions are welcome.

1. Fork the repository.
2. Create a new branch for your changes.
3. Commit your changes with a descriptive message.
4. Open a pull request.

## License

A license has not yet been specified. Add a `LICENSE` file to clarify the terms under which this project may be used, modified, and distributed.

