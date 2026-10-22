import os
import whois
import socket
import tldextract
import requests
import time
from datetime import datetime
from transformers import pipeline
from urllib.parse import urlparse
from dotenv import load_dotenv

# Load API key from .env file
load_dotenv()
VT_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")

print("Loading ML Model...")
classifier = pipeline("text-classification", model="Eason918/malicious-url-detector")

def trace_redirects(url: str):
    chain = [url]
    penalty = 0.0
    final_url = url
    try:
        response = requests.get(url, timeout=5, allow_redirects=True, stream=True)
        if response.history:
            for resp in response.history:
                chain.append(resp.url)
            final_url = response.url
            chain.append(final_url)
            penalty = min(len(response.history) * 0.1, 0.3)
    except Exception:
        pass # Silently fail if site is down
    return final_url, chain, penalty

def check_virustotal(url: str):
    """Queries VirusTotal for the URL report."""
    if not VT_API_KEY or VT_API_KEY == "your_long_api_key_here":
        return {"error": "VirusTotal API key not configured."}
    
    headers = {"x-apikey": VT_API_KEY}
    # VT API v3 expects the URL to be base64 encoded without padding for the GET request
    import base64
    url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
    
    # 1. Try to get an existing report
    response = requests.get(f"https://www.virustotal.com/api/v3/urls/{url_id}", headers=headers)
    
    if response.status_code == 200:
        stats = response.json()['data']['attributes']['last_analysis_stats']
        malicious_count = stats.get('malicious', 0)
        suspicious_count = stats.get('suspicious', 0)
        harmless_count = stats.get('harmless', 0)
        total_engines = malicious_count + suspicious_count + harmless_count + stats.get('undetected', 0)
        
        return {
            "malicious": malicious_count,
            "suspicious": suspicious_count,
            "total_engines": total_engines,
            "vt_penalty": min(malicious_count * 0.15, 0.6) # Add up to 0.6 penalty based on detections
        }
    
    # 2. If not found, submit the URL (Note: For a beginner project, we'll just return 0 if it's a new URL to avoid long wait times)
    return {"malicious": 0, "suspicious": 0, "total_engines": 70, "vt_penalty": 0.0, "note": "URL not in VT database yet."}

def analyze_url(url: str):
    # --- A. Trace Redirects First ---
    final_url, redirect_chain, redirect_penalty = trace_redirects(url)
    
    # --- B. ML Model Inference ---
    ml_result = classifier(final_url)[0]
    is_ml_malicious = ml_result['label'] == 'LABEL_1'
    ml_score = ml_result['score'] if is_ml_malicious else (1 - ml_result['score'])
    
    # --- C. VirusTotal Check ---
    vt_result = check_virustotal(final_url)
    vt_penalty = vt_result.get('vt_penalty', 0.0)
    
    # --- D. Heuristic Checks ---
    heuristics = {}
    penalty = redirect_penalty + vt_penalty # Start with redirect and VT penalties
    
    try:
        suspicious_keywords = ['login', 'verify', 'secure', 'account', 'update', 'banking', 'phishing', 'admin']
        url_lower = final_url.lower()
        found_keywords = [kw for kw in suspicious_keywords if kw in url_lower]
        
        if found_keywords:
            heuristics['suspicious_keywords'] = found_keywords
            penalty += 0.35

        extracted = tldextract.extract(final_url)
        root_domain = f"{extracted.domain}.{extracted.suffix}"
        
        if not root_domain or root_domain == ".":
            root_domain = urlparse(final_url).netloc or final_url.split('/')[0]

        try:
            socket.gethostbyname(root_domain)
            heuristics['dns_resolved'] = True
        except socket.gaierror:
            heuristics['dns_resolved'] = False
            penalty += 0.4
            
        try:
            w = whois.whois(root_domain)
            if isinstance(w, str):
                 heuristics['whois_error'] = "No WHOIS record found."
            else:
                creation_date = w.creation_date
                if isinstance(creation_date, list):
                    creation_date = creation_date[0]
                if creation_date:
                    if creation_date.tzinfo:
                        now = datetime.now(creation_date.tzinfo)
                    else:
                        now = datetime.now()
                    age_days = (now - creation_date).days
                    heuristics['domain_age_days'] = age_days
                    if age_days < 30:
                        penalty += 0.3
                else:
                    heuristics['domain_age_days'] = "Unknown"
        except Exception as e:
            heuristics['whois_error'] = str(e)[:100]
            
    except Exception as e:
        heuristics['parsing_error'] = str(e)

    # --- E. Score Fusion ---
    final_score = min(ml_score + penalty, 1.0)
    
    if final_score >= 0.7:
        verdict = "malicious"
    elif final_score >= 0.3:
        verdict = "suspicious"
    else:
        verdict = "benign"

    return {
        "url": url,
        "risk_score": round(final_score, 3),
        "verdict": verdict,
        "details": {
            "ml_model_score": round(ml_score, 3),
            "heuristic_penalty": round(penalty, 3),
            "redirect_chain": redirect_chain,
            "virustotal_stats": vt_result, # Send VT data to frontend
            "checks": heuristics
        }
    }