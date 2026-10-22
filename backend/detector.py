import whois
import socket
import tldextract
from datetime import datetime
from transformers import pipeline
from urllib.parse import urlparse

print("Loading ML Model...")
classifier = pipeline("text-classification", model="Eason918/malicious-url-detector")

def analyze_url(url: str):
    # --- A. ML Model Inference ---
    ml_result = classifier(url)[0]
    is_ml_malicious = ml_result['label'] == 'LABEL_1'
    ml_score = ml_result['score'] if is_ml_malicious else (1 - ml_result['score'])
    
    # --- B. Heuristic Checks ---
    heuristics = {}
    penalty = 0.0
    
    try:
        # 1. Keyword Heuristics (Catches suspicious paths)
        suspicious_keywords = ['login', 'verify', 'secure', 'account', 'update', 'banking', 'phishing', 'admin']
        url_lower = url.lower()
        found_keywords = [kw for kw in suspicious_keywords if kw in url_lower]
        
        if found_keywords:
            heuristics['suspicious_keywords'] = found_keywords
            penalty += 0.35 # Add a flat penalty if any suspicious keyword is found

        # Extract root domain properly using tldextract
        extracted = tldextract.extract(url)
        # This combines subdomain + domain + suffix (e.g., appspot.com)
        root_domain = f"{extracted.domain}.{extracted.suffix}"
        
        if not root_domain or root_domain == ".":
            # Fallback if parsing fails
            root_domain = urlparse(url).netloc or url.split('/')[0]

        # 2. DNS Resolution Check
        try:
            socket.gethostbyname(root_domain)
            heuristics['dns_resolved'] = True
        except socket.gaierror:
            heuristics['dns_resolved'] = False
            penalty += 0.4  # Severe penalty if domain doesn't exist
            
        # 3. WHOIS Domain Age Check
        try:
            w = whois.whois(root_domain)
            
            # Handle cases where whois returns a string instead of a dict (like your error)
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
            heuristics['whois_error'] = str(e)[:100] # Truncate long errors
            
    except Exception as e:
        heuristics['parsing_error'] = str(e)

    # --- C. Score Fusion ---
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
            "checks": heuristics
        }
    }