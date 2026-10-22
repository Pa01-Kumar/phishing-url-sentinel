import whois
import socket
import tldextract
import requests
from datetime import datetime
from transformers import pipeline
from urllib.parse import urlparse

print("Loading ML Model...")
classifier = pipeline("text-classification", model="Eason918/malicious-url-detector")

def trace_redirects(url: str):
    """Follows redirects to find the final destination URL."""
    chain = [url]
    penalty = 0.0
    final_url = url
    
    try:
        # Send a request but don't download the whole page, just the headers
        response = requests.get(url, timeout=5, allow_redirects=True, stream=True)
        
        # If there was a redirect, record the history
        if response.history:
            for resp in response.history:
                chain.append(resp.url)
            final_url = response.url
            chain.append(final_url)
            
            # Penalize based on how many times it redirected (max 0.3 penalty)
            penalty = min(len(response.history) * 0.1, 0.3)
            
    except Exception as e:
        # If the site is down, it will timeout or throw an error
        chain.append("Error tracing redirects (Site may be offline)")
        
    return final_url, chain, penalty

def analyze_url(url: str):
    # --- A. Trace Redirects First ---
    final_url, redirect_chain, redirect_penalty = trace_redirects(url)
    
    # --- B. ML Model Inference (on the FINAL URL) ---
    ml_result = classifier(final_url)[0]
    is_ml_malicious = ml_result['label'] == 'LABEL_1'
    ml_score = ml_result['score'] if is_ml_malicious else (1 - ml_result['score'])
    
    # --- C. Heuristic Checks ---
    heuristics = {}
    penalty = redirect_penalty # Start with the redirect penalty
    
    try:
        # 1. Keyword Heuristics
        suspicious_keywords = ['login', 'verify', 'secure', 'account', 'update', 'banking', 'phishing', 'admin']
        url_lower = final_url.lower()
        found_keywords = [kw for kw in suspicious_keywords if kw in url_lower]
        
        if found_keywords:
            heuristics['suspicious_keywords'] = found_keywords
            penalty += 0.35

        # Extract root domain
        extracted = tldextract.extract(final_url)
        root_domain = f"{extracted.domain}.{extracted.suffix}"
        
        if not root_domain or root_domain == ".":
            root_domain = urlparse(final_url).netloc or final_url.split('/')[0]

        # 2. DNS Resolution Check
        try:
            socket.gethostbyname(root_domain)
            heuristics['dns_resolved'] = True
        except socket.gaierror:
            heuristics['dns_resolved'] = False
            penalty += 0.4
            
        # 3. WHOIS Domain Age Check
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

    # --- D. Score Fusion ---
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
            "redirect_chain": redirect_chain, # Send this to frontend
            "checks": heuristics
        }
    }