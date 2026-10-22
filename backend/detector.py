import os
import whois
import socket
import tldextract
import requests
import ipaddress
import math
from collections import Counter
from datetime import datetime
from transformers import pipeline
from urllib.parse import urlparse
from dotenv import load_dotenv
from rapidfuzz import fuzz

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
        pass
    return final_url, chain, penalty

def check_virustotal(url: str):
    if not VT_API_KEY or VT_API_KEY == "your_long_api_key_here":
        return {"error": "VirusTotal API key not configured."}
    
    headers = {"x-apikey": VT_API_KEY}
    import base64
    url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
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
            "vt_penalty": min(malicious_count * 0.15, 0.6) 
        }
    return {"malicious": 0, "suspicious": 0, "total_engines": 70, "vt_penalty": 0.0, "note": "URL not in VT database yet."}

def calculate_entropy(text: str) -> float:
    """Calculates Shannon entropy to detect random/DGA domains."""
    if not text:
        return 0.0
    entropy = 0.0
    length = len(text)
    # Count the frequency of each character
    counter = Counter(text)
    # Apply the Shannon entropy formula
    for count in counter.values():
        p_x = count / length
        entropy += - p_x * math.log2(p_x)
    return entropy

def analyze_url(url: str):
    final_url, redirect_chain, redirect_penalty = trace_redirects(url)
    
    ml_result = classifier(final_url)[0]
    is_ml_malicious = ml_result['label'] == 'LABEL_1'
    ml_score = ml_result['score'] if is_ml_malicious else (1 - ml_result['score'])
    
    vt_result = check_virustotal(final_url)
    vt_penalty = vt_result.get('vt_penalty', 0.0)
    
    heuristics = {}
    penalty = redirect_penalty + vt_penalty
    
    try:
        parsed_url = urlparse(final_url)
        hostname = parsed_url.hostname if parsed_url.hostname else final_url.split('/')[0]

        # 1. Expanded Keyword Heuristics
        suspicious_keywords = [
            'login', 'verify', 'secure', 'account', 'update', 'banking', 'phishing', 'admin', 
            'auth', 'confirm', 'signin', 'support', 'billing', 'wallet', 'crypto', 'recovery'
        ]
        url_lower = final_url.lower()
        hostname_lower = hostname.lower()
        
        found_in_domain = [kw for kw in suspicious_keywords if kw in hostname_lower]
        found_in_path = [kw for kw in suspicious_keywords if kw in url_lower and kw not in found_in_domain]

        if found_in_domain:
            heuristics['suspicious_keywords_in_domain'] = found_in_domain
            penalty += 0.4
        if found_in_path:
            heuristics['suspicious_keywords_in_path'] = found_in_path
            penalty += 0.1

        # 2. IP Address Detection
        is_ip = False
        try:
            ipaddress.ip_address(hostname)
            is_ip = True
            heuristics['is_ip_address'] = True
            penalty += 0.8
        except ValueError:
            heuristics['is_ip_address'] = False

        # Root Domain Extraction
        if is_ip:
            root_domain = hostname
            domain_name_only = hostname
            extracted = None
        else:
            extracted = tldextract.extract(hostname)
            root_domain = f"{extracted.domain}.{extracted.suffix}"
            domain_name_only = extracted.domain

        # 3. URL Shortener Detection
        shorteners = ['bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'is.gd', 'buff.ly', 'cutt.ly']
        if root_domain.lower() in shorteners:
            heuristics['is_url_shortener'] = True
            penalty += 0.2
        else:
            heuristics['is_url_shortener'] = False

        # 4. Structural Heuristics (Hyphens, TLDs, Subdomains)
        if not is_ip:
            # Excessive Hyphens
            if hostname.count('-') > 2:
                heuristics['excessive_hyphens'] = True
                penalty += 0.2
            
            # Suspicious TLDs
            bad_tlds = ['xyz', 'top', 'tk', 'gq', 'cf', 'ml', 'work', 'click']
            if extracted.suffix.lower() in bad_tlds:
                heuristics['suspicious_tld'] = extracted.suffix
                penalty += 0.3
                
            # Deep Subdomains
            if len(extracted.subdomain.split('.')) > 1:
                heuristics['deep_subdomains'] = extracted.subdomain
                penalty += 0.25

        # 5. Typosquatting Detection
        if not is_ip:
            popular_brands = ['paypal', 'google', 'microsoft', 'apple', 'amazon', 'netflix', 'facebook', 'instagram', 'linkedin', 'bankofamerica']
            typosquatting_target = None
            
            original_parsed = urlparse(url)
            original_hostname = original_parsed.hostname if original_parsed.hostname else url.split('/')[0]
            original_extracted = tldextract.extract(original_hostname)
            original_domain = original_extracted.domain

            for check_domain in set([original_domain, domain_name_only]):
                if not check_domain:
                    continue
                for brand in popular_brands:
                    if check_domain != brand:
                        similarity = fuzz.ratio(check_domain, brand)
                        if similarity > 80:
                            typosquatting_target = brand
                            penalty += 0.4
                            break 
                if typosquatting_target:
                    break
                        
            if typosquatting_target:
                heuristics['typosquatting_warning'] = f"Domain heavily resembles '{typosquatting_target}'"

        # --- NEW: Entropy Check (DGA Detection) ---
        if not is_ip:
            # Calculate entropy of just the domain name (e.g., "xj3k9f2a")
            domain_entropy = calculate_entropy(domain_name_only)
            heuristics['domain_entropy'] = round(domain_entropy, 2)
            
            # Normal human words usually have entropy < 3.0. 
            # DGA domains (random strings) usually have entropy > 3.2
            if domain_entropy > 3.2 and len(domain_name_only) > 6:
                heuristics['dga_entropy_warning'] = "Domain appears randomly generated (DGA)"
                penalty += 0.4 # Heavy penalty for random strings

        # 6. DNS Resolution
        try:
            socket.gethostbyname(root_domain)
            heuristics['dns_resolved'] = True
        except socket.gaierror:
            heuristics['dns_resolved'] = False
            penalty += 0.4
            
        # 7. WHOIS
        if not is_ip:
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
        else:
             heuristics['whois_skipped'] = "Skipped (IP Address)"
            
    except Exception as e:
        heuristics['parsing_error'] = str(e)

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
            "virustotal_stats": vt_result,
            "checks": heuristics
        }
    }