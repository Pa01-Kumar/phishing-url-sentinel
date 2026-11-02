import os
import re
import math
import base64
import socket
import ipaddress
import requests
import tldextract
import whois
from collections import Counter
from datetime import datetime
from transformers import pipeline
from urllib.parse import urlparse, unquote
from dotenv import load_dotenv
from rapidfuzz import fuzz

load_dotenv()
VT_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")

print("Loading ML Model...")
classifier = pipeline("text-classification", model="Eason918/malicious-url-detector")

def is_safe_url(url: str) -> bool:
    """SSRF Protection: Blocks requests to private, loopback, or internal IPs."""
    try:
        parsed = urlparse(url)
        hostname = parsed.hostname
        if not hostname:
            return False
        addr_info = socket.getaddrinfo(hostname, None)
        for info in addr_info:
            ip = ipaddress.ip_address(info[4][0])
            if (ip.is_private or ip.is_loopback or ip.is_link_local or 
                ip.is_multicast or ip.is_reserved or ip.is_unspecified):
                return False
        return True
    except Exception:
        return False

def trace_redirects(url: str):
    """Tracks HTTP redirects and scans for client-side JS redirects."""
    chain = [url]
    penalty = 0.0
    final_url = url
    
    if not is_safe_url(url):
        chain.append("⛔ Blocked: URL points to a private/internal network (SSRF Protection).")
        return final_url, chain, 1.0

    try:
        current_url = url
        max_redirects = 5
        
        for _ in range(max_redirects):
            response = requests.get(current_url, timeout=5, allow_redirects=False, stream=True)
            
            # 1. Check for HTTP 3xx redirects
            if response.status_code in (301, 302, 303, 307, 308):
                next_url = response.headers.get('Location')
                if not next_url: break
                if next_url.startswith('/'):
                    parsed_current = urlparse(current_url)
                    next_url = f"{parsed_current.scheme}://{parsed_current.netloc}{next_url}"
                if not is_safe_url(next_url):
                    chain.append("⛔ Blocked: Redirect target points to internal network.")
                    return current_url, chain, 1.0
                chain.append(next_url)
                current_url = next_url
                penalty += 0.1
            else:
                # 2. Check for Client-Side JavaScript Redirects
                try:
                    html_content = response.text[:5000] # Only read first 5KB
                    js_match = re.search(r'(?:window\.location|document\.location|location\.href)\s*=\s*[\'"]([^\'"]+)[\'"]', html_content)
                    meta_match = re.search(r'<meta[^>]+http-equiv=[\'"]?refresh[\'"]?[^>]+url=([^\'">]+)', html_content, re.IGNORECASE)
                    
                    js_redirect = js_match.group(1) if js_match else (meta_match.group(1) if meta_match else None)
                    
                    if js_redirect:
                        if not js_redirect.startswith('http'):
                            js_redirect = f"http://{urlparse(current_url).hostname}/{js_redirect.lstrip('/')}"
                        chain.append(f"⚠️ Client-Side JS Redirect -> {js_redirect}")
                        current_url = js_redirect
                        penalty += 0.1 # Reduced penalty
                        continue
                except Exception:
                    pass
                break
                
        final_url = current_url
        penalty = min(penalty, 0.3)
    except Exception:
        pass
    return final_url, chain, penalty

def check_virustotal(url: str):
    if not VT_API_KEY or VT_API_KEY == "your_long_api_key_here":
        return {"error": "VirusTotal API key not configured."}
    headers = {"x-apikey": VT_API_KEY}
    url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
    response = requests.get(f"https://www.virustotal.com/api/v3/urls/{url_id}", headers=headers)
    if response.status_code == 200:
        stats = response.json()['data']['attributes']['last_analysis_stats']
        malicious_count = stats.get('malicious', 0)
        total_engines = malicious_count + stats.get('suspicious', 0) + stats.get('harmless', 0) + stats.get('undetected', 0)
        return {"malicious": malicious_count, "suspicious": stats.get('suspicious', 0), "total_engines": total_engines, "vt_penalty": min(malicious_count * 0.15, 0.6)}
    return {"malicious": 0, "suspicious": 0, "total_engines": 70, "vt_penalty": 0.0}

def calculate_entropy(text: str) -> float:
    if not text: return 0.0
    entropy = 0.0
    counter = Counter(text)
    for count in counter.values():
        p_x = count / len(text)
        entropy += - p_x * math.log2(p_x)
    return entropy

def analyze_url(url: str):
    heuristics = {}
    penalty = 0.0
    
    # --- EVASION FIX 1: URL Percent-Encoding ---
    decoded_url = unquote(url)
    if decoded_url != url:
        heuristics['percent_encoding_detected'] = True
        penalty += 0.2

    final_url, redirect_chain, redirect_penalty = trace_redirects(decoded_url)
    penalty += redirect_penalty
    
    # ML Model
    ml_result = classifier(final_url)[0]
    is_ml_malicious = ml_result['label'] == 'LABEL_1'
    ml_score = ml_result['score'] if is_ml_malicious else (1 - ml_result['score'])
    
    # VirusTotal
    vt_result = check_virustotal(final_url)
    penalty += vt_result.get('vt_penalty', 0.0)
    
    try:
        parsed_url = urlparse(final_url)
        hostname = parsed_url.hostname if parsed_url.hostname else final_url.split('/')[0]

        # --- EVASION FIX 2: Punycode / IDN Homoglyphs ---
        if hostname.startswith('xn--') or any(ord(c) > 127 for c in hostname):
            heuristics['punycode_homoglyph_attack'] = True
            penalty += 0.6

        # --- EVASION FIX 5: IP Encodings (Hex/Octal) ---
        is_ip = False
        try:
            ipaddress.ip_address(hostname)
            is_ip = True
        except ValueError:
            try:
                if hostname.startswith('0x'):
                    ipaddress.ip_address(int(hostname, 16))
                    is_ip = True
                elif hostname.isdigit():
                    ipaddress.ip_address(int(hostname))
                    is_ip = True
            except ValueError:
                pass
                
        if is_ip:
            heuristics['is_ip_address'] = True
            penalty += 0.8

        # Extract Root Domain safely
        if not is_ip:
            extracted = tldextract.extract(hostname)
            root_domain = f"{extracted.domain}.{extracted.suffix}"
            domain_name_only = extracted.domain
            subdomain = extracted.subdomain
            
            # --- NEW: TRUSTED SSO DETECTION ---
            trusted_sso_brands = ['microsoft', 'microsoftonline', 'office', 'live', 'google', 'apple', 'okta', 'auth0', 'duosecurity']
            is_trusted_sso = any(brand in domain_name_only.lower() for brand in trusted_sso_brands)

            # --- EVASION FIX 6: Legit Subdomain Inversion ---
            suspicious_keywords = ['login', 'verify', 'secure', 'account', 'update', 'banking', 'phishing', 'admin', 'auth', 'confirm', 'signin', 'support', 'billing', 'wallet', 'crypto', 'recovery']
            
            found_in_domain = [kw for kw in suspicious_keywords if kw in domain_name_only.lower()]
            found_in_subdomain = [kw for kw in suspicious_keywords if kw in subdomain.lower()]
            
            if not is_trusted_sso:
                if found_in_domain:
                    heuristics['suspicious_keywords_in_root'] = found_in_domain
                    penalty += 0.4
                
                safe_brands = ['google', 'microsoft', 'apple', 'amazon', 'facebook', 'paypal', 'instagram', 'linkedin']
                if found_in_subdomain and domain_name_only.lower() not in safe_brands:
                    heuristics['suspicious_keywords_in_subdomain'] = found_in_subdomain
                    penalty += 0.2

            # --- EVASION FIX 3: Substring Brand Spoofing ---
            popular_brands = ['paypal', 'google', 'microsoft', 'apple', 'amazon', 'netflix', 'facebook', 'instagram', 'linkedin', 'bankofamerica']
            typosquatting_target = None
            
            if not is_trusted_sso:
                for brand in popular_brands:
                    if fuzz.ratio(domain_name_only.lower(), brand) > 80:
                        typosquatting_target = brand
                        break
                    elif brand in domain_name_only.lower() and domain_name_only.lower() != brand:
                        typosquatting_target = brand
                        break
                    elif fuzz.partial_ratio(domain_name_only.lower(), brand) > 85 and domain_name_only.lower() != brand:
                        typosquatting_target = brand
                        break
                        
                if typosquatting_target:
                    heuristics['typosquatting_warning'] = f"Domain mimics brand: '{typosquatting_target}'"
                    penalty += 0.5

            # Structural Checks
            if not is_trusted_sso:
                if hostname.count('-') > 2:
                    heuristics['excessive_hyphens'] = True
                    penalty += 0.2
                if extracted.suffix.lower() in ['xyz', 'top', 'tk', 'gq', 'cf', 'ml', 'work', 'click']:
                    heuristics['suspicious_tld'] = extracted.suffix
                    penalty += 0.3
                if len(subdomain.split('.')) > 1:
                    heuristics['deep_subdomains'] = subdomain
                    penalty += 0.25

            # Entropy Check
            domain_entropy = calculate_entropy(domain_name_only)
            heuristics['domain_entropy'] = round(domain_entropy, 2)
            if not is_trusted_sso and domain_entropy > 3.2 and len(domain_name_only) > 6:
                heuristics['dga_entropy_warning'] = "Randomly generated domain (DGA)"
                penalty += 0.4
            
            # Apply SSO Override
            if is_trusted_sso:
                heuristics['trusted_sso_flow'] = True
                penalty = min(penalty, 0.1)

        # DNS & WHOIS
        if not is_ip:
            try:
                socket.gethostbyname(root_domain)
                heuristics['dns_resolved'] = True
            except socket.gaierror:
                heuristics['dns_resolved'] = False
                penalty += 0.4
            
            try:
                w = whois.whois(root_domain)
                creation_date = w.creation_date[0] if isinstance(w.creation_date, list) else w.creation_date
                if creation_date:
                    now = datetime.now(creation_date.tzinfo) if creation_date.tzinfo else datetime.now()
                    age_days = (now - creation_date).days
                    heuristics['domain_age_days'] = age_days
                    if age_days < 30 and not is_trusted_sso:
                        if found_in_domain or found_in_subdomain:
                            penalty += 0.4
                            heuristics['new_domain_with_keywords'] = True
                        else:
                            penalty += 0.15
            except Exception:
                pass
                
    except Exception as e:
        heuristics['parsing_error'] = str(e)

    final_score = min(ml_score + penalty, 1.0)
    
    if final_score >= 0.7: verdict = "malicious"
    elif final_score >= 0.3: verdict = "suspicious"
    else: verdict = "benign"

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