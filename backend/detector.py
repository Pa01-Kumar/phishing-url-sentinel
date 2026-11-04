import os
import re
import math
import base64
import socket
import ipaddress
import requests
import tldextract
import whois
import idna
import time  # NEW: For caching
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

# --- NEW: Browser User-Agent to bypass anti-bot filters ---
BROWSER_HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
}

# --- NEW: In-Memory Cache for VirusTotal (Saves API Quota) ---
VT_CACHE = {}
CACHE_TTL = 900  # 15 minutes in seconds

HIGH_REPUTATION_DOMAINS = {
    'google', 'microsoft', 'apple', 'amazon', 'facebook', 'meta', 'netflix', 'adobe', 
    'github', 'gitlab', 'dropbox', 'zoom', 'slack', 'salesforce', 'oracle', 'ibm', 
    'cisco', 'vmware', 'cloudflare', 'akamai', 'digitalocean', 'heroku',
    'microsoftonline', 'office', 'live', 'okta', 'auth0', 'duosecurity', 'onelogin', 
    'pingidentity', 'jumpcloud',
    'paypal', 'chase', 'bankofamerica', 'wellsfargo', 'citibank', 'capitalone', 
    'americanexpress', 'visa', 'mastercard', 'stripe', 'squareup', 'coinbase', 'binance',
    'instagram', 'linkedin', 'twitter', 'x', 'tiktok', 'youtube', 'spotify', 'steam', 
    'roblox', 'epicgames', 'twitch', 'discord',
    'gov', 'mil', 'edu'
}

def is_safe_url(url: str) -> bool:
    try:
        parsed = urlparse(url)
        hostname = parsed.hostname
        if not hostname: return False
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
            # FIX 4.3: Add BROWSER_HEADERS to bypass evasion
            response = requests.get(current_url, timeout=5, allow_redirects=False, stream=True, headers=BROWSER_HEADERS)
            
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
                try:
                    html_content = response.text[:5000]
                    js_match = re.search(r'(?:window\.location|document\.location|location\.href)\s*=\s*[\'"]([^\'"]+)[\'"]', html_content)
                    meta_match = re.search(r'<meta[^>]+http-equiv=[\'"]?refresh[\'"]?[^>]+url=([^\'">]+)', html_content, re.IGNORECASE)
                    
                    js_redirect = js_match.group(1) if js_match else (meta_match.group(1) if meta_match else None)
                    
                    if js_redirect:
                        if not js_redirect.startswith('http'):
                            js_redirect = f"http://{urlparse(current_url).hostname}/{js_redirect.lstrip('/')}"
                        chain.append(f"⚠️ Client-Side JS Redirect -> {js_redirect}")
                        current_url = js_redirect
                        penalty += 0.1
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
    # FIX 4.2: Check Cache First
    if url in VT_CACHE:
        cached_time, cached_result = VT_CACHE[url]
        if time.time() - cached_time < CACHE_TTL:
            return cached_result

    if not VT_API_KEY or VT_API_KEY == "your_long_api_key_here":
        return {"error": "VirusTotal API key not configured.", "malicious": 0, "vt_penalty": 0.0}
    
    headers = {"x-apikey": VT_API_KEY, **BROWSER_HEADERS}
    url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
    try:
        response = requests.get(f"https://www.virustotal.com/api/v3/urls/{url_id}", headers=headers, timeout=5)
        if response.status_code == 200:
            stats = response.json()['data']['attributes']['last_analysis_stats']
            malicious_count = stats.get('malicious', 0)
            total_engines = malicious_count + stats.get('suspicious', 0) + stats.get('harmless', 0) + stats.get('undetected', 0)
            res = {"malicious": malicious_count, "suspicious": stats.get('suspicious', 0), "total_engines": total_engines, "vt_penalty": min(malicious_count * 0.15, 0.6)}
            
            # Save to Cache
            VT_CACHE[url] = (time.time(), res)
            return res
            
        elif response.status_code == 429:
            # FIX 4.2: Handle Rate Limiting Gracefully
            return {"error": "VirusTotal Rate Limit Reached. Wait a minute.", "malicious": 0, "vt_penalty": 0.0}
            
    except Exception:
        pass
    return {"malicious": 0, "suspicious": 0, "total_engines": 70, "vt_penalty": 0.0}

def calculate_entropy(text: str) -> float:
    if not text: return 0.0
    entropy = 0.0
    counter = Counter(text)
    for count in counter.values():
        p_x = count / len(text)
        entropy += - p_x * math.log2(p_x)
    return entropy

def normalize_homoglyphs(text: str) -> str:
    homoglyphs = {
        'а': 'a', 'е': 'e', 'о': 'o', 'р': 'p', 'с': 'c', 'у': 'y', 'х': 'x',
        'і': 'i', 'ј': 'j', 'ѕ': 's', 'ԁ': 'd', 'ԛ': 'q', 'ԝ': 'w', 'ӏ': 'l',
        'Α': 'A', 'Β': 'B', 'Ε': 'E', 'Ζ': 'Z', 'Η': 'H', 'Ι': 'I', 'Κ': 'K', 
        'Μ': 'M', 'Ν': 'N', 'Ο': 'O', 'Ρ': 'P', 'Τ': 'T', 'Υ': 'Y', 'Χ': 'X'
    }
    return ''.join(homoglyphs.get(c, c) for c in text)

def analyze_url(url: str):
    heuristics = {}
    penalty = 0.0
    override_ml_score = False 
    is_high_reputation = False
    is_established_domain = False
    
    decoded_url = unquote(url)
    if decoded_url != url:
        heuristics['percent_encoding_detected'] = True
        penalty += 0.2

    final_url, redirect_chain, redirect_penalty = trace_redirects(decoded_url)
    penalty += redirect_penalty
    
    ml_result = classifier(final_url)[0]
    is_ml_malicious = ml_result['label'] == 'LABEL_1'
    ml_score = ml_result['score'] if is_ml_malicious else (1 - ml_result['score'])
    
    vt_result = check_virustotal(final_url)
    penalty += vt_result.get('vt_penalty', 0.0)
    
    try:
        parsed_url = urlparse(final_url)
        raw_hostname = parsed_url.hostname if parsed_url.hostname else final_url.split('/')[0]

        try:
            decoded_hostname = idna.decode(raw_hostname)
        except idna.IDNAError:
            decoded_hostname = raw_hostname
            
        normalized_hostname = normalize_homoglyphs(decoded_hostname)

        if decoded_hostname != raw_hostname or normalized_hostname != decoded_hostname:
            heuristics['punycode_homoglyph_attack'] = True
            heuristics['original_hostname'] = raw_hostname
            heuristics['normalized_hostname'] = normalized_hostname
            penalty += 1.0 

        hostname = normalized_hostname

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

        if not is_ip:
            extracted = tldextract.extract(hostname)
            root_domain = f"{extracted.domain}.{extracted.suffix}"
            domain_name_only = extracted.domain.lower()
            subdomain = extracted.subdomain.lower()
            
            is_high_reputation = (domain_name_only in HIGH_REPUTATION_DOMAINS) or (extracted.suffix.lower() in HIGH_REPUTATION_DOMAINS)

            try:
                w = whois.whois(root_domain)
                creation_date = w.creation_date[0] if isinstance(w.creation_date, list) else w.creation_date
                if creation_date:
                    now = datetime.now(creation_date.tzinfo) if creation_date.tzinfo else datetime.now()
                    age_days = (now - creation_date).days
                    heuristics['domain_age_days'] = age_days
                    
                    if age_days > 730 and vt_result.get('malicious', 0) == 0:
                        is_established_domain = True
                        heuristics['dynamic_trust_granted'] = True
            except Exception:
                pass

            suspicious_keywords = ['login', 'verify', 'secure', 'account', 'update', 'banking', 'phishing', 'admin', 'auth', 'confirm', 'signin', 'support', 'billing', 'wallet', 'crypto', 'recovery']
            found_in_domain = [kw for kw in suspicious_keywords if kw in domain_name_only]
            found_in_subdomain = [kw for kw in suspicious_keywords if kw in subdomain]
            
            if not is_high_reputation and not is_established_domain:
                if found_in_domain:
                    heuristics['suspicious_keywords_in_root'] = found_in_domain
                    penalty += 0.4
                
                if found_in_subdomain and domain_name_only not in HIGH_REPUTATION_DOMAINS:
                    heuristics['suspicious_keywords_in_subdomain'] = found_in_subdomain
                    penalty += 0.2

            popular_brands = list(HIGH_REPUTATION_DOMAINS)
            typosquatting_target = None
            
            if not is_high_reputation and not is_established_domain:
                if domain_name_only not in popular_brands:
                    for brand in popular_brands:
                        if fuzz.ratio(domain_name_only, brand) > 80:
                            typosquatting_target = brand
                            break
                        if brand in domain_name_only and len(domain_name_only) > len(brand):
                            if '-' in domain_name_only or len(domain_name_only) > len(brand) + 3:
                                typosquatting_target = brand
                                break
                        if fuzz.partial_ratio(domain_name_only, brand) > 90:
                            typosquatting_target = brand
                            break
                            
                    if typosquatting_target:
                        heuristics['typosquatting_warning'] = f"Domain mimics brand: '{typosquatting_target}'"
                        penalty += 0.5

            if not is_high_reputation and not is_established_domain:
                if hostname.count('-') > 2:
                    heuristics['excessive_hyphens'] = True
                    penalty += 0.2
                if extracted.suffix.lower() in ['xyz', 'top', 'tk', 'gq', 'cf', 'ml', 'work', 'click']:
                    heuristics['suspicious_tld'] = extracted.suffix
                    penalty += 0.3
                if len(subdomain.split('.')) > 1:
                    heuristics['deep_subdomains'] = subdomain
                    penalty += 0.25

            domain_entropy = calculate_entropy(domain_name_only)
            heuristics['domain_entropy'] = round(domain_entropy, 2)
            
            if not is_high_reputation and not is_established_domain and len(domain_name_only) > 6:
                digits = sum(1 for c in domain_name_only if c.isdigit())
                vowels = sum(1 for c in domain_name_only if c in 'aeiou')
                vowel_ratio = vowels / len(domain_name_only)
                is_dga = False
                if domain_entropy > 3.8:
                    is_dga = True
                elif domain_entropy > 3.3:
                    if digits >= 2 or vowel_ratio < 0.2:
                        is_dga = True
                if is_dga:
                    heuristics['dga_entropy_warning'] = "Randomly generated domain (DGA) characteristics"
                    penalty += 0.4

        if not is_ip:
            try:
                socket.getaddrinfo(root_domain, None)
                heuristics['dns_resolved'] = True
            except socket.gaierror:
                heuristics['dns_resolved'] = False
                if not is_high_reputation and not is_established_domain:
                    penalty += 0.4
            
    except Exception as e:
        heuristics['parsing_error'] = str(e)

    if (is_high_reputation or is_established_domain) and not heuristics.get('punycode_homoglyph_attack') and not heuristics.get('typosquatting_warning'):
        heuristics['trusted_domain'] = True
        penalty = min(penalty, 0.1)
        ml_score = 0.0
        heuristics['ml_score_overridden'] = True

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