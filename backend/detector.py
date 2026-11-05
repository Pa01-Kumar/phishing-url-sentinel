import os
import re
import math
import base64
import socket
import ssl
import ipaddress
import requests
import tldextract
import whois
import idna
import time
import mmh3
from collections import Counter
from datetime import datetime
from bs4 import BeautifulSoup
from urllib.parse import urlparse, unquote
from dotenv import load_dotenv
from rapidfuzz import fuzz

load_dotenv()
VT_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
HF_TOKEN = os.getenv("HF_TOKEN")

BROWSER_HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
}

VT_CACHE = {}
CACHE_TTL = 900

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

def check_hf_model(url: str):
    """Calls the Hugging Face Inference API instead of running PyTorch locally."""
    if not HF_TOKEN:
        return 0.5 
    
    api_url = "https://api-inference.huggingface.co/models/Eason918/malicious-url-detector"
    headers = {"Authorization": f"Bearer {HF_TOKEN}"}
    payload = {"inputs": url}
    
    try:
        response = requests.post(api_url, headers=headers, json=payload, timeout=12)
        if response.status_code == 200:
            result = response.json()[0]
            is_ml_malicious = result['label'] == 'LABEL_1'
            return result['score'] if is_ml_malicious else (1 - result['score'])
    except Exception:
        pass
    return 0.1 

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

def get_ssl_info(hostname: str):
    try:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, 443), timeout=3) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                return {
                    "issuer": dict(x[0] for x in cert['issuer']).get('organizationName', 'Unknown'),
                    "subject": dict(x[0] for x in cert['subject']).get('commonName', 'Unknown'),
                    "valid_until": cert.get('notAfter', 'Unknown')
                }
    except Exception:
        return None

def get_ip_info(ip_addr: str):
    try:
        response = requests.get(f"http://ip-api.com/json/{ip_addr}?fields=status,country,city,isp,org,as", timeout=3)
        if response.status_code == 200:
            data = response.json()
            if data.get("status") == "success":
                return {
                    "country": data.get("country"),
                    "city": data.get("city"),
                    "isp": data.get("isp"),
                    "asn": data.get("as")
                }
    except Exception:
        pass
    return None

def check_urlhaus(url: str):
    try:
        response = requests.post("https://urlhaus-api.abuse.ch/v1/url/", data={"url": url}, timeout=5)
        if response.status_code == 200:
            data = response.json()
            if data.get("query_status") == "ok":
                return {"status": data.get("url_status"), "threat": data.get("threat")}
    except Exception:
        pass
    return None

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
                break
        final_url = current_url
        penalty = min(penalty, 0.3)
    except Exception:
        pass
    return final_url, chain, penalty

def check_virustotal(url: str):
    if url in VT_CACHE:
        cached_time, cached_result = VT_CACHE[url]
        if time.time() - cached_time < CACHE_TTL:
            return cached_result

    if not VT_API_KEY:
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
            VT_CACHE[url] = (time.time(), res)
            return res
        elif response.status_code == 429:
            return {"error": "VirusTotal Rate Limit Reached.", "malicious": 0, "vt_penalty": 0.0}
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

def get_favicon_hash(url: str):
    try:
        response = requests.get(url, timeout=3, headers=BROWSER_HEADERS)
        soup = BeautifulSoup(response.text, 'html.parser')
        icon_link = soup.find("link", rel=lambda x: x and 'icon' in x.lower())
        if icon_link and icon_link.get('href'):
            icon_url = urlparse(url)._replace(path=icon_link['href']).geturl()
            icon_response = requests.get(icon_url, timeout=3, headers=BROWSER_HEADERS)
            if icon_response.status_code == 200:
                favicon = base64.b64encode(icon_response.content)
                return mmh3.hash(favicon)
    except Exception:
        pass
    return None

def analyze_url(url: str):
    heuristics = {}
    penalty = 0.0
    override_ml_score = False 
    is_high_reputation = False
    is_established_domain = False
    network_iocs = {}
    
    decoded_url = unquote(url)
    if decoded_url != url:
        heuristics['percent_encoding_detected'] = True
        penalty += 0.2

    final_url, redirect_chain, redirect_penalty = trace_redirects(decoded_url)
    penalty += redirect_penalty
    
    ml_score = check_hf_model(final_url)
    
    vt_result = check_virustotal(final_url)
    penalty += vt_result.get('vt_penalty', 0.0)
    
    urlhaus_result = check_urlhaus(final_url)
    if urlhaus_result and urlhaus_result.get("status") == "online":
        heuristics['urlhaus_threat'] = urlhaus_result.get("threat", "Malware")
        penalty += 0.8
    
    try:
        parsed_url = urlparse(final_url)
        raw_hostname = parsed_url.hostname if parsed_url.hostname else final_url.split('/')[0]

        try:
            decoded_hostname = idna.decode(raw_hostname)
        except idna.IDNAError:
            decoded_hostname = raw_hostname
            
        normalized_hostname = normalize_homoglyphs(decoded_hostname)
        hostname = normalized_hostname

        try:
            ip_addr = socket.gethostbyname(hostname)
            network_iocs['ip_address'] = ip_addr
            network_iocs['ssl_cert'] = get_ssl_info(hostname)
            network_iocs['favicon_hash'] = get_favicon_hash(final_url)
            
            ip_info = get_ip_info(ip_addr)
            if ip_info:
                network_iocs['asn_geoip'] = ip_info
                
        except Exception:
            pass

        if decoded_hostname != raw_hostname or normalized_hostname != decoded_hostname:
            heuristics['punycode_homoglyph_attack'] = True
            heuristics['original_hostname'] = raw_hostname
            heuristics['normalized_hostname'] = normalized_hostname
            penalty += 1.0 

        is_ip = False
        try:
            ipaddress.ip_address(hostname)
            is_ip = True
        except ValueError:
            try:
                if hostname.startswith('0x'): ipaddress.ip_address(int(hostname, 16)); is_ip = True
                elif hostname.isdigit(): ipaddress.ip_address(int(hostname)); is_ip = True
            except ValueError: pass
                
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
            except Exception: pass

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
            
            if domain_name_only not in popular_brands:
                for brand in popular_brands:
                    if fuzz.ratio(domain_name_only, brand) > 80: typosquatting_target = brand; break
                    if brand in domain_name_only and len(domain_name_only) > len(brand):
                        if '-' in domain_name_only or len(domain_name_only) > len(brand) + 3: typosquatting_target = brand; break
                    if fuzz.partial_ratio(domain_name_only, brand) > 90: typosquatting_target = brand; break
                if typosquatting_target:
                    heuristics['typosquatting_warning'] = f"Domain mimics brand: '{typosquatting_target}'"
                    penalty += 0.6

            if not is_high_reputation and not is_established_domain:
                if hostname.count('-') > 2: heuristics['excessive_hyphens'] = True; penalty += 0.2
                if extracted.suffix.lower() in ['xyz', 'top', 'tk', 'gq', 'cf', 'ml', 'work', 'click']: heuristics['suspicious_tld'] = extracted.suffix; penalty += 0.3
                if len(subdomain.split('.')) > 1: heuristics['deep_subdomains'] = subdomain; penalty += 0.25

            domain_entropy = calculate_entropy(domain_name_only)
            heuristics['domain_entropy'] = round(domain_entropy, 2)
            
            if not is_high_reputation and not is_established_domain and len(domain_name_only) > 6:
                digits = sum(1 for c in domain_name_only if c.isdigit())
                vowels = sum(1 for c in domain_name_only if c in 'aeiou')
                vowel_ratio = vowels / len(domain_name_only)
                is_dga = False
                if domain_entropy > 3.8: is_dga = True
                elif domain_entropy > 3.3:
                    if digits >= 2 or vowel_ratio < 0.2: is_dga = True
                if is_dga: heuristics['dga_entropy_warning'] = "Randomly generated domain (DGA) characteristics"; penalty += 0.4

        if not is_ip:
            try:
                socket.getaddrinfo(root_domain, None)
                heuristics['dns_resolved'] = True
            except socket.gaierror:
                heuristics['dns_resolved'] = False
                if not is_high_reputation and not is_established_domain: penalty += 0.4
            
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
            "urlhaus_stats": urlhaus_result,
            "network_iocs": network_iocs,
            "checks": heuristics
        }
    }