import json
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
from datetime import datetime, timezone
from bs4 import BeautifulSoup
from urllib.parse import urlparse, unquote, urljoin
from dotenv import load_dotenv
from rapidfuzz import fuzz

# Load environment variables from both root and backend directories
load_dotenv()
load_dotenv(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env"))

VT_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
HF_TOKEN = os.getenv("HF_TOKEN")
ABUSE_API_KEY = os.getenv("ABUSEIPDB_API_KEY")

# Load the brand hashes safely using absolute script path
HASHES_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "brand_hashes.json")
try:
    with open(HASHES_PATH, "r", encoding="utf-8") as f:
        BRAND_FAVICONS = json.load(f)
except Exception:
    BRAND_FAVICONS = {} 

BROWSER_HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
}

VT_CACHE = {}
CACHE_TTL = 900

# High reputation brand names / platform domains (excluding raw TLDs)
HIGH_REPUTATION_DOMAINS = {
    'google', 'microsoft', 'apple', 'amazon', 'facebook', 'meta', 'netflix', 'adobe', 
    'github', 'gitlab', 'dropbox', 'zoom', 'slack', 'salesforce', 'oracle', 'ibm', 
    'cisco', 'vmware', 'cloudflare', 'akamai', 'digitalocean', 'heroku',
    'microsoftonline', 'office', 'live', 'okta', 'auth0', 'duosecurity', 'onelogin', 
    'pingidentity', 'jumpcloud',
    'paypal', 'chase', 'bankofamerica', 'wellsfargo', 'citibank', 'capitalone', 
    'americanexpress', 'visa', 'mastercard', 'stripe', 'squareup', 'coinbase', 'binance',
    'instagram', 'linkedin', 'twitter', 'x', 'tiktok', 'youtube', 'spotify', 'steam', 
    'roblox', 'epicgames', 'twitch', 'discord'
}

# High reputation TLDs / government / education suffixes
HIGH_REPUTATION_TLDS = {'gov', 'mil', 'edu'}

METADATA_HOSTS = {
    '169.254.169.254',
    'metadata.google.internal',
    'metadata',
    'instance-data'
}

def check_hf_model(url: str):
    """Calls the Hugging Face Inference API."""
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
    """SSRF Protection: Blocks requests to non-HTTP schemes, private, loopback, or metadata IPs."""
    try:
        if not url or not isinstance(url, str):
            return False
            
        parsed = urlparse(url)
        if parsed.scheme.lower() not in ('http', 'https'):
            return False
            
        hostname = parsed.hostname
        if not hostname:
            return False
            
        hostname_lower = hostname.lower().strip()
        if hostname_lower in METADATA_HOSTS or hostname_lower.endswith('.internal'):
            return False

        # Attempt to parse direct IP string
        try:
            direct_ip = ipaddress.ip_address(hostname_lower)
            if isinstance(direct_ip, ipaddress.IPv6Address) and direct_ip.ipv4_mapped:
                direct_ip = direct_ip.ipv4_mapped
            if (direct_ip.is_private or direct_ip.is_loopback or direct_ip.is_link_local or 
                direct_ip.is_multicast or direct_ip.is_reserved or direct_ip.is_unspecified or
                str(direct_ip) in ('169.254.169.254', '0.0.0.0')):
                return False
        except ValueError:
            pass

        # Resolve hostname and inspect all resolved IPs
        try:
            addr_info = socket.getaddrinfo(hostname, None)
            for info in addr_info:
                ip_str = info[4][0]
                ip = ipaddress.ip_address(ip_str)
                if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
                    ip = ip.ipv4_mapped
                if (ip.is_private or ip.is_loopback or ip.is_link_local or 
                    ip.is_multicast or ip.is_reserved or ip.is_unspecified or
                    str(ip) in ('169.254.169.254', '0.0.0.0')):
                    return False
            return True
        except socket.gaierror:
            # Domain does not resolve. Not an internal network hit.
            return True
    except Exception:
        return False

def get_ssl_info(hostname: str):
    try:
        # Create an unverified context so we can inspect cert details safely
        context = ssl._create_unverified_context()
        with socket.create_connection((hostname, 443), timeout=3) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                if not cert:
                    return None
                
                issuer_dict = dict(x[0] for x in cert.get('issuer', []))
                subject_dict = dict(x[0] for x in cert.get('subject', []))
                
                issuer = issuer_dict.get('organizationName', 'Unknown')
                subject = subject_dict.get('commonName', 'Unknown')
                valid_from_str = cert.get('notBefore', 'Unknown')
                valid_until_str = cert.get('notAfter', 'Unknown')
                
                # Calculate certificate age in days
                days_old = None
                if valid_from_str != 'Unknown':
                    try:
                        # Format: 'Jan 27 23:59:59 2027 GMT'
                        dt_valid_from = datetime.strptime(valid_from_str, '%b %d %H:%M:%S %Y %Z').replace(tzinfo=timezone.utc)
                        days_old = (datetime.now(timezone.utc) - dt_valid_from).days
                    except Exception:
                        pass

                # Check if the certificate is self-signed
                is_self_signed = (issuer == subject and issuer != 'Unknown')

                return {
                    "issuer": issuer,
                    "subject": subject,
                    "valid_from": valid_from_str,
                    "valid_until": valid_until_str,
                    "days_old": days_old,
                    "is_self_signed": is_self_signed
                }
    except Exception:
        return None
    
def get_ip_info(ip_addr: str):
    try:
        # Verify IP is not private or loopback before external lookup
        ip = ipaddress.ip_address(ip_addr)
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved:
            return None
            
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

def check_ip_reputation(ip_address: str):
    """Checks AbuseIPDB for the IP's reputation score."""
    if not ABUSE_API_KEY:
        return {"error": "ABUSEIPDB_API_KEY is missing in environment variables."}
    try:
        ip = ipaddress.ip_address(ip_address)
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved:
            return {"error": "Skipped: IP address is private or reserved."}

        url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip_address}&maxAgeInDays=90"
        headers = {"Key": ABUSE_API_KEY, "Accept": "application/json"}
        response = requests.get(url, headers=headers, timeout=5)
        
        if response.status_code == 200:
            data = response.json().get("data", {})
            return {
                "abuse_confidence_score": data.get("abuseConfidenceScore", 0),
                "country": data.get("countryCode", "Unknown"),
                "isp": data.get("isp", "Unknown")
            }
        else:
            return {"error": f"API Error: {response.status_code}"}
            
    except Exception as e:
        return {"error": f"Exception: {str(e)}"}

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
    """Tracks HTTP/JS redirects and scans for AiTM/Phishing Kit signatures."""
    chain = [url]
    penalty = 0.0
    final_url = url
    extra_heuristics = {}
    
    if not is_safe_url(url):
        chain.append("⛔ Blocked: URL points to a private/internal network (SSRF Protection).")
        return final_url, chain, 1.0, extra_heuristics

    try:
        current_url = url
        max_redirects = 5
        for _ in range(max_redirects):
            response = None
            try:
                response = requests.get(current_url, timeout=5, allow_redirects=False, stream=True, headers=BROWSER_HEADERS)
                
                if response.status_code in (301, 302, 303, 307, 308):
                    next_url = response.headers.get('Location')
                    if not next_url: 
                        break
                    
                    next_url = urljoin(current_url, next_url)
                    
                    if not is_safe_url(next_url):
                        chain.append("⛔ Blocked: Redirect target points to internal network.")
                        return current_url, chain, 1.0, extra_heuristics
                    chain.append(next_url)
                    current_url = next_url
                    penalty += 0.1
                else:
                    try:
                        html_content = response.text[:15000]
                        html_lower = html_content.lower()
                        
                        # 1. JS Redirect Check
                        js_match = re.search(r'(?:window\.location|document\.location|location\.href)\s*=\s*[\'"]([^\'"]+)[\'"]', html_content)
                        meta_match = re.search(r'<meta[^>]+http-equiv=[\'"]?refresh[\'"]?[^>]+url=([^\'">]+)', html_content, re.IGNORECASE)
                        
                        js_redirect = js_match.group(1) if js_match else (meta_match.group(1) if meta_match else None)
                        
                        if js_redirect:
                            js_redirect = urljoin(current_url, js_redirect)
                            if not is_safe_url(js_redirect):
                                chain.append("⛔ Blocked: JS Redirect target points to internal network.")
                                return current_url, chain, 1.0, extra_heuristics

                            chain.append(f"⚠️ Client-Side JS Redirect -> {js_redirect}")
                            current_url = js_redirect
                            penalty += 0.1
                            continue
                        
                        # 2. BiTB (Browser-in-the-Browser) Full-Screen Iframes
                        if '<iframe' in html_lower:
                            if any(x in html_lower for x in ['width:100%', 'height:100vh', 'position:fixed', 'width: 100%', 'height: 100vh', 'position: fixed']):
                                extra_heuristics['aitm_browser_in_browser'] = "Suspicious full-screen iframe detected (Possible BiTB)"
                                penalty += 0.5

                        # 3. Detect Known AiTM Kits (Evilginx, Sneaky 2FA, Modlishka, Cephas)
                        kit_signatures = ['evilginx', 'sneaky2fa', 'modlishka', 'cephas', 'reverse-proxy-phish']
                        for sig in kit_signatures:
                            if sig in html_lower:
                                extra_heuristics['known_phishing_kit'] = f"Detected signature of known AiTM kit: {sig}"
                                penalty += 1.0
                                break

                        # 4. Detect Heavy JavaScript Obfuscation
                        if 'eval(function(p,a,c,k,e,d)' in html_lower or 'atob(' in html_lower or 'base64_decode' in html_lower:
                            extra_heuristics['heavy_js_obfuscation'] = "Page uses heavy JavaScript obfuscation (Common in AiTM kits)"
                            penalty += 0.4
                            
                        # 5. Form Action Mismatch (Credential Harvesting)
                        if '<input type="password"' in html_lower or "<input type='password'" in html_lower:
                            form_action = re.search(r'<form[^>]+action=[\'"]([^\'"]+)[\'"]', html_content, re.IGNORECASE)
                            if form_action:
                                action_url = urljoin(current_url, form_action.group(1))
                                if action_url.startswith(('http://', 'https://')):
                                    action_domain = urlparse(action_url).hostname
                                    current_domain = urlparse(current_url).hostname
                                    if action_domain and current_domain and action_domain not in current_domain:
                                        extra_heuristics['credential_harvesting_mismatch'] = f"Password form submits to a different domain: {action_domain}"
                                        penalty += 0.7

                    except Exception:
                        pass
                    break
            finally:
                if response is not None:
                    response.close()
                    
        final_url = current_url
        penalty = min(penalty, 1.0)
    except Exception:
        pass
        
    return final_url, chain, penalty, extra_heuristics

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
            stats = response.json().get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
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
    if not is_safe_url(url):
        return None
    try:
        response = requests.get(url, timeout=3, headers=BROWSER_HEADERS)
        soup = BeautifulSoup(response.text, 'html.parser')
        icon_link = soup.find("link", rel=lambda x: x and 'icon' in x.lower())
        if icon_link and icon_link.get('href'):
            icon_url = urljoin(url, icon_link['href'])
            if not is_safe_url(icon_url):
                return None
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
    is_high_reputation = False
    is_established_domain = False
    network_iocs = {}
    
    # 1. Percent Encoding Check
    decoded_url = unquote(url)
    if decoded_url != url:
        heuristics['percent_encoding_detected'] = True
        penalty += 0.2

    # CRITICAL SSRF CHECK: Stop immediately if target is internal / loopback / metadata
    if not is_safe_url(decoded_url):
        return {
            "url": url,
            "risk_score": 1.0,
            "verdict": "malicious",
            "details": {
                "ml_model_score": 0.0,
                "heuristic_penalty": 1.0,
                "redirect_chain": [url, "⛔ Blocked: URL points to a private/internal network (SSRF Protection)."],
                "virustotal_stats": {"error": "Skipped: Internal/Private destination blocked.", "malicious": 0, "vt_penalty": 0.0},
                "urlhaus_stats": None,
                "network_iocs": {},
                "checks": {
                    "ssrf_blocked": True,
                    "reason": "URL points to a private, loopback, or metadata address"
                }
            }
        }

    # 2. Trace Redirects & AiTM
    final_url, redirect_chain, redirect_penalty, redirect_heuristics = trace_redirects(decoded_url)
    penalty += redirect_penalty
    heuristics.update(redirect_heuristics)

    # If redirect pointed to internal network, return malicious immediately
    if not is_safe_url(final_url):
        return {
            "url": url,
            "risk_score": 1.0,
            "verdict": "malicious",
            "details": {
                "ml_model_score": 0.0,
                "heuristic_penalty": round(penalty, 3),
                "redirect_chain": redirect_chain,
                "virustotal_stats": {"error": "Skipped: Redirected to private destination.", "malicious": 0, "vt_penalty": 0.0},
                "urlhaus_stats": None,
                "network_iocs": {},
                "checks": heuristics
            }
        }
    
    # 3. ML Model
    ml_score = check_hf_model(final_url)
    
    # 4. VirusTotal
    vt_result = check_virustotal(final_url)
    penalty += vt_result.get('vt_penalty', 0.0)
    
    # 5. URLhaus
    urlhaus_result = check_urlhaus(final_url)
    if urlhaus_result and urlhaus_result.get("status") == "online":
        heuristics['urlhaus_threat'] = urlhaus_result.get("threat", "Malware")
        penalty += 0.8
    
    try:
        parsed_url = urlparse(final_url)
        raw_hostname = parsed_url.hostname if parsed_url.hostname else final_url.split('/')[0]
        if not raw_hostname:
            raw_hostname = ""

        try:
            decoded_hostname = idna.decode(raw_hostname)
        except Exception:
            decoded_hostname = raw_hostname
            
        normalized_hostname = normalize_homoglyphs(decoded_hostname)
        hostname = normalized_hostname

        # --- Network IOCs (IP, SSL, AbuseIPDB) ---
        if is_safe_url(final_url):
            try:
                ip_addr = socket.gethostbyname(hostname)
                network_iocs['ip_address'] = ip_addr
                
                # Reliable SSL Verification
                try:
                    requests.get(f"https://{hostname}", timeout=5, verify=True, headers=BROWSER_HEADERS)
                    heuristics['ssl_valid'] = True
                except requests.exceptions.SSLError:
                    heuristics['invalid_ssl_certificate'] = "Invalid or Self-Signed SSL Certificate"
                    penalty += 0.6
                except Exception:
                    pass

                ssl_info = get_ssl_info(hostname)
                if ssl_info:
                    network_iocs['ssl_cert'] = ssl_info
                    if ssl_info.get('days_old') is not None and ssl_info['days_old'] < 7:
                        heuristics['new_ssl_certificate'] = f"Certificate issued only {ssl_info['days_old']} days ago"
                        penalty += 0.4

                network_iocs['favicon_hash'] = get_favicon_hash(final_url)
                
                ip_info = get_ip_info(ip_addr)
                if ip_info:
                    network_iocs['asn_geoip'] = ip_info
                    
                abuse_info = check_ip_reputation(ip_addr)
                if abuse_info and not abuse_info.get('error'):
                    network_iocs['abuseipdb'] = abuse_info
                    if abuse_info.get('abuse_confidence_score', 0) > 50:
                        heuristics['malicious_ip_reputation'] = f"IP has a {abuse_info['abuse_confidence_score']}% abuse score"
                        penalty += 0.6
                    
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

        if not is_ip and hostname:
            extracted = tldextract.extract(hostname)
            root_domain = f"{extracted.domain}.{extracted.suffix}" if extracted.domain and extracted.suffix else hostname
            domain_name_only = extracted.domain.lower() if extracted.domain else ""
            subdomain = extracted.subdomain.lower() if extracted.subdomain else ""
            suffix = extracted.suffix.lower() if extracted.suffix else ""

            # Visual Brand Cloning Detection
            scanned_favicon = network_iocs.get('favicon_hash')
            if scanned_favicon and BRAND_FAVICONS:
                for brand, brand_hash in BRAND_FAVICONS.items():
                    if scanned_favicon == brand_hash:
                        if brand not in domain_name_only:
                            heuristics['visual_brand_cloning'] = f"Favicon matches '{brand}', but domain does not. (Logo Theft)"
                            penalty += 1.0
                        break
            
            # Check high reputation domain or TLD
            is_high_reputation = (domain_name_only in HIGH_REPUTATION_DOMAINS) or (suffix in HIGH_REPUTATION_TLDS)

            # WHOIS Check
            if root_domain and '.' in root_domain:
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

            suspicious_keywords = [
                'login', 'verify', 'secure', 'account', 'update', 'banking', 
                'phishing', 'admin', 'auth', 'confirm', 'signin', 'support', 
                'billing', 'wallet', 'crypto', 'recovery'
            ]
            found_in_domain = [kw for kw in suspicious_keywords if kw in domain_name_only]
            found_in_subdomain = [kw for kw in suspicious_keywords if kw in subdomain]
            
            if not is_high_reputation and not is_established_domain:
                if found_in_domain:
                    heuristics['suspicious_keywords_in_root'] = found_in_domain
                    penalty += 0.4
                if found_in_subdomain and domain_name_only not in HIGH_REPUTATION_DOMAINS:
                    heuristics['suspicious_keywords_in_subdomain'] = found_in_subdomain
                    penalty += 0.2

            # Typosquatting and Combo-squatting detection
            popular_brands = [b for b in HIGH_REPUTATION_DOMAINS if len(b) >= 4]
            typosquatting_target = None
            
            if domain_name_only not in HIGH_REPUTATION_DOMAINS and domain_name_only:
                for brand in popular_brands:
                    # Direct fuzzy typo match (e.g., paypa1 vs paypal)
                    if fuzz.ratio(domain_name_only, brand) >= 80 and abs(len(domain_name_only) - len(brand)) <= 2:
                        typosquatting_target = brand
                        break
                    # Combo-squatting with hyphens (e.g. paypal-login, apple-support)
                    if f"{brand}-" in domain_name_only or f"-{brand}" in domain_name_only:
                        typosquatting_target = brand
                        break
                    # Combo-squatting with suspicious keywords (e.g. paypalbilling, chaseverify)
                    elif brand in domain_name_only and len(domain_name_only) > len(brand):
                        remainder = domain_name_only.replace(brand, '')
                        if any(kw in remainder for kw in suspicious_keywords):
                            typosquatting_target = brand
                            break
                        
                if typosquatting_target:
                    heuristics['typosquatting_warning'] = f"Domain mimics brand: '{typosquatting_target}'"
                    penalty += 0.6

            if not is_high_reputation and not is_established_domain:
                if hostname.count('-') > 2: 
                    heuristics['excessive_hyphens'] = True
                    penalty += 0.2
                if suffix in ['xyz', 'top', 'tk', 'gq', 'cf', 'ml', 'work', 'click']: 
                    heuristics['suspicious_tld'] = suffix
                    penalty += 0.3
                if len(subdomain.split('.')) > 1: 
                    heuristics['deep_subdomains'] = subdomain
                    penalty += 0.25

            if domain_name_only:
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

        if not is_ip and root_domain:
            try:
                socket.getaddrinfo(root_domain, None)
                heuristics['dns_resolved'] = True
            except socket.gaierror:
                heuristics['dns_resolved'] = False
                if not is_high_reputation and not is_established_domain: 
                    penalty += 0.4
            
    except Exception as e:
        heuristics['parsing_error'] = str(e)

    # Only override score for trusted domains if there are NO critical threat indicators
    has_critical_indicators = (
        heuristics.get('punycode_homoglyph_attack') or
        heuristics.get('typosquatting_warning') or
        heuristics.get('visual_brand_cloning') or
        heuristics.get('invalid_ssl_certificate') or
        heuristics.get('new_ssl_certificate') or
        heuristics.get('urlhaus_threat') or
        heuristics.get('known_phishing_kit') or
        heuristics.get('credential_harvesting_mismatch') or
        vt_result.get('malicious', 0) >= 2
    )

    if (is_high_reputation or is_established_domain) and not has_critical_indicators:
        heuristics['trusted_domain'] = True
        penalty = min(penalty, 0.1)
        ml_score = 0.0
        heuristics['ml_score_overridden'] = True

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
            "urlhaus_stats": urlhaus_result,
            "network_iocs": network_iocs,
            "checks": heuristics
        }
    }

def analyze_email(text: str):
    """Analyzes raw email text for social engineering, brand impersonation, and hidden URLs."""
    if not text or not isinstance(text, str):
        text = ""

    # 1. Extract URLs
    url_pattern = r'https?://[^\s<>"\'\)]+|www\.[^\s<>"\'\)]+'
    urls = re.findall(url_pattern, text)
    
    # 2. Social Engineering Keyword Heuristics
    urgency_keywords = [
        'urgent', 'immediate action', 'suspended', 'verify your account', 
        'click here', 'password reset', 'unauthorized', 'account alert', 
        'security warning', 'account locked', 'suspension notice'
    ]
    financial_keywords = [
        'wire transfer', 'bank account', 'invoice attached', 'payment due', 
        'bitcoin', 'crypto wallet', 'billing problem', 'refund request'
    ]
    
    text_lower = text.lower()
    found_urgency = [kw for kw in urgency_keywords if kw in text_lower]
    found_financial = [kw for kw in financial_keywords if kw in text_lower]
    
    penalty = 0.0
    heuristics = {}
    ai_warning = None
    
    if found_urgency:
        heuristics['urgency_keywords_detected'] = found_urgency
        penalty += min(0.15 * len(found_urgency), 0.4)
        
    if found_financial:
        heuristics['financial_keywords_detected'] = found_financial
        penalty += min(0.15 * len(found_financial), 0.4)
        
    # 3. Scan the URL (if found)
    url_result = None
    if urls:
        clean_url = urls[0].rstrip('.,;:)')
        if not clean_url.startswith('http'):
            clean_url = 'https://' + clean_url
        url_result = analyze_url(clean_url)
        penalty += url_result['risk_score']
    else:
        if len(found_urgency) >= 2 or len(found_financial) >= 2:
            penalty += 0.3

    # AI-Generated Brand Impersonation Check (word boundary search, skipping ambiguous common words)
    ambiguous_words = {'live', 'meta', 'zoom', 'slack', 'steam', 'visa', 'x'}
    brands_in_text = []
    for brand in HIGH_REPUTATION_DOMAINS:
        if len(brand) >= 4 and brand not in ambiguous_words:
            if re.search(r'\b' + re.escape(brand) + r'\b', text_lower):
                brands_in_text.append(brand)
    
    if brands_in_text and urls:
        for brand in brands_in_text:
            if not any(brand in u.lower() for u in urls):
                heuristics['ai_brand_impersonation'] = f"Text claims to be from '{brand}', but URL does not belong to them."
                penalty += 0.4
                break

    if penalty >= 0.5:
        ai_warning = "⚠️ AI DECEPTION WARNING: This message uses urgency or brand impersonation patterns typical of phishing. NEVER trust a link based on email text alone; verify the sender through a separate verified channel."

    final_score = min(penalty, 1.0)
    
    if final_score >= 0.7: 
        verdict = "malicious"
    elif final_score >= 0.3: 
        verdict = "suspicious"
    else: 
        verdict = "benign"

    return {
        "type": "email_analysis",
        "url": urls[0] if urls else "No URLs found in email text",
        "extracted_urls": urls,
        "risk_score": round(final_score, 3),
        "verdict": verdict,
        "ai_warning": ai_warning,
        "details": {
            "text_heuristics": heuristics,
            "url_scan_result": url_result
        }
    }
