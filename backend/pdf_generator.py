import json
from fpdf import FPDF
from datetime import datetime

def safe_str(s):
    """Safely sanitizes text for Latin-1 PDF rendering and handles complex types."""
    if s is None:
        return ""
    if isinstance(s, (dict, list)):
        s = json.dumps(s)
    elif not isinstance(s, str):
        s = str(s)
    return s.encode('latin-1', 'replace').decode('latin-1')

class ThreatReport(FPDF):
    def header(self):
        self.set_font('helvetica', 'B', 18)
        self.set_text_color(41, 128, 185) # Blue
        self.cell(190, 10, 'Phishing URL Sentinel - Threat Report', 0, 1, 'C')
        self.set_font('helvetica', 'I', 10)
        self.set_text_color(100, 100, 100)
        self.cell(190, 8, f'Generated on: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}', 0, 1, 'C')
        self.ln(6)

    def footer(self):
        self.set_y(-15)
        self.set_font('helvetica', 'I', 8)
        self.set_text_color(128)
        self.cell(190, 10, f'Page {self.page_no()}', 0, 0, 'C')

    def section_title(self, title):
        self.set_font('helvetica', 'B', 13)
        self.set_text_color(0, 0, 0)
        self.set_fill_color(230, 230, 230)
        self.cell(190, 9, f"  {title}", 0, 1, 'L', True) 
        self.ln(2)

    def key_value(self, key, value):
        self.set_font('helvetica', 'B', 10)
        self.set_text_color(50, 50, 50)
        self.cell(50, 7, f"{safe_str(key)}:", 0, 0)
        
        self.set_font('helvetica', '', 10)
        self.set_text_color(0, 0, 0)
        self.multi_cell(140, 7, safe_str(value)) 

def generate_pdf(data: dict) -> bytes:
    if not isinstance(data, dict):
        data = {}

    details = data.get('details')
    if not isinstance(details, dict):
        details = {}

    pdf = ThreatReport()
    pdf.add_page()
    
    # 1. Executive Summary
    pdf.section_title('1. Executive Summary')
    
    is_email_analysis = data.get('type') == 'email_analysis'
    analyzed_input = data.get('url', 'Email Text Analysis' if is_email_analysis else 'Unknown')
    pdf.key_value('Analyzed Input', analyzed_input)
    
    # Colored Verdict Banner
    verdict = str(data.get('verdict', 'unknown')).upper()
    pdf.set_font('helvetica', 'B', 11)
    pdf.cell(50, 9, 'Final Verdict:', 0, 0)
    
    if verdict == 'MALICIOUS':
        pdf.set_fill_color(231, 76, 60) # Red
        pdf.set_text_color(255, 255, 255)
    elif verdict == 'SUSPICIOUS':
        pdf.set_fill_color(241, 196, 15) # Yellow
        pdf.set_text_color(0, 0, 0)
    else:
        pdf.set_fill_color(46, 204, 113) # Green
        pdf.set_text_color(255, 255, 255)
        
    pdf.cell(140, 9, f"  {verdict}  ", 0, 1, 'L', True) 
    
    pdf.set_text_color(0, 0, 0)
    try:
        risk_score_val = float(data.get('risk_score', 0))
    except (ValueError, TypeError):
        risk_score_val = 0.0
    pdf.key_value('Risk Score', f"{risk_score_val * 100:.1f}%")
    pdf.ln(4)

    # If this is an email analysis
    if is_email_analysis:
        pdf.section_title('2. Email Threat Analysis')
        ai_warning = data.get('ai_warning')
        if ai_warning:
            pdf.set_font('helvetica', 'B', 10)
            pdf.set_text_color(200, 0, 0)
            pdf.multi_cell(190, 6, safe_str(ai_warning))
            pdf.ln(2)
            pdf.set_text_color(0, 0, 0)

        extracted_urls = data.get('extracted_urls', [])
        if extracted_urls:
            pdf.key_value('Extracted URLs', ", ".join(extracted_urls))
        else:
            pdf.key_value('Extracted URLs', 'None detected')

        text_heuristics = details.get('text_heuristics')
        if isinstance(text_heuristics, dict) and text_heuristics:
            for k, v in text_heuristics.items():
                pdf.key_value(k.replace('_', ' ').title(), safe_str(v))
        pdf.ln(4)

        # If there was an embedded URL scan result inside email analysis
        url_scan_result = details.get('url_scan_result')
        if isinstance(url_scan_result, dict):
            details = url_scan_result.get('details', {})
            if not isinstance(details, dict):
                details = {}

    # Threat Intelligence Feeds (for URL scans or embedded URL in email)
    if not is_email_analysis or details.get('virustotal_stats') or details.get('urlhaus_stats'):
        pdf.section_title('3. Threat Intelligence Feeds')
        
        vt = details.get('virustotal_stats')
        if isinstance(vt, dict) and not vt.get('error'):
            pdf.key_value('VirusTotal', f"{vt.get('malicious', 0)} / {vt.get('total_engines', 70)} security vendors flagged this URL")
        elif isinstance(vt, dict) and vt.get('error'):
            pdf.key_value('VirusTotal', safe_str(vt.get('error')))
        else:
            pdf.key_value('VirusTotal', 'No data available')
            
        urlhaus = details.get('urlhaus_stats')
        if isinstance(urlhaus, dict) and urlhaus.get('status') == 'online':
            pdf.key_value('URLhaus', f"Known Malware: {urlhaus.get('threat', 'Unspecified')}")
        else:
            pdf.key_value('URLhaus', 'Clean (Not listed in database)')
        pdf.ln(4)

    # Network IOCs
    iocs = details.get('network_iocs')
    if isinstance(iocs, dict) and iocs:
        pdf.section_title('4. Network Indicators (IOCs)')
        if iocs.get('ip_address'):
            pdf.key_value('IP Address', iocs['ip_address'])
        
        if isinstance(iocs.get('asn_geoip'), dict):
            geo = iocs['asn_geoip']
            pdf.key_value('ASN / ISP', f"{geo.get('asn', 'Unknown')} ({geo.get('isp', 'Unknown')})")
            pdf.key_value('Location', f"{geo.get('city', 'Unknown')}, {geo.get('country', 'Unknown')}")
            
        if isinstance(iocs.get('abuseipdb'), dict):
            abuse = iocs['abuseipdb']
            pdf.key_value('AbuseIPDB', f"{abuse.get('abuse_confidence_score', 0)}% Abuse Score")
            
        if isinstance(iocs.get('ssl_cert'), dict):
            ssl_c = iocs['ssl_cert']
            pdf.key_value('SSL Issuer', ssl_c.get('issuer', 'Unknown'))
            pdf.key_value('SSL Expiry', ssl_c.get('valid_until', 'Unknown'))
            if ssl_c.get('is_self_signed'):
                pdf.key_value('SSL Status', 'Self-Signed (Untrusted)')
        pdf.ln(4)

    # Heuristic Detection Details
    checks = details.get('checks')
    if isinstance(checks, dict) and checks:
        pdf.section_title('5. Heuristic Detection Details')
        for key, value in checks.items():
            clean_key = key.replace('_', ' ').title()
            val_str = safe_str(value)
            if len(val_str) > 120: 
                val_str = val_str[:117] + "..."
            pdf.key_value(clean_key, val_str)

    return pdf.output()
