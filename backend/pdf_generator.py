from fpdf import FPDF
from datetime import datetime

def safe_str(s):
    """Removes characters that break PDF rendering (like emojis)."""
    if isinstance(s, str):
        return s.encode('latin-1', 'replace').decode('latin-1')
    return str(s)

class ThreatReport(FPDF):
    def header(self):
        self.set_font('helvetica', 'B', 20)
        self.set_text_color(41, 128, 185) # Blue
        self.cell(190, 10, 'Phishing URL Sentinel - Threat Report', 0, 1, 'C')
        self.set_font('helvetica', 'I', 10)
        self.set_text_color(100, 100, 100)
        self.cell(190, 10, f'Generated on: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}', 0, 1, 'C')
        self.ln(10)

    def footer(self):
        self.set_y(-15)
        self.set_font('helvetica', 'I', 8)
        self.set_text_color(128)
        self.cell(190, 10, f'Page {self.page_no()}', 0, 0, 'C')

    def section_title(self, title):
        self.set_font('helvetica', 'B', 14)
        self.set_text_color(0, 0, 0)
        self.set_fill_color(230, 230, 230)
        # Explicit width 190mm to prevent overflow errors
        self.cell(190, 10, title, 0, 1, 'L', True) 
        self.ln(2)

    def key_value(self, key, value):
        self.set_font('helvetica', 'B', 11)
        self.set_text_color(50, 50, 50)
        self.cell(45, 8, f"{key}:", 0, 0) # Explicit width for key
        
        self.set_font('helvetica', '', 11)
        self.set_text_color(0, 0, 0)
        # Explicit width for value (140mm). This prevents the error.
        self.multi_cell(140, 8, safe_str(value)) 

def generate_pdf(data: dict) -> bytes:
    pdf = ThreatReport()
    pdf.add_page()
    
    # --- 1. Executive Summary ---
    pdf.section_title('1. Executive Summary')
    
    pdf.key_value('Analyzed URL', data.get('url', 'Unknown'))
    
    # Colored Verdict Banner
    verdict = str(data.get('verdict', 'unknown')).upper()
    pdf.set_font('helvetica', 'B', 12)
    pdf.cell(45, 10, 'Final Verdict:', 0, 0)
    
    if verdict == 'MALICIOUS':
        pdf.set_fill_color(231, 76, 60) # Red
        pdf.set_text_color(255, 255, 255)
    elif verdict == 'SUSPICIOUS':
        pdf.set_fill_color(241, 196, 15) # Yellow
        pdf.set_text_color(0, 0, 0)
    else:
        pdf.set_fill_color(46, 204, 113) # Green
        pdf.set_text_color(255, 255, 255)
        
    # Explicit width 145mm for the banner
    pdf.cell(145, 10, f"  {verdict}  ", 0, 1, 'L', True) 
    
    pdf.set_text_color(0, 0, 0)
    pdf.key_value('Risk Score', f"{float(data.get('risk_score', 0)) * 100:.1f}%")
    pdf.ln(5)

    # --- 2. Threat Intelligence ---
    pdf.section_title('2. Threat Intelligence Feeds')
    
    vt = data.get('details', {}).get('virustotal_stats', {})
    if vt and not vt.get('error'):
        pdf.key_value('VirusTotal', f"{vt.get('malicious')} / {vt.get('total_engines')} security vendors flagged this URL")
    else:
        pdf.key_value('VirusTotal', 'No data available')
        
    urlhaus = data.get('details', {}).get('urlhaus_stats')
    if urlhaus and urlhaus.get('status') == 'online':
        pdf.key_value('URLhaus', f"Known Malware: {urlhaus.get('threat')}")
    else:
        pdf.key_value('URLhaus', 'Clean (Not in database)')
    pdf.ln(5)

    # --- 3. Network IOCs ---
    pdf.section_title('3. Network Indicators (IOCs)')
    
    iocs = data.get('details', {}).get('network_iocs', {})
    if iocs:
        if iocs.get('ip_address'):
            pdf.key_value('IP Address', iocs['ip_address'])
        
        if iocs.get('asn_geoip'):
            geo = iocs['asn_geoip']
            pdf.key_value('ASN / ISP', f"{geo.get('asn')} ({geo.get('isp')})")
            pdf.key_value('Location', f"{geo.get('city')}, {geo.get('country')}")
            
        if iocs.get('abuseipdb'):
            abuse = iocs['abuseipdb']
            pdf.key_value('AbuseIPDB', f"{abuse.get('abuse_confidence_score')}% Abuse Score")
            
        if iocs.get('ssl_cert'):
            ssl = iocs['ssl_cert']
            pdf.key_value('SSL Issuer', ssl.get('issuer'))
            pdf.key_value('SSL Expiry', ssl.get('valid_until'))
    else:
        pdf.set_font('helvetica', 'I', 11)
        pdf.cell(190, 8, "No network IOCs extracted (Site may be offline).", 0, 1)
    pdf.ln(5)

    # --- 4. Detection Details ---
    pdf.section_title('4. Heuristic Detection Details')
    
    checks = data.get('details', {}).get('checks', {})
    if checks:
        for key, value in checks.items():
            clean_key = key.replace('_', ' ').title()
            val_str = safe_str(value)
            if len(val_str) > 120: val_str = val_str[:117] + "..."
            pdf.key_value(clean_key, val_str)
    else:
        pdf.cell(190, 8, "No structural anomalies detected.", 0, 1)

    # Return PDF as bytes
    return pdf.output()