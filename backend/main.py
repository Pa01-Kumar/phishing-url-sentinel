import time
import os
import uuid
import validators
import cv2
import numpy as np
from datetime import datetime, timezone
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request, File, UploadFile
from fastapi.responses import Response, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, field_validator
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

from pdf_generator import generate_pdf
from detector import analyze_url, analyze_email
import database

# Initialize the database when the server starts
@asynccontextmanager
async def lifespan(app: FastAPI):
    database.init_db()
    yield

limiter = Limiter(key_func=get_remote_address)

app = FastAPI(
    title="Phishing URL Sentinel",
    description="An API to detect phishing URLs using ML models and heuristics.",
    version="1.0.0",
    lifespan=lifespan
)

app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# CORS Configuration
origins = [
    "http://localhost:8080",
    "http://127.0.0.1:8080",
    "https://phishing-sentinel-two.vercel.app",
    "https://phishing-sentinel-gtbph3jrt-pa1kumar7668-7647.vercel.app"
]

env_origins = os.getenv("ALLOWED_ORIGINS")
if env_origins:
    origins.extend([o.strip() for o in env_origins.split(",") if o.strip()])

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_origin_regex=r"https://phishing-sentinel-.*\.vercel\.app",
    allow_credentials=False,
    allow_methods=["GET", "POST", "DELETE", "OPTIONS"],
    allow_headers=["*"],
)

class EmailRequest(BaseModel):
    text: str

    @field_validator('text')
    def validate_text(cls, v):
        if not v or not v.strip():
            raise ValueError("Email text cannot be empty")
        if len(v) > 10000:
            raise ValueError("Email text is too long (max 10,000 characters)")
        return v
    
class URLRequest(BaseModel):
    url: str

    @field_validator('url')
    def validate_url(cls, v):
        v = v.strip()
        if len(v) > 2048:
            raise ValueError("URL is too long (max 2048 characters)")
        if not validators.url(v):
            raise ValueError("Invalid URL format. Must start with http:// or https://")
        return v

class FeedbackRequest(BaseModel):
    scan_id: int
    feedback: str # 'true_positive' or 'false_positive'

    @field_validator('feedback')
    def validate_feedback(cls, v):
        v = v.strip().lower()
        if v not in ('true_positive', 'false_positive'):
            raise ValueError("Feedback must be 'true_positive' or 'false_positive'")
        return v

@app.get("/")
def read_root():
    return {"message": "Phishing Sentinel API is running!"}

@app.post("/scan")
@limiter.limit("5/minute") 
def scan_url(request: Request, url_request: URLRequest):
    result = analyze_url(url_request.url)
    database.save_scan(result["url"], result["risk_score"], result["verdict"])
    return result

@app.post("/scan/stix")
@limiter.limit("5/minute") 
def scan_url_stix(request: Request, url_request: URLRequest):
    result = analyze_url(url_request.url)
    now_iso = datetime.now(timezone.utc).isoformat()
    
    stix_bundle = {
        "type": "bundle",
        "id": f"bundle--{uuid.uuid4()}",
        "objects": [
            {
                "type": "indicator",
                "spec_version": "2.1",
                "id": f"indicator--{uuid.uuid4()}",
                "created": now_iso,
                "modified": now_iso,
                "name": f"Phishing Scan: {url_request.url}",
                "description": f"Risk Score: {result['risk_score']} | Verdict: {result['verdict']}",
                "indicator_types": ["malicious-activity" if result['verdict'] == 'malicious' else "anomalous-activity"],
                "pattern": f"[url:value = '{url_request.url}']",
                "pattern_type": "stix",
                "valid_from": now_iso,
                "x_sentinel_iocs": result['details'].get('network_iocs', {})
            }
        ]
    }
    return stix_bundle

@app.get("/history")
def get_scan_history(limit: int = 50):
    return database.get_history(limit=limit)

@app.delete("/history")
def clear_scan_history():
    database.clear_history()
    return {"message": "History cleared successfully"}

@app.delete("/history/{scan_id}")
def delete_single_scan(scan_id: int):
    database.delete_scan(scan_id)
    return {"message": f"Scan {scan_id} deleted successfully"}

@app.post("/feedback")
def submit_feedback(feedback_req: FeedbackRequest):
    database.update_feedback(feedback_req.scan_id, feedback_req.feedback)
    return {"message": "Feedback recorded successfully"}

@app.post("/scan_qr")
@limiter.limit("5/minute")
async def scan_qr_code(request: Request, file: UploadFile = File(...)):
    MAX_FILE_SIZE = 10 * 1024 * 1024 # 10MB limit
    try:
        image_bytes = await file.read(MAX_FILE_SIZE + 1)
        if len(image_bytes) > MAX_FILE_SIZE:
            return JSONResponse(status_code=400, content={"error": "Uploaded image file exceeds maximum allowed size (10MB)."})

        nparr = np.frombuffer(image_bytes, np.uint8)
        img = cv2.imdecode(nparr, cv2.IMREAD_COLOR)
        
        if img is None:
            return JSONResponse(status_code=400, content={"error": "Could not read the image file. Ensure it is a valid PNG, JPG, or WEBP image."})

        # Use OpenCV's built-in QRCodeDetector
        detector = cv2.QRCodeDetector()
        qr_url, _, _ = detector.detectAndDecode(img)
        
        if not qr_url:
            return JSONResponse(status_code=400, content={"error": "No QR code found in the image."})
            
        qr_url = qr_url.strip()
        if not qr_url.startswith(('http://', 'https://')):
            if '.' in qr_url and not any(qr_url.startswith(p) for p in ('WIFI:', 'BEGIN:', 'mailto:', 'tel:')):
                qr_url = 'https://' + qr_url
            else:
                return JSONResponse(status_code=400, content={"error": f"QR code content is not a URL: {qr_url[:100]}"})
            
        if not validators.url(qr_url):
            return JSONResponse(status_code=400, content={"error": f"Invalid URL inside QR code: {qr_url[:100]}"})

        result = analyze_url(qr_url)
        database.save_scan(result["url"], result["risk_score"], result["verdict"])
        return result
        
    except Exception as e:
        return JSONResponse(status_code=500, content={"error": f"Internal error scanning QR code: {str(e)}"})

@app.post("/scan_email")
@limiter.limit("5/minute")
def scan_email(request: Request, email_request: EmailRequest):
    result = analyze_email(email_request.text)
    if result.get('extracted_urls'):
        database.save_scan(result['extracted_urls'][0], result['risk_score'], result['verdict'])
    return result

@app.get("/analytics")
def get_analytics_data():
    return database.get_analytics()

@app.post("/export/pdf")
@limiter.limit("10/minute")
def export_pdf(request: Request, data: dict):
    if not isinstance(data, dict) or not data:
        return JSONResponse(status_code=400, content={"error": "Invalid payload for PDF generation"})
    try:
        pdf_bytes = generate_pdf(data)
        return Response(
            content=bytes(pdf_bytes),
            media_type="application/pdf",
            headers={"Content-Disposition": f"attachment; filename=Threat_Report_{int(time.time())}.pdf"}
        )
    except Exception as e:
        print(f"🚨 PDF GENERATION ERROR: {e}")
        return JSONResponse(status_code=500, content={"error": f"Failed to generate PDF: {str(e)}"})
