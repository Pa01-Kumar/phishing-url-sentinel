from fastapi import FastAPI, Request
from pydantic import BaseModel, field_validator
import validators
import uuid
from datetime import datetime
from fastapi.middleware.cors import CORSMiddleware
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from contextlib import asynccontextmanager
from detector import analyze_url
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
    "https://phishing-sentinel-two.vercel.app"  # <-- Must be here!
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=False,
    allow_methods=["GET", "POST", "DELETE", "OPTIONS"],
    allow_headers=["*"],
)

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

@app.get("/")
def read_root():
    return {"message": "Phishing Sentinel API is running!"}

# FIXED: Changed to 'def' to prevent Event Loop Starvation
@app.post("/scan")
@limiter.limit("5/minute") 
def scan_url(request: Request, url_request: URLRequest):
    result = analyze_url(url_request.url)
    database.save_scan(result["url"], result["risk_score"], result["verdict"])
    return result

# NEW: STIX 2.1 Threat Intel Export
@app.post("/scan/stix")
@limiter.limit("5/minute") 
def scan_url_stix(request: Request, url_request: URLRequest):
    # Run the normal scan first
    result = analyze_url(url_request.url)
    
    # Format into STIX 2.1 Bundle
    stix_bundle = {
        "type": "bundle",
        "id": f"bundle--{uuid.uuid4()}",
        "objects": [
            {
                "type": "indicator",
                "spec_version": "2.1",
                "id": f"indicator--{uuid.uuid4()}",
                "created": datetime.utcnow().isoformat() + "Z",
                "modified": datetime.utcnow().isoformat() + "Z",
                "name": f"Phishing Scan: {url_request.url}",
                "description": f"Risk Score: {result['risk_score']} | Verdict: {result['verdict']}",
                "indicator_types": ["malicious-activity" if result['verdict'] == 'malicious' else "anomalous-activity"],
                "pattern": f"[url:value = '{url_request.url}']",
                "pattern_type": "stix",
                "valid_from": datetime.utcnow().isoformat() + "Z",
                "x_sentinel_iocs": result['details'].get('network_iocs', {})
            }
        ]
    }
    return stix_bundle

@app.get("/history")
def get_scan_history():
    return database.get_history()

# FIXED: Clear history route is separate and correct
@app.delete("/history")
def clear_scan_history():
    database.clear_history()
    return {"message": "History cleared successfully"}

# FIXED: Single scan delete route is separate and correct
@app.delete("/history/{scan_id}")
def delete_single_scan(scan_id: int):
    database.delete_scan(scan_id)
    return {"message": f"Scan {scan_id} deleted successfully"}

from pydantic import BaseModel

class FeedbackRequest(BaseModel):
    scan_id: int
    feedback: str # 'true_positive' or 'false_positive'

@app.post("/feedback")
def submit_feedback(feedback_req: FeedbackRequest):
    database.update_feedback(feedback_req.scan_id, feedback_req.feedback)
    return {"message": "Feedback recorded successfully"}