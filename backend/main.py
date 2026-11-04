from fastapi import FastAPI, Request
from pydantic import BaseModel, field_validator
import validators
from fastapi.middleware.cors import CORSMiddleware
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from contextlib import asynccontextmanager  # NEW: For database startup
from detector import analyze_url
import database

# NEW: Initialize the database when the server starts
@asynccontextmanager
async def lifespan(app: FastAPI):
    database.init_db()
    yield

limiter = Limiter(key_func=get_remote_address)

app = FastAPI(
    title="Phishing URL Sentinel",
    description="An API to detect phishing URLs using ML models and heuristics.",
    version="1.0.0",
    lifespan=lifespan  # NEW: Connect the lifespan handler
)

app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# CORS Configuration
origins = [
    "http://localhost:8080",
    "http://127.0.0.1:8080",
    "http://localhost:5500",
    "http://127.0.0.1:5500"
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

@app.post("/scan")
@limiter.limit("5/minute") 
async def scan_url(request: Request, url_request: URLRequest):
    result = analyze_url(url_request.url)
    database.save_scan(result["url"], result["risk_score"], result["verdict"])
    return result

@app.get("/history")
def get_scan_history():
    return database.get_history()

# FIXED 3.1: Clear history route is now separate and correct
@app.delete("/history")
def clear_scan_history():
    database.clear_history()
    return {"message": "History cleared successfully"}

# FIXED 3.1: Single scan delete route is now separate and correct
@app.delete("/history/{scan_id}")
def delete_single_scan(scan_id: int):
    database.delete_scan(scan_id)
    return {"message": f"Scan {scan_id} deleted successfully"}