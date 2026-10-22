from fastapi import FastAPI
from pydantic import BaseModel
from detector import analyze_url
from fastapi.middleware.cors import CORSMiddleware
import database  # <-- NEW: Import our database file

app = FastAPI(
    title="Phishing URL Sentinel",
    description="An API to detect phishing URLs using ML models and heuristics.",
    version="0.1.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class URLRequest(BaseModel):
    url: str

@app.get("/")
def read_root():
    return {"message": "Phishing Sentinel API is running!"}

@app.post("/scan")
async def scan_url(request: URLRequest):
    result = analyze_url(request.url)
    
    # NEW: Save the result to the database
    database.save_scan(result["url"], result["risk_score"], result["verdict"])
    
    return result

# NEW: Endpoint to get recent scans
@app.get("/history")
def get_scan_history():
    return database.get_history()