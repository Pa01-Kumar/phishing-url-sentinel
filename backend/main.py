from fastapi.middleware.cors import CORSMiddleware
from fastapi import FastAPI
from pydantic import BaseModel
from detector import analyze_url # Import our new function!

app = FastAPI(
    title="Phishing URL Sentinel",
    description="An API to detect phishing URLs using ML models and heuristics.",
    version="0.1.0"
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], # Allows any frontend to talk to this API
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
    # Call the detector logic
    result = analyze_url(request.url)
    return result