import requests
import mmh3
import base64
import json
import os
from urllib.parse import urlparse

# The brands we want to protect
BRANDS = {
    "paypal": "https://www.paypal.com/favicon.ico",
    "microsoft": "https://www.microsoft.com/favicon.ico",
    "google": "https://www.google.com/favicon.ico",
    "apple": "https://www.apple.com/favicon.ico",
    "facebook": "https://www.facebook.com/favicon.ico",
    "amazon": "https://www.amazon.com/favicon.ico",
    "netflix": "https://www.netflix.com/favicon.ico",
    "github": "https://github.com/favicon.ico",
    "instagram": "https://www.instagram.com/favicon.ico",
    "linkedin": "https://www.linkedin.com/favicon.ico"
}

def generate_hashes():
    hash_db = {}
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"}
    
    for brand, url in BRANDS.items():
        print(f"Fetching favicon for {brand}...")
        try:
            response = requests.get(url, headers=headers, timeout=5)
            if response.status_code == 200:
                # Convert image to base64, then to MurmurHash3
                favicon_base64 = base64.b64encode(response.content)
                favicon_hash = mmh3.hash(favicon_base64)
                hash_db[brand] = favicon_hash
                print(f"  -> Hash: {favicon_hash}")
            else:
                print(f"  -> Failed (Status: {response.status_code})")
        except Exception as e:
            print(f"  -> Error: {e}")
            
    # Save to JSON file
    with open("brand_hashes.json", "w") as f:
        json.dump(hash_db, f, indent=4)
    print("\nSuccessfully saved to brand_hashes.json!")

if __name__ == "__main__":
    generate_hashes()