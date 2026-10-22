import sqlite3
from datetime import datetime

DB_FILE = "history.db"

def init_db():
    """Creates the database and table if they don't exist."""
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            url TEXT NOT NULL,
            risk_score REAL NOT NULL,
            verdict TEXT NOT NULL,
            timestamp TEXT NOT NULL
        )
    ''')
    conn.commit()
    conn.close()

def save_scan(url: str, risk_score: float, verdict: str):
    """Saves a new scan result to the database."""
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    cursor.execute('''
        INSERT INTO scans (url, risk_score, verdict, timestamp)
        VALUES (?, ?, ?, ?)
    ''', (url, risk_score, verdict, timestamp))
    conn.commit()
    conn.close()

def get_history(limit: int = 10):
    """Fetches the most recent scans."""
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute('''
        SELECT url, risk_score, verdict, timestamp 
        FROM scans 
        ORDER BY id DESC 
        LIMIT ?
    ''', (limit,))
    rows = cursor.fetchall()
    conn.close()
    
    # Convert to a list of dictionaries for FastAPI to return as JSON
    history = []
    for row in rows:
        history.append({
            "url": row[0],
            "risk_score": row[1],
            "verdict": row[2],
            "timestamp": row[3]
        })
    return history

# Initialize the database when this file is imported
init_db()