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
    # 1. Add 'id' to the SELECT statement
    cursor.execute('''
        SELECT id, url, risk_score, verdict, timestamp 
        FROM scans 
        ORDER BY id DESC 
        LIMIT ?
    ''', (limit,))
    rows = cursor.fetchall()
    conn.close()
    
    history = []
    for row in rows:
        history.append({
            "id": row[0],       # NEW: Send ID to frontend
            "url": row[1],
            "risk_score": row[2],
            "verdict": row[3],
            "timestamp": row[4]
        })
    return history

def delete_scan(scan_id: int):
    """Deletes a specific scan by its ID."""
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute('DELETE FROM scans WHERE id = ?', (scan_id,))
    conn.commit()
    conn.close()

def clear_history():
    """Deletes all records from the scans table."""
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute('DELETE FROM scans')
    conn.commit()
    conn.close()