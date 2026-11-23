import sqlite3
import os
from datetime import datetime

DB_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "history.db")

def get_connection():
    conn = sqlite3.connect(DB_FILE, timeout=15.0)
    conn.execute("PRAGMA journal_mode=WAL;")
    return conn

def init_db():
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                url TEXT NOT NULL,
                risk_score REAL NOT NULL,
                verdict TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                feedback TEXT DEFAULT 'none'
            )
        ''')
        conn.commit()

def save_scan(url: str, risk_score: float, verdict: str):
    init_db()
    with get_connection() as conn:
        cursor = conn.cursor()
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        cursor.execute('''
            INSERT INTO scans (url, risk_score, verdict, timestamp)
            VALUES (?, ?, ?, ?)
        ''', (url, float(risk_score), verdict, timestamp))
        conn.commit()

def update_feedback(scan_id: int, feedback: str):
    if feedback not in ('true_positive', 'false_positive', 'none'):
        return False
    init_db()
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute('UPDATE scans SET feedback = ? WHERE id = ?', (feedback, scan_id))
        conn.commit()
    return True

def get_history(limit: int = 50):
    init_db()
    safe_limit = max(1, min(int(limit), 200))
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT id, url, risk_score, verdict, timestamp, feedback FROM scans ORDER BY id DESC LIMIT ?', (safe_limit,))
        rows = cursor.fetchall()
    
    history = []
    for row in rows:
        history.append({
            "id": row[0],
            "url": row[1],
            "risk_score": row[2],
            "verdict": row[3],
            "timestamp": row[4],
            "feedback": row[5]
        })
    return history

def delete_scan(scan_id: int):
    init_db()
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute('DELETE FROM scans WHERE id = ?', (scan_id,))
        conn.commit()

def clear_history():
    init_db()
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute('DELETE FROM scans')
        conn.commit()

def get_analytics():
    """Fetches counts of each verdict type and total scans."""
    init_db()
    with get_connection() as conn:
        cursor = conn.cursor()
        
        # Get total scans
        cursor.execute("SELECT COUNT(*) FROM scans")
        total = cursor.fetchone()[0]
        
        # Get counts per verdict
        cursor.execute("SELECT verdict, COUNT(*) FROM scans GROUP BY verdict")
        verdict_counts = dict(cursor.fetchall())
    
    return {
        "total_scans": total,
        "benign": verdict_counts.get("benign", 0),
        "suspicious": verdict_counts.get("suspicious", 0),
        "malicious": verdict_counts.get("malicious", 0)
    }
