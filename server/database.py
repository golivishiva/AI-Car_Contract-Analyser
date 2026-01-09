# database.py
import sqlite3
import os

DB_PATH = "contracts.db"

def get_connection():
    """Get database connection"""
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    return conn

def init_db():
    """Initialize database with required tables"""
    conn = get_connection()
    cur = conn.cursor()
    
    # Create contracts table
    cur.execute("""
        CREATE TABLE IF NOT EXISTS contracts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            filename TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
    """)
    
    # Create contract_data table
    cur.execute("""
        CREATE TABLE IF NOT EXISTS contract_data (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            contract_id INTEGER NOT NULL,
            summary TEXT,
            sla TEXT,
            FOREIGN KEY (contract_id) REFERENCES contracts(id)
        )
    """)
    
    # Create chat_messages table
    cur.execute("""
        CREATE TABLE IF NOT EXISTS chat_messages (
            contract_id INTEGER NOT NULL,
            role TEXT NOT NULL,
            message TEXT NOT NULL,
            timestamp TEXT NOT NULL,
            FOREIGN KEY (contract_id) REFERENCES contracts(id)
        )
    """)
    
    conn.commit()
    conn.close()

def get_contract_history(contract_id):
    """Retrieve all chat messages for a specific contract"""
    conn = get_connection()
    cur = conn.cursor()
    
    cur.execute(
        "SELECT role, message FROM chat_messages WHERE contract_id=? ORDER BY timestamp",
        (contract_id,)
    )
    
    rows = cur.fetchall()
    conn.close()
    
    return [{"role": r[0], "content": r[1]} for r in rows]

def get_all_contracts():
    """Get list of all contracts"""
    conn = get_connection()
    cur = conn.cursor()
    
    cur.execute("SELECT id, filename, created_at FROM contracts ORDER BY created_at DESC")
    rows = cur.fetchall()
    conn.close()
    
    return rows