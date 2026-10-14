"""
storage.py
SQLite-backed storage for runs, endpoints, logs, and findings.
"""
import sqlite3
import json
from datetime import datetime

class Storage:
    def __init__(self, path="agent.db"):
        self.conn = sqlite3.connect(path, check_same_thread=False)
        self._init()
        self._last_run_id = None

    def _init(self):
        c = self.conn.cursor()
        c.execute("""
        CREATE TABLE IF NOT EXISTS runs (
            id INTEGER PRIMARY KEY,
            target TEXT,
            created_at TEXT,
            plan TEXT
        )""")
        c.execute("""
        CREATE TABLE IF NOT EXISTS endpoints (
            id INTEGER PRIMARY KEY,
            url TEXT UNIQUE,
            status INTEGER,
            headers TEXT,
            last_seen TEXT
        )""")
        c.execute("""
        CREATE TABLE IF NOT EXISTS logs (
            id INTEGER PRIMARY KEY,
            run_id INTEGER,
            kind TEXT,
            payload TEXT,
            created_at TEXT
        )""")
        c.execute("""
        CREATE TABLE IF NOT EXISTS findings (
            id INTEGER PRIMARY KEY,
            run_id INTEGER,
            title TEXT,
            severity TEXT,
            description TEXT,
            evidence TEXT,
            confirmed INTEGER DEFAULT 0,
            created_at TEXT
        )""")
        self.conn.commit()

    def record_run(self, target, plan):
        c = self.conn.cursor()
        c.execute("INSERT INTO runs (target, created_at, plan) VALUES (?,?,?)", (target, datetime.utcnow().isoformat(), json.dumps(plan)))
        self.conn.commit()
        return c.lastrowid

    def set_last_run_id(self, run_id):
        self._last_run_id = run_id

    def last_run_id(self):
        return self._last_run_id

    def save_endpoint(self, url, status, headers):
        c = self.conn.cursor()
        c.execute("INSERT OR REPLACE INTO endpoints (url, status, headers, last_seen) VALUES (?,?,?,?)",
                  (url, status, json.dumps(headers or {}), datetime.utcnow().isoformat()))
        self.conn.commit()

    def save_logs(self, kind, payload):
        c = self.conn.cursor()
        c.execute("INSERT INTO logs (run_id, kind, payload, created_at) VALUES (?,?,?,?)", (self._last_run_id, kind, json.dumps(payload), datetime.utcnow().isoformat()))
        self.conn.commit()

    def add_finding(self, run_id, title, severity, description, evidence, confirmed=False):
        c = self.conn.cursor()
        c.execute("INSERT INTO findings (run_id, title, severity, description, evidence, confirmed, created_at) VALUES (?,?,?,?,?,?,?)",
                  (run_id, title, severity, description, json.dumps(evidence), 1 if confirmed else 0, datetime.utcnow().isoformat()))
        self.conn.commit()
        return c.lastrowid

    def export_report_by_run(self, run_id):
        c = self.conn.cursor()
        c.execute("SELECT id, target, created_at, plan FROM runs WHERE id=?", (run_id,))
        run = c.fetchone()
        if not run:
            return None
        # findings
        c.execute("SELECT title,severity,description,evidence,confirmed,created_at FROM findings WHERE run_id=?", (run_id,))
        findings = [dict(title=r[0], severity=r[1], description=r[2], evidence=json.loads(r[3]) if r[3] else {}, confirmed=bool(r[4]), created_at=r[5]) for r in c.fetchall()]
        # logs
        c.execute("SELECT kind,payload,created_at FROM logs WHERE run_id=?", (run_id,))
        logs = [dict(kind=r[0], payload=json.loads(r[1]), created_at=r[2]) for r in c.fetchall()]
        return {"target": run[1], "run_id": run_id, "findings": findings, "logs": logs}
