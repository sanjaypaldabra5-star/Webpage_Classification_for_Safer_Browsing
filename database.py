"""
database.py
SQLite storage for Signal://Scan history.
Standard-library only (sqlite3) - no extra install required.
"""

import sqlite3
import os
import json
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from datetime import datetime, timezone
from urllib.parse import urlparse

DEFAULT_DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "scans.db")
DB_PATH = os.path.abspath(os.environ.get("SIGNAL_SCAN_DB", DEFAULT_DB_PATH))


def get_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    """Create the scans table if it doesn't exist yet. Safe to call every startup."""
    conn = get_connection()
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS scans (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            url             TEXT NOT NULL,
            host            TEXT,
            score           REAL NOT NULL,
            level           TEXT NOT NULL,   -- safe | warn | danger
            label           TEXT NOT NULL,   -- LOW RISK | USE CAUTION | HIGH RISK
            signals_json    TEXT,            -- JSON array of {level, name, desc}
            used_page_text  INTEGER DEFAULT 0,
            scanned_at      TEXT NOT NULL
        )
        """
    )
    conn.commit()
    conn.close()


def insert_scan(url, host, score, level, label, signals, used_page_text=False) -> int:
    """Store one scan result. `signals` is a list of dicts, stored as JSON."""
    conn = get_connection()
    cur = conn.execute(
        """
        INSERT INTO scans (url, host, score, level, label, signals_json, used_page_text, scanned_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            url,
            host,
            score,
            level,
            label,
            json.dumps(signals),
            1 if used_page_text else 0,
            datetime.now(timezone.utc).isoformat(timespec="seconds"),
        ),
    )
    conn.commit()
    new_id = cur.lastrowid
    conn.close()
    return new_id


def get_history(limit: int = 20):
    """Return the most recent scans, newest first, as a list of dicts."""
    conn = get_connection()
    rows = conn.execute(
        """
        SELECT id, url, host, score, level, label, signals_json, used_page_text, scanned_at
        FROM scans ORDER BY id DESC LIMIT ?
        """,
        (limit,),
    ).fetchall()
    conn.close()

    result = []
    for row in rows:
        d = dict(row)
        try:
            d["signals"] = json.loads(d.pop("signals_json") or "[]")
        except (json.JSONDecodeError, TypeError):
            d["signals"] = []
            d.pop("signals_json", None)
        d["used_page_text"] = bool(d["used_page_text"])
        result.append(d)
    return result


def get_stats():
    """Return a count of scans per risk level, for a small summary widget."""
    conn = get_connection()
    rows = conn.execute(
        "SELECT level, COUNT(*) as count FROM scans GROUP BY level"
    ).fetchall()
    conn.close()
    return {row["level"]: row["count"] for row in rows}


def clear_history():
    conn = get_connection()
    conn.execute("DELETE FROM scans")
    conn.commit()
    conn.close()


class SignalRequestHandler(SimpleHTTPRequestHandler):
    """Serve the page and expose the SQLite scan-history API."""

    def end_headers(self):
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        super().end_headers()

    def do_OPTIONS(self):
        self.send_response(204)
        self.end_headers()

    def do_GET(self):
        path = urlparse(self.path).path
        if path == "/api/history":
            self.send_json({"scans": get_history()})
            return
        if path == "/api/stats":
            self.send_json(get_stats())
            return
        super().do_GET()

    def do_POST(self):
        if urlparse(self.path).path != "/api/scans":
            self.send_error(404, "Not found")
            return

        try:
            length = int(self.headers.get("Content-Length", "0"))
            payload = json.loads(self.rfile.read(length))
            scan_id = insert_scan(
                url=payload["url"],
                host=payload.get("host", ""),
                score=float(payload["score"]),
                level=payload["level"],
                label=payload["label"],
                signals=payload.get("signals", []),
                used_page_text=bool(payload.get("used_page_text", False)),
            )
        except (KeyError, TypeError, ValueError, json.JSONDecodeError):
            self.send_error(400, "Invalid scan payload")
            return

        self.send_json({"id": scan_id}, status=201)

    def send_json(self, data, status=200):
        body = json.dumps(data).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


if __name__ == "__main__":
    init_db()
    os.chdir(os.path.dirname(os.path.abspath(__file__)))
    server = ThreadingHTTPServer(("127.0.0.1", 8000), SignalRequestHandler)
    print(f"Signal://Scan using database: {DB_PATH}")
    print("Signal://Scan running at http://127.0.0.1:8000/main.html")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()