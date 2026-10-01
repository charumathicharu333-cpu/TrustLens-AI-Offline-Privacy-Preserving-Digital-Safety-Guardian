import json
import re
import sqlite3
import threading
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit
import os


ROOT = Path(__file__).parent
DB_PATH = ROOT / "trustlens.db"
KNOWLEDGE_BASE_PATH = ROOT / "knowledge_base.json"

DB_LOCK = threading.Lock()


def utc_now():
    return datetime.now(timezone.utc).isoformat()


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    with DB_LOCK:
        conn = get_db()
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS analyses (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                created_at TEXT NOT NULL,
                input_text TEXT NOT NULL,
                risk_level TEXT NOT NULL,
                risk_score INTEGER NOT NULL,
                category TEXT NOT NULL,
                explanation TEXT NOT NULL,
                actions TEXT NOT NULL
            )
            """
        )
        conn.commit()
        conn.close()


def load_knowledge_base():
    if not KNOWLEDGE_BASE_PATH.exists():
        return {}

    try:
        with KNOWLEDGE_BASE_PATH.open("r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


def normalize_text(text):
    return re.sub(r"\s+", " ", text.strip().lower())


def analyze_text(text):
    """
    Deterministic local analysis.
    No external API or cloud AI is used.
    """

    normalized = normalize_text(text)

    risk_score = 0
    reasons = []
    category = "General Safety"

    rules = [
        (
            r"\b(otp|one[- ]time password)\b",
            30,
            "The message requests or references an OTP.",
            "Credential Theft",
        ),
        (
            r"\b(password|passcode|login password)\b",
            25,
            "The message mentions password or login credentials.",
            "Credential Theft",
        ),
        (
            r"\b(click here|click the link|open this link)\b",
            20,
            "The message contains a link-clicking instruction.",
            "Phishing",
        ),
        (
            r"\b(urgent|immediately|act now|right now)\b",
            15,
            "Urgency or pressure language is present.",
            "Social Engineering",
        ),
        (
            r"\b(prize|winner|won|reward|lottery)\b",
            20,
            "The message contains prize or reward language.",
            "Scam",
        ),
        (
            r"\b(bank|bank account|credit card|debit card)\b",
            20,
            "Financial information is mentioned.",
            "Financial Scam",
        ),
        (
            r"\b(send money|transfer money|pay now|payment)\b",
            25,
            "The message requests a financial action.",
            "Financial Scam",
        ),
        (
            r"\b(verify your account|account verification|verify account)\b",
            20,
            "The message requests account verification.",
            "Phishing",
        ),
        (
            r"\b(free gift|free money|cashback)\b",
            15,
            "The message contains an unusually attractive offer.",
            "Scam",
        ),
    ]

    for pattern, score, reason, detected_category in rules:
        if re.search(pattern, normalized):
            risk_score += score
            reasons.append(reason)
            category = detected_category

    url_matches = re.findall(r"https?://\S+|www\.\S+", text, re.IGNORECASE)

    if url_matches:
        risk_score += 15
        reasons.append("The message contains an external URL.")

    if len(text) > 500:
        risk_score += 5
        reasons.append("The message is unusually long.")

    risk_score = min(risk_score, 100)

    if risk_score >= 70:
        risk_level = "HIGH"
    elif risk_score >= 35:
        risk_level = "MEDIUM"
    else:
        risk_level = "LOW"

    if not reasons:
        reasons.append("No major suspicious patterns were detected.")

    actions = []

    if risk_level == "HIGH":
        actions = [
            "Do not click links.",
            "Do not share OTPs or passwords.",
            "Do not send money.",
            "Verify the sender through an official channel.",
        ]
    elif risk_level == "MEDIUM":
        actions = [
            "Check the sender carefully.",
            "Avoid clicking unexpected links.",
            "Verify the request independently.",
        ]
    else:
        actions = [
            "Continue normal caution.",
            "Avoid sharing sensitive information.",
        ]

    return {
        "risk_level": risk_level,
        "risk_score": risk_score,
        "category": category,
        "explanation": reasons,
        "actions": actions,
        "detected_urls": url_matches,
    }


def save_analysis(input_text, result):
    with DB_LOCK:
        conn = get_db()

        conn.execute(
            """
            INSERT INTO analyses
            (
                created_at,
                input_text,
                risk_level,
                risk_score,
                category,
                explanation,
                actions
            )
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                utc_now(),
                input_text,
                result["risk_level"],
                result["risk_score"],
                result["category"],
                json.dumps(result["explanation"]),
                json.dumps(result["actions"]),
            ),
        )

        conn.commit()
        conn.close()


def get_history():
    with DB_LOCK:
        conn = get_db()

        rows = conn.execute(
            """
            SELECT
                id,
                created_at,
                input_text,
                risk_level,
                risk_score,
                category,
                explanation,
                actions
            FROM analyses
            ORDER BY id DESC
            LIMIT 100
            """
        ).fetchall()

        conn.close()

    history = []

    for row in rows:
        history.append(
            {
                "id": row["id"],
                "created_at": row["created_at"],
                "input_text": row["input_text"],
                "risk_level": row["risk_level"],
                "risk_score": row["risk_score"],
                "category": row["category"],
                "explanation": json.loads(row["explanation"]),
                "actions": json.loads(row["actions"]),
            }
        )

    return history


def delete_history():
    with DB_LOCK:
        conn = get_db()
        conn.execute("DELETE FROM analyses")
        conn.commit()
        conn.close()


init_db()


class Handler(BaseHTTPRequestHandler):

    def send_json(self, data, status=200):
        payload = json.dumps(data, ensure_ascii=False).encode("utf-8")

        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()

        self.wfile.write(payload)

    def send_text(self, text, status=200, content_type="text/plain"):
        payload = text.encode("utf-8")

        self.send_response(status)
        self.send_header("Content-Type", f"{content_type}; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()

        self.wfile.write(payload)

    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()

    def do_GET(self):
        path = urlsplit(self.path).path

        if path == "/":
            self.serve_file(ROOT / "index.html", "text/html")
            return

        if path == "/api/system/status":
            self.send_json(
                {
                    "status": "online",
                    "mode": "offline",
                    "privacy": "local processing",
                    "ai": "deterministic local rules",
                    "database": "SQLite",
                }
            )
            return

        if path == "/api/analysis/history":
            self.send_json(
                {
                    "success": True,
                    "history": get_history(),
                }
            )
            return

        if path == "/api/demo/examples":
            examples = [
                {
                    "title": "OTP Scam",
                    "text": "URGENT! Your bank account will be blocked. Share your OTP immediately to verify your account.",
                },
                {
                    "title": "Prize Scam",
                    "text": "Congratulations! You have won a free cash reward. Click here immediately to claim your prize.",
                },
                {
                    "title": "Suspicious Payment",
                    "text": "Your payment failed. Please click here and verify your card details immediately.",
                },
                {
                    "title": "Safe Message",
                    "text": "Your college seminar is scheduled for tomorrow at 10 AM in the seminar hall.",
                },
            ]

            self.send_json(
                {
                    "success": True,
                    "examples": examples,
                }
            )
            return

        if path == "/api/knowledge-base":
            self.send_json(
                {
                    "success": True,
                    "knowledge_base": load_knowledge_base(),
                }
            )
            return

        # Static files
        requested = path.lstrip("/")

        if requested:
            file_path = ROOT / requested

            try:
                file_path = file_path.resolve()
                root_resolved = ROOT.resolve()

                if str(file_path).startswith(str(root_resolved)):
                    if file_path.exists() and file_path.is_file():
                        extension = file_path.suffix.lower()

                        content_types = {
                            ".html": "text/html",
                            ".css": "text/css",
                            ".js": "application/javascript",
                            ".json": "application/json",
                            ".png": "image/png",
                            ".jpg": "image/jpeg",
                            ".jpeg": "image/jpeg",
                            ".svg": "image/svg+xml",
                            ".ico": "image/x-icon",
                        }

                        content_type = content_types.get(
                            extension,
                            "application/octet-stream",
                        )

                        self.serve_file(file_path, content_type)
                        return

            except Exception:
                pass

        self.send_json(
            {
                "success": False,
                "error": "Not found",
            },
            status=404,
        )

    def do_POST(self):
        path = urlsplit(self.path).path

        if path == "/api/analyze":
            try:
                content_length = int(
                    self.headers.get("Content-Length", "0")
                )

                raw_body = self.rfile.read(content_length)

                data = json.loads(
                    raw_body.decode("utf-8")
                )

                input_text = str(
                    data.get("text", "")
                ).strip()

                if not input_text:
                    self.send_json(
                        {
                            "success": False,
                            "error": "Text is required.",
                        },
                        status=400,
                    )
                    return

                result = analyze_text(input_text)

                save_analysis(
                    input_text,
                    result,
                )

                self.send_json(
                    {
                        "success": True,
                        "result": result,
                    }
                )

            except json.JSONDecodeError:
                self.send_json(
                    {
                        "success": False,
                        "error": "Invalid JSON request.",
                    },
                    status=400,
                )

            except Exception as exc:
                self.send_json(
                    {
                        "success": False,
                        "error": str(exc),
                    },
                    status=500,
                )

            return

        self.send_json(
            {
                "success": False,
                "error": "Not found",
            },
            status=404,
        )

    def do_DELETE(self):
        path = urlsplit(self.path).path

        if path == "/api/analysis/history":
            try:
                delete_history()

                self.send_json(
                    {
                        "success": True,
                        "message": "Analysis history cleared.",
                    }
                )

            except Exception as exc:
                self.send_json(
                    {
                        "success": False,
                        "error": str(exc),
                    },
                    status=500,
                )

            return

        self.send_json(
            {
                "success": False,
                "error": "Not found",
            },
            status=404,
        )

    def serve_file(self, file_path, content_type):
        try:
            with file_path.open("rb") as f:
                content = f.read()

            self.send_response(200)
            self.send_header(
                "Content-Type",
                f"{content_type}; charset=utf-8",
            )
            self.send_header(
                "Content-Length",
                str(len(content)),
            )
            self.send_header(
                "Access-Control-Allow-Origin",
                "*",
            )
            self.end_headers()

            self.wfile.write(content)

        except FileNotFoundError:
            self.send_json(
                {
                    "success": False,
                    "error": "File not found",
                },
                status=404,
            )

    def log_message(self, format, *args):
        print(
            f"[{self.log_date_time_string()}] "
            f"{self.address_string()} - "
            f"{format % args}"
        )


# ============================================================
# RENDER / PRODUCTION SERVER
# ============================================================

if __name__ == "__main__":

    # Render provides the PORT environment variable.
    # Local development falls back to port 8000.
    PORT = int(os.environ.get("PORT", 8000))

    # IMPORTANT:
    # 0.0.0.0 allows Render to access the application.
    server = ThreadingHTTPServer(
        ("0.0.0.0", PORT),
        Handler
    )

    print(
        f"TrustLens AI running on port {PORT}"
    )

    try:
        server.serve_forever()

    except KeyboardInterrupt:
        print("\nTrustLens stopped.")

    finally:
        server.server_close()
