#!/usr/bin/env python3
"""TrustLens AI: offline-first local safety analyzer and web server."""
from __future__ import annotations

import json
import re
import sqlite3
import threading
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit

ROOT = Path(__file__).parent
DB = ROOT / "trustlens.db"
MAX_INPUT = 10_000
URL_RE = re.compile(r"https?://[^\s<>\"']+", re.I)
RULES = {
    "urgency": (18, [r"urgent", r"immediately", r"(?:within|in) \d+\s*(?:minutes?|hours?)", r"today only", r"act now", r"expires? soon"]),
    "fear": (15, [r"blocked", r"suspended", r"locked", r"account will be", r"legal action", r"arrest"]),
    "authority": (8, [r"from your bank", r"police", r"government", r"tax department", r"customer support", r"official notice"]),
    "reward": (12, [r"you (?:have )?won", r"winner", r"prize", r"congratulations", r"free gift"]),
    "greed": (10, [r"guaranteed profit", r"double your money", r"risk.free returns", r"easy income"]),
    "threat": (13, [r"will be blocked", r"fine will", r"penalty", r"lose access", r"account termination"]),
    "secrecy": (12, [r"don't tell", r"do not tell", r"keep this secret", r"tell no one"]),
    "payment": (20, [r"pay(?:ment)?\s*(?:₹|rs\.?|inr)?\s*\d", r"send (?:the )?money", r"processing fee", r"transfer funds", r"pay now", r"upi id", r"scan (?:the )?qr"]),
    "credentials": (25, [r"password", r"login details", r"sign in", r"verify your account", r"enter your (?:card|bank)", r"credentials"]),
    "otp": (30, [r"\botp\b", r"one.time password", r"verification code", r"share the code"]),
    "emotional": (9, [r"emergency", r"help me urgently", r"i need you", r"family is in trouble"]),
}
BRANDS = {"bank": ["bank", "sbi", "hdfc", "icici", "axis"], "government": ["government", "police", "tax department", "aadhaar"], "delivery": ["delivery", "parcel", "courier", "fedex", "dhl"], "e-commerce": ["amazon", "flipkart", "order"], "social media": ["instagram", "facebook", "account recovery"], "support": ["customer support", "technical support"]}
BAD_TLDS = {".zip", ".top", ".click", ".work", ".country", ".gq", ".tk"}


def _db():
    con = sqlite3.connect(DB)
    con.execute("CREATE TABLE IF NOT EXISTS history (id INTEGER PRIMARY KEY, created TEXT NOT NULL, label TEXT NOT NULL, score INTEGER NOT NULL, category TEXT NOT NULL)")
    return con


def analyze(text: str) -> dict:
    """Deterministic, explainable analysis. No network calls or model confidence claims."""
    if not isinstance(text, str) or not text.strip():
        raise ValueError("Enter a message or URL to analyze.")
    if len(text) > MAX_INPUT:
        raise ValueError(f"Input is too long. Keep it under {MAX_INPUT:,} characters.")
    low = text.lower()
    signals = []
    score = 0
    for key, (points, patterns) in RULES.items():
        matches = [p for p in patterns if re.search(p, low)]
        if key == "otp" and (re.search(r"(?:don't|do not|never|avoid)\s+(?:share|send|reveal|give).*\botp\b|\botp\b.*(?:don't|do not|never|avoid)", low) or ("otp" in low and "பகிர வேண்டாம்" in text)):
            matches = []
        if matches:
            score += points
            signals.append({"key": key, "label": key.replace("_", " ").title(), "points": points, "why": _signal_why(key)})

    urls = URL_RE.findall(text)
    url_facts = []
    for raw in urls[:5]:
        fact = analyze_url(raw.rstrip(".,);!?") )
        url_facts.append(fact)
        score += fact["points"]
        if fact["signals"]:
            signals.append({"key": "url", "label": "Suspicious URL structure", "points": fact["points"], "why": "; ".join(fact["signals"])})

    claimed = next((brand for brand, words in BRANDS.items() if any(w in low for w in words)), None)
    identity_pressure = any(s["key"] in {"urgency", "fear", "threat"} for s in signals)
    impersonation = bool(claimed and (urls or any(s["key"] in {"payment", "credentials", "otp"} for s in signals) or (claimed == "bank" and identity_pressure)))
    if impersonation:
        score += 15
        signals.append({"key": "impersonation", "label": "Potential impersonation", "points": 15, "why": f"The message invokes {claimed} identity while also requesting action or sharing a link. Verify through the official channel."})

    score = min(100, score)
    level = "LOW" if score <= 25 else "CAUTION" if score <= 50 else "HIGH" if score <= 75 else "CRITICAL"
    social = [s["label"] for s in signals if s["key"] in {"urgency", "fear", "authority", "reward", "greed", "threat", "secrecy", "emotional"}]
    if not signals:
        category = "Routine message"
    elif any(s["key"] == "otp" for s in signals): category = "OTP scam"
    elif any(s["key"] == "payment" for s in signals): category = "Payment request"
    elif claimed: category = f"Possible {claimed} impersonation"
    elif any(s["key"] == "reward" for s in signals): category = "Prize / lottery scam"
    else: category = "Suspicious message"
    recommendations = ["Do not click links or reply while unsure.", "Never share a password, OTP, or verification code.", "Verify using a phone number or website you find independently.", "If you already paid or shared details, contact your bank using its official number."] if score > 25 else ["No strong warning signs were found by local checks.", "Still verify unexpected requests through a separate trusted channel."]
    passport = {"identity": "CAUTION" if claimed else "UNCHECKED", "domain": "HIGH RISK" if any(u["points"] >= 15 for u in url_facts) else "NOT CHECKED" if not urls else "NO STRONG FLAG", "language": "PRESSURE" if social else "CALM", "intent": "SENSITIVE REQUEST" if any(s["key"] in {"payment", "credentials", "otp"} for s in signals) else "UNCLEAR" if signals else "ROUTINE", "pressure": "HIGH" if any(s["key"] in {"urgency", "fear", "threat", "secrecy"} for s in signals) else "LOW", "payment": "FLAGGED" if any(s["key"] == "payment" for s in signals) else "NOT DETECTED", "credentials": "FLAGGED" if any(s["key"] in {"credentials", "otp"} for s in signals) else "NOT DETECTED"}
    nodes = [{"title": "Message received", "detail": "A message asks the recipient to act."}]
    if claimed: nodes.append({"title": "Identity claim", "detail": f"The message references {claimed}; the claim is not verified."})
    if urls: nodes.append({"title": "Link shared", "detail": "A link is present. Structural checks are not a live reputation lookup."})
    if any(s["key"] == "credentials" for s in signals): nodes.append({"title": "Credential request", "detail": "The wording may lead to a sign-in or information request."})
    if any(s["key"] == "otp" for s in signals): nodes.append({"title": "OTP request", "detail": "Sharing a one-time code can enable account access."})
    if any(s["key"] == "payment" for s in signals): nodes.append({"title": "Payment request", "detail": "Money may be at risk if the request is followed."})
    if len(nodes) == 1: nodes.append({"title": "No obvious next step", "detail": "Local rules found no clear attack chain. This is not a guarantee of safety."})
    result = {"risk_level": level, "risk_score": score, "confidence": None, "confidence_note": "No calibrated ML confidence is produced; this score is a transparent sum of local rule signals.", "category": category, "signals": signals, "social_engineering": social, "impersonation": {"detected": impersonation, "claimed_identity": claimed, "explanation": "Potential identity mismatch; the claim is unverified." if impersonation else "No strong impersonation pattern detected."}, "urls": url_facts, "passport": passport, "attack_path": nodes, "recommendations": recommendations, "education": _lesson(signals, level), "privacy": "Analyzed locally. The message is not sent to any service."}
    _save(result)
    return result


def _signal_why(key):
    return {"urgency":"Time pressure can discourage careful checking.","fear":"Fear language may push a person to act before verifying.","authority":"An authority claim should be verified independently.","reward":"Unexpected prizes can be used to lure people into sharing details or paying fees.","greed":"Unrealistic returns are a common manipulation warning sign.","threat":"Threats or penalties can pressure a rushed decision.","secrecy":"Secrecy discourages a second opinion.","payment":"A payment request in an unsolicited message deserves independent verification.","credentials":"Requests for login details are sensitive; do not enter them from message links.","otp":"One-time codes should never be shared with another person.","emotional":"Emotional pressure can reduce time for careful verification."}.get(key,"A local rule matched this pattern.")


def _lesson(signals, level):
    if any(s["key"] == "otp" for s in signals): return "An OTP is a temporary key to your account. A real support agent does not need you to read it out."
    if any(s["key"] == "urgency" for s in signals): return "Scammers use urgency to stop you from thinking. Pause, then verify using a contact method you find yourself."
    if level == "LOW": return "A calm message with no sensitive request has fewer warning signs, but local checks cannot prove a sender is genuine."
    return "Look at the request, not just the logo or name. Unexpected money, login, and code requests need a second-channel check."


def analyze_url(raw):
    try:
        parsed = urlsplit(raw if "://" in raw else "https://" + raw)
        host = parsed.hostname or ""
        if not host or any(c.isspace() for c in host): raise ValueError()
    except (ValueError, UnicodeError):
        return {"url": raw[:200], "domain": "Invalid URL", "points": 0, "signals": ["Could not parse this address; verify it manually."], "valid": False}
    flags, points = [], 0
    if parsed.scheme != "https": flags.append("Not using HTTPS"); points += 8
    if len(raw) > 100: flags.append("Unusually long URL"); points += 8
    if "@" in parsed.netloc: flags.append("Contains @ sign that can obscure the real destination"); points += 18
    if re.fullmatch(r"(?:\d{1,3}\.){3}\d{1,3}", host): flags.append("Uses a raw IP address instead of a domain name"); points += 18
    if host.startswith("xn--") or ".xn--" in host: flags.append("Internationalized domain encoding may conceal lookalike characters"); points += 18
    if host.rsplit(".",1)[-1] and ("." + host.rsplit(".",1)[-1]) in BAD_TLDS: flags.append("Uses a less common high-abuse TLD; this alone does not prove harm"); points += 10
    if re.search(r"%[0-9a-f]{2}", raw, re.I): flags.append("Contains URL-encoded characters"); points += 4
    if re.search(r"login|verify|credential|password|wallet|payment|otp", parsed.path + "?" + parsed.query, re.I): flags.append("Path or query mentions login, verification, or payment"); points += 12
    if len(host.split(".")) > 4: flags.append("Has many subdomain levels"); points += 8
    if any(brand in host for brand in ("bank", "paypal", "amazon", "google", "microsoft")) and not host.endswith((".com", ".org", ".net")):
        flags.append("Brand-like wording in domain; ownership is not verified"); points += 10
    return {"url": raw[:200], "domain": host, "scheme": parsed.scheme, "points": min(35, points), "signals": flags, "valid": True}


def _save(result):
    try:
        with _LOCK, _db() as con:
            con.execute("INSERT INTO history(created,label,score,category) VALUES(?,?,?,?)", (datetime.now(timezone.utc).isoformat(), result["risk_level"], result["risk_score"], result["category"]))
    except sqlite3.Error:
        pass


_LOCK = threading.Lock()


class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        pass

    def _json(self, code, obj):
        payload = json.dumps(obj, ensure_ascii=False).encode()
        self.send_response(code); self.send_header("Content-Type", "application/json; charset=utf-8"); self.send_header("Content-Length", str(len(payload))); self.send_header("Cache-Control", "no-store"); self.end_headers(); self.wfile.write(payload)

    def do_GET(self):
        if self.path == "/api/system/status": return self._json(200, {"mode":"OFFLINE — PRIVATE ANALYSIS", "local_processing":True,"cloud_ai":False,"data_upload":"NONE"})
        if self.path == "/api/analysis/history":
            with _LOCK, _db() as con: rows = con.execute("SELECT id,created,label,score,category FROM history ORDER BY id DESC LIMIT 10").fetchall()
            return self._json(200, {"items":[dict(zip(("id","created","label","score","category"),r)) for r in rows]})
        if self.path == "/api/demo/examples": return self._json(200, {"examples":examples()})
        if self.path == "/api/knowledge-base": return self._json(200, {"categories":["phishing","UPI scam","OTP scam","job scam","investment scam","parcel scam","lottery scam","bank impersonation","government impersonation","customer-support scam","social-media recovery scam","romance scam","QR scam"]})
        if self.path == "/": self.path = "/index.html"
        file = (ROOT / self.path.lstrip("/")).resolve()
        if ROOT.resolve() not in file.parents or not file.is_file(): return self.send_error(404)
        content = file.read_bytes(); self.send_response(200); self.send_header("Content-Type", "text/html; charset=utf-8" if file.suffix == ".html" else "application/octet-stream"); self.send_header("Content-Length", str(len(content))); self.end_headers(); self.wfile.write(content)

    def do_POST(self):
        if self.path == "/api/analyze":
            try:
                size = int(self.headers.get("Content-Length", "0"))
                if size > MAX_INPUT * 4: return self._json(413, {"error":"Request is too large."})
                body = json.loads(self.rfile.read(size) or b"{}")
                return self._json(200, analyze(body.get("text", "")))
            except (ValueError, json.JSONDecodeError) as exc: return self._json(400, {"error":str(exc)})
            except Exception: return self._json(500, {"error":"Something went wrong while analyzing this input."})
        return self._json(404, {"error":"Not found"})

    def do_DELETE(self):
        if self.path == "/api/analysis/history":
            with _LOCK, _db() as con: con.execute("DELETE FROM history")
            return self._json(200, {"cleared":True})
        return self._json(404, {"error":"Not found"})


def examples():
    return [
        {"name":"Bank account warning","text":"URGENT! Your bank account will be blocked today. Verify immediately using this link: http://secure-bank-login.top/verify","type":"SCAM SIMULATION"},
        {"name":"Parcel fee request","text":"Your parcel delivery is pending. Pay ₹25 processing fee now at http://parcel-fee.click/pay","type":"SCAM SIMULATION"},
        {"name":"Remote job offer","text":"Congratulations! You are selected for a work-from-home job. Pay ₹499 registration fee to secure your position.","type":"SCAM SIMULATION"},
        {"name":"Customer support impersonation","text":"Amazon Customer Support: Your order is cancelled. Call this number and share the OTP to receive your refund.","type":"SCAM SIMULATION"},
        {"name":"Government warning","text":"Official tax department notice: pay penalty immediately or legal action and account block will follow.","type":"SCAM SIMULATION"},
        {"name":"Normal note","text":"Hey, are you free for lunch tomorrow? We can meet at noon.","type":"HARMLESS EXAMPLE"},
    ]


if __name__ == "__main__":
    server = ThreadingHTTPServer(("127.0.0.1", 8000), Handler)
    print("TrustLens AI running at http://127.0.0.1:8000 (local only)")
    try: server.serve_forever()
    except KeyboardInterrupt: print("\nTrustLens stopped.")
