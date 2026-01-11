from flask import Flask, request
from twilio.twiml.messaging_response import MessagingResponse
import sqlite3
import os
import re
from datetime import datetime

app = Flask(__name__)

# ==================================================
# DATABASE
# ==================================================

DB_PATH = "scam_reports.db"

def init_db():
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()

    cur.execute("""
    CREATE TABLE IF NOT EXISTS reported_patterns (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        keyword TEXT UNIQUE,
        count INTEGER DEFAULT 1,
        category TEXT,
        last_seen TEXT
    )
    """)

    conn.commit()
    conn.close()

init_db()

# ==================================================
# LANGUAGE DETECTION
# ==================================================

def is_tamil(text):
    return any('\u0B80' <= ch <= '\u0BFF' for ch in text)

def is_hindi(text):
    return any('\u0900' <= ch <= '\u097F' for ch in text)

def get_language(text):
    if is_tamil(text):
        return "TA"
    if is_hindi(text):
        return "HI"
    return "EN"

# ==================================================
# KEYWORDS & DOMAINS
# ==================================================

SCAM_CATEGORIES = {
    "LOTTERY": ["lottery", "winner", "prize", "jackpot", "लॉटरी", "பரிசு"],
    "BANK_KYC": ["account", "kyc", "blocked", "verify", "bank", "खाता", "கணக்கு"],
    "JOB_LOAN": ["job", "loan", "offer", "salary", "नौकरी", "வேலை"]
}

TRUSTED_DOMAINS = ["gov.in", "rbi.org.in", "income-tax.gov.in"]
SUSPICIOUS_DOMAINS = [".xyz", ".win", ".click", ".online"]

MONEY_WORDS = ["₹", "rs", "rupees", "रुपये", "ரூபாய்"]

# ==================================================
# COMMUNITY LEARNING
# ==================================================

def save_reported_patterns(message, category):
    words = set(re.findall(r"\b\w+\b", message.lower()))
    now = datetime.utcnow().isoformat()

    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()

    for word in words:
        if len(word) >= 5:
            cur.execute("""
            INSERT INTO reported_patterns(keyword, count, category, last_seen)
            VALUES (?, 1, ?, ?)
            ON CONFLICT(keyword)
            DO UPDATE SET
                count = count + 1,
                last_seen = ?
            """, (word, category, now, now))

    conn.commit()
    conn.close()

def get_reported_patterns():
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("SELECT keyword, count, category FROM reported_patterns")
    rows = cur.fetchall()
    conn.close()
    return rows

# ==================================================
# FRAUD DETECTION
# ==================================================

def classify_category(message):
    msg = message.lower()
    for cat, words in SCAM_CATEGORIES.items():
        if any(w in msg for w in words):
            return cat
    return "GENERAL"

def detect_fraud(message):
    msg = message.lower()
    score = 0

    category = classify_category(message)

    # Money signals
    for w in MONEY_WORDS:
        if w in msg:
            score += 1

    # Suspicious domains
    for d in SUSPICIOUS_DOMAINS:
        if d in msg:
            score += 2

    # Trusted domain reduction
    for d in TRUSTED_DOMAINS:
        if d in msg:
            score -= 3

    # Community boost
    for keyword, count, _ in get_reported_patterns():
        if keyword in msg:
            score += min(3, count)

    # Category weight
    if category != "GENERAL":
        score += 2

    # Confidence mapping
    confidence = min(95, 50 + score * 10)

    if score >= 6:
        label = "FRAUD"
    elif score >= 3:
        label = "SUSPICIOUS"
    else:
        label = "GENUINE"

    return label, confidence, category

# ==================================================
# ADMIN VIEW
# ==================================================

@app.route("/admin/reports")
def admin_reports():
    rows = get_reported_patterns()
    return {
        "total_patterns": len(rows),
        "patterns": [
            {"keyword": r[0], "count": r[1], "category": r[2]}
            for r in rows
        ]
    }

# ==================================================
# WHATSAPP WEBHOOK
# ==================================================

last_message_cache = {}

@app.route("/whatsapp", methods=["POST"])
def whatsapp_reply():
    incoming = request.values.get("Body", "").strip()
    user = request.values.get("From")
    lang = get_language(incoming)

    resp = MessagingResponse()
    reply = resp.message()

    # HELP
    if incoming.upper() == "HELP":
        reply.body(
            "ℹ️ *Scam Detection Bot*\n\n"
            "• Detects fraud messages\n"
            "• Supports Tamil / Hindi / English\n"
            "• REPORT → help others\n"
            "• EXIT → stop alerts"
        )
        return str(resp)

    # EXIT
    if incoming.upper() == "EXIT":
        reply.body(
            "Alerts stopped safely.\n"
            "You can message again anytime."
        )
        return str(resp)

    # REPORT
    if incoming.upper() == "REPORT":
        if user in last_message_cache:
            msg, cat = last_message_cache[user]
            save_reported_patterns(msg, cat)
            reply.body("✅ Scam reported. Community protected.")
        else:
            reply.body("⚠️ Nothing to report.")
        return str(resp)

    label, confidence, category = detect_fraud(incoming)
    last_message_cache[user] = (incoming, category)

    # RESPONSE
    if label == "FRAUD":
        reply.body(
            f"🔴 FRAUD ALERT\n\n"
            f"Category: {category}\n"
            f"Confidence: {confidence}%\n\n"
            "Do NOT click links or send money.\n"
            "Reply REPORT to help others."
        )
    elif label == "SUSPICIOUS":
        reply.body(
            f"🟡 SUSPICIOUS MESSAGE\n\n"
            f"Confidence: {confidence}%\n"
            "Please verify carefully."
        )
    else:
        reply.body(
            "🟢 LIKELY GENUINE\n"
            "No strong scam indicators detected."
        )

    return str(resp)

# ==================================================
# SERVER
# ==================================================

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 8080)))
