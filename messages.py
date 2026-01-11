from flask import Flask, request
from twilio.twiml.messaging_response import MessagingResponse
import sqlite3
import os
import re

app = Flask(__name__)

# ==================================================
# DATABASE CONFIG
# ==================================================

DB_PATH = "scam_reports.db"

def init_db():
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS reported_patterns (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            keyword TEXT UNIQUE
        )
    """)
    conn.commit()
    conn.close()

init_db()

# ==================================================
# BASE SCAM KEYWORDS (MULTI-LANGUAGE)
# ==================================================

HIGH_RISK = [
    # English
    "lottery", "winner", "congratulations", "claim", "urgent",
    "click", "verify", "limited time", "final warning", "free gift",
    "selected", "approved",

    # Hindi
    "लॉटरी", "इनाम", "तुरंत", "चयनित", "अंतिम चेतावनी",
    "लिंक पर क्लिक करें", "सत्यापित करें",

    # Tamil
    "லாட்டரி", "பரிசு", "வென்றுள்ளீர்கள்", "உடனே",
    "கிளிக்", "லிங்க்", "இறுதி எச்சரிக்கை",
    "உடனடி நடவடிக்கை"
]

MONEY_WORDS = [
    "₹", "rs", "rupees", "amount", "payment", "fee",
    "रुपये", "भुगतान",
    "ரூபாய்", "பணம்", "கட்டணம்", "பரிசு தொகை"
]

SUSPICIOUS_DOMAINS = [
    ".xyz", ".win", ".click", ".online", ".top"
]

# ==================================================
# COMMUNITY DATABASE FUNCTIONS
# ==================================================

def get_reported_patterns():
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("SELECT keyword FROM reported_patterns")
    rows = cur.fetchall()
    conn.close()
    return [r[0] for r in rows]

def save_reported_patterns(message):
    words = set(re.findall(r"\b\w+\b", message.lower()))
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()

    for word in words:
        if len(word) >= 5:  # avoid noise
            try:
                cur.execute(
                    "INSERT OR IGNORE INTO reported_patterns(keyword) VALUES (?)",
                    (word,)
                )
            except:
                pass

    conn.commit()
    conn.close()

# ==================================================
# FRAUD DETECTION LOGIC
# ==================================================

def detect_fraud(message):
    msg = message.lower()
    score = 0
    matched = []

    # Base keyword rules
    for w in HIGH_RISK:
        if w.lower() in msg:
            score += 2
            matched.append(w)

    for w in MONEY_WORDS:
        if w.lower() in msg:
            score += 1
            matched.append(w)

    for d in SUSPICIOUS_DOMAINS:
        if d in msg:
            score += 2
            matched.append(d)

    # 🔥 Community learning boost
    for p in get_reported_patterns():
        if p in msg:
            score += 3
            matched.append(f"community:{p}")

    if score >= 6:
        label = "FRAUD"
    elif score >= 3:
        label = "SUSPICIOUS"
    else:
        label = "GENUINE"

    return label, score, matched

# ==================================================
# ADMIN VIEW (OPTION 1)
# ==================================================

@app.route("/admin/reports", methods=["GET"])
def view_reports():
    patterns = get_reported_patterns()
    return {
        "total_patterns": len(patterns),
        "patterns": patterns
    }

# ==================================================
# WHATSAPP WEBHOOK
# ==================================================

last_message_cache = {}

@app.route("/whatsapp", methods=["POST"])
def whatsapp_reply():
    incoming_msg = request.values.get("Body", "").strip()
    user = request.values.get("From")

    print("INCOMING:", incoming_msg)

    resp = MessagingResponse()
    reply = resp.message()

    # EXIT command (sandbox-safe)
    if incoming_msg.upper() == "EXIT":
        reply.body(
            "✅ Alerts stopped safely.\n\n"
            "You can send any message again anytime."
        )
        return str(resp)

    # REPORT command
    if incoming_msg.upper() == "REPORT":
        if user in last_message_cache:
            save_reported_patterns(last_message_cache[user])
            reply.body(
                "✅ Scam reported successfully.\n\n"
                "This helps protect other users."
            )
        else:
            reply.body("⚠️ No recent message found to report.")
        return str(resp)

    # Save last message for REPORT
    last_message_cache[user] = incoming_msg

    label, score, matched = detect_fraud(incoming_msg)

    if label == "FRAUD":
        reply.body(
            "🔴 *FRAUD ALERT*\n\n"
            f"🚦 Risk Score: {score}\n\n"
            "⚠️ Do NOT click links or send money.\n\n"
            "👉 Reply *REPORT* to help others\n"
            "👉 Reply *EXIT* to stop alerts\n\n"
            "🔗 Verify only on official portals:\n"
            "https://www.india.gov.in\n"
            "https://www.cybercrime.gov.in"
        )

    elif label == "SUSPICIOUS":
        reply.body(
            "🟡 *SUSPICIOUS MESSAGE*\n\n"
            f"🚦 Risk Score: {score}\n\n"
            "Please verify before acting."
        )

    else:
        reply.body(
            "🟢 *LIKELY GENUINE*\n\n"
            "No strong scam indicators detected.\n"
            "Still verify from official sources."
        )

    return str(resp)

# ==================================================
# START SERVER (RAILWAY SAFE)
# ==================================================

if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=int(os.environ.get("PORT", 8080))
    )
