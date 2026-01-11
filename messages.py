from flask import Flask, request
from twilio.twiml.messaging_response import MessagingResponse
import sqlite3
import os
import re

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
            keyword TEXT UNIQUE
        )
    """)
    conn.commit()
    conn.close()

init_db()

# ==================================================
# LANGUAGE CHECK (STRICT)
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
# KEYWORDS
# ==================================================

HIGH_RISK = [
    "lottery", "winner", "claim", "urgent", "click", "verify",
    "लॉटरी", "इनाम", "तुरंत",
    "லாட்டரி", "பரிசு", "உடனே"
]

MONEY_WORDS = [
    "₹", "rs", "rupees", "payment",
    "रुपये", "भुगतान",
    "ரூபாய்", "பணம்"
]

SUSPICIOUS_DOMAINS = [".xyz", ".win", ".click", ".online"]

# ==================================================
# COMMUNITY DB
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
        if len(word) >= 5:
            cur.execute(
                "INSERT OR IGNORE INTO reported_patterns(keyword) VALUES (?)",
                (word,)
            )
    conn.commit()
    conn.close()

# ==================================================
# FRAUD DETECTION
# ==================================================

def detect_fraud(message):
    msg = message.lower()
    score = 0

    for w in HIGH_RISK:
        if w.lower() in msg:
            score += 2

    for w in MONEY_WORDS:
        if w.lower() in msg:
            score += 1

    for d in SUSPICIOUS_DOMAINS:
        if d in msg:
            score += 2

    for p in get_reported_patterns():
        if p in msg:
            score += 3

    if score >= 6:
        return "FRAUD", score
    elif score >= 3:
        return "SUSPICIOUS", score
    else:
        return "GENUINE", score

# ==================================================
# ADMIN VIEW
# ==================================================

@app.route("/admin/reports", methods=["GET"])
def view_reports():
    patterns = get_reported_patterns()
    return {"total_patterns": len(patterns), "patterns": patterns}

# ==================================================
# WHATSAPP WEBHOOK
# ==================================================

last_message_cache = {}

@app.route("/whatsapp", methods=["POST"])
def whatsapp_reply():
    incoming_msg = request.values.get("Body", "").strip()
    user = request.values.get("From")
    lang = get_language(incoming_msg)

    resp = MessagingResponse()
    reply = resp.message()

    # ---------------- EXIT ----------------
    if incoming_msg.upper() == "EXIT":
        if lang == "TA":
            reply.body(
                "✅ அறிவிப்புகள் நிறுத்தப்பட்டன.\n"
                "மீண்டும் தொடங்க எந்த செய்தியையும் அனுப்பலாம்.\n\n"
                "✅ Alerts stopped safely.\n"
                "You can send any message again anytime."
            )
        elif lang == "HI":
            reply.body(
                "✅ अलर्ट रोक दिए गए हैं।\n"
                "फिर से शुरू करने के लिए कोई भी संदेश भेजें।\n\n"
                "✅ Alerts stopped safely.\n"
                "You can send any message again anytime."
            )
        else:
            reply.body(
                "✅ Alerts stopped safely.\n"
                "You can send any message again anytime."
            )
        return str(resp)

    # ---------------- REPORT ----------------
    if incoming_msg.upper() == "REPORT":
        if user in last_message_cache:
            save_reported_patterns(last_message_cache[user])
            reply.body(
                "✅ Scam reported successfully.\n"
                "This helps protect other users."
            )
        else:
            reply.body("⚠️ No recent message found to report.")
        return str(resp)

    last_message_cache[user] = incoming_msg
    label, score = detect_fraud(incoming_msg)

    # ---------------- RESPONSES ----------------
    if label == "FRAUD":
        if lang == "TA":
            reply.body(
                "🔴 மோசடி எச்சரிக்கை!\n"
                f"ஆபத்து மதிப்பு: {score}\n\n"
                "பணம் அனுப்ப வேண்டாம் / லிங்க் கிளிக் செய்ய வேண்டாம்.\n\n"
                "🔴 FRAUD ALERT\n"
                f"Risk Score: {score}\n"
                "Do NOT click links or send money."
            )
        elif lang == "HI":
            reply.body(
                "🔴 धोखाधड़ी चेतावनी!\n"
                f"जोखिम स्कोर: {score}\n\n"
                "पैसे न भेजें / लिंक पर क्लिक न करें।\n\n"
                "🔴 FRAUD ALERT\n"
                f"Risk Score: {score}\n"
                "Do NOT click links or send money."
            )
        else:
            reply.body(
                "🔴 FRAUD ALERT\n"
                f"Risk Score: {score}\n"
                "Do NOT click links or send money."
            )

    elif label == "SUSPICIOUS":
        if lang == "TA":
            reply.body(
                "🟡 சந்தேகமான செய்தி\n\n"
                "சரிபார்த்த பிறகே செயல்படுங்கள்.\n\n"
                "🟡 SUSPICIOUS MESSAGE\n"
                "Please verify before acting."
            )
        elif lang == "HI":
            reply.body(
                "🟡 संदिग्ध संदेश\n\n"
                "कार्य करने से पहले सत्यापित करें।\n\n"
                "🟡 SUSPICIOUS MESSAGE\n"
                "Please verify before acting."
            )
        else:
            reply.body(
                "🟡 SUSPICIOUS MESSAGE\n"
                "Please verify before acting."
            )

    else:
        if lang == "TA":
            reply.body(
                "🟢 இந்த செய்தி பாதுகாப்பானது.\n\n"
                "🟢 LIKELY GENUINE\n"
                "No strong scam indicators detected."
            )
        elif lang == "HI":
            reply.body(
                "🟢 यह संदेश सुरक्षित लगता है।\n\n"
                "🟢 LIKELY GENUINE\n"
                "No strong scam indicators detected."
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
    app.run(
        host="0.0.0.0",
        port=int(os.environ.get("PORT", 8080))
    )
