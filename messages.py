from flask import Flask, request
from twilio.twiml.messaging_response import MessagingResponse
import sqlite3
import os
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity

app = Flask(__name__)

# ==================================================
# DATABASE SETUP
# ==================================================

DB_PATH = "scam_system.db"

def init_db():
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()

    cur.execute("""
        CREATE TABLE IF NOT EXISTS confirmed_scams (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            message TEXT UNIQUE,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS pending_scams (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            message TEXT,
            reporter TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
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
# NLP SIMILARITY (INTERNAL)
# ==================================================

SIM_HIGH = 0.65
SIM_MED = 0.40
LEARN_THRESHOLD = 3

def fetch_messages(table):
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute(f"SELECT message FROM {table}")
    rows = cur.fetchall()
    conn.close()
    return [r[0] for r in rows]

def save_pending(msg, reporter):
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO pending_scams(message, reporter) VALUES (?, ?)",
        (msg, reporter)
    )
    conn.commit()
    conn.close()

def promote_to_confirmed(msg):
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute(
        "INSERT OR IGNORE INTO confirmed_scams(message) VALUES (?)",
        (msg,)
    )
    cur.execute(
        "DELETE FROM pending_scams WHERE message = ?",
        (msg,)
    )
    conn.commit()
    conn.close()

def similarity_score(msg, corpus):
    if not corpus:
        return 0.0
    texts = corpus + [msg]
    tfidf = TfidfVectorizer().fit_transform(texts)
    scores = cosine_similarity(tfidf[-1], tfidf[:-1])
    return max(scores[0])

# ==================================================
# KEYWORDS + OTP CONTEXT LOGIC
# ==================================================

HIGH_RISK_KEYWORDS = [
    "lottery", "winner", "prize", "won", "claim",
    "urgent", "act fast", "limited time", "final warning",
    "click here", "verify now",
    "invest", "investment", "returns", "profit", "double",
    "crypto", "bitcoin", "trading",
    "free money", "guaranteed",
    "account blocked", "account suspended",

    "லாட்டரி", "பரிசு", "வெற்றி",
    "உடனே", "அவசரம்", "முதலீடு", "லாபம்",
    "கணக்கு முடக்கம்",

    "लॉटरी", "इनाम", "जीत",
    "तुरंत", "निवेश", "लाभ",
    "खाता बंद"
]

MEDIUM_RISK_KEYWORDS = [
    "offer", "opportunity", "promotion",
    "selected", "shortlisted",
    "package", "delivery", "courier",
    "subscription", "renewal",

    "சலுகை", "வாய்ப்பு", "டெலிவரி", "பார்சல்",

    "ऑफर", "अवसर", "डिलीवरी", "पार्सल"
]

MONEY_INDICATORS = ["₹", "rs", "rupees", "usd", "ரூபாய்", "रुपये"]
LINK_INDICATORS = ["http", "https", ".com", ".in", ".xyz", ".link", ".win", "bit.ly"]

OTP_WORDS = ["otp", "one time password", "ஓடிபி", "ओटीपी"]

OTP_SAFE_PHRASES = [
    "do not share", "never share", "do not disclose",
    "for your security", "do not reply",
    "பகிர வேண்டாம்", "பகிராதீர்கள்",
    "साझा न करें", "मत साझा करें"
]

OTP_DANGEROUS_ACTIONS = [
    "share otp", "send otp", "confirm otp",
    "enter otp", "submit otp", "reply otp",
    "verify otp", "otp now", "otp immediately",
    "ओटीपी भेजें", "otp அனுப்பு"
]

def rule_score(msg):
    msg_l = msg.lower()
    score = 0

    for w in HIGH_RISK_KEYWORDS:
        if w in msg_l:
            score += 2

    for w in MEDIUM_RISK_KEYWORDS:
        if w in msg_l:
            score += 1

    for w in MONEY_INDICATORS:
        if w in msg_l:
            score += 1

    for w in LINK_INDICATORS:
        if w in msg_l:
            score += 1

    has_otp = any(w in msg_l for w in OTP_WORDS)

    if has_otp:
        if any(p in msg_l for p in OTP_SAFE_PHRASES):
            score -= 2
        if any(p in msg_l for p in OTP_DANGEROUS_ACTIONS):
            score += 3
        if score < 2:
            score += 1

    return max(score, 0)

# ==================================================
# ADMIN DASHBOARD
# ==================================================

@app.route("/admin/dashboard")
def admin_dashboard():
    return {
        "confirmed_scams": len(fetch_messages("confirmed_scams")),
        "pending_reports": len(fetch_messages("pending_scams")),
        "recent_confirmed": fetch_messages("confirmed_scams")[-5:],
        "recent_pending": fetch_messages("pending_scams")[-5:]
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

    # EXIT
    if incoming.upper() == "EXIT":
        reply.body("Alerts stopped safely.")
        return str(resp)

    # REPORT
    if incoming.upper() == "REPORT":
        if user in last_message_cache:
            msg, label = last_message_cache[user]
            if label in ["FRAUD", "CAUTION"]:
                save_pending(msg, user)
                reply.body("Report received. We monitor similar patterns over time.")
            else:
                reply.body("Report noted. No immediate risk detected.")
        else:
            reply.body("No message to report.")
        return str(resp)

    # DETECTION
    r_score = rule_score(incoming)

    confirmed = fetch_messages("confirmed_scams")
    pending = fetch_messages("pending_scams")

    confirmed_sim = similarity_score(incoming, confirmed)
    pending_sim = similarity_score(incoming, pending)

    if pending_sim >= SIM_HIGH:
        promote_to_confirmed(incoming)

    repeat_count = sum(
        1 for p in pending
        if similarity_score(incoming, [p]) >= SIM_HIGH
    )

    if r_score >= 6 or confirmed_sim >= SIM_HIGH or repeat_count >= LEARN_THRESHOLD:
        label = "FRAUD"
    elif r_score >= 4 or pending_sim >= SIM_MED:
        label = "CAUTION"
    else:
        label = "GENUINE"

    last_message_cache[user] = (incoming, label)

    def respond(ta, en, hi):
        if lang == "TA":
            return f"{ta}\n\n{en}"
        if lang == "HI":
            return f"{hi}\n\n{en}"
        return en

    if label == "FRAUD":
        reply.body(respond(
            "🔴 மோசடி எச்சரிக்கை!\nஇந்த செய்தி ஆபத்தானது.",
            "🔴 FRAUD ALERT\nDo NOT share details or click links.",
            "🔴 धोखाधड़ी चेतावनी!\nयह संदेश खतरनाक है।"
        ))
    elif label == "CAUTION":
        reply.body(respond(
            "🟠 எச்சரிக்கை\nஇந்த செய்தியை முழுமையாக சரிபார்க்க முடியவில்லை.",
            "🟠 CAUTION\nWe cannot fully verify this message.",
            "🟠 सावधानी\nइस संदेश की पुष्टि नहीं हो सकी।"
        ))
    else:
        reply.body(respond(
            "🟢 இந்த செய்தி பாதுகாப்பாக இருக்கலாம்.",
            "🟢 LIKELY GENUINE\nNo strong scam indicators detected.",
            "🟢 यह संदेश सुरक्षित लगता है।"
        ))

    return str(resp)

# ==================================================
# SERVER
# ==================================================

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 8080)))
