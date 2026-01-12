from flask import Flask, request
from twilio.twiml.messaging_response import MessagingResponse
import sqlite3
import os
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity

app = Flask(__name__)

# ==================================================
# DATABASE
# ==================================================

DB_PATH = "scam_system.db"

def init_db():
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()

    # Confirmed scams
    cur.execute("""
        CREATE TABLE IF NOT EXISTS confirmed_scams (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            message TEXT UNIQUE
        )
    """)

    # Pending (reported but not confirmed)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS pending_scams (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            message TEXT,
            reporter TEXT
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
LEARN_THRESHOLD = 3  # 👈 very important

def get_confirmed():
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("SELECT message FROM confirmed_scams")
    rows = cur.fetchall()
    conn.close()
    return [r[0] for r in rows]

def get_pending():
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("SELECT message FROM pending_scams")
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
# RULE-BASED CHECK
# ==================================================

SCAM_WORDS = [
    "lottery", "winner", "prize", "urgent", "click",
    "invest", "investment", "returns", "profit",
    "crypto", "bitcoin", "act fast",
    "₹", "rs",
    "லாட்டரி", "பரிசு",
    "लॉटरी", "इनाम"
]

def rule_score(msg):
    return sum(1 for w in SCAM_WORDS if w.lower() in msg.lower())

# ==================================================
# ADMIN DASHBOARD
# ==================================================

@app.route("/admin/dashboard")
def admin_dashboard():
    return {
        "confirmed_scams": len(get_confirmed()),
        "pending_reports": len(get_pending()),
        "recent_confirmed": get_confirmed()[-5:],
        "recent_pending": get_pending()[-5:]
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

    # ---------------- EXIT ----------------
    if incoming.upper() == "EXIT":
        if lang == "TA":
            reply.body(
                "✅ அறிவிப்புகள் நிறுத்தப்பட்டன.\n\n"
                "Alerts stopped safely."
            )
        elif lang == "HI":
            reply.body(
                "✅ अलर्ट बंद कर दिए गए हैं।\n\n"
                "Alerts stopped safely."
            )
        else:
            reply.body("Alerts stopped safely.")
        return str(resp)

    # ---------------- REPORT ----------------
    if incoming.upper() == "REPORT":
        if user in last_message_cache:
            msg, label = last_message_cache[user]
            if label in ["FRAUD", "CAUTION"]:
                save_pending(msg, user)
                reply.body(
                    "⚠️ Report received.\n"
                    "We monitor similar patterns over time."
                )
            else:
                reply.body(
                    "ℹ️ Report noted.\n"
                    "No immediate risk detected."
                )
        else:
            reply.body("No message to report.")
        return str(resp)

    # ---------------- DETECTION ----------------
    r_score = rule_score(incoming)

    confirmed_sim = similarity_score(incoming, get_confirmed())
    pending_sim = similarity_score(incoming, get_pending())

    # learning logic
    if pending_sim >= SIM_HIGH:
        promote_to_confirmed(incoming)

    pending_count = sum(
        1 for p in get_pending()
        if similarity_score(incoming, [p]) >= SIM_HIGH
    )

    if r_score >= 3 or confirmed_sim >= SIM_HIGH or pending_count >= LEARN_THRESHOLD:
        label = "FRAUD"
    elif r_score >= 2 or pending_sim >= SIM_MED:
        label = "CAUTION"
    else:
        label = "GENUINE"

    last_message_cache[user] = (incoming, label)

    # ---------------- RESPONSE ----------------
    def bilingual(ta, en, hi=None):
        if lang == "TA":
            return f"{ta}\n\n{en}"
        if lang == "HI":
            return f"{hi}\n\n{en}"
        return en

    if label == "FRAUD":
        reply.body(bilingual(
            "🔴 மோசடி எச்சரிக்கை!\nஇந்த செய்தி ஆபத்தானது.",
            "🔴 FRAUD ALERT\nDo NOT share details or click links.",
            "🔴 धोखाधड़ी चेतावनी!\nयह संदेश खतरनाक है।"
        ))
    elif label == "CAUTION":
        reply.body(bilingual(
            "🟠 எச்சரிக்கை\nஇந்த செய்தியை முழுமையாக சரிபார்க்க முடியவில்லை.",
            "🟠 CAUTION\nWe cannot fully verify this message.",
            "🟠 सावधानी\nइस संदेश की पुष्टि नहीं हो सकी।"
        ))
    else:
        reply.body(bilingual(
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
