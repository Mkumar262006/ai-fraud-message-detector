from flask import Flask, request
from twilio.twiml.messaging_response import MessagingResponse
import sqlite3, os, re
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity

app = Flask(__name__)
DB_PATH = "scam_system.db"

# ==================================================
# DATABASE
# ==================================================

def init_db():
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()

    cur.execute("""
    CREATE TABLE IF NOT EXISTS pending_scams (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        message TEXT,
        reporter TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS confirmed_scams (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        message TEXT UNIQUE,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
    """)

    conn.commit()
    conn.close()

init_db()

# ==================================================
# LANGUAGE DETECTION
# ==================================================

def detect_language(text):
    for ch in text:
        if '\u0B80' <= ch <= '\u0BFF':
            return "TA"
        if '\u0900' <= ch <= '\u097F':
            return "HI"
    return "EN"

# ==================================================
# BANK IMPERSONATION (TEXT-ONLY) RULE
# ==================================================

BANK_KEYWORDS = [
    "bank", "account", "kyc", "rbi",
    "sbi", "icici", "hdfc", "axis",
    "बैंक", "खाता", "केवाईसी",
    "வங்கி", "கணக்கு", "கேஒய்சி"
]

SENSITIVE_DATA_REQUESTS = [
    "send your bank details",
    "share bank details",
    "provide account details",
    "verify your account",
    "renewal of service",
    "send card details",
    "send account number",

    "बैंक विवरण भेजें",
    "खाता विवरण साझा करें",

    "வங்கி விவரங்களை அனுப்பவும்",
    "கணக்கு விவரங்களை பகிரவும்"
]

URGENCY_PHRASES = [
    "immediately", "urgent", "blocked",
    "suspended", "permanent suspension",
    "verify now", "temporarily blocked",

    "तुरंत", "ब्लॉक",
    "உடனே", "தடை"
]

def is_text_only_bank_scam(text):
    t = text.lower()
    return (
        any(b in t for b in BANK_KEYWORDS)
        and (
            any(s in t for s in SENSITIVE_DATA_REQUESTS)
            or any(u in t for u in URGENCY_PHRASES)
        )
    )

# ==================================================
# UNVERIFIED FINANCIAL HELP (CAUTION)
# ==================================================

FINANCIAL_HELP_KEYWORDS = [
    "please help", "need help", "send money",
    "donate", "food", "rent", "medical",
    "मदद करें", "पैसे भेजें",
    "உதவி செய்யுங்கள்", "பணம் அனுப்புங்கள்"
]

def is_unverified_financial_request(text):
    return (
        any(k in text.lower() for k in FINANCIAL_HELP_KEYWORDS)
        and re.search(r"\b\d{9,13}\b", text)
    )

# ==================================================
# SIMILARITY & FAIR LEARNING
# ==================================================

SIM_THRESHOLD = 0.65
MIN_REPORTERS = 3

def fetch(table):
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute(f"SELECT message FROM {table}")
    rows = [r[0] for r in cur.fetchall()]
    conn.close()
    return rows

def save_pending(msg, reporter):
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO pending_scams(message, reporter) VALUES (?, ?)",
        (msg, reporter)
    )
    conn.commit()
    conn.close()

def promote_if_trusted(msg):
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()

    cur.execute("""
        SELECT COUNT(DISTINCT reporter)
        FROM pending_scams WHERE message=?
    """, (msg,))
    count = cur.fetchone()[0]

    if count >= MIN_REPORTERS:
        cur.execute(
            "INSERT OR IGNORE INTO confirmed_scams(message) VALUES (?)",
            (msg,)
        )
        cur.execute(
            "DELETE FROM pending_scams WHERE message=?",
            (msg,)
        )
        conn.commit()

    conn.close()

def similarity(msg, corpus):
    if not corpus:
        return 0
    tfidf = TfidfVectorizer().fit_transform(corpus + [msg])
    return max(cosine_similarity(tfidf[-1], tfidf[:-1])[0])

# ==================================================
# WHATSAPP WEBHOOK
# ==================================================

last_seen = {}   # user -> (previous_message, label)

@app.route("/whatsapp", methods=["POST"])
def whatsapp():
    incoming = request.values.get("Body", "").strip()
    user = request.values.get("From")
    lang = detect_language(incoming)

    resp = MessagingResponse()
    reply = resp.message()

    # -------- EXIT --------
    if incoming.upper() == "EXIT":
        reply.body("Alerts stopped safely.")
        return str(resp)

    # -------- REPORT (FIXED ORDER) --------
    if incoming.upper() == "REPORT":
        if user in last_seen:
            msg, lbl = last_seen[user]

            if lbl != "GENUINE":
                save_pending(msg, user)
                promote_if_trusted(msg)

                reply.body(
                    "✅ Report received.\n\n"
                    "You can also report this officially:\n\n"
                    "🇮🇳 Cybercrime Portal:\nhttps://cybercrime.gov.in\n\n"
                    "🏦 RBI Banking Complaints:\nhttps://cms.rbi.org.in\n\n"
                    "📱 Telecom / SMS Spam (TRAI):\nhttps://sancharsaathi.gov.in\n\n"
                    "Your report helps protect others."
                )
            else:
                reply.body("Thank you. This message shows no immediate scam indicators.")
        else:
            reply.body("No previous message found to report.")

        return str(resp)

    # -------- CORE DECISION --------
    if is_text_only_bank_scam(incoming):
        label = "FRAUD"
    elif is_unverified_financial_request(incoming):
        label = "CAUTION"
    else:
        if similarity(incoming, fetch("confirmed_scams")) > SIM_THRESHOLD:
            label = "FRAUD"
        elif similarity(incoming, fetch("pending_scams")) > SIM_THRESHOLD:
            label = "CAUTION"
        else:
            label = "GENUINE"

    # Store ONLY non-command messages
    last_seen[user] = (incoming, label)

    # -------- MULTILINGUAL RESPONSE --------
    def respond(ta, en, hi):
        if lang == "TA":
            return f"{ta}\n\n{en}"
        if lang == "HI":
            return f"{hi}\n\n{en}"
        return en

    if label == "FRAUD":
        reply.body(respond(
            "🔴 மோசடி எச்சரிக்கை!\nவங்கிகள் எப்போதும் செய்திகளில் விவரங்களை கேட்காது.",
            "🔴 FRAUD ALERT\nBanks never ask for details via messages.",
            "🔴 धोखाधड़ी चेतावनी!\nबैंक कभी संदेशों में विवरण नहीं मांगते।"
        ))
    elif label == "CAUTION":
        reply.body(respond(
            "🟠 எச்சரிக்கை\nஇந்த செய்தி உறுதிப்படுத்தப்படவில்லை.",
            "🟠 CAUTION\nThis message cannot be verified.",
            "🟠 सावधानी\nइस संदेश की पुष्टि नहीं हुई है।"
        ))
    else:
        reply.body(respond(
            "🟢 இந்த செய்தி பாதுகாப்பாக இருக்கலாம்.",
            "🟢 LIKELY GENUINE\nNo strong scam indicators detected.",
            "🟢 यह संदेश सुरक्षित लगता है।"
        ))

    return str(resp)

# ==================================================
# ADMIN DASHBOARD
# ==================================================

@app.route("/admin/dashboard")
def admin():
    return {
        "pending_scams": len(fetch("pending_scams")),
        "confirmed_scams": len(fetch("confirmed_scams"))
    }

# ==================================================
# SERVER
# ==================================================

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 8080)))
