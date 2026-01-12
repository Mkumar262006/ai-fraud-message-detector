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
# BANK IMPERSONATION (TEXT‑ONLY)
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
    "send card details",
    "बैंक विवरण भेजें",
    "खाता विवरण साझा करें",
    "வங்கி விவரங்களை அனுப்பவும்",
    "கணக்கு விவரங்களை பகிரவும்"
]

URGENCY_PHRASES = [
    "immediately", "urgent", "blocked", "suspended",
    "verify now", "temporarily blocked",
    "तुरंत", "ब्लॉक",
    "உடனே", "தடை"
]

def is_text_only_bank_scam(text):
    t = text.lower()
    return (
        any(b in t for b in BANK_KEYWORDS) and
        (any(s in t for s in SENSITIVE_DATA_REQUESTS) or
         any(u in t for u in URGENCY_PHRASES))
    )

# ==================================================
# UNVERIFIED FINANCIAL HELP
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
    cur.execute(
        "SELECT COUNT(DISTINCT reporter) FROM pending_scams WHERE message=?",
        (msg,)
    )
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

def is_community_reported(msg):
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute(
        "SELECT COUNT(DISTINCT reporter) FROM pending_scams WHERE message=?",
        (msg,)
    )
    count = cur.fetchone()[0]
    conn.close()
    return count >= MIN_REPORTERS

# ==================================================
# VERIFICATION NOTE (ALWAYS SHOWN)
# ==================================================
def verification_note(lang):
    if lang == "TA":
        return (
            "🔎 வெளிப்புற சரிபார்ப்பு பரிந்துரை:\n"
            "அதிகாரப்பூர்வ அல்லது நம்பகமான ஆதாரங்களில் இருந்து "
            "இந்த தகவலை உறுதிப்படுத்தவும்.\n\n"
            "🔗 https://www.india.gov.in\n"
            "🔗 https://cybercrime.gov.in"
        )
    if lang == "HI":
        return (
            "🔎 बाहरी सत्यापन सुझाव:\n"
            "कृपया आधिकारिक या विश्वसनीय स्रोतों से जानकारी की पुष्टि करें।\n\n"
            "🔗 https://www.india.gov.in\n"
            "🔗 https://cybercrime.gov.in"
        )
    return (
        "🔎 Verification Suggestion:\n"
        "Please double‑check this information using official or trusted sources.\n\n"
        "🔗 https://www.india.gov.in\n"
        "🔗 https://cybercrime.gov.in"
    )

# ==================================================
# WHATSAPP WEBHOOK
# ==================================================
last_seen = {}   # user -> (message, label)

@app.route("/whatsapp", methods=["POST"])
def whatsapp():
    incoming = request.values.get("Body", "").strip()
    user = request.values.get("From")
    lang = detect_language(incoming)

    resp = MessagingResponse()
    reply = resp.message()

    # EXIT
    if incoming.upper() == "EXIT":
        reply.body("Alerts stopped safely.")
        return str(resp)

    # REPORT
    if incoming.upper() == "REPORT":
        if user in last_seen:
            msg, lbl = last_seen[user]
            if lbl != "GENUINE":
                save_pending(msg, user)
                promote_if_trusted(msg)
                reply.body(
                    "✅ Report received.\n\n"
                    "You can also report officially:\n"
                    "https://cybercrime.gov.in\n"
                    "https://cms.rbi.org.in"
                )
            else:
                reply.body("Thank you. No strong scam indicators detected earlier.")
        else:
            reply.body("No previous message found to report.")
        return str(resp)

    # CORE DECISION
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

    last_seen[user] = (incoming, label)

    community_flag = is_community_reported(incoming)

    def respond(ta, en, hi):
        if lang == "TA":
            return f"{ta}\n\n{en}"
        if lang == "HI":
            return f"{hi}\n\n{en}"
        return en

    community_note = respond(
        "⚠️ சமூக எச்சரிக்கை:\nபல பயனர்கள் இதே போன்ற செய்தியை புகார் செய்துள்ளனர்.",
        "⚠️ COMMUNITY ALERT:\nMultiple users have reported similar messages.",
        "⚠️ सामुदायिक चेतावनी:\nकई उपयोगकर्ताओं ने इस तरह के संदेश की रिपोर्ट की है।"
    ) if community_flag else ""

    if label == "FRAUD":
        reply.body(
            respond(
                "🔴 மோசடி எச்சரிக்கை!",
                "🔴 FRAUD ALERT",
                "🔴 धोखाधड़ी चेतावनी!"
            )
            + ("\n\n" + community_note if community_note else "")
            + "\n\n"
            + verification_note(lang)
        )

    elif label == "CAUTION":
        reply.body(
            respond(
                "🟠 எச்சரிக்கை",
                "🟠 CAUTION",
                "🟠 सावधानी"
            )
            + ("\n\n" + community_note if community_note else "")
            + "\n\n"
            + verification_note(lang)
        )

    else:
        reply.body(
            respond(
                "🟢 இந்த செய்தி பாதுகாப்பாக இருக்கலாம்.",
                "🟢 LIKELY GENUINE",
                "🟢 यह संदेश सुरक्षित लग सकता है।"
            )
            + "\n\n"
            + verification_note(lang)
        )

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
