# ===============================
# HARM-FOCUSED MISINFORMATION AI
# ===============================

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
# HARM SIGNAL KEYWORDS
# ==================================================

URGENCY_WORDS = [
    "urgent","immediately","act now","final warning","blocked",
    "suspended","action required","तुरंत","உடனே"
]

FINANCIAL_WORDS = [
    "send money","transfer","donate","pay","upi",
    "பணம்","पैसे"
]

SENSITIVE_WORDS = [
    "otp","bank details","account number","card details"
]

EMOTIONAL_WORDS = [
    "help","poor","family suffering","save me"
]

EMOTIONAL_VOLATILITY_WORDS = [
    "panic","fear","last chance","danger","people dying"
]

CALL_TO_ACTION_PATTERNS = [
    "send now","transfer immediately","click now",
    "join protest","share this message","forward urgently"
]

DOG_WHISTLE_PATTERNS = [
    "they are taking over",
    "protect our people",
    "our culture is under threat"
]

MEDICAL_MISINFO_WORDS = [
    "avoid doctor","stop medicine","home cure only"
]

BANK_KEYWORDS = [
    "bank","account","kyc","rbi","sbi","hdfc",
    "bank of america","paypal","visa","mastercard"
]

ACCOUNT_VERIFICATION_PATTERNS = [
    "verify your account",
    "confirm your account",
    "update account information",
    "account hold","account suspended"
]

CLICK_ACTION_WORDS = [
    "click here","tap link","open link","visit link"
]

URL_PATTERN = r"(https?://|www\.)"

# ==================================================
# HARM INDEX CALCULATION
# ==================================================
def calculate_harm_index(text):

    text_l = text.lower()
    score = 0
    reasons = []

    if any(w in text_l for w in EMOTIONAL_VOLATILITY_WORDS):
        score += 2
        reasons.append("Creates emotional panic or fear")

    if any(w in text_l for w in URGENCY_WORDS):
        score += 2
        reasons.append("Creates urgency pressure")

    if any(w in text_l for w in FINANCIAL_WORDS):
        score += 3
        reasons.append("Encourages financial transaction")

    if any(w in text_l for w in SENSITIVE_WORDS):
        score += 3
        reasons.append("Requests sensitive personal data")

    if any(w in text_l for w in EMOTIONAL_WORDS):
        score += 2
        reasons.append("Uses emotional manipulation")

    if any(w in text_l for w in CALL_TO_ACTION_PATTERNS):
        score += 3
        reasons.append("Encourages specific risky action")

    if any(w in text_l for w in MEDICAL_MISINFO_WORDS):
        score += 3
        reasons.append("May lead to medical negligence")

    if any(w in text_l for w in DOG_WHISTLE_PATTERNS):
        score += 3
        reasons.append("Contains coded social messaging")

    if any(w in text_l for w in ACCOUNT_VERIFICATION_PATTERNS):
        score += 3
        reasons.append("Requests account verification")

    if any(w in text_l for w in CLICK_ACTION_WORDS):
        score += 2
        reasons.append("Encourages clicking unknown links")

    if re.search(URL_PATTERN, text_l):
        score += 2
        reasons.append("Contains external link")

    if any(b in text_l for b in BANK_KEYWORDS) and any(w in text_l for w in ACCOUNT_VERIFICATION_PATTERNS):
        score += 3
        reasons.append("Possible bank impersonation")

    return min(score,10), reasons

# ==================================================
# CLASSIFICATION
# ==================================================
def classify_from_harm(score):
    if score >= 7:
        return "FRAUD"
    elif score >= 4:
        return "CAUTION"
    return "LOW RISK"

# ==================================================
# COMMUNITY LEARNING
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

def similarity(msg, corpus):
    if not corpus:
        return 0
    tfidf = TfidfVectorizer().fit_transform(corpus + [msg])
    return max(cosine_similarity(tfidf[-1], tfidf[:-1])[0])

def save_pending(msg, reporter):
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("INSERT INTO pending_scams(message, reporter) VALUES (?,?)",(msg,reporter))
    conn.commit()
    conn.close()

def promote_if_trusted(msg):
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("SELECT COUNT(DISTINCT reporter) FROM pending_scams WHERE message=?",(msg,))
    count = cur.fetchone()[0]

    if count >= MIN_REPORTERS:
        cur.execute("INSERT OR IGNORE INTO confirmed_scams(message) VALUES (?)",(msg,))
        cur.execute("DELETE FROM pending_scams WHERE message=?",(msg,))
        conn.commit()

    conn.close()

# ==================================================
# WHATSAPP WEBHOOK
# ==================================================
last_seen = {}

@app.route("/whatsapp", methods=["POST"])
def whatsapp():

    incoming = request.values.get("Body","").strip()
    user = request.values.get("From")
    lang = detect_language(incoming)

    resp = MessagingResponse()
    reply = resp.message()

    if incoming.upper() == "EXIT":
        reply.body("Alerts stopped safely.")
        return str(resp)

    if incoming.upper() == "REPORT":
        if user in last_seen:
            msg,_ = last_seen[user]
            save_pending(msg,user)
            promote_if_trusted(msg)
            reply.body("✅ Report received.\nhttps://cybercrime.gov.in")
        else:
            reply.body("No message found to report.")
        return str(resp)

    # Harm Analysis
    harm_score, reasons = calculate_harm_index(incoming)

    history_flag = False
    if similarity(incoming, fetch("confirmed_scams")) > SIM_THRESHOLD:
        harm_score = max(harm_score,8)
        history_flag = True

    label = classify_from_harm(harm_score)
    last_seen[user] = (incoming,label)

    history_note = ""
    if history_flag:
        history_note = "\n• Similar harmful messages were previously reported."

    explanation = "\n".join([f"• {r}" for r in reasons]) + history_note

    def respond(ta,en,hi):
        if lang == "TA":
            return f"{ta}\n\n{en}"
        if lang == "HI":
            return f"{hi}\n\n{en}"
        return en

    message = f"""
📊 Harm Index: {harm_score}/10
Risk Level: {label}

Why this message is risky:
{explanation}

Recommended Action:
Avoid sharing sensitive data.
Verify using official sources.
"""

    reply.body(respond("⚠️ ஆபத்து பகுப்பாய்வு",message,"⚠️ जोखिम विश्लेषण"))

    return str(resp)

# ==================================================
# ADMIN
# ==================================================
@app.route("/admin/dashboard")
def admin():
    return {
        "pending": len(fetch("pending_scams")),
        "confirmed": len(fetch("confirmed_scams"))
    }

# ==================================================
# SERVER
# ==================================================
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT",8080)))
