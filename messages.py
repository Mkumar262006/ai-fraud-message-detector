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
# HARM ANALYSIS KEYWORDS
# ==================================================

URGENCY_WORDS = [
    "urgent","immediately","act now","final warning","blocked",
    "suspended","तुरंत","உடனே"
]

FINANCIAL_WORDS = [
    "send money","transfer","donate","pay","upi",
    "பணம்","पैसे"
]

SENSITIVE_WORDS = [
    "otp","bank details","account number","card details",
    "ओटीपी","கணக்கு"
]

EMOTIONAL_WORDS = [
    "help","poor","family suffering","save me",
    "गरीब","உதவி"
]

VIOLENCE_WORDS = [
    "attack","riot","fight","destroy"
]

MEDICAL_MISINFO_WORDS = [
    "avoid doctor","stop medicine","home cure only"
]

# ==================================================
# HARM INDEX CALCULATION
# ==================================================

def calculate_harm_index(text):

    text_l = text.lower()
    score = 0
    reasons = []

    if any(w in text_l for w in URGENCY_WORDS):
        score += 2
        reasons.append("Creates urgency or panic")

    if any(w in text_l for w in FINANCIAL_WORDS):
        score += 3
        reasons.append("Encourages financial transaction")

    if any(w in text_l for w in SENSITIVE_WORDS):
        score += 3
        reasons.append("Requests sensitive personal data")

    if any(w in text_l for w in EMOTIONAL_WORDS):
        score += 2
        reasons.append("Uses emotional manipulation")

    if any(w in text_l for w in VIOLENCE_WORDS):
        score += 4
        reasons.append("Contains potential violence trigger")

    if any(w in text_l for w in MEDICAL_MISINFO_WORDS):
        score += 3
        reasons.append("May cause medical negligence")

    return min(score,10), reasons

# ==================================================
# CLASSIFICATION USING HARM SCORE
# ==================================================
def classify_from_harm(score):
    if score >= 7:
        return "FRAUD"
    elif score >= 4:
        return "CAUTION"
    return "GENUINE"

# ==================================================
# SIMILARITY LEARNING
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

    # EXIT
    if incoming.upper() == "EXIT":
        reply.body("Alerts stopped safely.")
        return str(resp)

    # REPORT
    if incoming.upper() == "REPORT":
        if user in last_seen:
            msg,_ = last_seen[user]
            save_pending(msg,user)
            promote_if_trusted(msg)

            reply.body(
                "✅ Report received.\n"
                "Report officially:\n"
                "https://cybercrime.gov.in"
            )
        else:
            reply.body("No message found to report.")
        return str(resp)

    # ================= HARM ANALYSIS =================
    harm_score, reasons = calculate_harm_index(incoming)

    # similarity learning boost
    if similarity(incoming, fetch("confirmed_scams")) > SIM_THRESHOLD:
        harm_score = max(harm_score,8)

    label = classify_from_harm(harm_score)
    last_seen[user] = (incoming,label)

    # ================= RESPONSE BUILDER =================
    explanation = "\n".join([f"• {r}" for r in reasons]) if reasons else "No major harmful triggers detected."

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
Do not share personal or financial details.
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
