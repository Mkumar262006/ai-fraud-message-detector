from flask import Flask, request, render_template, redirect, url_for
from twilio.twiml.messaging_response import MessagingResponse
import sqlite3, os, re
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity

app = Flask(__name__)
DB_PATH = "scam_system.db"

# ================= DATABASE =================
def init_db():
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()

    cur.execute("""
    CREATE TABLE IF NOT EXISTS pending_scams (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        message TEXT,
        reporter TEXT
    )
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS confirmed_scams (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        message TEXT UNIQUE
    )
    """)

    conn.commit()
    conn.close()

init_db()

# ================= LANGUAGE DETECTION =================
def detect_language(text):
    for ch in text:
        if '\u0B80' <= ch <= '\u0BFF':
            return "TA"
        if '\u0900' <= ch <= '\u097F':
            return "HI"
    return "EN"

# ================= KEYWORDS =================

EMOTIONAL_WORDS = [
    "help","poor","family emergency","medical emergency",
    "உதவி","குடும்ப அவசரம்",
    "मदद","परिवार संकट"
]

FINANCIAL_WORDS = [
    "send money","transfer","upi","pay","processing fee",
    "பணம்","பணம் அனுப்பு",
    "पैसे","भुगतान"
]

BANK_WORDS = [
    "bank","kyc","rbi","account blocked",
    "வங்கி","கணக்கு",
    "बैंक","खाता"
]

SENSITIVE_WORDS = [
    "otp","account number","card details","cvv",
    "ஒடிபி","கணக்கு எண்",
    "ओटीपी"
]

URGENCY_WORDS = [
    "urgent","act now","immediately",
    "அவசரம்","உடனே",
    "तुरंत"
]

GOVT_WORDS = [
    "government scheme","aadhaar update","pm yojana",
    "அரசு திட்டம்",
    "सरकारी योजना"
]

CHARITY_WORDS = [
    "charity","donation","fundraiser","ngo",
    "நன்கொடை",
    "दान"
]

SOCIAL_ENGINEERING = [
    "limited offer","secret opportunity","trusted source"
]

PHONE_PATTERN = r"\b\d{9,13}\b"
UPI_PATTERN = r"[a-zA-Z0-9.\-_]+@[a-zA-Z]+"
URL_PATTERN = r"(https?://|www\.)"

# ================= HARM INDEX =================
def calculate_harm_index(text):

    t = text.lower()
    score = 0
    reasons = []

    emotional_flag = any(w in t for w in EMOTIONAL_WORDS)
    financial_flag = any(w in t for w in FINANCIAL_WORDS)

    if emotional_flag:
        score += 2
        reasons.append("Emotional manipulation")

    if financial_flag:
        score += 3
        reasons.append("Financial request")

    if any(w in t for w in BANK_WORDS):
        score += 3
        reasons.append("Bank impersonation")

    if any(w in t for w in SENSITIVE_WORDS):
        score += 3
        reasons.append("Sensitive data request")

    if any(w in t for w in URGENCY_WORDS):
        score += 2
        reasons.append("Urgency pressure")

    if any(w in t for w in GOVT_WORDS):
        score += 3
        reasons.append("Government impersonation")

    if any(w in t for w in CHARITY_WORDS) and financial_flag:
        score += 3
        reasons.append("Donation fraud")

    if any(w in t for w in SOCIAL_ENGINEERING):
        score += 2
        reasons.append("Social engineering")

    if re.search(UPI_PATTERN, t):
        score += 3
        reasons.append("UPI payment detected")

    if re.search(PHONE_PATTERN, t) and financial_flag:
        score += 3
        reasons.append("Money requested via number")

    if re.search(URL_PATTERN, t):
        score += 2
        reasons.append("External link")

    if emotional_flag and re.search(PHONE_PATTERN, t):
        score = max(score,4)

    return min(score,10), reasons

def classify(score):
    if score >= 7:
        return "FRAUD"
    elif score >= 4:
        return "CAUTION"
    return "LOW RISK"

# ================= COMMUNITY LEARNING =================
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
    cur.execute("INSERT INTO pending_scams VALUES(NULL,?,?)",(msg,reporter))
    conn.commit()
    conn.close()

def promote_if_trusted(msg):
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("SELECT COUNT(DISTINCT reporter) FROM pending_scams WHERE message=?",(msg,))
    count = cur.fetchone()[0]

    if count >= MIN_REPORTERS:
        cur.execute("INSERT OR IGNORE INTO confirmed_scams VALUES(NULL,?)",(msg,))
        cur.execute("DELETE FROM pending_scams WHERE message=?",(msg,))
        conn.commit()

    conn.close()

# ================= WHATSAPP BOT =================
last_seen = {}

@app.route("/whatsapp", methods=["POST"])
def whatsapp():

    incoming = request.values.get("Body","").strip()
    user = request.values.get("From")
    lang = detect_language(incoming)

    resp = MessagingResponse()
    reply = resp.message()

    if incoming.upper() == "EXIT":
        reply.body("Alerts stopped")
        return str(resp)

    if incoming.upper() == "REPORT":
        if user in last_seen:
            msg,_ = last_seen[user]
            save_pending(msg,user)
            promote_if_trusted(msg)
            reply.body("Report saved. https://cybercrime.gov.in")
        return str(resp)

    harm_score, reasons = calculate_harm_index(incoming)

    if similarity(incoming, fetch("confirmed_scams")) > SIM_THRESHOLD:
        harm_score = max(harm_score,8)

    label = classify(harm_score)
    last_seen[user] = (incoming,label)

    explanation = "\n".join(reasons) if reasons else "No major risk signals"

    if lang == "TA":
        message = f"ஆபத்து மதிப்பீடு: {harm_score}/10\nநிலை: {label}\n{explanation}"
    elif lang == "HI":
        message = f"जोखिम स्कोर: {harm_score}/10\nस्थिति: {label}\n{explanation}"
    else:
        message = f"Harm Index: {harm_score}/10\nRisk: {label}\n{explanation}"

    reply.body(message)
    return str(resp)

# ================= ADMIN DASHBOARD =================
@app.route("/admin")
def admin_home():
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()

    cur.execute("SELECT COUNT(*) FROM pending_scams")
    pending = cur.fetchone()[0]

    cur.execute("SELECT COUNT(*) FROM confirmed_scams")
    confirmed = cur.fetchone()[0]

    conn.close()

    return render_template("dashboard.html", pending=pending, confirmed=confirmed)

@app.route("/admin/pending")
def admin_pending():
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()

    cur.execute("""
        SELECT message, COUNT(DISTINCT reporter)
        FROM pending_scams
        GROUP BY message
    """)

    data = cur.fetchall()
    conn.close()

    return render_template("pending.html", data=data)

@app.route("/admin/confirmed")
def admin_confirmed():
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()

    cur.execute("SELECT message FROM confirmed_scams")
    data = cur.fetchall()

    conn.close()
    return render_template("confirmed.html", data=data)

@app.route("/admin/approve")
def approve_scam():
    msg = request.args.get("msg")

    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()

    cur.execute("INSERT OR IGNORE INTO confirmed_scams VALUES(NULL,?)",(msg,))
    cur.execute("DELETE FROM pending_scams WHERE message=?",(msg,))

    conn.commit()
    conn.close()

    return redirect(url_for("admin_pending"))

@app.route("/admin/delete")
def delete_scam():
    msg = request.args.get("msg")

    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()

    cur.execute("DELETE FROM pending_scams WHERE message=?",(msg,))
    conn.commit()
    conn.close()

    return redirect(url_for("admin_pending"))

# ================= SERVER =================
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT",8080)))
