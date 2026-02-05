from flask import Flask, request
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

# ================= MULTILINGUAL KEYWORDS =================

# Emotional manipulation
EMOTIONAL_WORDS = [
    # English
    "help","poor","family emergency","urgent help","hospital bill",
    "save my family","need help",

    # Tamil
    "உதவி","ஏழை","குடும்ப அவசரம்","மருத்துவ செலவு","உதவி செய்யுங்கள்",

    # Hindi
    "मदद","गरीब","परिवार संकट","अस्पताल खर्च","तुरंत मदद"
]

# Financial keywords
FINANCIAL_WORDS = [
    "send money","transfer money","upi","pay now","processing fee",

    "பணம் அனுப்பு","பணம் செலுத்துங்கள்","கட்டணம்",

    "पैसे भेजो","भुगतान करो","शुल्क"
]

# Bank impersonation
BANK_WORDS = [
    "bank","kyc","rbi","account blocked","account suspended",
    "sbi","hdfc","icici","axis","bank of america","paypal",

    "வங்கி","கணக்கு முடக்கம்","கேஒய்சி",

    "बैंक","खाता बंद","केवाईसी"
]

# Sensitive data
SENSITIVE_WORDS = [
    "otp","account number","card details","cvv","pin",

    "ஒடிபி","கணக்கு எண்","வங்கி விவரம்",

    "ओटीपी","खाता नंबर","कार्ड विवरण"
]

# Urgency
URGENCY_WORDS = [
    "urgent","act now","immediately","last warning","final notice",

    "அவசரம்","உடனே",

    "तुरंत","अभी करें"
]

# Government impersonation
GOVT_WORDS = [
    "government scheme","free money scheme","rbi notice",
    "pm yojana","aadhaar update",

    "அரசு திட்டம்","ஆதார் புதுப்பிப்பு",

    "सरकारी योजना","आधार अपडेट"
]

# Charity fraud
CHARITY_WORDS = [
    "charity","donation drive","ngo help","fundraiser",

    "நன்கொடை","அரக்கட்டளை உதவி",

    "दान अभियान","एनजीओ सहायता"
]

# Social engineering
SOCIAL_ENGINEERING = [
    "trusted source","secret opportunity","limited offer",
    "only selected people"
]

# ================= PATTERNS =================
PHONE_PATTERN = r"\b\d{9,13}\b"
UPI_PATTERN = r"[a-zA-Z0-9.\-_]+@[a-zA-Z]+"
URL_PATTERN = r"(https?://|www\.)"

# ================= HARM ANALYSIS =================
def calculate_harm_index(text):

    t = text.lower()
    score = 0
    reasons = []

    emotional_flag = any(w in t for w in EMOTIONAL_WORDS)
    financial_flag = any(w in t for w in FINANCIAL_WORDS)

    if emotional_flag:
        score += 2
        reasons.append("Emotional manipulation detected")

    if financial_flag:
        score += 3
        reasons.append("Financial request detected")

    if any(w in t for w in BANK_WORDS):
        score += 3
        reasons.append("Possible bank impersonation")

    if any(w in t for w in SENSITIVE_WORDS):
        score += 3
        reasons.append("Sensitive data request detected")

    if any(w in t for w in URGENCY_WORDS):
        score += 2
        reasons.append("Urgency pressure detected")

    if any(w in t for w in GOVT_WORDS):
        score += 3
        reasons.append("Government impersonation suspected")

    if any(w in t for w in CHARITY_WORDS) and financial_flag:
        score += 3
        reasons.append("Possible donation fraud")

    if any(w in t for w in SOCIAL_ENGINEERING):
        score += 2
        reasons.append("Social engineering language detected")

    if re.search(UPI_PATTERN, t):
        score += 3
        reasons.append("Payment ID detected")

    if re.search(PHONE_PATTERN, t) and financial_flag:
        score += 3
        reasons.append("Money requested via phone number")

    if re.search(URL_PATTERN, t):
        score += 2
        reasons.append("External link detected")

    # Emotional + payment → enforce CAUTION
    if emotional_flag and re.search(PHONE_PATTERN, t):
        score = max(score,4)

    return min(score,10), reasons

# ================= CLASSIFICATION =================
def classify_from_harm(score):
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
        conn.commit()

    conn.close()

# ================= WHATSAPP WEBHOOK =================
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
        if lang == "TA":
            reply.body("அறிவிப்புகள் நிறுத்தப்பட்டது")
        elif lang == "HI":
            reply.body("सूचनाएं बंद कर दी गई हैं")
        else:
            reply.body("Alerts stopped")
        return str(resp)

    # REPORT
    if incoming.upper() == "REPORT":
        if user in last_seen:
            msg,_ = last_seen[user]
            save_pending(msg,user)
            promote_if_trusted(msg)

            reply.body(
                "Report saved.\nhttps://cybercrime.gov.in"
            )
        return str(resp)

    # Harm Analysis
    harm_score, reasons = calculate_harm_index(incoming)

    if similarity(incoming, fetch("confirmed_scams")) > SIM_THRESHOLD:
        harm_score = max(harm_score,8)

    label = classify_from_harm(harm_score)
    last_seen[user] = (incoming,label)

    explanation = "\n".join(reasons) if reasons else "No major risk signals detected"

    # ================= RESPONSE =================
    if lang == "TA":
        message = f"""
⚠️ ஆபத்து மதிப்பீடு: {harm_score}/10
நிலை: {label}

காரணங்கள்:
{explanation}

பரிந்துரை:
தனிப்பட்ட தகவலை பகிர வேண்டாம்.
அதிகாரப்பூர்வ தளங்களில் சரிபார்க்கவும்.
"""
    elif lang == "HI":
        message = f"""
⚠️ जोखिम स्कोर: {harm_score}/10
स्थिति: {label}

कारण:
{explanation}

सुझाव:
व्यक्तिगत जानकारी साझा न करें।
आधिकारिक स्रोतों से जांच करें।
"""
    else:
        message = f"""
⚠️ Harm Index: {harm_score}/10
Risk Level: {label}

Reasons:
{explanation}

Advice:
Do not share personal data.
Verify using official sources.
"""

    reply.body(message)
    return str(resp)

# ================= SERVER =================
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT",8080)))
