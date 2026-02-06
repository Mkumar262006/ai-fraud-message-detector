from flask import Flask, request, render_template, redirect, Response
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user
from flask_socketio import SocketIO
from twilio.twiml.messaging_response import MessagingResponse
from openai import OpenAI
import sqlite3, os, re, datetime
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity

# ================= OPENAI =================
client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))

# ================= APP =================
app = Flask(__name__)
app.secret_key = "adminsecret"
socketio = SocketIO(app)

DB_PATH = "scam_system.db"

# ================= LOGIN =================
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "admin_login"

class Admin(UserMixin):
    id = "admin"

@login_manager.user_loader
def load_user(user_id):
    return Admin()

# ================= DATABASE =================
def init_db():
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()

    cur.execute("""
    CREATE TABLE IF NOT EXISTS pending_scams(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        message TEXT,
        reporter TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS confirmed_scams(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        message TEXT UNIQUE,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
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




# CYBER QUESTION DETECTION
# ===============================
CYBER_QN_KEYWORDS = [
    "cybercrime","cyber threat","online fraud","scam","cybersafety",
    "phishing","otp fraud","bank fraud","digital fraud","cybersecurity"
    "types of scams","what is scam","how scams work",
    "cyber safety","online safety","is this scam"
]

def is_cyber_question(text):
    t = text.lower()
    return (
        ("?" in text or any(w in t for w in ["what","how","why","explain","types"])) and
        any(k in t for k in CYBER_QN_KEYWORDS)
    )

# ===============================
# OPENAI CYBER AWARENESS RESPONSE
# ===============================
def cyber_awareness_response(user_text, lang):

    system_prompt = (
        "You are a cybersecurity awareness assistant for Indian users. "
        "Explain scams, cybercrime, and online safety in simple terms. "
        "You also need to help the user regarding all cyber questions"
        "Do NOT explain how to commit crimes. Keep under 150 words."
    )

    if lang == "TA":
        system_prompt += " Reply in Tamil and English."
    elif lang == "HI":
        system_prompt += " Reply in Hindi and English."
    else:
        system_prompt += " Reply in English."

    response = client.chat.completions.create(
        model="gpt-4o-mini",
        messages=[
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_text}
        ],
        temperature=0.3
    )

    return response.choices[0].message.content.strip()

# ================= KEYWORDS =================
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

SCAM_WORDS = (
    EMOTIONAL_WORDS
    + FINANCIAL_WORDS
    + BANK_WORDS
    + SENSITIVE_WORDS
    + URGENCY_WORDS
    + GOVT_WORDS
    + CHARITY_WORDS
    + SOCIAL_ENGINEERING
)


# ================= INTENT DETECTION =================
def looks_like_scam(text):
    t = text.lower()

    return (
        any(w in t for w in SCAM_WORDS)
        or re.search(PHONE_PATTERN,t)
        or re.search(UPI_PATTERN,t)
        or re.search(URL_PATTERN,t)
    )

# ================= HARM INDEX =================
def calculate_harm(text):

    t = text.lower()
    score = 0
    reasons = []

    if any(w in t for w in EMOTIONAL_WORDS):
        score += 2
        reasons.append("Emotional manipulation")

    if any(w in t for w in FINANCIAL_WORDS):
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
        score += 2
        reasons.append("Government impersonation")

    if re.search(UPI_PATTERN,t):
        score += 3
        reasons.append("UPI payment detected")

    if re.search(PHONE_PATTERN,t):
        score += 2
        reasons.append("Phone number shared")

    if re.search(URL_PATTERN,t):
        score += 2
        reasons.append("External suspicious link")

    return min(score,10), reasons


def classify(score):
    if score >= 7: return "FRAUD"
    if score >= 4: return "CAUTION"
    return "LOW RISK"

# ================= COMMUNITY LEARNING =================
SIM_THRESHOLD = 0.65
MIN_REPORTERS = 3
last_seen = {}

def fetch(table):
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute(f"SELECT message FROM {table}")
    rows = [r[0] for r in cur.fetchall()]
    conn.close()
    return rows

def similarity(msg, corpus):
    if not corpus: return 0
    tfidf = TfidfVectorizer().fit_transform(corpus + [msg])
    return max(cosine_similarity(tfidf[-1], tfidf[:-1])[0])

def save_pending(msg, reporter):
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("INSERT INTO pending_scams(message,reporter) VALUES (?,?)",(msg,reporter))
    conn.commit()
    conn.close()

def promote_if_trusted(msg):

    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()

    cur.execute("""
        SELECT COUNT(DISTINCT reporter)
        FROM pending_scams WHERE message=?
    """,(msg,))

    if cur.fetchone()[0] >= MIN_REPORTERS:
        cur.execute("INSERT OR IGNORE INTO confirmed_scams(message) VALUES (?)",(msg,))
        cur.execute("DELETE FROM pending_scams WHERE message=?",(msg,))
        conn.commit()

    conn.close()


# ================= COMMAND MENU =================
def command_menu(lang):
    if lang == "TA":
        return "HELP → உதவி\nREPORT → புகார்\nTIPS → பாதுகாப்பு குறிப்புகள்"
    if lang == "HI":
        return "HELP → सहायता\nREPORT → रिपोर्ट\nTIPS → सुरक्षा सुझाव"
    return "HELP → Guide\nREPORT → Report scam\nTIPS → Safety tips"


# ================= MULTILINGUAL SCAM RESPONSE =================
def scam_reply(lang, score, label, reasons):

    explanation = "\n".join(reasons)

    if lang == "TA":
        return f"⚠ ஆபத்து நிலை: {label}\nஆபத்து மதிப்பெண்: {score}\nகாரணங்கள்:\n{explanation}"

    if lang == "HI":
        return f"⚠ जोखिम स्तर: {label}\nजोखिम स्कोर: {score}\nकारण:\n{explanation}"

    return f"⚠ Risk Level: {label}\nHarm Score: {score}\nReasons:\n{explanation}"

# ================= BROADCAST STATS =================
def broadcast_stats():

    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()

    cur.execute("SELECT COUNT(*) FROM pending_scams")
    pending = cur.fetchone()[0]

    cur.execute("SELECT COUNT(*) FROM confirmed_scams")
    confirmed = cur.fetchone()[0]

    conn.close()

    socketio.emit("stats_update",{
        "pending": pending,
        "confirmed": confirmed
    })

def faq_router(text, lang):

    t = text.lower()

    if any(q in t for q in ["report","complaint","how to report","file scam"]):

        if lang == "TA":
            return (
                "📢 மோசடி புகார் செய்ய:\n"
                "1️⃣ சந்தேகமான செய்தியை அனுப்புங்கள்\n"
                "2️⃣ பிறகு REPORT என்று டைப் செய்யுங்கள்\n\n"
                "அது நிர்வாகிக்கு அனுப்பப்படும்."
            )

        if lang == "HI":
            return (
                "📢 धोखाधड़ी रिपोर्ट करने के लिए:\n"
                "1️⃣ संदिग्ध संदेश भेजें\n"
                "2️⃣ फिर REPORT टाइप करें\n\n"
                "यह एडमिन को भेज दिया जाएगा।"
            )

        return (
            "📢 To report a scam:\n"
            "1️⃣ Send the suspicious message\n"
            "2️⃣ Then type REPORT\n\n"
            "Our system will review it."
        )

    return None
# =======GREETING=====================
def is_greeting(text):
    t = text.lower().strip()
    greetings = [
        "hi", "hello", "hey", "hai",
        "who are you", "what is this",
        "help", "start"
    ]
    return t in greetings

# ================= WHATSAPP BOT =================
@app.route("/whatsapp", methods=["POST"])
def whatsapp():

    incoming = request.values.get("Body","").strip()
    user = request.values.get("From")
    lang = detect_language(incoming)

    resp = MessagingResponse()
    reply = resp.message()

    # REPORT
    if incoming.upper() == "REPORT":

        if user in last_seen:

            msg, _ = last_seen[user]

            # Save pending report
            save_pending(msg, user)

            # Community learning promotion
            promote_if_trusted(msg)

            # Live dashboard update
            broadcast_stats()

            if lang == "TA":
                reply.body(
                    "✅ புகார் பதிவு செய்யப்பட்டது\n"
                    "🔎 அதிகாரப்பூர்வ புகார்:\n"
                    "https://cybercrime.gov.in"
                )

            elif lang == "HI":
                reply.body(
                    "✅ रिपोर्ट दर्ज हो गई\n"
                    "🔎 आधिकारिक शिकायत:\n"
                    "https://cybercrime.gov.in"
                )

            else:
                reply.body(
                    "✅ Report recorded successfully\n"
                    "🔎 Official complaint portal:\n"
                    "https://cybercrime.gov.in"
                )

        else:

            if lang == "TA":
                reply.body("⚠ முதலில் சந்தேகமான செய்தியை அனுப்பவும்")

            elif lang == "HI":
                reply.body("⚠ पहले संदिग्ध संदेश भेजें")

            else:
                reply.body("⚠ Please send suspicious message first")

        return str(resp)

     # GREETING RESPONSE
    if is_greeting(incoming):
        if lang == "TA":
            reply.body(
                "👋 வணக்கம்!\n"
                "நான் மோசடி மற்றும் ஆபத்தான செய்திகளை சரிபார்க்க உதவுகிறேன்.\n"
                "சந்தேகமான செய்தியை அனுப்புங்கள்."
            )
        elif lang == "HI":
            reply.body(
                "👋 नमस्ते!\n"
                "मैं धोखाधड़ी और जोखिम भरे संदेशों की जांच करता हूँ।\n"
                "कृपया कोई संदिग्ध संदेश भेजें।"
            )
        else:
            reply.body(
                "👋 Hi!\n"
                "I help check messages for scams or harm.\n"
                "Please paste a suspicious message."
            )
        return str(resp)

    # FAQ
    faq = faq_router(incoming, lang)
    if faq:
        reply.body(faq)
        return str(resp)

   
        
    # CYBER AWARENESS Q&A (IMPORTANT: BEFORE FALLBACK)
    if is_cyber_question(incoming):
        answer = cyber_awareness_response(incoming, lang)
        reply.body(answer)
        return str(resp)

     # 5️⃣ SCAM DETECTION
    if looks_like_scam(incoming):
        score, reasons = calculate_harm(incoming)

        if similarity(incoming, fetch("confirmed_scams")) > SIM_THRESHOLD:
            score = max(score, 8)

        label = classify(score)
        last_seen[user] = (incoming, label)

        reply.body(
            f"⚠ Risk Level: {label}\n"
            f"Harm Score: {score}\n"
            + "\n".join(reasons)
        )
        return str(resp)

    # 6️⃣ FINAL FALLBACK (ONLY IF NOTHING MATCHES)
    if lang == "TA":
        reply.body("ℹ️ தயவுசெய்து ஒரு சந்தேகமான செய்தி அல்லது கேள்வி அனுப்புங்கள்.")
    elif lang == "HI":
        reply.body("ℹ️ कृपया कोई संदिग्ध संदेश या प्रश्न भेजें।")
    else:
        reply.body("ℹ️ Please send a suspicious message or a cyber safety question.")

    return str(resp)


# ================= ADMIN LOGIN =================
@app.route("/admin/login", methods=["GET","POST"])
def admin_login():

    if request.method == "POST":
        if request.form["username"] == "admin" and request.form["password"] == "1234":
            login_user(Admin())
            return redirect("/admin")

    return render_template("login.html")

@app.route("/admin/logout")
@login_required
def admin_logout():
    logout_user()
    return redirect("/admin/login")

# ================= DASHBOARD =================
@app.route("/admin")
@login_required
def dashboard():

    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()

    cur.execute("SELECT COUNT(*) FROM pending_scams")
    pending = cur.fetchone()[0]

    cur.execute("SELECT COUNT(*) FROM confirmed_scams")
    confirmed = cur.fetchone()[0]

    conn.close()

    return render_template("dashboard.html",pending=pending,confirmed=confirmed)

# ================= PENDING =================
@app.route("/admin/pending")
def admin_pending():
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()

    cur.execute("""
        SELECT message, COUNT(DISTINCT reporter) as reports
        FROM pending_scams
        GROUP BY message
        ORDER BY reports DESC
    """)

    data = cur.fetchall()
    conn.close()

    return render_template("pending.html", data=data)


# ================= CONFIRMED =================
@app.route("/admin/confirmed")
@login_required
def confirmed():

    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()

    cur.execute("SELECT message FROM confirmed_scams")
    data = cur.fetchall()
    conn.close()

    return render_template("confirmed.html",data=data)

# ================= APPROVE =================
@app.route("/admin/approve")
def approve_scam():
    try:
        msg = request.args.get("msg")

        if not msg:
            return redirect(url_for("admin_pending"))

        conn = sqlite3.connect(DB_PATH)
        cur = conn.cursor()

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

    except Exception as e:
        print("APPROVE ERROR:", e)

    return redirect(url_for("admin_pending"))



# ================= DELETE =================
@app.route("/admin/delete")
def delete_scam():
    try:
        msg = request.args.get("msg")

        if not msg:
            return redirect(url_for("admin_pending"))

        conn = sqlite3.connect(DB_PATH)
        cur = conn.cursor()

        cur.execute(
            "DELETE FROM pending_scams WHERE message=?",
            (msg,)
        )

        conn.commit()
        conn.close()

    except Exception as e:
        print("DELETE ERROR:", e)

    return redirect(url_for("admin_pending"))


# ================= EXPORT =================
@app.route("/admin/export")
@login_required
def export_csv():

    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("SELECT message FROM confirmed_scams")
    rows = cur.fetchall()
    conn.close()

    def generate():
        yield "Message\n"
        for r in rows:
            yield f"{r[0]}\n"

    return Response(generate(),
        mimetype="text/csv",
        headers={"Content-Disposition":"attachment;filename=scams.csv"})

# ================= SERVER =================
if __name__ == "__main__":
    socketio.run(
        app,
        host="0.0.0.0",
        port=int(os.environ.get("PORT", 8080)),
        allow_unsafe_werkzeug=True
    )

