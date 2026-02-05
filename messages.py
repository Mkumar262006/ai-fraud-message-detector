from flask import Flask, request, render_template, redirect, Response
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user
from flask_socketio import SocketIO
from twilio.twiml.messaging_response import MessagingResponse
from openai import OpenAI
import sqlite3, os, re, datetime
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity

# ================= OPENAI =================
client = OpenAI(api_key="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")

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
    score = sum(w in t for w in SCAM_WORDS)
    reasons = [w for w in SCAM_WORDS if w in t]

    if re.search(URL_PATTERN,t):
        score += 2
        reasons.append("External Link")

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

# ================= AI MEMORY =================
ai_memory = {}

# ================= MULTILINGUAL AI CHAT =================
def ai_chat(user, message, lang):

    if user not in ai_memory:
        ai_memory[user] = []

    ai_memory[user].append({"role":"user","content":message})

    language_prompt = {
        "TA": "Respond ONLY in Tamil.",
        "HI": "Respond ONLY in Hindi.",
        "EN": "Respond ONLY in English."
    }

    response = client.chat.completions.create(
        model="gpt-4o-mini",
        messages=[
            {
                "role":"system",
                "content":
                "You are a cyber safety assistant helping users avoid scams.\n"
                + language_prompt.get(lang,"Respond in English.")
            }
        ] + ai_memory[user][-6:]
    )

    reply = response.choices[0].message.content
    ai_memory[user].append({"role":"assistant","content":reply})

    return reply

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
            msg,_ = last_seen[user]
            save_pending(msg,user)
            promote_if_trusted(msg)
            broadcast_stats()

            if lang == "TA":
                reply.body("புகார் சேமிக்கப்பட்டது")
            elif lang == "HI":
                reply.body("रिपोर्ट सहेजी गई")
            else:
                reply.body("Report saved")

        return str(resp)

    # ===== AI ASSISTANT =====
    if not looks_like_scam(incoming):

        ai_response = ai_chat(user, incoming, lang)
        reply.body(ai_response)
        return str(resp)

    # ===== SCAM DETECTION =====
    score,reasons = calculate_harm(incoming)

    if similarity(incoming, fetch("confirmed_scams")) > SIM_THRESHOLD:
        score = max(score,8)

    label = classify(score)
    last_seen[user] = (incoming,label)

    reply.body(scam_reply(lang, score, label, reasons))
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
@login_required
def pending():

    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()

    cur.execute("""
        SELECT message, COUNT(DISTINCT reporter)
        FROM pending_scams
        GROUP BY message
    """)

    data = cur.fetchall()
    conn.close()

    return render_template("pending.html",data=data)

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
@login_required
def approve():

    msg = request.args.get("msg")

    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()

    cur.execute("INSERT OR IGNORE INTO confirmed_scams(message) VALUES (?)",(msg,))
    cur.execute("DELETE FROM pending_scams WHERE message=?",(msg,))
    conn.commit()
    conn.close()

    broadcast_stats()
    return redirect("/admin/pending")

# ================= DELETE =================
@app.route("/admin/delete")
@login_required
def delete():

    msg = request.args.get("msg")

    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()

    cur.execute("DELETE FROM pending_scams WHERE message=?",(msg,))
    conn.commit()
    conn.close()

    broadcast_stats()
    return redirect("/admin/pending")

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
    socketio.run(app, host="0.0.0.0", port=int(os.environ.get("PORT", 8080)))
