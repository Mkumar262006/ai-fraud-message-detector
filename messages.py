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

DB_PATH = "scam_messages.db"

def init_db():
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS scam_texts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            message TEXT UNIQUE
        )
    """)
    conn.commit()
    conn.close()

init_db()

# ==================================================
# LANGUAGE DETECTION (STRICT)
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
# NLP SIMILARITY (INTERNAL ONLY)
# ==================================================

SIMILARITY_HIGH = 0.65
SIMILARITY_MEDIUM = 0.40

def get_scam_messages():
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("SELECT message FROM scam_texts")
    rows = cur.fetchall()
    conn.close()
    return [r[0] for r in rows]

def save_scam_message(msg):
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute(
        "INSERT OR IGNORE INTO scam_texts(message) VALUES (?)",
        (msg,)
    )
    conn.commit()
    conn.close()

def compute_similarity(new_msg):
    scams = get_scam_messages()
    if not scams:
        return 0.0
    corpus = scams + [new_msg]
    tfidf = TfidfVectorizer().fit_transform(corpus)
    scores = cosine_similarity(tfidf[-1], tfidf[:-1])
    return max(scores[0])

# ==================================================
# RULE-BASED SCORING
# ==================================================

SCAM_WORDS = [
    "lottery", "winner", "prize", "claim", "urgent", "click",
    "₹", "rs",
    "லாட்டரி", "பரிசு",
    "लॉटरी", "इनाम"
]

def rule_score(msg):
    score = 0
    for w in SCAM_WORDS:
        if w.lower() in msg.lower():
            score += 1
    return score

# ==================================================
# ADMIN DASHBOARD (INTERNAL VIEW)
# ==================================================

@app.route("/admin/dashboard")
def admin_dashboard():
    scams = get_scam_messages()
    return {
        "total_scam_samples": len(scams),
        "recent_samples": scams[-5:]
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
                "✅ அறிவிப்புகள் நிறுத்தப்பட்டன.\n"
                "மீண்டும் எந்த செய்தியையும் அனுப்பலாம்.\n\n"
                "✅ Alerts stopped safely.\n"
                "You can message again anytime."
            )
        elif lang == "HI":
            reply.body(
                "✅ अलर्ट रोक दिए गए हैं।\n"
                "आप फिर से कोई भी संदेश भेज सकते हैं।\n\n"
                "✅ Alerts stopped safely.\n"
                "You can message again anytime."
            )
        else:
            reply.body(
                "✅ Alerts stopped safely.\n"
                "You can message again anytime."
            )
        return str(resp)

    # ---------------- REPORT ----------------
    if incoming.upper() == "REPORT":
        if user in last_message_cache:
            last_msg, last_label = last_message_cache[user]
            if last_label == "FRAUD":
                save_scam_message(last_msg)
                reply.body(
                    "✅ Scam reported.\n"
                    "This helps protect others."
                )
            else:
                reply.body(
                    "⚠️ Report noted.\n"
                    "We monitor similar patterns over time."
                )
        else:
            reply.body("⚠️ No message to report.")
        return str(resp)

    # ---------------- DETECTION ----------------
    r_score = rule_score(incoming)
    sim_score = compute_similarity(incoming)  # internal only

    if r_score >= 3 or sim_score >= SIMILARITY_HIGH:
        label = "FRAUD"
    elif r_score == 2:
        label = "SUSPICIOUS"
    elif sim_score >= SIMILARITY_MEDIUM:
        label = "CAUTION"
    else:
        label = "GENUINE"

    last_message_cache[user] = (incoming, label)

    # ---------------- RESPONSE (LANGUAGE-AWARE) ----------------
    if label == "FRAUD":
        if lang == "TA":
            reply.body(
                "🔴 மோசடி எச்சரிக்கை!\n"
                "இந்த செய்தி ஆபத்தானது.\n"
                "பணம் அல்லது விவரங்களை பகிர வேண்டாம்.\n\n"
                "🔴 FRAUD ALERT\n"
                "This message shows strong scam indicators.\n"
                "Do NOT share details or click links."
            )
        elif lang == "HI":
            reply.body(
                "🔴 धोखाधड़ी चेतावनी!\n"
                "यह संदेश खतरनाक हो सकता है।\n"
                "पैसे या व्यक्तिगत जानकारी साझा न करें।\n\n"
                "🔴 FRAUD ALERT\n"
                "This message shows strong scam indicators.\n"
                "Do NOT share details or click links."
            )
        else:
            reply.body(
                "🔴 FRAUD ALERT\n\n"
                "This message shows strong scam indicators.\n"
                "Do NOT share details or click links."
            )

    elif label == "SUSPICIOUS":
        if lang == "TA":
            reply.body(
                "🟡 சந்தேகமான செய்தி\n"
                "சரிபார்த்த பிறகு மட்டும் செயல்படுங்கள்.\n\n"
                "🟡 SUSPICIOUS MESSAGE\n"
                "Please verify before acting."
            )
        elif lang == "HI":
            reply.body(
                "🟡 संदिग्ध संदेश\n"
                "कार्य करने से पहले सत्यापित करें।\n\n"
                "🟡 SUSPICIOUS MESSAGE\n"
                "Please verify before acting."
            )
        else:
            reply.body(
                "🟡 SUSPICIOUS MESSAGE\n"
                "Please verify before acting."
            )

    elif label == "CAUTION":
        if lang == "TA":
            reply.body(
                "🟠 எச்சரிக்கை\n"
                "இந்த செய்தியை முழுமையாக சரிபார்க்க முடியவில்லை.\n"
                "தனிப்பட்ட தகவல்களை பகிர வேண்டாம்.\n\n"
                "🟠 CAUTION\n"
                "We cannot fully verify this message.\n"
                "Do NOT share personal details."
            )
        elif lang == "HI":
            reply.body(
                "🟠 सावधानी\n"
                "इस संदेश की पूरी तरह पुष्टि नहीं हो सकी।\n"
                "व्यक्तिगत जानकारी साझा न करें।\n\n"
                "🟠 CAUTION\n"
                "We cannot fully verify this message.\n"
                "Do NOT share personal details."
            )
        else:
            reply.body(
                "🟠 CAUTION\n\n"
                "We cannot fully verify this message.\n"
                "Do NOT share personal details."
            )

    else:
        if lang == "TA":
            reply.body(
                "🟢 இந்த செய்தி பாதுகாப்பாக இருக்கலாம்.\n\n"
                "🟢 LIKELY GENUINE\n"
                "No strong scam indicators detected."
            )
        elif lang == "HI":
            reply.body(
                "🟢 यह संदेश सुरक्षित लग रहा है।\n\n"
                "🟢 LIKELY GENUINE\n"
                "No strong scam indicators detected."
            )
        else:
            reply.body(
                "🟢 LIKELY GENUINE\n"
                "No strong scam indicators detected."
            )

    return str(resp)

# ==================================================
# SERVER
# ==================================================

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 8080)))
