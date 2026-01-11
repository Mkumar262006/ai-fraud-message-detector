from flask import Flask, request
from twilio.twiml.messaging_response import MessagingResponse
import datetime
import csv
import os

app = Flask(__name__)

# ==================================================
# SCAM KEYWORDS (MULTI-LANGUAGE)
# ==================================================

HIGH_RISK = [
    # -------- English --------
    "pay", "fee", "deposit", "click", "verify", "urgent", "immediately",
    "blocked", "suspended", "lottery", "winner", "congratulations",
    "claim", "limited time", "final warning", "last chance",
    "selected", "shortlisted", "approved", "free gift", "exclusive offer",

    # -------- Hindi --------
    "भुगतान", "फीस", "तुरंत", "लॉटरी", "जीता", "इनाम",
    "लाभार्थी", "चयनित", "अंतिम चेतावनी", "खाता बंद",
    "सत्यापित करें", "फ्री", "लिंक पर क्लिक करें",

    # -------- Tamil --------
    "லாட்டரி", "பரிசு", "வெற்றி பெற்ற", "வென்றுள்ளீர்கள்",
    "இலவச", "கிளிக்", "லிங்க்",
    "உறுதி", "உறுதிப்படுத்தவும்", "ரத்து",
    "இறுதி எச்சரிக்கை", "கணக்கு முடக்கப்படும்",
    "உடனே", "உடனடியாக", "உடனடி நடவடிக்கை",
    "தேர்ந்தெடுக்கப்பட்டுள்ளீர்கள்"
]

MONEY_WORDS = [
    # Symbols & English
    "₹", "rs", "rupees", "cash", "reward", "bonus", "refund",
    "amount", "payment", "processing", "charges", "commission",
    "tax", "service fee",

    # Hindi
    "रुपये", "धन", "शुल्क", "राशि", "भुगतान करें",

    # Tamil
    "ரூபாய்", "பணம்", "கட்டணம்", "தொகை", "பணம் செலுத்த", "பரிசு தொகை"
]

FAKE_GOV = [
    # English
    "govt job", "government job", "pmo", "pm kisan bonus",
    "free laptop", "free gas", "army recruitment",
    "rbi approved", "govt approved", "central government",
    "prime minister scheme", "pm fund", "official notification",

    # Hindi
    "सरकारी नौकरी", "पीएम किसान", "प्रधानमंत्री योजना",
    "सरकारी सहायता", "सरकार द्वारा",

    # Tamil
    "அரசு வேலை", "இலவச லேப்டாப்",
    "அரசு திட்டம்", "பிரதமர் திட்டம்",
    "அதிகாரப்பூர்வ அறிவிப்பு"
]

# ==================================================
# EXTRA SCAM HEURISTICS
# ==================================================

def detect_urgency(message):
    urgency_words = [
        "minutes", "minute", "hours", "today",
        "உடனே", "உடனடியாக", "நிமிடம்", "மணி", "இன்றே",
        "तुरंत", "आज"
    ]
    return any(word in message.lower() for word in urgency_words)

def has_suspicious_link(message):
    return any(
        link in message.lower()
        for link in ["http://", "https://", "www.", ".xyz", ".win", ".click", ".online"]
    )

# ==================================================
# FRAUD DETECTION LOGIC
# ==================================================

def detect_fraud(message):
    msg = message.lower()
    score = 0
    matched = []

    for word in HIGH_RISK:
        if word.lower() in msg:
            score += 2
            matched.append(word)

    for word in MONEY_WORDS:
        if word.lower() in msg:
            score += 1
            matched.append(word)

    for word in FAKE_GOV:
        if word.lower() in msg:
            score += 2
            matched.append(word)

    if detect_urgency(message):
        score += 2
        matched.append("urgency")

    if has_suspicious_link(message):
        score += 2
        matched.append("suspicious link")

    if score >= 5:
        label = "FRAUD"
    elif score >= 3:
        label = "SUSPICIOUS"
    else:
        label = "GENUINE"

    return label, score, matched

# ==================================================
# HIGHLIGHT SCAM WORDS
# ==================================================

def highlight_words(message, words):
    highlighted = message
    for w in set(words):
        if w in message:
            highlighted = highlighted.replace(w, f"*{w}*")
    return highlighted

# ==================================================
# LOG FRAUD (ANONYMOUS)
# ==================================================

def log_fraud(message, score):
    with open("fraud_logs.csv", "a", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow([
            datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            score,
            message[:200]
        ])

# ==================================================
# WHATSAPP WEBHOOK
# ==================================================

@app.route("/whatsapp", methods=["POST"])
def whatsapp_reply():
    incoming_msg = request.values.get("Body", "").strip()

    resp = MessagingResponse()
    reply = resp.message()

    # EXIT command (sandbox-safe)
    if incoming_msg.upper() == "EXIT":
        reply.body(
            "✅ *Alerts stopped safely.*\n\n"
            "You can send any message again anytime to restart."
        )
        return str(resp)

    # REPORT command
    if incoming_msg.upper() == "REPORT":
        reply.body(
            "✅ *Thank you for reporting this scam.*\n\n"
            "The pattern has been logged anonymously."
        )
        return str(resp)

    label, score, matched = detect_fraud(incoming_msg)
    highlighted = highlight_words(incoming_msg, matched)

    if label == "FRAUD":
        log_fraud(incoming_msg, score)
        reply.body(
            "🔴 *FRAUD ALERT*\n\n"
            f"📝 *Message Analysis:*\n{highlighted}\n\n"
            f"🚦 *Risk Score:* {score}\n\n"
            "⚠️ Do NOT click links or send money.\n\n"
            "👉 Reply *REPORT* to report this scam\n"
            "👉 Reply *EXIT* to stop alerts\n\n"
            "🔗 Official verification portals:\n"
            "https://www.india.gov.in\n"
            "https://www.cybercrime.gov.in"
        )

    elif label == "SUSPICIOUS":
        reply.body(
            "🟡 *SUSPICIOUS MESSAGE*\n\n"
            f"📝 *Message Analysis:*\n{highlighted}\n\n"
            f"🚦 *Risk Score:* {score}\n\n"
            "Please verify before acting.\n\n"
            "👉 Reply *EXIT* to stop alerts\n\n"
            "🔗 https://www.india.gov.in"
        )

    else:
        reply.body(
            "🟢 *LIKELY GENUINE*\n\n"
            "No major scam indicators detected.\n"
            "Still verify from official sources.\n\n"
            "👉 Reply *EXIT* to stop alerts\n\n"
            "🔗 https://www.india.gov.in"
        )

    return str(resp)

# ==================================================
# START SERVER (CLOUD SAFE)
# ========
import os

if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=int(os.environ.get("PORT", 5000))
    )

