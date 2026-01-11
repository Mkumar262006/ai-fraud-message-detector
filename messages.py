from flask import Flask, request
from twilio.twiml.messaging_response import MessagingResponse
import datetime
import csv

app = Flask(__name__)

# ======================================
# KEYWORDS
# ======================================
HIGH_RISK = [
    "pay", "fee", "deposit", "click", "verify", "urgent", "immediately",
    "blocked", "suspended", "lottery", "winner", "Congratulations",
    "भुगतान", "फीस", "तुरंत", "लॉटरी",
    "உடனடி", "பணம்", "கட்டணம்", "வெற்றி"
]

MONEY_WORDS = [
    "₹", "rs", "rupees", "cash", "reward", "bonus", "refund",
    "रुपये", "धन",
    "ரூபாய்", "பரிசு"
]

FAKE_GOV = [
    "govt job", "government job", "pmo", "pm kisan bonus",
    "free laptop", "free gas", "army recruitment",
    "सरकारी नौकरी", "पीएम किसान",
    "அரசு வேலை", "இலவச லேப்டாப்"
]

# ======================================
# FRAUD LOGIC
# ======================================
def detect_fraud(message):
    msg = message.lower()
    score = 0
    matched = []

    for word in HIGH_RISK:
        if word in msg:
            score += 2
            matched.append(word)

    for word in MONEY_WORDS:
        if word in msg:
            score += 1
            matched.append(word)

    for word in FAKE_GOV:
        if word in msg:
            score += 2
            matched.append(word)

    if score >= 5:
        label = "FRAUD"
    elif score >= 3:
        label = "SUSPICIOUS"
    else:
        label = "GENUINE"

    return label, score, matched

# ======================================
# LOG FRAUD ANONYMOUSLY
# ======================================
def log_fraud(message, score):
    with open("fraud_logs.csv", "a", newline="", encoding="utf-8") as file:
        writer = csv.writer(file)
        writer.writerow([
            datetime.datetime.now(),
            score,
            message[:200]   # store only first 200 chars (privacy-safe)
        ])

# ======================================
# HIGHLIGHT WORDS
# ======================================
def highlight_words(message, words):
    highlighted = message
    for w in set(words):
        highlighted = highlighted.replace(w, f"*{w}*")
    return highlighted

# ======================================
# WHATSAPP WEBHOOK
# ======================================
@app.route("/whatsapp", methods=["POST"])
def whatsapp_reply():
    incoming_msg = request.values.get("Body", "").strip()

    resp = MessagingResponse()
    reply = resp.message()

    # ------------------------------
    # EXIT command (SAFE replacement for STOP)
    # ------------------------------
    if incoming_msg.upper() == "EXIT":
        reply.body(
            "✅ *You have exited scam alerts.*\n\n"
            "You will no longer receive automated responses.\n"
            "You can send any message again anytime to restart."
        )
        return str(resp)

    # ------------------------------
    # REPORT command
    # ------------------------------
    if incoming_msg.upper() == "REPORT":
        reply.body(
            "✅ *Thank you for reporting this scam.*\n\n"
            "The pattern has been logged anonymously.\n"
            "Your phone number is NOT stored."
        )
        return str(resp)

    # ------------------------------
    # FRAUD DETECTION
    # ------------------------------
    label, score, matched = detect_fraud(incoming_msg)
    highlighted_msg = highlight_words(incoming_msg, matched)

    if label == "FRAUD":
        log_fraud(incoming_msg, score)
        reply.body(
            "🔴 *FRAUD ALERT*\n\n"
            f"📝 *Message Analysis:*\n{highlighted_msg}\n\n"
            f"🚦 *Risk Score:* {score}\n\n"
            "⚠️ Do NOT click links or send money.\n\n"
            "👉 Reply *REPORT* to report this scam\n"
            "👉 Reply *EXIT* to stop alerts\n\n"
            "🔗 Verify only on official portals:\n"
            "https://www.india.gov.in\n"
            "https://www.cybercrime.gov.in"
        )

    elif label == "SUSPICIOUS":
        reply.body(
            "🟡 *SUSPICIOUS MESSAGE*\n\n"
            f"📝 *Message Analysis:*\n{highlighted_msg}\n\n"
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


import os

if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=int(os.environ.get("PORT", 5000))
    )


