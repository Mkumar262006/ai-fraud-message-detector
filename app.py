import streamlit as st

# ===============================
# KEYWORD LISTS
# ===============================
HIGH_RISK = [
    "pay", "fee", "deposit", "processing fee", "registration fee",
    "click", "link", "verify", "urgent", "immediately",
    "blocked", "suspended", "deactivated",
    "lottery", "winner", "congratulations"
]

MONEY_WORDS = [
    "₹", "rs", "rupees", "cash", "reward", "bonus", "refund"
]

FAKE_GOV = [
    "pmo", "govt job", "government job",
    "pm kisan bonus", "free laptop",
    "free gas", "army recruitment"
]

# ===============================
# FRAUD DETECTION FUNCTION
# ===============================
def detect_fraud(message):
    message = message.lower()
    score = 0
    reasons = []

    for word in HIGH_RISK:
        if word in message:
            score += 2
            reasons.append(f"High-risk keyword detected: '{word}'")

    for word in MONEY_WORDS:
        if word in message:
            score += 1
            reasons.append(f"Money-related keyword detected: '{word}'")

    for word in FAKE_GOV:
        if word in message:
            score += 2
            reasons.append(f"Suspicious government claim: '{word}'")

    if score >= 4:
        return "Fraud", score, reasons
    elif score >= 2:
        return "Suspicious", score, reasons
    else:
        return "Genuine", score, reasons

# ===============================
# STREAMLIT UI
# ===============================
st.set_page_config(page_title="Fraud Message Detector", layout="centered")

st.title("🔍 AI Fake Government Scheme & Job Fraud Detector")
st.caption("Explainable AI using keyword-based detection")

st.markdown("---")

user_message = st.text_area(
    "📩 Paste WhatsApp / SMS message here:",
    height=150
)

if st.button("Analyze Message"):
    if user_message.strip() == "":
        st.warning("Please enter a message.")
    else:
        label, score, reasons = detect_fraud(user_message)

        if label == "Fraud":
            st.error(f"🔴 FRAUD DETECTED (Score: {score})")
        elif label == "Suspicious":
            st.warning(f"🟡 SUSPICIOUS MESSAGE (Score: {score})")
        else:
            st.success(f"🟢 LIKELY GENUINE (Score: {score})")

        st.markdown("### 🔎 Reasons:")
        for r in reasons:
            st.write("•", r)

st.markdown("---")
st.caption("⚠️ This tool provides awareness only. Always verify from official sources.")
