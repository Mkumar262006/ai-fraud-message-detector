import streamlit as st
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.naive_bayes import MultinomialNB

# =====================================
# DATASET (Synthetic but realistic)
# =====================================
data = [
    ("Congratulations! You have won ₹10,000. Click link now", "Fraud"),
    ("Govt job offer. Pay ₹2000 registration fee today", "Fraud"),
    ("Urgent! Your bank account will be blocked today", "Fraud"),
    ("Free laptop scheme apply immediately", "Fraud"),
    ("Verify Aadhaar immediately to receive benefits", "Fraud"),
    ("PM Kisan installment credited to your account", "Genuine"),
    ("Electricity bill reminder from TNEB", "Genuine"),
    ("Scholarship amount credited successfully", "Genuine"),
    ("Railway exam results announced on official website", "Genuine"),
]

df = pd.DataFrame(data, columns=["message", "label"])

# =====================================
# MODEL TRAINING
# =====================================
vectorizer = TfidfVectorizer(stop_words="english")
X = vectorizer.fit_transform(df["message"])
y = df["label"]

model = MultinomialNB()
model.fit(X, y)

# =====================================
# STREAMLIT UI
# =====================================
st.set_page_config(page_title="Fraud Message Detector", layout="centered")

st.title("🔍 AI Fake Government Scheme & Job Fraud Detector")
st.caption("Helping citizens identify scam messages using AI")

st.markdown("---")

user_message = st.text_area(
    "📩 Paste WhatsApp / SMS message here:",
    height=150,
    placeholder="Example: Congratulations! You are selected for govt job. Pay ₹2000 now."
)

if st.button("Analyze Message"):
    if user_message.strip() == "":
        st.warning("Please enter a message to analyze.")
    else:
        message_vector = vectorizer.transform([user_message])
        prediction = model.predict(message_vector)[0]

        if prediction == "Fraud":
            st.error("🔴 FRAUD DETECTED")
            st.write("⚠️ This message contains common scam patterns such as urgency or money requests.")
        else:
            st.success("🟢 LIKELY GENUINE")
            st.write("✅ No major fraud indicators found.")

st.markdown("---")
st.caption("⚠️ This tool provides awareness support only. Always verify with official sources.")
