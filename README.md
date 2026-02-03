# 🛡️ AI-Based WhatsApp Scam Detection System

## 📌 Overview
This project is a **WhatsApp-based AI system** designed to help people in India **identify scam and fraud messages** in real time.  
It works directly on WhatsApp, supports **Tamil, Hindi, and English**, and focuses on **social good and digital safety**.

The system detects:
- Bank impersonation scams
- OTP fraud
- Fake KYC alerts
- Investment & lottery scams
- Suspicious financial help requests

It also allows users to **report scams safely** and guides them to **official government complaint portals**.

---

## 🎯 Problem Statement
Millions of people receive fraudulent messages every day through WhatsApp and SMS.  
Many users:
- Trust messages claiming to be from banks
- Are not comfortable with English
- Lose money before realizing it is a scam

There is a need for a **simple, accessible, and ethical AI solution** that works on platforms people already use.

---

## 💡 Solution
We built a **WhatsApp-based AI bot** that:
- Analyzes incoming messages
- Classifies them as **GENUINE**, **CAUTION**, or **FRAUD**
- Responds in the user’s language
- Avoids false accusations
- Learns scam patterns safely through community reporting

No app installation is required.

---

## 🧠 Key Features

### 🔹 Multilingual Support
| User Language | Bot Response |
|--------------|--------------|
| Tamil | Tamil + English |
| Hindi | Hindi + English |
| English | English only |

---

### 🔹 Scam Detection Logic
The system uses **three layers of intelligence**:

1. **Rule-based Detection**
   - Scam keywords
   - Bank impersonation
   - Urgency and threat language
   - Requests for sensitive data

2. **Special Safety Rules**
   - Detects text-only bank scams (no links required)
   - Flags unverified financial help requests as **CAUTION**
   - Distinguishes OTP warnings from OTP requests

3. **NLP Similarity Matching**
   - Compares new messages with known scam patterns
   - Uses TF-IDF and cosine similarity

---

### 🔹 Ethical Classification
| Label | Meaning |
|------|--------|
| 🟢 GENUINE | No strong scam indicators |
| 🟠 CAUTION | Suspicious but not confirmed |
| 🔴 FRAUD | High confidence scam |

This prevents false accusations and panic.

---

### 🔹 Community Reporting (REPORT)
- Users can type **REPORT** to report the **previous message**
- Reports are stored in a **pending list**
- A message is learned as a scam **only after 3 different users report it**
- Prevents false or malicious reporting

---

### 🔹 Government Complaint Guidance
When a user reports a scam, the system shares official reporting links:

- 🇮🇳 Cybercrime Portal  
  https://cybercrime.gov.in
- 🏦 RBI Banking Complaints  
  https://cms.rbi.org.in
- 📱 TRAI Spam Reporting  
  https://sancharsaathi.gov.in

This connects AI detection with **real-world action**.

---

## 🗂️ Database Design

### 📌 pending_scams
- User-reported messages
- Not yet confirmed
- Requires multiple independent reports

### 📌 confirmed_scams
- Verified scam patterns
- Used for future detection

---

## 🧑‍💻 Admin Dashboard
Endpoint:
