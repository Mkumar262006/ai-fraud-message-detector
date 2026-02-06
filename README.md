#  Harm-Focused Misinformation Risk Analysis System

## Overview
This project is an **AI-based harm analysis system** designed to help people in India **assess the real-world risk of messages** received via **WhatsApp and SMS**.

Instead of treating misinformation as simply *true or false*, the system evaluates the **risk of harm** a message may cause — such as financial loss, panic, emotional manipulation, or unsafe actions.

The solution works directly on platforms people already use and supports **English, Tamil, and Hindi**, making it suitable for grassroots adoption.

---

##  Problem Statement
In India, misinformation often spreads through private channels like WhatsApp and SMS.  
Many harmful messages are not outright false but still cause damage by:

- Creating panic or urgency
- Manipulating emotions
- Triggering unsafe financial or personal actions
- Exploiting language and trust barriers

Existing solutions focus on fact-checking, but users need **immediate, contextual guidance** about **potential harm**, not delayed verification.

---

##  Solution Summary
We built a **Harm-Focused Misinformation Risk Analysis System** that:

- Analyzes message content for behavioral risk signals
- Computes a **Harm Index (0–10)** instead of binary truth labels
- Classifies messages as **LOW RISK**, **CAUTION**, or **FRAUD**
- Explains *why* a message is risky in simple language
- Responds in the user’s preferred language
- Uses community reporting and admin review for fairness

No additional app installation is required.

---

##  Core Capabilities

###  Supported Platforms
- any sms or whatsapp msg can sent to WhatsApp (via Twilio)

---

###  Multilingual Support
| User Language | Bot Response |
|---------------|--------------|
| Tamil | Tamil + English |
| Hindi | Hindi + English |
| English | English |

---

###  Harm-Based Detection Logic
The system analyzes **free-text messages** using multiple risk signals:

- Emotional manipulation (fear, sympathy, urgency)
- Financial requests (money, UPI, donations)
- Bank or authority impersonation
- Requests for sensitive data (OTP, account details)
- Urgent calls to action
- Suspicious links or contact numbers

These signals are combined to compute a **Harm Index**, which estimates potential real-world impact.

---

###  Ethical Classification
| Label | Meaning |
|------|--------|
| 🟢 LOW RISK | No strong harmful signals detected |
| 🟠 CAUTION | Suspicious or unverified, needs user attention |
| 🔴 FRAUD | High likelihood of harmful intent |

The system avoids false accusations and clearly explains its reasoning.

---

###  Community Reporting (REPORT)
- Users can type **REPORT** to report the previous message
- Reports are stored in a **pending review list**
- A message is confirmed as a scam only after **multiple independent reports**
- Prevents malicious or false reporting
- Ensures human oversight

---

###  Admin Moderation Panel
Admins can:
- View pending reported messages
- See report counts
- Approve confirmed scam patterns
- Delete false or misleading reports

This ensures transparency and responsible AI behavior.

---

###  Government Guidance & Safety
When users report scams, the system provides official complaint resources:

- 🇮🇳 Cybercrime Portal: https://cybercrime.gov.in  
-  RBI Banking Complaints: https://cms.rbi.org.in  
-  Telecom & Spam Reporting: https://sancharsaathi.gov.in  

This connects AI insights with real-world action.

---

##  Data Design

###  pending_scams
- Stores community-reported messages
- Under human review
- Requires multiple reports before confirmation

###  confirmed_scams
- Verified harmful message patterns
- Used to improve future detection

---

##  Tech Stack
- Python
- Flask
- Twilio (WhatsApp & SMS)
- SQLite (prototype database)
- Scikit-learn (TF-IDF & similarity)
- Railway (Cloud Deployment)
- GitHub (Version Control)

---

##  System Workflow
1. User sends or forwards a message
2. Language is detected
3. Harm signals are extracted
4. Harm Index is calculated
5. Risk level and explanation are returned
6. User may report suspicious messages
7. Admin reviews and confirms patterns

---

##  Ethics, Safety & Responsibility
- The Harm Index is presented as **guidance**, not absolute truth
- No automatic blocking or censorship
- Human-in-the-loop moderation
- Community validation before learning
- External verification encouraged

---

##  Impact
- Helps prevent financial fraud
- Reduces panic and emotional exploitation
- Supports non-technical and rural users
- Encourages responsible digital behavior
- Aligns with Digital India and cyber safety initiatives

---

##  Simple Explanation
> “This system warns people when a message might be dangerous, before they lose money or act in panic.”

---


##  How to Start Using the Prototype (WhatsApp)

Before using the scam detection system, you need to connect to the WhatsApp bot.

1️⃣ **Message to this WhatsApp number**  
```bash
+1 415 523 8886
```
2️⃣ **Open WhatsApp and send this message:**  
```bash
   join factor-sang
```
3️⃣ Once you receive the confirmation message, **you are connected** to the system.

4️⃣ Now you can start sending:
- Suspicious messages
- Bank alerts
- OTP or payment requests
- Cybercrime or online safety questions

The system will instantly analyze your message and guide you safely.

---

### No app installation required. Works directly inside WhatsApp.

##  How The Prototype Works 

This prototype works as a real-time WhatsApp-based AI assistant that helps users identify scam, fraud, and harmful messages using ethical, harm-focused reasoning.

###  Step 1: User Sends a Message
The user forwards or types any message received on WhatsApp (SMS-style or chat text) to the bot.

Examples:
- Bank alerts
- OTP requests
- Financial help messages
- Investment offers
- Cybercrime questions

---

###  Step 2: Language Detection
The system automatically detects the message language:
- Tamil
- Hindi
- English

The response language is adjusted accordingly.

---

###  Step 3: Intent Identification
The system checks the message intent in the following order:
1. Scam or fraud content  
2. Cyber awareness or cybersecurity question  
3. Normal greeting or polite exit  

This ensures natural conversation and avoids unnecessary warnings.

---

###  Step 4: Harm-Focused Risk Analysis
Instead of simple true/false classification, the system calculates a **Harm Index (0–10)** using:
- Urgency or panic language
- Emotional manipulation
- Requests for money or personal data
- Bank or government impersonation
- Presence of phone numbers, UPI IDs, or links

Each detected risk factor contributes to the final score.

---

###  Step 5: Risk Classification
Based on the Harm Index:
- **LOW RISK** – No strong harmful indicators
- **CAUTION** – Suspicious or potentially misleading
- **FRAUD** – High likelihood of scam or harm

Clear reasons are shown to the user for transparency.

---

###  Step 6: Multilingual Explanation
The system explains:
- Why the message is risky
- What action the user should take

Responses are shown in:
- Tamil + English
- Hindi + English
- English only

---

###  Step 7: Community Reporting (Optional)
If the user types **REPORT**:
- The previous message is saved in a pending review list
- The system waits for multiple independent reports
- Only after sufficient community confirmation is it learned as a scam

This prevents false reporting and misuse.

---

###  Step 8: Official Guidance
For confirmed or high-risk cases, the system provides links to official Indian portals:
- Cybercrime reporting
- Banking complaint systems
- Telecom spam reporting

This bridges AI detection with real-world action.

---

###  Step 9: Admin Moderation Dashboard
Admins can:
- View pending scam reports
- Approve or reject reports
- Review confirmed scam patterns
- Export verified scam data

All learning remains human-supervised and ethical.

---

###  Step 10: Continuous Learning
The system improves over time by:
- Learning from confirmed scam patterns
- Preventing learning from single or malicious reports
- Maintaining explainability and user trust

##  Domain & Category
  . Primary Domain: Social Good

  . Secondary Domain: Applied Engineering

  . Use Case: Harm-Focused Misinformation & Scam Prevention

##  Conclusion

This project demonstrates how reasoning-based AI, combined with human oversight and ethical design, can reduce real-world harm caused by misinformation.
It prioritizes impact, clarity, and responsibility over black-box automation.
