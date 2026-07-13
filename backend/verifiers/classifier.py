import os
import re
import math
import json
import requests
import collections
from verifiers.domain_verifier import OFFICIAL_DOMAINS, extract_domain

# --- Local TF-IDF NLP Model Resources ---
CORPUS = {
    "Job Scam": [
        "Earn rupees daily part-time job from home by liking videos and joining telegram task commission.",
        "WFH data entry job opportunity daily payout. Pay registration fee to activate account and start task commissions.",
        "Part time wfh job recruit. Youtube subscribe task daily income extra salary. No experience required telegram task.",
        "Urgent hiring for online review task. Make money daily from home. Join telegram for commissions details."
    ],
    "Lottery / Prize Scam": [
        "Congratulations! You won KBC lottery draw cash prize. Click link to claim reward and pay processing fee.",
        "You have won a free gift card prize. Verify netbanking account and claim reward now.",
        "KBC lucky draw winner crores jackpot cash prize. Send bank account details and pay registration fee to receive reward.",
        "Selected winner for lucky draw rewards point. Claim gift voucher immediately by verifying credentials."
    ],
    "Fake Bank Alert": [
        "Alert: Your netbanking account blocked suspended. Update KYC immediately or verify pan card details link.",
        "Debit card suspended blocked due to pending KYC update. Login to verify netbanking account credentials.",
        "SBI HDFC account lock alert. Unauthorized transaction noticed. Click link immediately to verify details.",
        "Urgent: Pan card mismatch alert. Update account details and verify kyc to reactivate blocked netbanking."
    ],
    "Payment / UPI Scam": [
        "PhonePe GPay cashback refund pending payment. Click link to receive money and scan QR code.",
        "Receive refund money phonepe gpay upi. Scan QR code to accept pending cash transfer.",
        "UPI payment refund request pending. Scan QR code and send screenshot to double your money.",
        "Pending cash reward of rupees. Click link to scan upi pay address and verify transaction."
    ],
    "Safe": [
        "Do cross-check that you have applied to all of today’s job openings. If not, apply as soon as possible!",
        "Cognizant careers off-campus hiring opportunities. Apply on official portal for software developer positions.",
        "IKEA and Uber recruitment drive software engineer roles. Official links are updated on careers website.",
        "Your transaction at HDFC Bank was successful. Thank you for banking with us. Report issues to official support.",
        "Security reminder: Never share your OTP, password, or PIN with anyone. HDFC Bank will never ask for credentials.",
        "Meeting scheduled for today at 3 PM. Please review the attached document before the call."
    ]
}

def tokenize(text: str):
    return [w for w in re.findall(r'[a-z0-9]+', text.lower()) if len(w) > 2]

# Compute vocabulary and IDFs
vocab = set()
for cat, docs in CORPUS.items():
    for doc in docs:
        vocab.update(tokenize(doc))
vocab = sorted(list(vocab))

doc_count = sum(len(docs) for docs in CORPUS.values())
doc_freqs = collections.defaultdict(int)
for cat, docs in CORPUS.items():
    for doc in docs:
        words_in_doc = set(tokenize(doc))
        for w in words_in_doc:
            doc_freqs[w] += 1

idfs = {}
for w in vocab:
    idfs[w] = math.log((1 + doc_count) / (1 + doc_freqs[w]))

def get_tfidf_vector(text: str):
    tokens = tokenize(text)
    if not tokens:
        return {}
    tf = collections.defaultdict(int)
    for t in tokens:
        tf[t] += 1
    
    vec = {}
    for w in tokens:
        if w in idfs:
            vec[w] = (tf[w] / len(tokens)) * idfs[w]
    return vec

category_vectors = {}
for cat, docs in CORPUS.items():
    cat_vecs = []
    for doc in docs:
        cat_vecs.append(get_tfidf_vector(doc))
    
    avg_vec = collections.defaultdict(float)
    for vec in cat_vecs:
        for w, val in vec.items():
            avg_vec[w] += val
    for w in avg_vec:
        avg_vec[w] /= len(docs)
    category_vectors[cat] = dict(avg_vec)

def cosine_similarity(vec1: dict, vec2: dict) -> float:
    dot = 0.0
    for w, val in vec1.items():
        if w in vec2:
            dot += val * vec2[w]
            
    mag1 = math.sqrt(sum(val**2 for val in vec1.values()))
    mag2 = math.sqrt(sum(val**2 for val in vec2.values()))
    
    if mag1 == 0.0 or mag2 == 0.0:
        return 0.0
        
    return dot / (mag1 * mag2)

# --- Standard Rulesets ---
TOPICS = {
    "Job": [
        "job", "wfh", "work from home", "hiring", "vacancy", "career", "careers", 
        "recruitment", "salary", "income", "part-time", "part time"
    ],
    "Lottery": [
        "lottery", "lucky draw", "prize", "won", "kbc", "crores", "gift card", 
        "reward", "rewards", "jackpot", "winner", "vouchers", "voucher"
    ],
    "Bank": [
        "bank", "account", "kyc", "pan", "card", "netbanking", "debit", "credit"
    ],
    "Payment": [
        "refund", "payment", "receive money", "gpay", "phonepe", "upi", "paytm"
    ]
}

TRIGGERS = {
    "Fee": [
        "fee", "fees", "deposit", "charge", "charges", "registration", 
        "processing", "activation", "pay money", "security deposit", "application fee"
    ],
    "Task": [
        "task", "tasks", "like", "subscribe", "youtube", "telegram", 
        "google map", "review", "commission", "commissions", "earn money"
    ],
    "Credential": [
        "otp", "pin", "password", "blocked", "suspended", "lock", 
        "unauthorized", "update", "verify", "credentials", "login"
    ]
}

def contains_unofficial_url(text: str) -> bool:
    urls = re.findall(r'https?://[^\s]+', text)
    if not urls:
        return False
    
    for url in urls:
        clean_url = url.rstrip('.,…')
        domain = extract_domain(clean_url)
        if not domain:
            continue
            
        is_official = False
        for brand, official_list in OFFICIAL_DOMAINS.items():
            for off_dom in official_list:
                if domain == off_dom or domain.endswith("." + off_dom):
                    is_official = True
                    break
            if is_official:
                break
        
        if not is_official:
            return True
            
    return False

PUBLIC_EMAIL_DOMAINS = [
    "gmail.com", "yahoo.com", "hotmail.com", "outlook.com", "aol.com", "icloud.com", "mail.com"
]

def check_sender_mismatch(sender_name: str, sender_email: str) -> dict:
    if not sender_name or not sender_email:
        return {"safe": True, "verdict": "SAFE", "reason": ""}

    sender_name_lower = sender_name.lower()
    sender_email_lower = sender_email.lower()
    
    domain = ""
    if "@" in sender_email_lower:
        domain = sender_email_lower.split("@")[1]

    for brand, official_list in OFFICIAL_DOMAINS.items():
        is_claiming_brand = brand in sender_name_lower
        if not is_claiming_brand:
            continue
            
        is_official = False
        for off_dom in official_list:
            if domain == off_dom or domain.endswith("." + off_dom):
                is_official = True
                break
        
        if not is_official:
            is_public_domain = domain in PUBLIC_EMAIL_DOMAINS
            reason = ""
            if is_public_domain:
                reason = f"Identity Spoofing: Sender display name '{sender_name}' claims to be official brand '{brand.upper()}', but the email originates from a public address domain (@{domain}) rather than an official domain."
            else:
                reason = f"Identity Spoofing: Sender display name '{sender_name}' claims to be official brand '{brand.upper()}', but email domain '@{domain}' is not in the verified domains list for this institution."
                
            return {
                "safe": False,
                "verdict": "MALICIOUS",
                "reason": reason,
                "category": "Fake Identity / Sender Mismatch"
            }

    return {"safe": True, "verdict": "SAFE", "reason": ""}

# --- Gemini API Call Block ---
def check_gemini_classification(text: str) -> dict:
    api_key = os.getenv("GEMINI_API_KEY") or os.getenv("GOOGLE_API_KEY")
    if not api_key:
        return {"active": False}
        
    try:
        url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key={api_key}"
        prompt = f"""
Analyze the following message and classify it for cybersecurity safety.
You must determine if it is a Scam/Phishing message or Safe.
Return a JSON object with:
{{
  "verdict": "SAFE" or "MALICIOUS",
  "category": "Job Scam", "Lottery / Prize Scam", "Fake Bank Alert", "Payment / UPI Scam", or "Safe",
  "reason": "Brief explanation of your verdict"
}}
Do not return any markdown formatting, code block markers (like ```json), or prefix. Return only raw JSON.

Message to analyze:
"{text}"
"""
        payload = {
            "contents": [{"parts": [{"text": prompt}]}]
        }
        res = requests.post(url, json=payload, timeout=4)
        if res.status_code == 200:
            data = res.json()
            reply = data["candidates"][0]["content"]["parts"][0]["text"]
            clean_reply = reply.strip()
            if clean_reply.startswith("```"):
                lines = clean_reply.splitlines()
                clean_reply = "\n".join(lines[1:-1]) if len(lines) > 2 else ""
            
            result = json.loads(clean_reply.strip())
            return {
                "active": True,
                "safe": result.get("verdict") == "SAFE",
                "verdict": result.get("verdict"),
                "category": result.get("category"),
                "reason": result.get("reason") + " (Verified by Gemini AI)"
            }
    except Exception:
        pass
        
    return {"active": False}

def classify_text_message(text: str, sender_name: str = "", sender_email: str = "") -> dict:
    sender_check = check_sender_mismatch(sender_name, sender_email)
    if not sender_check["safe"]:
        return sender_check

    gemini_res = check_gemini_classification(text)
    if gemini_res.get("active"):
        return {
            "safe": gemini_res["safe"],
            "verdict": gemini_res["verdict"],
            "category": gemini_res["category"],
            "reason": gemini_res["reason"]
        }

    text_lower = text.lower()
    has_unofficial_url = contains_unofficial_url(text)

    def matches_any(keywords, text):
        for kw in keywords:
            pattern = r'\b' + re.escape(kw) + r'\b'
            if re.search(pattern, text):
                return True
        return False

    has_job_topic = matches_any(TOPICS["Job"], text_lower)
    has_job_scam_trigger = (
        matches_any(TRIGGERS["Fee"], text_lower) or 
        matches_any(TRIGGERS["Task"], text_lower) or
        "upi://" in text_lower
    )
    if has_job_topic and has_job_scam_trigger:
        return {
            "safe": False,
            "verdict": "MALICIOUS",
            "category": "Job Scam",
            "reason": "Message contains job recruitment topics combined with high-risk payment or task-commission indicators."
        }

    has_lottery_topic = matches_any(TOPICS["Lottery"], text_lower)
    has_lottery_scam_trigger = (
        matches_any(TRIGGERS["Fee"], text_lower) or 
        matches_any(TRIGGERS["Credential"], text_lower) or
        has_unofficial_url
    )
    if has_lottery_topic and has_lottery_scam_trigger:
        return {
            "safe": False,
            "verdict": "MALICIOUS",
            "category": "Lottery / Prize Scam",
            "reason": "Message contains lottery or prize claims combined with suspicious link, fee request, or credential triggers."
        }

    has_bank_topic = matches_any(TOPICS["Bank"], text_lower)
    if has_bank_topic:
        is_suspicious_bank = False
        if has_unofficial_url:
            is_suspicious_bank = True
        elif matches_any(["block", "suspend", "verify", "update", "otp", "pin", "credentials", "locked"], text_lower):
            is_suspicious_bank = True
            
        if is_suspicious_bank:
            return {
                "safe": False,
                "verdict": "MALICIOUS",
                "category": "Fake Bank Alert",
                "reason": "Message claims to be from a financial institution but contains an unverified URL or requests sensitive verification action."
            }

    has_payment_topic = matches_any(TOPICS["Payment"], text_lower)
    has_payment_scam_trigger = (
        matches_any(["scan", "pay", "send", "click", "screenshot", "double"], text_lower) or 
        "upi://" in text_lower
    )
    if has_payment_topic and has_payment_scam_trigger:
        if matches_any(["refund", "receive", "pending", "double", "claim"], text_lower):
            return {
                "safe": False,
                "verdict": "MALICIOUS",
                "category": "Payment / UPI Scam",
                "reason": "Message indicates a payment or refund scam, requesting a transaction action (scan/pay) or screenshot verification."
            }

    input_vec = get_tfidf_vector(text)
    if input_vec:
        scores = {}
        for cat, cat_vec in category_vectors.items():
            scores[cat] = cosine_similarity(input_vec, cat_vec)
        
        best_cat, best_score = max(scores.items(), key=lambda x: x[1])
        if best_cat != "Safe" and best_score >= 0.22:
            return {
                "safe": False,
                "verdict": "MALICIOUS" if "Scam" in best_cat or "Alert" in best_cat else "SUSPICIOUS",
                "category": best_cat,
                "reason": f"Classified as '{best_cat}' by local TF-IDF Cosine Similarity engine (confidence: {best_score:.2f})."
            }

    suspicious_phrases = ["free gift", "click link to claim", "otp do not share", "verify account details"]
    matched_suspicious = [phrase for phrase in suspicious_phrases if phrase in text_lower]
    if matched_suspicious:
        return {
            "safe": False,
            "verdict": "SUSPICIOUS",
            "category": "General Scam Indicator",
            "reason": f"Detected precursor phrases: {', '.join(matched_suspicious)}"
        }

    return {
        "safe": True,
        "verdict": "SAFE",
        "category": "Safe",
        "reason": "No scam patterns or sender mismatches detected."
    }
