"""
CyberShield Smart Detector — Drop into your backend as smart_detector.py
Fixes all false positives seen in screenshots and adds robust patterns for WhatsApp scam templates.
Integrated with Mule Account Tracker database (mule_accounts.json).
"""

import re, hashlib
from urllib.parse import urlparse
from difflib import SequenceMatcher
from mule_tracker import check_upi as check_mule_upi, check_phone as check_mule_phone, check_account_number as check_mule_account

TRUSTED_DOMAINS = {
    # Indian Banks
    "sbi.co.in","onlinesbi.sbi","onlinesbi.sbi.co.in","sbi.bank.in",
    "hdfcbank.com","netbanking.hdfcbank.com",
    "icicibank.com","axisbank.com","kotak.com","yesbank.in",
    "pnbindia.in","canarabank.in","unionbankofindia.co.in",
    "bankofbaroda.in","indianbank.in","idfcfirstbank.com",
    # Payments
    "paytm.com","phonepe.com","gpay.app","googlepay.com",
    "bhimupi.org.in","npci.org.in","amazonpay.in",
    # Government
    "gov.in","nic.in","india.gov.in","mygov.in","uidai.gov.in",
    "incometax.gov.in","gst.gov.in","irctc.co.in","indiapost.gov.in",
    "passport.gov.in","epfindia.gov.in","digilocker.gov.in",
    # Safe platforms
    "youtube.com","youtu.be","google.com","gmail.com",
    "whatsapp.com","facebook.com","instagram.com","twitter.com","x.com",
    "amazon.in","flipkart.com","github.com",
}

IMPERSONATED_BRANDS = {
    "sbi":["onlinesbi","sbi","statebank"],
    "hdfc":["hdfc","hdfcbank"],
    "icici":["icici","icicidirect"],
    "axis":["axis","axisbank"],
    "paytm":["paytm"],
    "phonepe":["phonepe","phone-pe"],
    "aadhaar":["aadhaar","aadhar","uidai"],
    "irctc":["irctc","indianrail"],
}

SUSPICIOUS_HOSTING = [
    "vercel.app","netlify.app","herokuapp.com","glitch.me",
    "github.io","pages.dev","workers.dev","web.app",
    "firebaseapp.com","replit.dev","ngrok.io",
]

SCAM_PATTERNS = [
    # 1. KYC / Account / FASTag / SIM Threats
    (r"\b(kyc|account|fastag|sim|profile|identity|card|pan).{0,35}(expire|block|suspend|restrict|incomplete|verify|update|alert|close)\b", 85, "KYC/Account Threat Alert"),
    (r"\b(expire|block|suspend|restrict|incomplete|verify|update|alert|close).{0,35}(kyc|account|fastag|sim|profile|identity|card|pan)\b", 85, "KYC/Account Threat Alert"),

    # 2. OTP/Credential Requests
    (r"\b(send|share|enter|provide|message).{0,15}otp\b", 85, "OTP Request Alert"),
    (r"\b(otp).{0,15}(send|share|enter|provide|message)\b", 85, "OTP Request Alert"),

    # 3. Utility Bill / Electricity Disconnection
    (r"\b(electricity|power|bill|utility).{0,35}(disconnect|overdue|pending|cut|suspend)\b", 85, "Utility Disconnection Alert"),
    (r"\b(disconnect|overdue|pending|cut|suspend).{0,35}(electricity|power|bill|utility)\b", 85, "Utility Disconnection Alert"),

    # 4. Tax / Refund Scams
    (r"\b(tax|refund).{0,30}(eligible|process|claim|verify|receive|pending)\b", 80, "Tax Refund Alert"),
    (r"\b(eligible|process|claim|verify|receive|pending).{0,30}(tax|refund)\b", 80, "Tax Refund Alert"),

    # 5. Parcel / Delivery / Courier Scams
    (r"\b(parcel|delivery|courier|package|bluedart).{0,35}(fail|reschedule|incorrect|pay|address|hold)\b", 80, "Courier Delivery Scam Alert"),
    (r"\b(fail|reschedule|incorrect|pay|address|hold).{0,35}(parcel|delivery|courier|package|bluedart)\b", 80, "Courier Delivery Scam Alert"),

    # 6. Prize / Lottery / Cashback Rewards
    (r"\b(won|win|winner|cashback|reward|prize|lottery).{0,35}(prize|lottery|cashback|reward|claim|expire|offer|crore|lakh|won|win)\b", 85, "Prize/Cashback Reward Scam"),
]

SAFE_PHRASES = [
    "payment done","payment received","payment successful",
    "order confirmed","delivery","invoice","bill paid",
    "meeting","schedule","reminder","youtube","youtu.be",
    "upi payment","paid successfully","transaction successful",
]

def extract_domain(url):
    try:
        p = urlparse(url if url.startswith("http") else "https://"+url)
        return p.netloc.lower().replace("www.","")
    except: return url.lower()

def is_trusted(domain):
    domain = domain.lower().replace("www.","")
    for t in TRUSTED_DOMAINS:
        if domain == t or domain.endswith("."+t):
            return True
    return False

def check_typosquat(domain):
    dl = domain.lower()
    for brand, keywords in IMPERSONATED_BRANDS.items():
        for kw in keywords:
            if kw in dl:
                for sus in SUSPICIOUS_HOSTING:
                    if dl.endswith(sus):
                        return 95, f"FAKE {brand.upper()} SITE on {sus}"
                for trusted in TRUSTED_DOMAINS:
                    if brand in trusted:
                        sim = SequenceMatcher(None, dl, trusted).ratio()
                        if 0.55 < sim < 0.92:
                            return 80, f"Typosquatting '{domain}' looks like '{trusted}'"
    return 0, ""

def verify_url(url):
    domain = extract_domain(url)
    if is_trusted(domain):
        return {"safe":True,"verdict":"SAFE","reason":f"Trusted domain: {domain}",
                "category":"trusted","risk_score":0}
    risk = 0; reasons = []
    ts, tr = check_typosquat(domain)
    if ts: risk += ts; reasons.append(tr)
    # Generic Vercel/Netlify hosting domains are NOT flagged as suspicious by default unless there is typosquatting
    # This addresses the user's requirement that their own deployed trusted Vercel link remains SAFE.
    for sus in SUSPICIOUS_HOSTING:
        if domain.endswith(sus) and risk == 0:
            pass # Skip general suspicious risk score to allow trusted Vercel deploys
    if any(domain == s or domain.endswith("."+s) for s in ["bit.ly","tinyurl.com","rb.gy","cutt.ly","ow.ly"]):
        risk += 65; reasons.append("URL shortener hides real destination")
    if re.match(r'\d+\.\d+\.\d+\.\d+', domain):
        risk += 65; reasons.append("IP address URL")
    hyphens = domain.split(".")[0].count("-")
    if hyphens >= 2: risk += 20; reasons.append(f"{hyphens} hyphens in domain")
    risk = min(100, risk)
    if risk >= 60:
        return {"safe":False,"verdict":"MALICIOUS","reason":" | ".join(reasons),
                "category":"Phishing URL","risk_score":risk}
    elif risk >= 30:
        return {"safe":False,"verdict":"SUSPICIOUS","reason":" | ".join(reasons),
                "category":"Suspicious URL","risk_score":risk}
    return {"safe":True,"verdict":"SAFE","reason":"No threats","category":"safe","risk_score":risk}

def check_mule_bank_accounts(text):
    account_regex = r'\b\d{9,18}\b'
    accounts = re.findall(account_regex, text)
    for acc in accounts:
        acc_res = check_mule_account(acc)
        if acc_res["found"]:
            return {
                "safe": False,
                "verdict": acc_res["verdict"],
                "reason": acc_res["reason"],
                "category": "Mule Bank Account",
                "risk_score": acc_res["risk_score"],
                "reported_count": acc_res["account"].get("reported_count", 0) if acc_res.get("account") else 0
            }
    return None

def verify_text(text):
    tl = text.lower()

    # 1. Check for plain text UPI handles in the text against the mule database
    raw_upi_regex = r'\b[a-zA-Z0-9.\-_]{2,256}@[a-zA-Z]{2,64}\b'
    raw_upis = re.findall(raw_upi_regex, text)
    for raw_upi in raw_upis:
        mule_res = check_mule_upi(raw_upi)
        if mule_res["found"]:
            return {
                "safe": False,
                "verdict": mule_res["verdict"],
                "reason": mule_res["reason"],
                "category": "UPI Scam",
                "risk_score": 100,
                "reported_count": mule_res["account"].get("reported_count", 0) if mule_res.get("account") else 0
            }

    # 2. Check for bank account numbers in the text against the mule database
    mule_bank_check = check_mule_bank_accounts(text)
    if mule_bank_check:
        return mule_bank_check

    # 3. Check for phone numbers in the text against the mule database
    phone_regex = r'\b\d{10}\b'
    phones = re.findall(phone_regex, text)
    for phone in phones:
        phone_res = check_mule_phone(phone)
        if phone_res["found"]:
            return {
                "safe": False,
                "verdict": phone_res["verdict"],
                "reason": phone_res["reason"],
                "category": "Mule Phone Number",
                "risk_score": phone_res["risk_score"],
                "reported_count": phone_res["account"].get("reported_count", 0) if phone_res.get("account") else 0
            }

    # 4. Safe phrase check — if clearly normal, return safe UNLESS strong scam pattern
    safe_hit = any(p in tl for p in SAFE_PHRASES)

    # 5. Strong scam patterns
    for pattern, weight, label in SCAM_PATTERNS:
        if re.search(pattern, tl, re.IGNORECASE):
            return {"safe":False,"verdict":"MALICIOUS","reason":label,
                    "category":"Scam Message","risk_score":weight}
    if safe_hit:
        return {"safe":True,"verdict":"SAFE","reason":"Normal message",
                "category":"safe","risk_score":0}

    # 6. Weak multi-signal scoring
    risk = 0; flags = []
    weak = [
        (r"\botp\b", 20, "OTP mention"),
        (r"\b(urgent|immediately|expire)\b", 15, "Urgency"),
        (r"\b(lottery|lucky draw)\b", 30, "Lottery"),
        (r"\bclick (here|this link)\b", 20, "Click link"),
        (r"\bverify.{0,15}account\b", 20, "Verify account"),
    ]
    for pat, w, f in weak:
        if re.search(pat, tl, re.IGNORECASE):
            risk += w; flags.append(f)
    if risk >= 40 and len(flags) >= 2:
        return {"safe":False,"verdict":"SUSPICIOUS",
                "reason":"Multiple signals: "+", ".join(flags),
                "category":"Suspicious Message","risk_score":risk}
    return {"safe":True,"verdict":"SAFE","reason":"No threats","category":"safe","risk_score":risk}

def verify_upi(upi_id, payee_name=""):
    ul = upi_id.lower().strip()
    pn = payee_name.lower().strip()
    
    # 1. Check if UPI address matches any blacklisted handle in the mule database
    mule_res = check_mule_upi(upi_id)
    if mule_res["found"]:
        return {
            "safe": False,
            "verdict": mule_res["verdict"],
            "reason": mule_res["reason"],
            "category": mule_res["account"]["category"] if mule_res.get("account") else "UPI Scam",
            "risk_score": mule_res["risk_score"],
            "reported_count": mule_res["account"].get("reported_count", 0) if mule_res.get("account") else 0
        }

    # 2. Financial Impersonation check: payee name claims official bank but uses personal provider handle
    legit = ["@okaxis","@okhdfcbank","@okicici","@oksbi","@ybl","@ibl","@axl",
             "@paytm","@apl","@upi","@waicici","@wahdfcbank","@ptyes","@pthdfc"]
    
    official_keywords = ["bank", "sbi", "hdfc", "icici", "axis", "electricity", "board", "fastag", 
                         "support", "tax", "refund", "courier", "bluedart", "kyc", "cashback", "rewards"]
    
    if pn:
        is_claiming_official = any(kw in pn for kw in official_keywords)
        handle_prov = ul.split("@")[1] if "@" in ul else ""
        is_personal_handle = any(h == "@" + handle_prov for h in legit)
        if is_claiming_official and is_personal_handle:
            return {"safe":False,"verdict":"MALICIOUS",
                    "reason":f"Financial Impersonation: UPI payee display name '{payee_name}' claims to represent an official bank or authority, but uses a standard personal handle (@{handle_prov}).",
                    "category":"Financial Impersonation","risk_score":90}

    # 3. Handle specific legit handle list logic
    for h in legit:
        if ul.endswith(h):
            username = ul.split("@")[0]
            if re.search(r"(prize|lottery|reward|claim|win|free|scam|fraud)", username, re.IGNORECASE):
                return {"safe":False,"verdict":"MALICIOUS",
                        "reason":"Scam keyword in UPI username","category":"UPI Scam","risk_score":85}
            return {"safe":True,"verdict":"SAFE","reason":f"Legitimate handle {h}",
                    "category":"safe","risk_score":0}
                    
    risk = 0; reasons = []
    if re.search(r'\b(prize|lottery|reward|free|win)\b', ul): risk+=55; reasons.append("Scam keyword")
    if re.search(r'\d{8,}', ul): risk+=20; reasons.append("Too many digits")
    if risk >= 50:
        return {"safe":False,"verdict":"MALICIOUS","reason":" | ".join(reasons),
                "category":"UPI Scam","risk_score":risk}
    return {"safe":True,"verdict":"SAFE","reason":"Looks normal","category":"safe","risk_score":risk}
