import urllib.parse
import Levenshtein
import os
import re
import requests
import ssl
import socket
import datetime
import math

# Reference list of official domains
OFFICIAL_DOMAINS = {
    "sbi": ["sbi.co.in", "statebankofindia.com", "onlinesbi.sbi", "onlinesbi.com", "sbicard.com", "sbisecurities.in", "sbipf.org.in", "sbilife.co.in", "sbimutualfund.com"],
    "hdfc": ["hdfcbank.com", "hdfc.com", "hdfclife.com", "hdfcergo.com", "hdfcfund.com", "hdfcsec.com", "hdfccredila.com"],
    "icici": ["icicibank.com", "icicidirect.com", "iciciprulife.com", "icicilombard.com", "icicipruamc.com", "icicibank.co.in"],
    "rbi": ["rbi.org.in"],
    "axis": ["axisbank.com", "axisdirect.in", "axisbank.co.in", "axismutual.com"],
    "govt": ["gov.in", "nic.in", "india.gov.in", "incometax.gov.in"],
    "paytm": ["paytm.com"],
    "phonepe": ["phonepe.com"],
    "google": ["google.com", "gmail.com"],
    "microsoft": ["microsoft.com", "outlook.com"],
    "whatsapp": ["whatsapp.com", "wa.me"],
    "media": ["youtube.com", "youtu.be", "facebook.com", "instagram.com", "linkedin.com", "twitter.com", "x.com", "netflix.com", "spotify.com"],
    "infrastructure": ["rdap.org", "phishtank.com", "github.com", "localhost"]
}

# Known phishing/scam domains for demonstration
MOCK_MALICIOUS_DOMAINS = [
    "sbi-security-login.com",
    "hdfc-bank-verification.net",
    "income-tax-refund-govt.in",
    "rbi-helpdesk-alert.org",
    "paytm-reward-claim.com",
    "free-lottery-prize.info",
    "verify-your-bank-icici.com",
    "whatsapp-security-update.com"
]

def extract_domain(url: str) -> str:
    """Extracts the registered domain name (like google.com) from a full URL."""
    try:
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
        parsed = urllib.parse.urlparse(url)
        netloc = parsed.netloc.lower()
        if ':' in netloc:
            netloc = netloc.split(':')[0]
        if netloc.startswith('www.'):
            netloc = netloc[4:]
        return netloc
    except Exception:
        return ""

def calculate_shannon_entropy(s: str) -> float:
    """Calculates character entropy of a string (higher means more random)."""
    if not s:
        return 0.0
    probabilities = [float(s.count(c)) / len(s) for c in set(s)]
    return - sum(p * math.log(p, 2) for p in probabilities)

def check_dga_domain(domain: str) -> dict:
    """Analyzes domain structural metrics to detect algorithmic scam names."""
    main_part = extract_main_domain_part(domain)
    if not main_part:
        return {"safe": True}
        
    length = len(main_part)
    digits = sum(c.isdigit() for c in main_part)
    digit_ratio = digits / length if length > 0 else 0
    entropy = calculate_shannon_entropy(main_part)
    
    # Flags random looking subparts
    if length >= 8:
        is_dga = False
        if entropy > 3.8 and digit_ratio > 0.25:
            is_dga = True
        elif entropy > 4.1:  # Highly random string (e.g. jw9q2k1o)
            is_dga = True
        elif digit_ratio > 0.45:  # Mostly numbers
            is_dga = True
            
        if is_dga:
            return {
                "safe": False,
                "verdict": "MALICIOUS",
                "reason": f"DGA Pattern Detected: Domain '{domain}' exhibits algorithmic properties (entropy: {entropy:.2f}, digit ratio: {digit_ratio:.2f}), suggesting an automated scam site.",
                "source": "CyberShield DGA Scanner"
            }
    return {"safe": True}

def check_ssl_certificate(domain: str) -> dict:
    """Performs real-time secure handshake to check certificate validity."""
    try:
        context = ssl.create_default_context()
        # Verify socket connection on port 443
        with socket.create_connection((domain, 443), timeout=3) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                return {"safe": True, "reason": "SSL handshake verified."}
    except ssl.SSLError as e:
        return {
            "safe": False,
            "verdict": "MALICIOUS",
            "reason": f"Insecure SSL Certificate: Handshake failed for '{domain}'. Untrusted/self-signed/expired certificate.",
            "source": "CyberShield SSL Handshake Engine"
        }
    except Exception as e:
        # Fallback to suspicious for connection failure (legitimate banks require secure HTTPS)
        return {
            "safe": False,
            "verdict": "SUSPICIOUS",
            "reason": f"Secure Handshake Failed: Domain '{domain}' does not accept secure HTTPS connections on port 443. Connection timed out or refused.",
            "source": "CyberShield Port Monitor"
        }

def get_domain_creation_date(domain: str) -> str:
    """Queries RDAP standard directory to fetch domain registration creation date."""
    try:
        res = requests.get(f"https://rdap.org/domain/{domain}", timeout=3)
        if res.status_code == 200:
            data = res.json()
            events = data.get("events", [])
            for event in events:
                if event.get("eventAction") in {"registration", "creation"}:
                    date_str = event.get("eventDate")
                    return date_str[:10]  # Return YYYY-MM-DD
    except Exception:
        pass
    return None

def check_domain_age(domain: str) -> dict:
    """Flags domains registered less than 30 days ago."""
    creation_str = get_domain_creation_date(domain)
    if not creation_str:
        return {"safe": True, "reason": "RDAP record unavailable"}
    
    try:
        creation_date = datetime.datetime.strptime(creation_str, "%Y-%m-%d").date()
        today = datetime.date.today()
        age_days = (today - creation_date).days
        
        if age_days < 30:
            return {
                "safe": False,
                "verdict": "MALICIOUS",
                "reason": f"Suspiciously New Domain: Domain '{domain}' is only {age_days} days old (registered {creation_str}). Fresh domains are high-risk indicators of scam landing pages.",
                "source": "CyberShield WHOIS Engine"
            }
    except Exception:
        pass
    return {"safe": True, "reason": f"Domain age verified: {creation_str}"}

def check_safe_browsing(url: str) -> dict:
    """Checks URL against local threats list, Google Safe Browsing, and runs active SSL/DGA/Age checks."""
    api_key = os.getenv("GOOGLE_SAFE_BROWSING_API_KEY")
    domain = extract_domain(url)
    
    # 1. Local list checks
    for malicious in MOCK_MALICIOUS_DOMAINS:
        if malicious in domain:
            return {
                "safe": False,
                "verdict": "MALICIOUS",
                "reason": f"Domain matches confirmed threat record: {malicious}",
                "source": "CyberShield Local Threat Database"
            }
            
    # 2. Google Safe Browsing checks
    if api_key:
        try:
            endpoint = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={api_key}"
            payload = {
                "client": {"clientId": "cybershield-app", "clientVersion": "1.0.0"},
                "threatInfo": {
                    "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
                    "platformTypes": ["ANY_PLATFORM"],
                    "threatEntryTypes": ["URL"],
                    "threatEntries": [{"url": url}]
                }
            }
            res = requests.post(endpoint, json=payload, timeout=4)
            if res.status_code == 200:
                data = res.json()
                if "matches" in data:
                    match_info = data["matches"][0]
                    return {
                        "safe": False,
                        "verdict": "MALICIOUS",
                        "reason": f"Flagged by Google Safe Browsing: {match_info.get('threatType')}",
                        "source": "Google Safe Browsing API"
                    }
        except Exception:
            pass

    # 3. Active analysis (Skip for known whitelisted domains)
    is_official = False
    for brand, official_list in OFFICIAL_DOMAINS.items():
        for off_dom in official_list:
            if domain == off_dom or domain.endswith("." + off_dom):
                is_official = True
                break
        if is_official:
            break
            
    if not is_official and domain:
        # Check DGA Pattern
        dga_res = check_dga_domain(domain)
        if not dga_res["safe"]:
            return dga_res
            
        # Check SSL Handshake
        ssl_res = check_ssl_certificate(domain)
        if not ssl_res["safe"]:
            return ssl_res
            
        # Check Domain Age via RDAP
        age_res = check_domain_age(domain)
        if not age_res["safe"]:
            return age_res

    return {
        "safe": True,
        "verdict": "SAFE",
        "reason": "No match in threat intelligence databases",
        "source": "CyberShield Intelligence Feed"
    }

def extract_main_domain_part(domain: str) -> str:
    """Extracts the main brand or domain part of a domain name."""
    parts = domain.lower().split('.')
    if len(parts) < 2:
        return domain
    
    if len(parts) >= 3:
        suffix = ".".join(parts[-2:])
        if suffix in {"co.in", "org.in", "gov.in", "nic.in", "com.tr", "co.uk", "org.uk", "gov.uk"}:
            return parts[-3]
            
    return parts[-2]

def check_typosquatting(url: str) -> dict:
    """Detects typosquatting against whitelist domains."""
    domain = extract_domain(url)
    if not domain:
        return {"safe": True, "verdict": "SAFE", "reason": ""}

    for brand, official_list in OFFICIAL_DOMAINS.items():
        for off_dom in official_list:
            if domain == off_dom or domain.endswith("." + off_dom):
                return {"safe": True, "verdict": "SAFE", "reason": "Verified official domain"}

    main_part = extract_main_domain_part(domain)

    for brand, official_list in OFFICIAL_DOMAINS.items():
        for off_dom in official_list:
            off_main = extract_main_domain_part(off_dom)
            
            contains_brand = False
            if len(off_main) >= 4:
                # Longer brands: simple substring matching
                if off_main in main_part and main_part != off_main:
                    contains_brand = True
            else:
                # Short brands (e.g., wa, sbi, rbi, gov, nic): check boundaries/affixes to avoid false positives
                # 1. Distinct token check (e.g., sbi-login, verify.rbi)
                pattern = rf"(^|[-_.])" + re.escape(off_main) + rf"([-_.]|$)"
                if re.search(pattern, main_part):
                    contains_brand = True
                else:
                    # 2. Check for common scam prefix/suffix patterns directly attached to the short brand
                    affixes = ["my", "online", "secure", "mobile", "login", "help", "support", "official", "verify"]
                    for affix in affixes:
                        if main_part == affix + off_main or main_part == off_main + affix:
                            contains_brand = True
                            break
                        if main_part.startswith(affix + off_main) or main_part.endswith(off_main + affix):
                            contains_brand = True
                            break

            dist = Levenshtein.distance(main_part, off_main)

            # Determine distance threshold based on brand length to avoid false positives on short names
            if len(off_main) <= 2:
                dist_threshold = 0
            elif len(off_main) == 3:
                dist_threshold = 1
            else:
                dist_threshold = 2

            if (dist > 0 and dist <= dist_threshold) or contains_brand:
                return {
                    "safe": False,
                    "verdict": "MALICIOUS",
                    "reason": f"Suspicious domain typosquatting detected. Looks like official brand '{brand.upper()}' (official: {off_dom}) but resolved as '{domain}'."
                }

    return {"safe": True, "verdict": "SAFE", "reason": "No typosquatting detected"}
