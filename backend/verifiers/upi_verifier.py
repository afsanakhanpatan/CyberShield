import urllib.parse
import re
import os
import json

# Path to the mule accounts database
MULE_ACCOUNTS_FILE = os.path.join(os.path.dirname(__file__), "../mule_accounts.json")

# Common personal UPI handle domains
PERSONAL_UPI_HANDLES = [
    "oksbi", "okhdfcbank", "okicici", "okaxis", "ybl", "paytm", "upi", 
    "apl", "axl", "ibl", "sib", "waaxis", "wasbi", "paytm", "postbank",
    "fbl", "federal", "jupiter", "sbi", "hdfcbank", "icici", "axisbank"
]

# Keywords that claim official/institutional status
OFFICIAL_KEYWORDS = [
    "govt", "government", "sbi", "hdfc", "icici", "bank", "refund", 
    "support", "helpdesk", "police", "tax", "lottery", "prize", 
    "rewards", "customer", "care", "verification", "kyc"
]

def load_mule_database() -> dict:
    if os.path.exists(MULE_ACCOUNTS_FILE):
        try:
            with open(MULE_ACCOUNTS_FILE, "r") as f:
                return json.load(f)
        except Exception:
            pass
    return {"upi_handles": [], "bank_accounts": []}

def parse_upi_uri(uri: str) -> dict:
    try:
        if not uri.lower().startswith("upi://"):
            return {}
        
        parsed = urllib.parse.urlparse(uri)
        query_params = urllib.parse.parse_qs(parsed.query)
        params = {k: v[0] for k, v in query_params.items()}
        return params
    except Exception:
        return {}

def verify_upi_address(upi_uri: str, raw_text: str = "") -> dict:
    """
    Verifies a UPI URI and checks the raw text for suspicious banking details
    like bank accounts, IFSC codes, and cross-references them with the mule database.
    """
    mule_db = load_mule_database()
    
    # 1. Inspect the raw text for bank account numbers and IFSC codes
    # Account numbers: typically 9 to 18 digits.
    # IFSC code: 4 letters + 0 + 6 alphanumeric characters.
    account_regex = r'\b\d{9,18}\b'
    ifsc_regex = r'\b[a-zA-Z]{4}0[a-zA-Z0-9]{6}\b'
    
    accounts = re.findall(account_regex, raw_text)
    ifsc_codes = [code.upper() for code in re.findall(ifsc_regex, raw_text)]
    
    # Check if any found account matches a known mule account
    for acc in accounts:
        for mule_acc in mule_db.get("bank_accounts", []):
            if acc == mule_acc.get("account_number"):
                # If there's an IFSC code in the text, check if it matches too (or just flag the account)
                mule_ifsc = mule_acc.get("ifsc", "")
                if not ifsc_codes or not mule_ifsc or any(code == mule_ifsc for code in ifsc_codes):
                    return {
                        "safe": False,
                        "verdict": "MALICIOUS",
                        "reason": f"Mule Bank Account Detected: Bank account '{acc}' (Bank: {mule_acc.get('bank_name')}) is in the threat database. Reason: {mule_acc.get('reason')}",
                        "details": {
                            "account_number": acc,
                            "ifsc": mule_ifsc,
                            "bank_name": mule_acc.get("bank_name")
                        }
                    }

    # 2. Parse UPI address if present
    params = parse_upi_uri(upi_uri)
    payee_id = params.get("pa", "").lower() if params else ""
    payee_name = params.get("pn", "").lower() if params else ""
    amount = params.get("am", "0") if params else "0"

    if payee_id:
        # Cross reference the UPI handle with mule database
        for handle in mule_db.get("upi_handles", []):
            if payee_id == handle.lower():
                return {
                    "safe": False,
                    "verdict": "MALICIOUS",
                    "reason": f"Mule UPI Handle Detected: UPI address '{payee_id}' matches a confirmed fraud receipt handle.",
                    "details": {
                        "payee_id": payee_id,
                        "payee_name": params.get("pn"),
                        "amount": amount
                    }
                }

        # Extract handle provider part
        handle_prov = ""
        if "@" in payee_id:
            handle_prov = payee_id.split("@")[1]

        # Financial Impersonation check: payee name claims official bank but uses personal provider handle
        is_claiming_official = any(keyword in payee_name for keyword in OFFICIAL_KEYWORDS)
        is_personal_handle = handle_prov in PERSONAL_UPI_HANDLES

        if is_claiming_official and is_personal_handle:
            return {
                "safe": False,
                "verdict": "MALICIOUS",
                "reason": f"Financial Impersonation: UPI payee display name '{params.get('pn')}' claims to represent an official bank or authority, but resolves to a standard personal handle (@{handle_prov}).",
                "details": {
                    "payee_id": payee_id,
                    "payee_name": params.get("pn"),
                    "amount": amount,
                    "handle": handle_prov
                }
            }

    # 3. If UPI URI was not valid but text has a raw UPI address pattern (e.g. upi_id@oksbi)
    # We can scan the raw text for plain text UPI handles
    raw_upi_regex = r'\b[a-zA-Z0-9.\-_]{2,256}@[a-zA-Z]{2,64}\b'
    raw_upis = re.findall(raw_upi_regex, raw_text)
    for raw_upi in raw_upis:
        upi_lower = raw_upi.lower()
        for handle in mule_db.get("upi_handles", []):
            if upi_lower == handle.lower():
                return {
                    "safe": False,
                    "verdict": "MALICIOUS",
                    "reason": f"Mule UPI Handle Detected: UPI address '{raw_upi}' matches a confirmed fraud receipt handle.",
                    "details": {
                        "payee_id": raw_upi,
                        "payee_name": "Unknown",
                        "amount": "0"
                    }
                }

    # If the text has bank account and IFSC, but they are not flagged as mules
    if accounts and ifsc_codes:
        # Just return safe with verification details
        return {
            "safe": True,
            "verdict": "SAFE",
            "reason": f"Extracted bank details: Account '{accounts[0]}' & IFSC '{ifsc_codes[0]}' verified clear of blacklist.",
            "details": {
                "account_number": accounts[0],
                "ifsc": ifsc_codes[0]
            }
        }

    return {
        "safe": True,
        "verdict": "SAFE",
        "reason": "No suspicious UPI details or mule accounts identified in input parameters.",
        "details": {
            "payee_id": payee_id,
            "payee_name": params.get("pn") if params else "",
            "amount": amount,
            "handle": payee_id.split("@")[1] if "@" in payee_id else ""
        }
    }
