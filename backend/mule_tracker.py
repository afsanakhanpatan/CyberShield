"""
CyberShield — Mule Account Tracker
Checks UPI IDs, account numbers, phone numbers against mule_accounts.json
Drop into: backend/mule_tracker.py
"""

import json
import os
import re
import hashlib
from datetime import datetime
from difflib import SequenceMatcher

DB_PATH = os.path.join(os.path.dirname(__file__), "mule_accounts.json")

# ─────────────────────────────────────────────────────
# DATABASE LOADER
# ─────────────────────────────────────────────────────

def load_db() -> dict:
    """Load mule database from JSON file."""
    try:
        with open(DB_PATH, "r") as f:
            return json.load(f)
    except FileNotFoundError:
        return {"mule_accounts": [], "mule_phones": [],
                "mule_account_numbers": [], "mule_ifsc_patterns": []}

def save_db(db: dict):
    """Save updated database back to JSON."""
    db["last_updated"] = datetime.now().strftime("%Y-%m-%d")
    db["total_accounts"] = len(db["mule_accounts"])
    with open(DB_PATH, "w") as f:
        json.dump(db, f, indent=2)


# ─────────────────────────────────────────────────────
# CORE LOOKUP FUNCTIONS
# ─────────────────────────────────────────────────────

def check_upi(upi_id: str) -> dict:
    """
    Check if a UPI ID is in the mule database.
    Also does fuzzy matching to catch slight variations.
    e.g., fraud123@ybl vs fraud_123@ybl
    """
    db = load_db()
    upi_lower = upi_id.lower().strip()

    for account in db["mule_accounts"]:
        db_upi = account.get("upi_id", "").lower()

        # Exact match
        if upi_lower == db_upi:
            return {
                "found": True,
                "match_type": "exact",
                "confidence": 100,
                "account": account,
                "verdict": "MULE ACCOUNT",
                "risk_score": 100,
                "reason": f"UPI '{upi_id}' is in mule database (Case #{account['id']}, reported {account['reported_count']} times)",
                "alert_level": "RED",
            }

        # Fuzzy match (catches typo variations of same mule)
        similarity = SequenceMatcher(None, upi_lower, db_upi).ratio()
        if similarity > 0.88:
            return {
                "found": True,
                "match_type": "fuzzy",
                "confidence": int(similarity * 100),
                "account": account,
                "verdict": "LIKELY MULE ACCOUNT",
                "risk_score": 90,
                "reason": f"UPI '{upi_id}' is {int(similarity*100)}% similar to known mule '{db_upi}'",
                "alert_level": "RED",
            }

    return {
        "found": False,
        "match_type": "none",
        "confidence": 0,
        "account": None,
        "verdict": "NOT IN DATABASE",
        "risk_score": 0,
        "reason": "UPI ID not found in mule database",
        "alert_level": "GREEN",
    }


def check_account_number(account_number: str) -> dict:
    """Check if a bank account number is in the mule database."""
    db = load_db()
    acc_clean = re.sub(r'\s+', '', account_number)

    # Check direct list AND accounts list
    all_accs = [a.get("account_number","") for a in db["mule_accounts"]]
    if acc_clean in db.get("mule_account_numbers", []) or acc_clean in all_accs:
        # Find the full account record
        for account in db["mule_accounts"]:
            if account.get("account_number") == acc_clean:
                return {
                    "found": True,
                    "account": account,
                    "verdict": "MULE ACCOUNT",
                    "risk_score": 100,
                    "reason": f"Account number is a known mule account (Case #{account['id']})",
                    "alert_level": "RED",
                }
        return {
            "found": True,
            "account": None,
            "verdict": "MULE ACCOUNT",
            "risk_score": 95,
            "reason": "Account number found in mule list",
            "alert_level": "RED",
        }

    return {
        "found": False,
        "account": None,
        "verdict": "NOT IN DATABASE",
        "risk_score": 0,
        "reason": "Account number not in mule database",
        "alert_level": "GREEN",
    }


def check_phone(phone: str) -> dict:
    """Check if a phone number is linked to a mule account."""
    db = load_db()
    phone_clean = re.sub(r'[\s\-\+]', '', phone)
    # Remove country code if present
    if phone_clean.startswith("91") and len(phone_clean) == 12:
        phone_clean = phone_clean[2:]

    if phone_clean in db.get("mule_phones", []):
        for account in db["mule_accounts"]:
            if account.get("phone") == phone_clean:
                return {
                    "found": True,
                    "account": account,
                    "verdict": "MULE PHONE NUMBER",
                    "risk_score": 95,
                    "reason": f"Phone {phone} linked to mule account (Case #{account['id']})",
                    "alert_level": "RED",
                }
        return {
            "found": True,
            "account": None,
            "verdict": "MULE PHONE NUMBER",
            "risk_score": 90,
            "reason": f"Phone {phone} found in mule phone list",
            "alert_level": "RED",
        }

    return {
        "found": False,
        "account": None,
        "verdict": "NOT IN DATABASE",
        "risk_score": 0,
        "reason": "Phone not in mule database",
        "alert_level": "GREEN",
    }


def check_any(value: str) -> dict:
    """
    Smart check — auto-detects if input is UPI, phone, or account number
    and checks all three databases.
    This is the main function to call from your API.
    """
    value = value.strip()

    # Detect type
    if "@" in value:
        result = check_upi(value)
        result["input_type"] = "upi"
    elif re.match(r'^[\d\s\-\+]{10,}$', value):
        digits = re.sub(r'\D', '', value)
        # Always try both phone AND account number
        r1 = check_phone(value)
        r2 = check_account_number(value)
        if r1["found"]:
            result = r1; result["input_type"] = "phone"
        elif r2["found"]:
            result = r2; result["input_type"] = "account_number"
        else:
            result = r1; result["input_type"] = "phone"
    else:
        result = {"found": False, "verdict": "UNKNOWN FORMAT",
                  "risk_score": 0, "reason": "Could not determine input type",
                  "alert_level": "YELLOW", "input_type": "unknown"}

    # Add evidence hash
    result["evidence_hash"] = hashlib.sha256(value.encode()).hexdigest()
    return result


# ─────────────────────────────────────────────────────
# DATABASE MANAGEMENT (Police use these)
# ─────────────────────────────────────────────────────

def add_mule_account(
    upi_id: str = "",
    account_number: str = "",
    phone: str = "",
    holder_name: str = "Unknown",
    category: str = "Reported Fraud",
    notes: str = "",
    reported_by: str = "Officer",
    location: str = "Unknown",
) -> dict:
    """
    Add a new mule account to the database.
    Called by police when a new fraud account is identified.
    """
    db = load_db()

    # Check if already exists
    for acc in db["mule_accounts"]:
        if upi_id and acc.get("upi_id", "").lower() == upi_id.lower():
            # Update report count instead
            acc["reported_count"] += 1
            acc["last_reported"] = datetime.now().strftime("%Y-%m-%d")
            if reported_by not in acc["reported_by"]:
                acc["reported_by"].append(reported_by)
            save_db(db)
            return {"action": "updated", "message": f"Report count increased to {acc['reported_count']}", "account": acc}

    # Create new entry
    new_id = f"M{str(len(db['mule_accounts']) + 1).zfill(3)}"
    new_account = {
        "id": new_id,
        "upi_id": upi_id,
        "account_number": account_number,
        "ifsc": "",
        "holder_name": holder_name,
        "phone": phone,
        "category": category,
        "reported_count": 1,
        "total_fraud_amount": 0,
        "status": "active",
        "first_reported": datetime.now().strftime("%Y-%m-%d"),
        "last_reported": datetime.now().strftime("%Y-%m-%d"),
        "reported_by": [reported_by],
        "location": location,
        "notes": notes,
    }

    db["mule_accounts"].append(new_account)
    if upi_id and upi_id not in db.get("mule_upi_ids", []):
        db.setdefault("mule_upi_ids", []).append(upi_id)
    if account_number and account_number not in db["mule_account_numbers"]:
        db["mule_account_numbers"].append(account_number)
    if phone and phone not in db["mule_phones"]:
        db["mule_phones"].append(phone)

    save_db(db)
    return {"action": "added", "message": f"New mule account added: {new_id}", "account": new_account}


def get_stats() -> dict:
    """Return database statistics for police dashboard."""
    db = load_db()
    accounts = db["mule_accounts"]
    active = [a for a in accounts if a.get("status") == "active"]
    blocked = [a for a in accounts if a.get("status") == "blocked"]
    total_fraud = sum(a.get("total_fraud_amount", 0) for a in accounts)
    categories = {}
    for a in accounts:
        cat = a.get("category", "Unknown")
        categories[cat] = categories.get(cat, 0) + 1

    return {
        "total_mule_accounts": len(accounts),
        "active": len(active),
        "blocked": len(blocked),
        "total_fraud_amount": total_fraud,
        "total_reports": sum(a.get("reported_count", 0) for a in accounts),
        "by_category": categories,
        "most_reported": sorted(accounts, key=lambda x: x.get("reported_count", 0), reverse=True)[:3],
    }


# ─────────────────────────────────────────────────────
# TEST
# ─────────────────────────────────────────────────────
if __name__ == "__main__":
    print("=" * 60)
    print("MULE ACCOUNT TRACKER — TEST RESULTS")
    print("=" * 60)

    tests = [
        ("fraud123@ybl",       "MULE ACCOUNT"),
        ("merchant@okaxis",    "NOT IN DATABASE"),
        ("paisa.free99@paytm", "MULE ACCOUNT"),
        ("9000000001",         "MULE PHONE NUMBER"),
        ("9876543210",         "MULE ACCOUNT"),
        ("9876543211",         "NOT IN DATABASE"),
        ("fraud_123@ybl",      "LIKELY MULE ACCOUNT"),  # fuzzy match
    ]

    passed = 0
    for val, expected in tests:
        r = check_any(val)
        ok = "✅" if expected in r["verdict"] else "❌"
        if expected in r["verdict"]: passed += 1
        print(f"{ok} {val:<30} → {r['verdict']} (score: {r['risk_score']})")
        if r.get("account"):
            print(f"   └─ Category: {r['account']['category']}, Reports: {r['account']['reported_count']}")

    print(f"\n{passed}/{len(tests)} passed")
    print("\n📊 Database Stats:")
    stats = get_stats()
    print(f"   Total mule accounts : {stats['total_mule_accounts']}")
    print(f"   Active              : {stats['active']}")
    print(f"   Total fraud amount  : ₹{stats['total_fraud_amount']:,}")
    print(f"   Total reports       : {stats['total_reports']}")
