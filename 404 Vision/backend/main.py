from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional
import os
import json
import hashlib
import time


from database import init_db, SessionLocal, EvidenceLog

from verifiers.domain_verifier import check_safe_browsing, check_typosquatting
from verifiers.upi_verifier import verify_upi_address
from verifiers.qr_verifier import decode_qr_base64
from verifiers.classifier import classify_text_message
from smart_detector import verify_url as smart_verify_url, verify_text as smart_verify_text, verify_upi as smart_verify_upi, check_mule_bank_accounts
from mule_tracker import check_any, check_upi, check_phone, check_account_number, add_mule_account, get_stats

app = FastAPI(
    title="CyberShield Verification API",
    description="Factual threat intelligence API for phishing, scam classification, and payment spoofing.",
    version="1.0.0"
)

# Enable CORS for Chrome Extension and Dashboard
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Initialize PostgreSQL database tables on startup
@app.on_event("startup")
def on_startup():
    init_db()
    print("[CyberShield] PostgreSQL database initialized.")


# Web3 Configuration (Hardhat local network defaults)
RPC_URL = os.getenv("RPC_URL", "http://127.0.0.1:8545")
# Standard Hardhat Account #0 private key (safe for local development/demos)
DEFAULT_PRIVATE_KEY = os.getenv("WEB3_PRIVATE_KEY", "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80")
CONTRACT_ADDRESS_FILE = os.path.join(os.path.dirname(__file__), "../blockchain/deployed_address.txt")

# Pydantic Schemas
class UrlRequest(BaseModel):
    url: str

class UpiRequest(BaseModel):
    upi_uri: str
    raw_text: str = ""

class TextRequest(BaseModel):
    text: str
    sender_name: str = ""
    sender_email: str = ""

class QrRequest(BaseModel):
    image_b64: str

class BlockchainLogRequest(BaseModel):
    category: str
    reason: str
    target: str
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    reporter: Optional[str] = None
    location: Optional[str] = None

def get_nearest_city(lat, lon):
    cities = [
        {"name": "Ongole, AP", "lat": 15.5057, "lon": 80.0499},
        {"name": "Vijayawada, AP", "lat": 16.5062, "lon": 80.6480},
        {"name": "Guntur, AP", "lat": 16.3067, "lon": 80.4365},
        {"name": "Hyderabad, TS", "lat": 17.3850, "lon": 78.4867},
        {"name": "Nellore, AP", "lat": 14.4426, "lon": 79.9865},
        {"name": "Visakhapatnam, AP", "lat": 17.6868, "lon": 83.2185}
    ]
    if lat is None or lon is None:
        return "Unknown Location"
    try:
        lat = float(lat)
        lon = float(lon)
    except:
        return "Unknown Location"
    min_dist = float('inf')
    best_city = "Unknown Location"
    for city in cities:
        dist = (city["lat"] - lat) ** 2 + (city["lon"] - lon) ** 2
        if dist < min_dist:
            min_dist = dist
            best_city = city["name"]
    return best_city

class EmailHeadersRequest(BaseModel):
    headers_text: str

# Helper to read deployed contract address
def get_contract_address():
    if os.path.exists(CONTRACT_ADDRESS_FILE):
        try:
            with open(CONTRACT_ADDRESS_FILE, "r") as f:
                return f.read().strip()
        except:
            pass
    return "0x5FbDB2315678afecb367f032d93F642f64180aa3" # Hardhat default first deploy address

# Helper to log evidence to PostgreSQL
def log_evidence_to_db(record: dict):
    db = SessionLocal()
    try:
        entry = EvidenceLog(
            evidence_hash=record["evidence_hash"],
            category=record["category"],
            reason=record["reason"],
            target=record["target"],
            timestamp=record["timestamp"],
            blockchain_logged=record.get("blockchain_logged", False),
            tx_hash=record.get("tx_hash", ""),
            reporter=record.get("reporter"),
            location=record.get("location"),
            latitude=record.get("latitude"),
            longitude=record.get("longitude"),
        )
        db.add(entry)
        db.commit()
    except Exception as e:
        db.rollback()
        print(f"[CyberShield] DB write error: {e}")
    finally:
        db.close()

# Endpoints
@app.get("/")
def health_check():
    return {"status": "online", "system": "CyberShield API"}

@app.post("/verify/url")
def verify_url(req: UrlRequest):
    return smart_verify_url(req.url)

@app.post("/verify/upi")
def verify_upi(req: UpiRequest):
    # 1. Check raw text for mule bank accounts
    if req.raw_text:
        mule_check = check_mule_bank_accounts(req.raw_text)
        if mule_check:
            mule_check["details"] = {
                "payee_id": "Bank Account",
                "payee_name": "Mule Bank Account",
                "amount": "0",
                "handle": ""
            }
            return mule_check

    # 2. Check UPI URI parameters
    upi_uri = req.upi_uri
    upi_id = upi_uri
    payee_name = ""
    if upi_uri.lower().startswith("upi://"):
        try:
            from urllib.parse import urlparse, parse_qs
            parsed = urlparse(upi_uri)
            query_params = parse_qs(parsed.query)
            pa = query_params.get("pa", [""]) [0]
            pn = query_params.get("pn", [""]) [0]
            if pa:
                upi_id = pa
            if pn:
                payee_name = pn
        except:
            pass
    res = smart_verify_upi(upi_id, payee_name=payee_name)
    if "details" not in res:
        res["details"] = {
            "payee_id": upi_id,
            "payee_name": payee_name or (upi_id.split("@")[0] if "@" in upi_id else upi_id),
            "amount": "0",
            "handle": upi_id.split("@")[1] if "@" in upi_id else ""
        }
    return res

@app.post("/verify/text")
def verify_text(req: TextRequest):
    if req.sender_name or req.sender_email:
        from verifiers.classifier import check_sender_mismatch
        sender_check = check_sender_mismatch(req.sender_name, req.sender_email)
        if not sender_check["safe"]:
            return sender_check
    return smart_verify_text(req.text)

@app.post("/verify/qr")
def verify_qr(req: QrRequest):
    return decode_qr_base64(req.image_b64)


@app.post("/blockchain/log")
def log_scam_blockchain(req: BlockchainLogRequest):
    # 1. Generate evidence hash locally
    timestamp = int(time.time())
    raw_data = f"{req.category}:{req.reason}:{req.target}:{timestamp}"
    evidence_hash = hashlib.sha256(raw_data.encode()).hexdigest()

    # Resolve location and coordinates
    lat = req.latitude
    lon = req.longitude
    location_name = req.location

    if lat is None or lon is None:
        try:
            import urllib.request
            import json
            # Query ip-api to get user's actual local testing coordinates
            with urllib.request.urlopen("http://ip-api.com/json/", timeout=3) as response:
                ip_data = json.loads(response.read().decode())
                if ip_data.get("status") == "success":
                    lat = ip_data.get("lat")
                    lon = ip_data.get("lon")
                    if not location_name or location_name == "Unknown Location":
                        location_name = f"{ip_data.get('city')}, {ip_data.get('regionName')}"
        except Exception as e:
            print(f"[CyberShield] IP physical location lookup failed: {e}")

        # Fallback to the real event location (Ongole, Prakasam District, AP) if IP location lookup fails
        if lat is None or lon is None:
            lat = 15.5057
            lon = 80.0499
            if not location_name or location_name == "Unknown Location":
                location_name = "Ongole, Andhra Pradesh"
    elif not location_name or location_name == "Unknown Location":
        location_name = get_nearest_city(lat, lon)

    # Resolve reporter
    reporter_name = req.reporter
    if not reporter_name:
        db = SessionLocal()
        try:
            existing_count = db.query(EvidenceLog).count()
        except:
            existing_count = 0
        finally:
            db.close()
        reporter_name = f"C{existing_count + 1}"

    local_record = {
        "evidence_hash": "0x" + evidence_hash,
        "category": req.category,
        "reason": req.reason,
        "target": req.target,
        "timestamp": timestamp,
        "blockchain_logged": False,
        "tx_hash": "",
        "latitude": lat,
        "longitude": lon,
        "location": location_name,
        "reporter": reporter_name
    }

    # 2. Attempt logging to Hardhat Blockchain node
    from web3 import Web3
    w3 = Web3(Web3.HTTPProvider(RPC_URL))
    
    # Check if RPC connection is active
    if w3.is_connected():
        try:
            contract_address = get_contract_address()
            
            # Simplified ABI of CyberShieldRegistry
            abi = [
                {
                    "inputs": [
                        {"internalType": "string", "name": "_category", "type": "string"},
                        {"internalType": "string", "name": "_details", "type": "string"},
                        {"internalType": "string", "name": "_target", "type": "string"}
                    ],
                    "name": "logScam",
                    "outputs": [{"internalType": "bytes32", "name": "", "type": "bytes32"}],
                    "stateMutability": "nonpayable",
                    "type": "function"
                }
            ]
            
            contract = w3.eth.contract(address=w3.to_checksum_address(contract_address), abi=abi)
            account = w3.eth.account.from_key(DEFAULT_PRIVATE_KEY)
            
            # Build transaction
            nonce = w3.eth.get_transaction_count(account.address)
            gas_price = w3.eth.gas_price
            
            txn = contract.functions.logScam(
                req.category,
                req.reason,
                req.target
            ).build_transaction({
                'chainId': 31337, # Local hardhat chain id
                'gas': 300000,
                'gasPrice': gas_price,
                'nonce': nonce,
            })
            
            # Sign and send transaction
            signed_txn = w3.eth.account.sign_transaction(txn, private_key=DEFAULT_PRIVATE_KEY)
            tx_hash = w3.eth.send_raw_transaction(signed_txn.rawTransaction)
            tx_receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
            
            real_tx_hash = w3.to_hex(tx_hash)
            local_record["blockchain_logged"] = True
            local_record["tx_hash"] = real_tx_hash
            
            log_evidence_to_db(local_record)
            
            return {
                "success": True,
                "evidence_hash": "0x" + evidence_hash,
                "tx_hash": real_tx_hash,
                "source": "Hardhat Local Node"
            }
            
        except Exception as e:
            # Fall back to simulated logging if tx fails (e.g. contract not deployed yet)
            print(f"[CyberShield] Hardhat ledger transaction failed: {e}. Falling back to local simulated registry.")

    # 3. Simulated Fallback Logging (No node connected or error occurred)
    simulated_tx = "0x" + hashlib.sha256(f"simulated-tx-{raw_data}".encode()).hexdigest()
    local_record["tx_hash"] = simulated_tx
    log_evidence_to_db(local_record)

    return {
        "success": True,
        "evidence_hash": "0x" + evidence_hash,
        "tx_hash": simulated_tx,
        "source": "CyberShield Local Cache (Simulated blockchain write)"
    }

# Endpoint for dashboard to read all reports
@app.get("/blockchain/reports")
def get_all_reports():
    db = SessionLocal()
    try:
        records = db.query(EvidenceLog).order_by(EvidenceLog.id.asc()).all()
        return [r.to_dict() for r in records]
    except Exception as e:
        print(f"[CyberShield] DB read error: {e}")
        return []
    finally:
        db.close()

@app.post("/verify/email-headers")
def verify_email_headers(req: EmailHeadersRequest):
    import re
    text = req.headers_text
    
    spf_match = re.search(r'spf\s*=\s*(pass|fail|neutral|softfail|none)', text, re.IGNORECASE)
    dkim_match = re.search(r'dkim\s*=\s*(pass|fail|none)', text, re.IGNORECASE)
    dmarc_match = re.search(r'dmarc\s*=\s*(pass|fail|none)', text, re.IGNORECASE)
    
    spf_status = spf_match.group(1).upper() if spf_match else "UNKNOWN"
    dkim_status = dkim_match.group(1).upper() if dkim_match else "UNKNOWN"
    dmarc_status = dmarc_match.group(1).upper() if dmarc_match else "UNKNOWN"
    
    safe = True
    verdict = "SAFE"
    reason = "Email authentication records (SPF, DKIM, DMARC) verified successfully."
    
    if spf_status == "FAIL" or dkim_status == "FAIL":
        safe = False
        verdict = "MALICIOUS"
        reason = f"Spoofing Alert: Email headers validation failed (SPF: {spf_status}, DKIM: {dkim_status}). The sender domain registration does not authorize this message."
    elif spf_status == "UNKNOWN" and dkim_status == "UNKNOWN":
        safe = True
        verdict = "SUSPICIOUS"
        reason = "Missing security headers: SPF/DKIM authentication details not found. Identity verification is incomplete."
        
    return {
        "safe": safe,
        "verdict": verdict,
        "reason": reason,
        "details": {
            "spf": spf_status,
            "dkim": dkim_status,
            "dmarc": dmarc_status
        }
    }

@app.post("/verify/smart")
def verify_smart_endpoint(data: dict):
    value = data.get("value", "").strip()
    if not value:
        return {"error": "value required"}
    return check_any(value)

@app.post("/verify/phone")
def verify_phone_endpoint(data: dict):
    phone = data.get("phone", "").strip()
    if not phone:
        return {"error": "phone required"}
    return check_phone(phone)

@app.post("/verify/account")
def verify_account_endpoint(data: dict):
    acc = data.get("account_number", "").strip()
    if not acc:
        return {"error": "account_number required"}
    return check_account_number(acc)

@app.post("/mule/report")
def report_mule_endpoint(data: dict):
    return add_mule_account(
        upi_id=data.get("upi_id", ""),
        account_number=data.get("account_number", ""),
        phone=data.get("phone", ""),
        holder_name=data.get("holder_name", "Unknown"),
        category=data.get("category", "Reported Fraud"),
        notes=data.get("notes", ""),
        reported_by=data.get("reported_by", "Officer"),
        location=data.get("location", "Unknown"),
    )

@app.get("/mule/stats")
def mule_stats_endpoint():
    return get_stats()

@app.get("/mule/list")
def mule_list_endpoint():
    from mule_tracker import load_db
    db = load_db()
    return {
        "total": len(db["mule_accounts"]),
        "accounts": db["mule_accounts"]
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8090, reload=True)
