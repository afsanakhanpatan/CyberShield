import cv2
import numpy as np
import base64
from verifiers.upi_verifier import verify_upi_address
from verifiers.domain_verifier import check_safe_browsing, check_typosquatting

def decode_qr_base64(image_b64: str) -> dict:
    """
    Decodes QR code from a base64 encoded image string,
    and runs the extracted content through the safety pipelines.
    """
    try:
        # Decode base64 string
        img_bytes = base64.b64decode(image_b64)
        nparr = np.frombuffer(img_bytes, np.uint8)
        img = cv2.imdecode(nparr, cv2.IMREAD_COLOR)
        
        if img is None:
            return {
                "decoded": False,
                "data": "",
                "verification": {"safe": True, "verdict": "SAFE", "reason": "Failed to load image payload"}
            }

        # Initialize OpenCV QR Code detector
        detector = cv2.QRCodeDetector()
        data, bbox, straight_qrcode = detector.detectAndDecode(img)

        if not data:
            return {
                "decoded": False,
                "data": "",
                "verification": {"safe": True, "verdict": "SAFE", "reason": "No QR code detected"}
            }

        # Run verification checks on decoded data
        verification = {"safe": True, "verdict": "SAFE", "reason": "QR content appears safe"}
        
        # 1. UPI payment payload check
        if data.lower().startswith("upi://"):
            upi_check = verify_upi_address(data)
            if not upi_check["safe"]:
                verification = {
                    "safe": False,
                    "verdict": upi_check["verdict"],
                    "reason": f"Fraudulent payment QR: {upi_check['reason']}"
                }
                
        # 2. URL check
        elif data.lower().startswith(("http://", "https://")):
            # Check typosquatting
            typo_check = check_typosquatting(data)
            if not typo_check["safe"]:
                verification = {
                    "safe": False,
                    "verdict": "MALICIOUS",
                    "reason": f"Malicious link QR: {typo_check['reason']}"
                }
            else:
                # Check threat intelligence databases
                sb_check = check_safe_browsing(data)
                if not sb_check["safe"]:
                    verification = {
                        "safe": False,
                        "verdict": "MALICIOUS",
                        "reason": f"Malicious link QR: {sb_check['reason']}"
                    }

        return {
            "decoded": True,
            "data": data,
            "verification": verification
        }

    except Exception as e:
        return {
            "decoded": False,
            "data": "",
            "verification": {"safe": True, "verdict": "SAFE", "reason": f"QR Processing Error: {str(e)}"}
        }
