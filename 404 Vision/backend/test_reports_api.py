import urllib.request
import json

try:
    with urllib.request.urlopen("http://localhost:8090/blockchain/reports", timeout=5) as response:
        data = json.loads(response.read().decode())
        print("Backend Status: Success!")
        print(f"Loaded {len(data)} cases.")
        for record in data:
            print(f"- Hash: {record.get('evidence_hash')[:10]}... | Category: {record.get('category')} | Target: {record.get('target')} | Location: {record.get('location')} | Reporter: {record.get('reporter')}")
except Exception as e:
    print("Failed to query backend API:", e)
