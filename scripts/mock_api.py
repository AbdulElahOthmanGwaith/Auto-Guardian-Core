import json
import random
import time
import os
from datetime import datetime

def generate_mock_data():
    """توليد بيانات أمان وهمية لمحاكاة التدفق اللحظي"""
    threat_types = ["Brute Force", "SQL Injection", "XSS Attack", "Port Scan", "DDoS Attempt"]
    locations = ["الرياض, SA", "دبي, UAE", "القاهرة, EG", "نيويورك, US", "لندن, UK"]
    
    data = {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "active_threats": random.randint(0, 15),
        "system_load": f"{random.randint(10, 85)}%",
        "recent_events": [
            {
                "id": i,
                "type": random.choice(threat_types),
                "source": f"{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}",
                "location": random.choice(locations),
                "severity": random.choice(["high", "medium", "low"]),
                "status": "Blocked"
            } for i in range(5)
        ]
    }
    return data

def update_api_file():
    output_path = "public/data/live_stats.json"
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    
    print("Starting Mock API Service (Simulated)...")
    try:
        while True:
            data = generate_mock_data()
            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=4, ensure_ascii=False)
            print(f"[{data['timestamp']}] API Updated with {data['active_threats']} active threats.")
            time.sleep(10) # تحديث كل 10 ثوانٍ
    except KeyboardInterrupt:
        print("API Service Stopped.")

if __name__ == "__main__":
    update_api_file()
