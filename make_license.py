import hashlib
import json
import os
from datetime import datetime, timedelta

# ملف التخزين
LICENSE_FILE = "license.key"

def generate_license_key(username: str, days_valid: int = 365):
    expiry_date = (datetime.now() + timedelta(days=days_valid)).strftime("%Y-%m-%d")
    raw = f"{username}-{expiry_date}-pcfix"
    key = hashlib.sha256(raw.encode()).hexdigest().upper()
    return {
        "user": username,
        "expiry": expiry_date,
        "key": key
    }

def save_license(data):
    with open(LICENSE_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
    print(f"✅ License key saved to {LICENSE_FILE}")

if __name__ == "__main__":
    print("=== PCFix License Generator ===")
    user = input("Enter username (or email): ").strip()
    days = input("Valid for how many days? [default 365]: ").strip()
    days = int(days) if days else 365

    license_data = generate_license_key(user, days)
    save_license(license_data)

    print("\n🔑 License info:")
    print(json.dumps(license_data, indent=2))
