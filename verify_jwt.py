from cryptography.hazmat.primitives import serialization
import jwt, sys

PUB_PATH = r".\public.pem"      # بجانب PCFixUltimate.py
LIC_PATH = r".\license.key"     # بجانب PCFixUltimate.py

# اقرأ المفتاح العام
with open(PUB_PATH, "rb") as f:
    public_pem = f.read()

# اقرأ التوكن
with open(LIC_PATH, "r", encoding="utf-8") as f:
    token = f.read().strip()

print("== Decoding with RS256 ==")
try:
    payload = jwt.decode(token, public_pem, algorithms=["RS256"])
    print("OK payload:", payload)
except Exception as e:
    print("DECODE ERROR:", repr(e))
