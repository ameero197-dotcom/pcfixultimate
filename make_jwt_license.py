from datetime import datetime, timezone
from cryptography.hazmat.primitives.serialization import pkcs12
import jwt

PFX_PATH = r".\keys\pcfix-self.pfx"
PFX_PASSWORD = b"152352"   # نفس كلمة السر اللي استخدمناها للتصدير
OUT_PATH = r".\keys\license.key"

# معلومات الترخيص
USER = "pcfixultimate"
EXP  = datetime(2035, 10, 30, 23, 59, 59, tzinfo=timezone.utc)  # انتهاء الترخيص

# 1) حمّل المفتاح الخاص من الـ PFX
with open(PFX_PATH, "rb") as f:
    pfx_data = f.read()

private_key, cert, add = pkcs12.load_key_and_certificates(pfx_data, PFX_PASSWORD)

# 2) ابنِ الـ JWT ووقّعه بـ RS256
payload = {
    "sub": USER,
    "exp": int(EXP.timestamp()),
}
token = jwt.encode(payload, private_key, algorithm="RS256")

# 3) احفظ التوكن كنص خام (بدون JSON) في license.key
with open(OUT_PATH, "w", encoding="utf-8") as f:
    f.write(token)

print("OK: JWT license written to", OUT_PATH)
