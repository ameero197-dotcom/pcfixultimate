from cryptography import x509
from cryptography.hazmat.primitives import serialization

with open(r".\keys\pcfix.cer","rb") as f:
    data = f.read()

try:
    cert = x509.load_pem_x509_certificate(data)
except Exception:
    cert = x509.load_der_x509_certificate(data)

pub = cert.public_key()
pem = pub.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)
with open(r".\keys\public.pem","wb") as f:
    f.write(pem)

print("OK: .\\keys\\public.pem created")
