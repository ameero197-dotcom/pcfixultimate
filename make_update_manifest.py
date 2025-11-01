import hashlib
import json
import os

# إعدادات المسار والإصدار
exe_path = os.path.join("dist", "PCFixUltimate", "PCFixUltimate.exe")
version = input("Enter new version (مثلاً 1.0.5): ").strip()
base_url = "https://ameero197-dotcom.github.io/pcfixultimate/dist/PCFixUltimate.exe"

# حساب SHA256 للملف التنفيذي
if not os.path.exists(exe_path):
    raise FileNotFoundError(f"EXE not found: {exe_path}")

with open(exe_path, "rb") as f:
    sha256 = hashlib.sha256(f.read()).hexdigest()

manifest = {
    "version": version,
    "url": base_url,
    "sha256": sha256
}

docs_path = "docs"
os.makedirs(docs_path, exist_ok=True)
json_path = os.path.join(docs_path, "latest.json")

with open(json_path, "w", encoding="utf-8") as f:
    json.dump(manifest, f, indent=2, ensure_ascii=False)

print(f"✅ Manifest updated at {json_path}")
print(json.dumps(manifest, indent=2, ensure_ascii=False))
