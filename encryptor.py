import base64, hashlib, json, qrcode
from datetime import datetime
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

def generate_key(password: str) -> bytes:
    hashed = hashlib.sha256(password.encode()).digest()
    return hashed  # 32 bytes for AES-256

def encrypt_payload(message: str, room_code: str, password: str) -> str:
    payload = {
        "room": room_code,
        "data": message,
        "timestamp": datetime.now().isoformat()
    }
    raw = json.dumps(payload).encode()
    key = generate_key(password)
    cipher = AES.new(key, AES.MODE_ECB)
    encrypted = cipher.encrypt(pad(raw, AES.block_size))
    return base64.b64encode(encrypted).decode()

def generate_qr(encrypted_text: str, filename: str = "encrypted_qr.png"):
    qr = qrcode.QRCode(
        version=5,
        error_correction=qrcode.constants.ERROR_CORRECT_H,
        box_size=10,
        border=4
    )
    qr.add_data(encrypted_text)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    img.save(filename)
    print(f"✅ QR code saved as {filename}")

if __name__ == "__main__":
    message = input("📥 Enter secret message: ")
    room_code = input("🏷 Enter room code: ")
    password = input("🔑 Enter password: ")
    encrypted_text = encrypt_payload(message, room_code, password)
    print(f"\n🔐 Encrypted (base64): {encrypted_text}\n")
    generate_qr(encrypted_text)
