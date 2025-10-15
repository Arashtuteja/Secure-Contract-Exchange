#demo.py
"""
Simple protocol demo:
- Uses ECDSA key pairs saved in ../keys
- If session_key exists (session_key.bin), reuses it (simulates repeated comms)
- Otherwise performs an authenticated ECDH-like ephemeral exchange simulation
- AES-GCM used for contract encryption
"""

from cryptography.hazmat.primitives import hashes, serialization, hmac
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.asymmetric import ec, utils
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os, time

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
KEYS_DIR = os.path.abspath(os.path.join(BASE_DIR, "../keys"))
APPENDIX_DIR = os.path.abspath(os.path.join(BASE_DIR, "../appendix"))
os.makedirs(KEYS_DIR, exist_ok=True)
os.makedirs(APPENDIX_DIR, exist_ok=True)

#  Helper: load or create long-term ECDSA keys (for H&R and Seller's solicitor and Buyer) 
def load_or_create_keypair(name):
    priv_path = os.path.join(KEYS_DIR, f"{name}_priv.pem")
    pub_path = os.path.join(KEYS_DIR, f"{name}_pub.pem")
    if os.path.exists(priv_path) and os.path.exists(pub_path):
        with open(priv_path, "rb") as f:
            priv = serialization.load_pem_private_key(f.read(), password=None)
        with open(pub_path, "rb") as f:
            pub = serialization.load_pem_public_key(f.read())
    else:
        priv = ec.generate_private_key(ec.SECP256R1())
        pub = priv.public_key()
        with open(priv_path, "wb") as f:
            f.write(priv.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            ))
        with open(pub_path, "wb") as f:
            f.write(pub.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ))
    return priv, pub

# KDF for deriving session keys from ECDH shared secret
def derive_session_key(shared_secret, info=b"hrs-ss-session"):
    hkdf = HKDF(algorithm=hashes.SHA256(), length=16, salt=None, info=info)
    return hkdf.derive(shared_secret)

# Sign/verify helpers
def sign_bytes(priv, data):
    return priv.sign(data, ec.ECDSA(hashes.SHA256()))

def verify_sig(pub, sig, data):
    try:
        pub.verify(sig, data, ec.ECDSA(hashes.SHA256()))
        return True
    except Exception:
        return False

# AES-GCM encrypt/decrypt
def aesgcm_encrypt(key, plaintext, aad=None):
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    ct = aesgcm.encrypt(nonce, plaintext, aad)
    return nonce + ct

def aesgcm_decrypt(key, payload, aad=None):
    aesgcm = AESGCM(key)
    nonce = payload[:12]
    ct = payload[12:]
    return aesgcm.decrypt(nonce, ct, aad)

# Simulate authenticated ECDH handshake between H&R and Seller's Solicitor
def authenticated_ecdh(priv_longterm, peer_pub_longterm):
    # generate ephemeral key
    eph_priv = ec.generate_private_key(ec.SECP256R1())
    eph_pub_bytes = eph_priv.public_key().public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.UncompressedPoint
    )
    # sign ephemeral public key using long term key
    sig = sign_bytes(priv_longterm, eph_pub_bytes)
    # Normally we'd send eph_pub_bytes + sig + cert and peer verifies
    # For this demo, return eph_priv and the signed bytes for the peer to verify
    return eph_priv, eph_pub_bytes, sig

# Demo workflow
def demo():
    # Load/create keys for H&R, Seller Solicitor (SS), and Buyer (B)
    hr_priv, hr_pub = load_or_create_keypair("hr")
    ss_priv, ss_pub = load_or_create_keypair("ss")
    b_priv, b_pub = load_or_create_keypair("buyer")

    # Check for existing session key between H&R and SS (simulate prior comms)
    session_path = os.path.join(KEYS_DIR, "hr_ss_session.bin")
    if os.path.exists(session_path):
        with open(session_path, "rb") as f:
            session_key = f.read()
        print("[demo] Reusing existing session key (H&R <-> SS).")
    else:
        # First-time: authenticated ECDH handshake simulation
        print("[demo] No session key found. Performing authenticated ECDH handshake (simulated).")
        # H&R -> SS
        eph_hr_priv, eph_hr_pub_bytes, sig_hr = authenticated_ecdh(hr_priv, ss_pub)
        # SS verifies H&R signature (would check cert in real world)
        if not verify_sig(hr_pub, sig_hr, eph_hr_pub_bytes):
            raise SystemExit("[demo] H&R signature verification failed at SS.")
        # SS creates its ephemeral and signs
        eph_ss_priv, eph_ss_pub_bytes, sig_ss = authenticated_ecdh(ss_priv, hr_pub)
        if not verify_sig(ss_pub, sig_ss, eph_ss_pub_bytes):
            raise SystemExit("[demo] SS signature verification failed at H&R.")
        # compute shared secret both sides
        shared1 = eph_hr_priv.exchange(ec.ECDH(), ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), eph_ss_pub_bytes))
        session_key = derive_session_key(shared1)
        with open(session_path, "wb") as f:
            f.write(session_key)
        print("[demo] Derived & stored session key (H&R <-> SS).")

    # Read contract bytes
    contract_file = os.path.join(BASE_DIR, "contract.txt")
    if not os.path.exists(contract_file):
        with open(contract_file, "wb") as f:
            f.write(b"Sample Contract: Parcel of land sale between Mrs. Harvey and Mr L.M. Facey.\n")
    with open(contract_file, "rb") as f:
        contract_bytes = f.read()

    # SS encrypts contract to H&R
    ts = str(int(time.time())).encode()
    ss_payload = contract_bytes + b"\n---META---\n" + ts
    enc = aesgcm_encrypt(session_key, ss_payload)
    enc_path = os.path.join(APPENDIX_DIR, "contract_encrypted_to_hr.bin")
    with open(enc_path, "wb") as f:
        f.write(enc)
    print("[demo] Seller -> H&R: Encrypted contract saved.")

    # H&R decrypts and forwards to Buyer (for demo we simulate H&R->Buyer direct using AES with new ephemeral key)
    decrypted = aesgcm_decrypt(session_key, enc)
    # Buyer verifies content, signs digest+timestamp
    digest = hashes.Hash(hashes.SHA256())
    digest.update(decrypted)
    doc_hash = digest.finalize()
    # Sign the document hash + ts to capture binding
    signature = sign_bytes(b_priv, doc_hash + ts)
    # H&R verifies buyer signature
    if verify_sig(b_pub, signature, doc_hash + ts):
        print("[demo] Buyer signature verified at H&R.")
    else:
        print("[demo] Buyer signature verification FAILED at H&R.")

    # H&R sends signed package back to SS under session_key
    signed_pkg = decrypted + b"\n---SIGNATURE---\n" + signature
    enc_back = aesgcm_encrypt(session_key, signed_pkg)
    final_path = os.path.join(APPENDIX_DIR, "contract_signed_package_to_ss.bin")
    with open(final_path, "wb") as f:
        f.write(enc_back)
    print("[demo] Signed package encrypted and saved for SS.")

    print("[demo] Demo complete. Files in:", APPENDIX_DIR)

if __name__ == "__main__":
    demo()
