## Overview
This project demonstrates a simplified cryptographic protocol for secure contract exchange between:

- **Hackit & Run LLP (H&R)**
- **Seller’s Solicitor (SS)**
- **Buyer (Mrs. Harvey)**

The protocol includes:
- Authenticated **ECDH** key exchange  
- **AES-GCM** encryption for confidentiality  
- **ECDSA** signatures for authenticity  
- Simulated session reuse for repeated communications  

---

## Directory Structure
```

root/  
┣ src/  
┃ ┣ demo.py → Main Python demo script  
┃ ┗ contract.txt → Sample contract file  
┣ keys/ 
┣ ┣ buyer_pub.pem 
┣ ┣ hr_pub.pem 
┣ ┗ hr_ss_session.bin
┣ appendix/  
┃ ┣ contract_encrypted_to_hr.bin  
┃ ┣ contract_signed_package_to_ss.bin  
┃ ┣ sequence_diagram.png  
┃ ┣ Output1.png / Output2.png  
┗ report.pdf → Final LaTeX report

```

---

## How to Run
### Prerequisites
Install the required library:
```

pip install cryptography

```

### Execution
Navigate into the `src/` directory and run:
```

python demo.py

```

### Behavior
1. Generates ECDSA keys for H&R, SS, and Buyer if not present.  
2. Checks if a `session_key.bin` exists — reuses it if available.  
3. Performs an authenticated ECDH exchange on first run.  
4. Encrypts and signs the contract exchange between parties.  
5. Saves encrypted and signed outputs in the appendix folder.  

---

## Output Files
| File | Description |
|------|--------------|
| contract_encrypted_to_hr.bin | Encrypted contract (Seller → H&R) |
| contract_signed_package_to_ss.bin | Final signed contract returned to Seller |
| contract.txt | Plaintext contract |
| sequence_diagram.png | Protocol message flow |
| Output1.png / Output2.png | Optional screenshots |

---

## Technical Details
- Curve: **secp256r1 (P-256)**  
- Encryption: **AES-GCM (128-bit)**  
- Signature: **ECDSA (SHA-256)**  
- Key Derivation: **HKDF (SHA-256)**  
- Communication: Simulated locally (no network)

---

## Author
**Arash**  
Cybersecurity Coursework — Assignment 1  
15 October 2025
