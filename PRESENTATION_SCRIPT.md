# 20-Minute Presentation Script (3 Speakers)

Project: **Secure File Encryption and Decryption Tool**  
Audience: Teacher and students  
Total Duration: **20 minutes**

---

## Speaker Split and Timing

- **Speaker 1:** 0:00 to 6:30
- **Speaker 2:** 6:30 to 13:00
- **Speaker 3:** 13:00 to 20:00

---

## Speaker 1 Script (0:00 to 6:30)

### 0:00 to 1:00 — Opening
“Good morning/afternoon everyone.  
We are presenting our mini-project for Fundamentals of Cyber Security: **Secure File Encryption and Decryption Tool**.  
In this presentation, we will explain why we built this project, how it works, and what security features it provides.”

### 1:00 to 3:00 — Problem and Aim
“Many important files are stored on personal systems without strong protection.  
If someone gets unauthorized access, private data can be exposed.  
Our aim was to build a local desktop tool that lets users encrypt files with a password and decrypt them only with the correct password.”

### 3:00 to 5:00 — Objectives and Features
“Our key objectives were:
- encrypt any file type securely,
- derive keys from user passwords safely,
- verify integrity during decryption,
- and provide a simple GUI for usability.

Main features include AES-256-GCM encryption, PBKDF2 key derivation with 600,000 iterations, random salt and nonce per file, a custom SFET file format, and a Tkinter-based desktop interface.”

### 5:00 to 6:30 — Architecture
“The project is modular:
- `main.py` starts the app,
- `gui.py` handles interface and user actions,
- `crypto_utils.py` contains encryption/decryption logic,
- `file_utils.py` provides hashing and logging utilities,
- and `tests/test_crypto.py` validates core behavior.”

“Now I hand over to Speaker 2 for the cryptographic workflow.”

---

## Speaker 2 Script (6:30 to 13:00)

### 6:30 to 9:30 — Encryption Workflow
“In encryption:
1. User selects a file and enters a password.
2. A random 16-byte salt is generated.
3. A 256-bit key is derived using PBKDF2-HMAC-SHA256 with 600,000 iterations.
4. A random 12-byte nonce is generated.
5. AAD is built from metadata like version, KDF ID, file name, and file size.
6. AES-256-GCM encrypts the file and produces ciphertext plus authentication tag.
7. Data is stored in our SFET format with required header fields.”

### 9:30 to 11:30 — Decryption Workflow
“In decryption:
1. Header is parsed and validated.
2. Salt, nonce, and iteration count are extracted.
3. Key is derived again from entered password.
4. AAD is reconstructed exactly.
5. AES-GCM verifies authenticity and decrypts only if verification passes.

If password is incorrect or data is tampered, authentication fails and plaintext is not written.”

### 11:30 to 13:00 — Security Design Highlights
“Why this is secure:
- AES-GCM provides confidentiality and integrity together.
- PBKDF2 slows brute-force attempts.
- Salt prevents same-password same-key reuse across files.
- Nonce ensures uniqueness for encryption.
- Metadata is authenticated using AAD.

So, both privacy and tamper-detection are handled.”

“Now Speaker 3 will show operation, testing, and conclusion.”

---

## Speaker 3 Script (13:00 to 20:00)

### 13:00 to 16:00 — Demo Talk Track
“We run the app using:
`python main.py`

Demo flow:
1. Select a sample file.
2. Enter password.
3. Click Encrypt to generate `.enc` file.
4. Select encrypted file and click Decrypt.
5. Show successful output and status.

If we use a wrong password or modify encrypted data, decryption fails due to authentication checks.”

### 16:00 to 17:30 — Testing Evidence
“We tested the core cryptographic behavior using unit tests in `tests/test_crypto.py`:
- round-trip encryption/decryption,
- wrong password handling,
- tampering detection,
- header validation,
- and output file conflict handling.

This helps confirm expected secure behavior.”

### 17:30 to 19:00 — Limitations and Future Work
“Current limitation: files are processed in memory, so very large files may use high RAM.

Future improvements:
- streaming/chunked encryption,
- Argon2id for password hardening,
- stronger key management options,
- better cross-platform packaging and UX.”

### 19:00 to 20:00 — Closing
“To conclude, our project demonstrates practical application of cybersecurity fundamentals:
secure encryption, authentication, and safe decryption in a user-friendly desktop tool.

Thank you for listening. We are ready for questions.”

---

## Quick Q&A Preparation

- **Why AES-GCM?** It provides encryption and integrity in one mode.
- **Why PBKDF2 with high iterations?** To make password guessing attacks more expensive.
- **What if encrypted file is changed?** Authentication fails and decryption is rejected.
- **Can it scale to large files?** Not efficiently yet; streaming mode is planned.
