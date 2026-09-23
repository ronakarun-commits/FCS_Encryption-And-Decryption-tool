# Secure File Encryption Tool

## Project Title
Secure File Encryption and Decryption Tool

## Project Context
This project is a mini-project for Fundamentals of Cyber Security (FCS). It is designed as a local desktop application that demonstrates the use of modern symmetric encryption, password-based key derivation, authentication, secure file handling, and basic secure software design in Python.

## Problem Statement
Files often need to be protected from unauthorized access. A desktop application can help encrypt files using a password and later decrypt them only with the correct password. The project demonstrates how confidentiality, integrity, and authentication can be supported using cryptographic primitives in a practical and educational way.

## Aim
To build a secure local desktop application that encrypts and decrypts files using a password while ensuring the encrypted data remains protected and authenticated.

## Objectives
- Encrypt arbitrary binary files securely.
- Derive a strong AES key from a user password using PBKDF2.
- Store essential metadata in a custom file header.
- Authenticate encrypted content using AES-GCM.
- Decrypt only after integrity verification succeeds.
- Provide a small Tkinter-based desktop interface.
- Document the project clearly for academic use.

## Features
- AES-256-GCM encryption
- PBKDF2-HMAC-SHA256 key derivation with 600,000 iterations
- Random 16-byte salt per file
- Random 12-byte nonce per file
- Custom SFET encrypted file format
- SHA-256 file hashing for educational verification
- Tkinter GUI with file selection, password input, and status updates
- Threaded encryption and decryption operations
- Safe logging without storing secrets

## Technology Stack
- Python 3
- Tkinter
- cryptography package
- hashlib
- pathlib
- logging
- threading

## System Architecture
The application is divided into a few Python modules:

- main.py: starts the GUI
- gui.py: handles the desktop interface and worker threads
- crypto_utils.py: implements encryption, decryption, and validation logic
- file_utils.py: handles hashing, file utilities, and logging
- tests/test_crypto.py: validates critical cryptographic behavior

## Encryption Workflow
1. A file is selected by the user.
2. A password is entered.
3. A random salt is created.
4. A PBKDF2-derived AES key is generated from the password and salt.
5. A random nonce is generated.
6. AAD is built from version, KDF ID, filename, and file size.
7. AES-256-GCM encrypts the plaintext.
8. The SFET header and ciphertext are written to a .enc file.

## Decryption Workflow
1. A user chooses the encrypted file.
2. The password is entered.
3. The header is parsed and validated.
4. The salt, nonce, and iteration count are extracted.
5. The key is re-derived from the password and stored salt.
6. The deterministic AAD is reconstructed.
7. AES-GCM decrypts the ciphertext only after tag verification passes.
8. The plaintext is written to disk only after successful authentication.

## AES-256-GCM Explanation
AES-GCM is a symmetric authenticated encryption mode. It provides both confidentiality and integrity. The plaintext is encrypted with AES-256, and the authentication tag verifies that the ciphertext and associated metadata were not altered.

## PBKDF2 Explanation
PBKDF2 is a password-based key derivation function. It transforms a user password into a fixed-length key using a salt and a large number of iterations. In this implementation, PBKDF2-HMAC-SHA256 with 600,000 iterations is used to slow down brute-force attacks and protect the key derivation process.

## Salt Explanation
A salt is a random value added to the password before derivation. It ensures identical passwords do not produce identical keys across different files. The salt is not secret and is stored in the encrypted file header.

## Nonce Explanation
A nonce is a unique random value used with AES-GCM. It must never repeat for the same key. The nonce is stored in the header so the correct decryption key can be derived and used with the ciphertext.

## Authentication Tag Explanation
AES-GCM produces an authentication tag during encryption. The tag is verified during decryption. If any part of the ciphertext or associated metadata has changed, the tag fails and decryption is rejected.

## AAD Explanation
Associated Authenticated Data (AAD) is non-secret metadata that is authenticated but not encrypted. This project authenticates the file format version, KDF identifier, original filename, and file size. This helps detect tampering of metadata even though it is not encrypted.

## SHA-256 Explanation
SHA-256 is a hashing algorithm used here as an educational file-integrity verification feature. It is not required for AES-GCM's ciphertext authentication. AES-GCM already provides authenticated encryption for the ciphertext and metadata. SHA-256 is included only to demonstrate a simple hash-based verification concept in a classroom context.

## Custom Encrypted File Format
The project uses a custom binary format called SFET (Secure File Encryption Tool):

- Magic number: SFET
- Version: 1
- KDF ID: 1
- PBKDF2 iterations: 600000
- Salt: 16 bytes
- Nonce: 12 bytes
- Filename length: 2 bytes
- Original filename
- Ciphertext + authentication tag

## Installation
1. Install Python 3.10+.
2. Open a terminal in the project folder.
3. Install dependencies:

```bash
pip install -r requirements.txt
```

## Usage
Run the application with:

```bash
python main.py
```

Then:
- Select a file
- Enter a password
- Choose an output location
- Click Encrypt or Decrypt
- Use the SHA-256 button for manual verification

## Testing
Run the test suite with:

```bash
python -m unittest discover -s tests -v
```

## Security Considerations
- Passwords are never stored.
- AES keys are never written to disk.
- Only PBKDF2-derived keys are used.
- AES-GCM authentication is mandatory before decryption output is written.
- Incorrect passwords lead to authentication failure.
- Any ciphertext modification is rejected.
- The implementation uses cryptographically secure randomness from os.urandom().

## Limitations
This project reads files fully into memory. This is acceptable for a mini-project, but large files may consume substantial RAM. For large-scale production use, a streaming or chunked authenticated encryption design would be better.

## Future Improvements
- Argon2id password hashing
- Streaming/chunked AEAD processing
- Better password-strength estimation
- Secure key management with OS key stores
- Hardware-backed key storage
- Drag-and-drop support
- Batch encryption and decryption
- Encrypted folder support
- Cloud storage integration
- Cross-platform packaging
- Advanced audit logging

## Project Structure

```text
SecureFileEncryption/
├── main.py
├── gui.py
├── crypto_utils.py
├── file_utils.py
├── requirements.txt
├── README.md
├── .gitignore
├── encrypted_files/
├── decrypted_files/
├── test_files/
├── logs/
└── tests/
    └── test_crypto.py
```

## Final Notes
AES-GCM already provides message authentication. SHA-256 is included mainly for educational understanding, not as a replacement for AES-GCM's integrity protection. Argon2id is a modern alternative to PBKDF2 for password-stretching and would be a strong future upgrade.
