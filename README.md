# Secure File Encryption Tool

## Overview

Secure File Encryption Tool is a local Python desktop application for protecting files with a password. It uses AES-GCM to encrypt the file and verify that it has not been changed. The password is converted into an encryption key with a password-based key derivation function (KDF), using PBKDF2 or the optional Argon2id method.

The application provides a Tkinter GUI where users can select a file, choose a KDF, encrypt or decrypt the file, and calculate a SHA-256 checksum. Encrypted files use the custom SFET format, which stores the information needed for secure decryption without storing the password or encryption key.

### Basic workflow

```text
Select file + enter password
        |
        v
    PBKDF2 or Argon2id
        |
        v
     AES-256-GCM
        |
        v
    encrypted_file.enc
```

To decrypt a file, select the `.enc` file and enter the same password used during encryption. The application reads the encrypted header, derives the key again, verifies the AES-GCM authentication tag, and writes the original file only when authentication succeeds.

### What the tool protects against

- Unauthorized reading of the encrypted file
- Incorrect passwords
- Modified or tampered encrypted files
- Partially written output files caused by an interrupted write

This is an educational local application. Users should keep strong passwords and retain backups of important original files.

## Project Title
Secure File Encryption and Decryption Tool

## Project Context
This project is a simple local desktop application for encrypting and decrypting files with a password. It is built for educational learning in cyber security and demonstrates modern symmetric encryption, authenticated data, password-based key derivation, and safe file handling in Python.

## Problem Statement
Files often need to be protected from unauthorized access. This tool allows the user to encrypt a file with a password and later decrypt it only when the correct password is supplied. The project focuses on confidentiality, integrity, and authentication using real cryptographic primitives in a way that is easy to understand.

## Aim
To build a secure and beginner-friendly tool that encrypts and decrypts files while ensuring the data is authenticated and protected from tampering.

## Objectives
- Encrypt ordinary files securely.
- Derive a strong key from a password using PBKDF2 or Argon2id.
- Store metadata in a custom SFET header.
- Use AES-GCM for authenticated encryption.
- Refuse decryption if tampering or a wrong password is detected.
- Provide a simple Tkinter GUI.
- Keep the code easy to read and learn from.

## New Features Added
- Argon2id support as an optional stronger password-based key derivation method
- Temp-file + atomic write flow to avoid partially-written files
- Chunked file reading for simpler memory-friendly processing
- Better GUI validation for missing input and weak passwords
- File-size display in the interface
- Improved default output handling and safer user interaction
- Cleaner beginner-friendly code structure

## Core Features
- AES-256-GCM encryption
- PBKDF2-HMAC-SHA256 with 600,000 iterations
- Optional Argon2id KDF support
- Random 16-byte salt per file
- Random 12-byte nonce per file
- Custom SFET file format
- SHA-256 hashing for verification
- Tkinter GUI for file selection, password entry, and status updates
- Threaded operations for encryption and decryption
- Safe logging without storing secrets

## Technology Stack
- Python 3
- Tkinter
- cryptography
- argon2-cffi
- hashlib
- pathlib
- logging
- threading

## System Architecture
The application is divided into a few Python modules:

- main.py: starts the GUI
- gui.py: handles the desktop interface and worker threads
- crypto_utils.py: implements encryption, decryption, validation, and key derivation
- file_utils.py: handles hashing, path logic, and logging
- tests/test_crypto.py: validates critical behavior

## Encryption Workflow
1. A file is selected by the user.
2. A password is entered.
3. A random salt is generated.
4. A key is derived using PBKDF2 or Argon2id.
5. A random nonce is generated.
6. AAD is built from version, KDF ID, filename, and file size.
7. AES-GCM encrypts the plaintext.
8. The SFET header and ciphertext are written to disk using atomic file writing.

## Decryption Workflow
1. A user chooses an encrypted file.
2. A password is entered.
3. The SFET header is parsed and validated.
4. The salt, nonce, and KDF data are extracted.
5. The key is re-derived using the same password and KDF.
6. The AAD is reconstructed.
7. AES-GCM verifies the tag before decryption is allowed.
8. The output file is written only after successful authentication.

## Password Derivation Explained
### PBKDF2
PBKDF2 is a classic password-based key derivation method. It stretches the password using a salt and many iterations, which makes brute-force attacks slower.

### Argon2id
Argon2id is a modern password hashing and key derivation method. It is designed to be memory-hard, which makes it stronger against large-scale password attacks.

## AES-GCM Explanation
AES-GCM is an authenticated encryption mode. It provides both confidentiality and integrity. The plaintext is encrypted with AES-256, and the authentication tag ensures that the data was not modified.

## Salt and Nonce Explanation
- Salt: a random value added before key derivation so identical passwords do not generate identical keys
- Nonce: a random value used once for AES-GCM encryption so the same key can safely encrypt multiple files

## Authentication Tag Explanation
AES-GCM creates an authentication tag during encryption. During decryption, the tag is checked. If the data or metadata was changed, the decryption fails and the file is rejected.

## AAD Explanation
Associated Authenticated Data (AAD) is metadata that is authenticated but not encrypted. This project includes the file version, KDF ID, filename, and file size.

## SHA-256 Explanation
SHA-256 is used as a file-integrity check and educational verification method. It is not a replacement for AES-GCM authentication.

## Custom Encrypted File Format
The project uses a custom binary format called SFET (Secure File Encryption Tool):

- Magic number: SFET
- Version: 1
- KDF ID: 1 or 2
- Iteration count or Argon2 time cost
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
- Choose the KDF (PBKDF2 or Argon2id if available)
- Pick an output folder
- Click Encrypt or Decrypt
- Use the SHA-256 button for manual verification

## Testing
Run the full test suite with:

```bash
python -m unittest discover -s tests -v
```

## Security Considerations
- Passwords are never stored.
- AES keys are never written to disk.
- The KDF is derived from the password and a random salt.
- AES-GCM authentication is required before output is written.
- Wrong passwords and tampered files fail authentication.
- Files are written using atomic file replacement to reduce corruption risk.
- The implementation uses cryptographically secure randomness from os.urandom().

## Limitations
This project is kept simple for learning. It reads files into memory and is best suited for ordinary personal files rather than very large datasets. For production-scale use, a streaming authenticated file format would be more efficient.

## Future Improvements
- Add batch encryption and batch decryption
- Add drag-and-drop support
- Add a command-line interface
- Add stronger password guidance and leak checking
- Package the app for Windows/macOS/Linux
- Add encryption for entire folders

## Project Structure

```text
FCS_Encryption-And-Decryption-tool/
├── main.py
├── gui.py
├── crypto_utils.py
├── file_utils.py
├── requirements.txt
├── README.md
├── ui/
│   ├── __init__.py
│   ├── helpers.py
│   └── main_window.py
├── encrypted_files/
├── decrypted_files/
├── test_files/
├── logs/
├── tests/
│   └── test_crypto.py
└── features/
    ├── __init__.py
    ├── kdf_utils.py
    ├── password_validation.py
    ├── safe_io.py
    └── batch_operations.py
```

### Folder-by-Folder Explanation

#### ui/
This folder contains the desktop GUI layer. It stores the Tkinter user interface modules, keeps the window logic separate from the encryption logic, and makes the app easier to maintain and extend. This is where the on-screen controls, file selection, password validation, and status updates are organized.

#### tests/
This folder contains the automated test suite. It verifies that encryption and decryption work correctly, checks security edge cases like tampering and wrong passwords, and guards the project from regressions.

#### encrypted_files/
This is the default folder for encrypted output files. When a file is encrypted, the result is usually saved here so the original file remains separate from the protected version.

#### decrypted_files/
This is the default folder for restored output files. It keeps decrypted data in a separate location so users can compare or recover files safely.

#### logs/
This folder stores activity logs for the application. Logs may include successful operations, errors, or file processing events that are useful for debugging and auditing.

#### test_files/
This folder contains sample or test data used to validate the app. It provides example files for manual testing without risking important personal files.

#### features/
This folder organizes the reusable feature modules used across the app. It keeps logic like KDF handling, password validation, atomic file writing, and batch operations in smaller, focused files instead of putting everything into one large script.

#### Root-level files
- main.py: starts the application
- gui.py: compatibility entry point for the desktop UI
- crypto_utils.py: implements the cryptographic logic
- file_utils.py: contains helper functions such as hashing, file handling, and logging
- requirements.txt: lists Python dependencies
- README.md: documentation for setup, usage, and architecture

## Final Notes
This project remains beginner-friendly, but it has been updated with safer file handling and stronger key-derivation choices. PBKDF2 is kept for simplicity and compatibility, while Argon2id is available as a stronger option when the dependency is installed.
