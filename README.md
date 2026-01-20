# encryyrced - A Tiny Message Sealing System

> *“Not all secrets need heavy armor. Some just need to be wrapped carefully.”*

encryyrced is a lightweight Python-based message **encoding + integrity verification** system.  
It lets you **seal a message**, send it safely, and **verify it hasn’t been tampered with** before reading.

This project is intentionally minimal — designed to demonstrate **encoding, hashing, and HMAC-based integrity checks**, not military-grade encryption.

---

## What’s Inside

.
├── encryption.py # Seals (encodes + signs) a message
├── decryption.py # Unseals (verifies + decodes) a message
└── README.md



---

## How It Works (High-Level)

### Encryption Flow
1. Message → UTF-8 text
2. Text → Hex encoding
3. Hex → Base64 encoding
4. Base64 → HMAC-SHA256 signature
5. Output → `encoded_message:signature`

### Decryption Flow
1. Split message & signature
2. Recompute HMAC using shared secret
3. Compare signatures securely
4. Decode Base64 → Hex → Original message

If **anything** changes in transit, decryption **fails loudly**

---

## Shared Secret (Important!)

Both files rely on a shared secret key:

```python
SECRET_KEY = "your_secret_here"

Usage

Encrypt a Message

In encryption.py:

message = "Hello, world!"
encrypted_msg = encrypt_message(message)
print(encrypted_msg)


Output will look like:

Njg2NTZjNmM2ZjI3NzY2ZjcyNmM2NA==:a1b2c3...

Decrypt a Message

Paste the encrypted output into decryption.py:

encrypted_msg = "PASTE_ENCRYPTED_MESSAGE_HERE"


Run the script:

python decryption.py


If valid:

Decrypted Message:
Hello, world!


If tampered:

Decryption failed: Invalid signature! Message integrity compromised.

What This Project Is (and Isn’t)

It IS

A demonstration of:

Encoding layers (Hex + Base64)

Message authentication (HMAC)

Secure comparison (compare_digest)

Great for learning data integrity concepts

It is NOT

Strong encryption

A replacement for AES / RSA / modern crypto libraries

Safe against key exposure

For real security, look into libraries like cryptography.

Why HMAC?

HMAC ensures:

Integrity — message wasn’t altered

Authenticity — sender knew the secret key

Even one changed character → verification fails.

Final Notes

This project is small by design.
Its goal is clarity over complexity, learning over hype.

Feel free to:

Extend it

Replace encoding with real encryption

Add file or network support

Happy hacking 🐙
