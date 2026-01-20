import base64
import hashlib
import hmac

SECRET_KEY = "**"  # replace with the same secret key used in encryption.py


def decrypt_message(encoded_message):
    """Decodes a Base64-encoded message and verifies its integrity using HMAC."""
    try:
        base64_encoded, provided_signature = encoded_message.rsplit(":", 1)

        # Verify HMAC signature
        expected_signature = hmac.new(SECRET_KEY.encode(), base64_encoded.encode(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected_signature, provided_signature):
            raise ValueError("Invalid signature! Message integrity compromised.")

        # Decode message
        hex_decoded = base64.b64decode(base64_encoded).decode('utf-8')
        return bytes.fromhex(hex_decoded).decode('utf-8')

    except Exception as e:
        return f"Decryption failed: {e}"
encrypted_msg = ""  # Replace with the actual encrypted message

# Decrypting the message
decrypted_msg = decrypt_message(encrypted_msg)
print(f"Decrypted Message:\n{decrypted_msg}")
