import base64
import hashlib
import hmac

SECRET_KEY = ":))"  # Should be kept secret and shared securely

def encrypt_message(message):
    """Encrypts a message by encoding it in hex and Base64, then appends an HMAC hash."""
    hex_encoded = message.encode('utf-8').hex()
    base64_encoded = base64.b64encode(hex_encoded.encode('utf-8')).decode('utf-8')

    # Generate HMAC signature
    signature = hmac.new(SECRET_KEY.encode(), base64_encoded.encode(), hashlib.sha256).hexdigest()
    
    # Append signature to encoded message
    return f"{base64_encoded}:{signature}"

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


message = """:)"""
# Encrypting the message
encrypted_msg = encrypt_message(message)
print(f"Encrypted Message:\n{encrypted_msg}\n")
