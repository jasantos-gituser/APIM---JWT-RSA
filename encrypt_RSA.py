#encrypt RSA
import json
import base64

from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding


PUBLIC_KEY_FILE = "jwt_test_public.pem"


def load_public_key(path: str):
    with open(path, "rb") as f: # --- open the public key PEM file in binary mode; required for cryptography libraries.
        return serialization.load_pem_public_key(f.read()) # --- reads the entire PEM file (from binary mode) as bytes.
                                                           # --- serialization turns bytes into keys.
                                                           # --- load_pem_public_key turns that into a usable RSA object.


def main():
    payload = {
        "request": {
            "name": "jack",
            "address": "ph",
            "age": 2
        }
    }

    payload_bytes = json.dumps(payload).encode("utf-8") # --- converts JSON payload into bytes so RSA can encrypt it.
                                                        # --- json.dumps() converts dict to JSON string.
                                                        # --- .encode("utf-8") converts string to bytes.

    public_key = load_public_key(PUBLIC_KEY_FILE) # --- loads the public key from PEM file.

    encrypted = public_key.encrypt( # --- performs RSA encryption using the public key.
        payload_bytes, # --- the bytes to encrypt.
        padding.OAEP( # --- defines the RSA padding scheme. required for security.
            mgf=padding.MGF1(algorithm=hashes.SHA256()), # --- used to randomize padding. Prevents attacks.
            algorithm=hashes.SHA256(), # --- hash used by OAEP. must match on decryption.
            label=None
        )  # --- required: without this, RSA encryption would be predictable and insecure.
    )

    # --- the bytes returned by RSA encryption are not safe to transport or embed.
    # --- encrypted bytes can contain non-printable characters.
    encrypted_b64 = base64.b64encode(encrypted).decode("utf-8")   # --- base64.b64encode() returns bytes.
                                                                  # --- .decode("utf-8") converts bytes to string.
                                                                  # --- base64 is required only if you need send the encrypted data over HTTP

    print(encrypted_b64)


if __name__ == "__main__":
    main()