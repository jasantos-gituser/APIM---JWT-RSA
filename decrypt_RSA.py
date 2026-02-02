#decrypt RSA
#!/usr/bin/env python3
import base64
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding


PRIVATE_KEY_FILE = "jwt_test_private.pem"

# Paste the Base64 output from encrypt_RSA.py here
ENCRYPTED_PAYLOAD_B64 = (
    "lP/6goAomYU9If3hTeZRfHs98PUMNhn5xGprdiq8jEPlGl+9bjk2EXc05eRoX1Z0y1T/GsxYK1p/tjV2DVoOScni/drChS17cTt7mFN55eYnmuV2k1zo8Qw/27C4q0KuA9utFbM49LvjaDIsLBj4I+Lhq3yXRWSZDE6euUlTywSVvTL2tjQYfQOLDbQaTTaZnTI1TJteYdCpnVLb57AWg25vkIuIfwficRTD0jzcNyndrVu2Wzwp8hjTCoCYWO/SA92ghh3yr0IZ1pNQ2vRKpL3g6m0t5+CsY5R98jxZB6eWtJ9vbod2AaQNVu+vewswhh6VsIwLYZHKpAWqfI3ghg=="
)


def load_private_key(path: str):
    with open(path, "rb") as f: # --- open the public key PEM file in binary mode; required for cryptography libraries.
        return serialization.load_pem_private_key( # --- serialization turns bytes into keys. load_pem_public_key turns that into a usable RSA object.
            f.read(), # --- reads the entire PEM file (from binary mode) as bytes.
            password=None # --- no password used for this private key.
        )


def main():
    encrypted_bytes = base64.b64decode(ENCRYPTED_PAYLOAD_B64) # --- decode the base64 string back into bytes.

    private_key = load_private_key(PRIVATE_KEY_FILE)

    decrypted_bytes = private_key.decrypt( # --- performs RSA decryption using the private key.
        encrypted_bytes, # --- the bytes to decrypt.
        padding.OAEP( # --- defines the RSA padding scheme. must match the encryption padding.
            mgf=padding.MGF1(algorithm=hashes.SHA256()), # --- used to randomize padding. Prevents attacks.
            algorithm=hashes.SHA256(), # --- hash used by OAEP. must match on encryption.
            label=None
        )   # --- required during encryption: without this, RSA encryption would be predictable and insecure.
    )

    decrypted_text = decrypted_bytes.decode("utf-8") # --- convert decrypted bytes back into string.

    print("Decrypted payload:")
    print(decrypted_text)


if __name__ == "__main__":
    main()