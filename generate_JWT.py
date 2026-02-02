#generate JWT token file

"""
Generate an RS256 JWT with custom header (kid) and payload (iss, nbf, name).

Requirements:
  pip install pyjwt

Usage example:
  python3 generate_JWT.py \
    --private-key jwt_test_private.pem \
    --kid dummy-kid-001 \
    --iss dummy-issuer \
    --name "John Doe" \
    --nbf-minutes 15
"""

#!/usr/bin/env python3
from datetime import datetime, timedelta, timezone # --- used for NBF and IAT payload fields
import jwt

DEFAULT_PRIVATE_KEY = "jwt_test_private.pem"


def read_pem(path: str) -> bytes: # --- read private key PEM file; JWT library needs the key as bytes
    try:
        with open(path, "rb") as f: # --- opens the file in binary mode; rb means "read binary"
            return f.read() # --- read the entire file content and return it as bytes
    except FileNotFoundError: # --- python error exception; handle file not found error
        raise SystemExit(f"Private key file not found: {path}") # --- exit the program with an error message
    except Exception as e: # --- catch all other exceptions/errors
        raise SystemExit(f"Failed to read private key file '{path}': {e}") # --- exit the program with an error message


def unix_ts(dt: datetime) -> int:
    return int(dt.timestamp()) # --- timestamp() converts datetime to unix timestamp
                               # --- timestamp() returns float value
                               # --- int() converts float timestamp to integer


def build_token(private_key_pem: bytes, kid: str, iss: str, name: str) -> str:
    now_utc = datetime.now(timezone.utc) # --- JWT requires UTC time
    nbf_utc = now_utc + timedelta(minutes=15) # --- nbf = not before time; nbf_minutes is assigned minutes in the future
                                              # --- integer provided by client to set the nbf time in minutes from now
    headers = {
        "alg": "RS256",
        "typ": "JWT",
        "kid": kid,
    }

    payload = {
        "name": name,
        "iss": iss,
        "nbf": unix_ts(nbf_utc)
        # "iat": unix_ts(now_utc),
    }

    token = jwt.encode(
        payload=payload,
        key=private_key_pem,
        algorithm="RS256",
        headers=headers,
    )

    if isinstance(token, bytes):
        token = token.decode("utf-8") # --- decode bytes to string if necessary
                                      # --- old versions of pyjwt return bytes

    return token


def main() -> None:
    print_json = True

    token = build_token(
        private_key_pem=read_pem(DEFAULT_PRIVATE_KEY), # --- bytes
        kid="dummy_keyid", # --- string provided by client to identify the key
        iss="dummy_keyid", # --- string provided by client to identify the issuer
        name="Johny Doe" # --- string provided by client to identify the user
    )

    print("TOKEN: ", token)

    # --- print unverified header and payload for debugging purposes; not necessary in production
    if print_json:
        try:
            header = jwt.get_unverified_header(token)
            payload = jwt.decode(token, options={"verify_signature": False})
            print("\nHEADER (unverified):")
            print(header)
            print("\nPAYLOAD (unverified):")
            print(payload)
        except Exception as e:
            print(f"\nCould not print unverified header/payload: {e}")


if __name__ == "__main__": # --- If you run a file directly, then execute main()
    main()

# token = generate_JWT.build_token(…) # --- If you import the file as a module
# # --- can be used to generate JWT token strings in other modules.