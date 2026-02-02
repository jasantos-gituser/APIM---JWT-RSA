# APIM---JWT-RSA

https://github.com/jasantos-gituser/APIM---JWT-RSA.git

# generate private keys
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out jwt_test_private.pem

# generate public keys
openssl pkey -in jwt_test_private.pem -pubout -out jwt_test_public.pem

# header
{
"alg": "RS256",
"typ": "JWT",
"kid": "dummy-issuer"
}

# payload
{
"name": "John Doe",
"iss": "dummy-issuer",
"nbf": 1769760000
}

# private key 
check jwt_test_private.pem

# public key
check jwt_test_public.pem

# create python environment
python3 -m venv .venv

# activiate python environment
source .venv/bin/activate

# install JWT for python
python -m pip install pyjwt

# JWT details
pip show pyjwt

Name: PyJWT
Version: 2.10.1

# for RS256
python -m pip install cryptography

# RSA details
pip show cryptography

Name: cryptography
Version: 46.0.4