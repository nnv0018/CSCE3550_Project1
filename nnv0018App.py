import time
import uuid
import base64
import jwt
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

from fastapi import FastAPI 
from fastapi import Request
from fastapi import FastAPI, Request, Response
nnv0018App = FastAPI()

@nnv0018App.get("/")
def root():
    return {"message": "JWKS Server is running"}

def generateKey():
    #generate new RSA rpivate key 
    private_key = rsa.generate_private_key(
        public_exponent=65537, #for security & performance
        key_size=2048, #strength of the key
    )
    #get the corresponding public key from the private key
    public_key = private_key.public_key();

    #associate a Key ID (kid) and expiry timestamp with each key
    kid = str(uuid.uuid4())
    expiry = int (time.time()) + 3600 #1hour

    return {"kid": kid,
            "expiry": expiry,
            "private_key": private_key,
            "public_key" : public_key
    }

print(generateKey())
active_key = generateKey()
expired_key = generateKey()
expired_key["expiry"]= int(time.time()) -10 
#10 seconds a go from the current time -> expired
keys = [active_key, expired_key]

@nnv0018App.get("/.well-known/jwks.json")
def getJkws():
    jwksKeys = []
    for key in keys:
        if key["expiry"] > int (time.time()):
            public_key = key["public_key"]
            public_numbers = public_key.public_numbers()

            mod = public_numbers.n
            exp = public_numbers.e
            mod_b64 = base64.urlsafe_b64encode(mod.to_bytes((mod.bit_length() + 7) // 8, 'big')).rstrip(b'=').decode('utf-8')
            exp_b64 = base64.urlsafe_b64encode(exp.to_bytes((exp.bit_length() + 7) // 8, 'big')).rstrip(b'=').decode('utf-8')

            jwk = {
                "kty": "RSA",
                "use": "sig",
                "alg": "RS256",
                "kid": key["kid"],
                "n": mod_b64,
                "e": exp_b64
            }

            jwksKeys.append(jwk)
    return {"keys" : jwksKeys}

@nnv0018App.post("/auth")
def auth(request: Request):
    status = request.query_params.get("expired")

    if status == "true": #"expired" query parameter is present
        signingKey = expired_key
    else:
        signingKey = active_key
    token_expiry = int(time.time()) + 900 #15minutes
    payload = {
        "sub" : "user321",
        "iat" : int(time.time()),
        "exp" : token_expiry
    }
    if status == "true":
        payload["exp"] = signingKey["expiry"]

    headers = {
        "kid" : signingKey["kid"]
    }
    token = jwt.encode(
        payload, signingKey["private_key"], algorithm="RS256", headers = headers
    )
    #print(f"Generated Token: {token}") FIX TOKEN error

    return Response(content=token, media_type="text/plain")