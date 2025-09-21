import pytest
import requests
import jwt
import time
# test_suite.py
import pytest
from fastapi.testclient import TestClient
import nnv0018App  # import the module

client = TestClient(nnv0018App.nnv0018App)  # the FastAPI instance

def test_root():
    response = client.get("/")
    assert response.status_code == 200

# The base URL for the running FastAPI server
BASE_URL = "http://127.0.0.1:8080" #url of the runnign server

# --- Test Cases ---
#Tests the root endpoint 
def test_root_endpoint():
    response = requests.get(BASE_URL + "/")
    assert response.status_code == 200
    assert response.json() == {"message": "JWKS Server is running"}
#Test the jwks endpoint
def test_jwks_endpoint_structure():
    response = requests.get(BASE_URL + "/.well-known/jwks.json")
    assert response.status_code == 200 #Must return 200 
    
    data = response.json()
    assert "keys" in data
    assert isinstance(data["keys"], list) #Must be a JSON object containing a 'keys' array
    assert len(data["keys"]) > 0, "JWKS 'keys' array should not be empty" #The 'keys' array should not be empty
    
    # Check the structure of the first key
    #Each key must have the required JWK fields
    jwk = data["keys"][0]
    required_fields = ["kty", "alg", "use", "kid", "n", "e"]
    for field in required_fields:
        assert field in jwk, f"JWK is missing required field: {field}"
#Test the flow for valid token
def test_get_and_verify_valid_jwt():
    # Fetch the token
    response = requests.post(BASE_URL + "/auth")
    assert response.status_code == 200
    token = response.text
    assert token, "Received an empty token string"

    # Get the Key ID from the token header
    try:
        header = jwt.get_unverified_header(token)
        kid = header["kid"]
    except jwt.DecodeError as e:
        pytest.fail(f"Could not decode token header: {e}")

    # Fetch the JWKS to find the public key
    jwks_response = requests.get(BASE_URL + "/.well-known/jwks.json")
    assert jwks_response.status_code == 200
    jwks = jwks_response.json()

    # Find the key that matches the token's 'kid'
    matching_key = next((key for key in jwks["keys"] if key["kid"] == kid), None)
    assert matching_key is not None, f"KID '{kid}' from token not found in JWKS"

    # Convert the JWK to a public key and verify the token
    try:
        public_key = jwt.algorithms.RSAAlgorithm.from_jwk(matching_key)
        decoded_payload = jwt.decode(
            token,
            key=public_key,
            algorithms=["RS256"]
        )
        assert decoded_payload["sub"] == "user321"
        assert decoded_payload["exp"] > int(time.time()), "Token should not be expired"
    except Exception as e:
        pytest.fail(f"Token verification failed: {e}")
#Tests the flow for an expired token.
def test_get_and_verify_expired_jwt():
    # Fetch the expired token
    response = requests.post(BASE_URL + "/auth?expired=true")
    assert response.status_code == 200
    expired_token = response.text
    assert expired_token, "Received an empty expired token string"

    # Check that the key for the expired token is not in the public JWKS
    header = jwt.get_unverified_header(expired_token)
    expired_kid = header["kid"]
    
    jwks_response = requests.get(BASE_URL + "/.well-known/jwks.json")
    jwks = jwks_response.json()
    
    matching_key = next((key for key in jwks["keys"] if key["kid"] == expired_kid), None)
    assert matching_key is None, "Expired key's KID should not be present in the active JWKS"

    # Decode the token's payload without checking the signature to verify the expiration claim
    try:
        payload = jwt.decode(expired_token, options={"verify_signature": False})
        assert payload["exp"] < int(time.time()), "Token's 'exp' claim should be in the past"
    except jwt.DecodeError as e:
        pytest.fail(f"Could not decode the expired token's payload: {e}")

#Ensure JWKS endpoint only returns keys that are not expired
def test_jwks_includes_only_active_keys():
    response = client.get("/.well-known/jwks.json") #the correct path have been fixed here
    assert response.status_code == 200
    jwks = response.json()
    for key in jwks["keys"]:
        kid = key["kid"]
        # Should not include expired_key
        assert kid != nnv0018App.expired_key["kid"]
#Ensure /auth payload contains correct 'sub' and 'iat' claims
def test_auth_payload_sub_and_iat():
    response = client.post("/auth")
    token = response.text
    payload = jwt.decode(token, options={"verify_signature": False})
    assert payload["sub"] == "user321"
    assert abs(payload["iat"] - int(time.time())) < 5  # iat within 5 seconds of current time

