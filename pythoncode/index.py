import json
import hashlib
import uuid
import time
from http.server import HTTPServer, BaseHTTPRequestHandler
from jwcrypto import jwk, jwt

# ✅ Load FIXED private key from file (matches public key on GitHub JWKS)
with open("private-jwk.json") as f:
    key = jwk.JWK.from_json(f.read())

# ✅ APEX-Compatible Payload
data_payload = {
    "dateSent": "20250611",
    "uen": "180027220M",
    "requestorEmail": "sebastianczh@outlook.sg",
    "requestorName": "SebastianCZH",
    "batchID": "batch1",
    "currentBatch": 1,
    "totalBatches": 1,
    "oedData": [
        {
            "fullName": "John Liu Lian Tao",
            "resStatusPassType": "Singapore Citizen/ PR",
            "nric": "S7744871C",
            "dateJoined": "20220503",
            "highestEducation": "2   Lower Secondary",
            "pwJobTitle": "[Cleaning] General Cleaner (F&B Establishment)",
            "mainJobTitle": "MJT",
            "mainJobDuties": "MJD",
            "occupationGroup": "3   Associate Professionals and Technicians",
            "typeOfEmployee": "Trainee",
            "jobType": "Full-Time",
            "department": "Finance",
            "standard_hr_wrk": "33",
            "actual_hr_wrk": "23",
            "totalWorkingDaysofMonth": "22",
            "actualWorkingDaysofMonth": "20",
            "paymentMode": "Month",
            "basicWage": "2000.00",
            "grossWage": "2500.00",
            "annualLeaves": "100.00",
            "premiseType": "Branch",
            "postalCode": "544123",
            "streetName": "Sample",
            "dateLeft": "20260531",
            "modeOfLeaving": "Retirements"
        }
    ]
}

# ✅ Save payload for hashing and POST
with open("payloadpy.json", "w") as f:
    json.dump(data_payload, f, separators=(',', ':'))

# ✅ Hash strict JSON directly
compact = json.dumps(data_payload, separators=(',', ':'))
hashed_payload = hashlib.sha256(compact.encode()).hexdigest()
print(f"\n✅ Final hash to use in JWT 'data' claim:\n{hashed_payload}\n")

# ✅ Safe iat/exp
timestamp_now = int(time.time())
timestamp_exp = timestamp_now + 180

# ✅ JWT claims
claims = {
    "data": hashed_payload,
    "jti": str(uuid.uuid4()),
    "iat": timestamp_now,
    "exp": timestamp_exp,
    "iss": "c66446db-9221-4b84-9632-2abd5781a250",
    "sub": "POST",
    "aud": "https://sandbox.api.gov.sg/mom/oed/jwt/lssp/ez/laboursurvey/prc/v2/Submission"
}

# ✅ JWT header
header = {
    "alg": "ES256",
    "kid": key.key_id,
    "typ": "JWT"
}

# ✅ Build and sign JWT
token = jwt.JWT(header=header, claims=claims)
token.make_signed_token(key)
print(f"\n✅ JWT Token:\n{token.serialize()}\n")

# ✅ Serve fixed JWKS (must match GitHub-hosted file)
with open("public-jwk.json") as f:
    public_jwk_json = json.load(f)

# ✅ Local HTTP server
class SimpleHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/.well-known/jwks.json":
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps(public_jwk_json).encode())
        elif self.path == "/get-jwt":
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps({ "token": token.serialize() }).encode())
        else:
            self.send_response(404)
            self.end_headers()

print("✅ JWKS server running at http://localhost:3000/.well-known/jwks.json")
print("✅ JWT endpoint available at http://localhost:3000/get-jwt")

httpd = HTTPServer(('localhost', 3000), SimpleHandler)
httpd.serve_forever()
