// ✅ APEX-Compatible JWT Generator using jose only (no PKCS8)
const express = require('express');
const fs = require('fs');
const crypto = require('crypto');
const jose = require('jose');
const { v4: uuidv4 } = require('uuid');

const app = express();
const port = 3000;

// ✅ API Payload (EXACT JSON TO BE HASHED AND SENT IN POSTMAN BODY UNDER { payload: ... })
const payloadData = {
  dateSent: "20250608",
  uen: "T15LP0010D",
  requestorEmail: "sebastianczh@outlook.sg",
  requestorName: "SebastianCZH",
  batchID: "batch1",
  currentBatch: 1,
  totalBatches: 1,
  oedData: [
    {
      fullName: "John Tan Ah Gao",
      resStatusPassType: "Singapore Citizen/ PR",
      nric: "S7744871C",
      dateJoined: "20220503",
      highestEducation: "2   Lower Secondary",
      pwJobTitle: "[Cleaning] General Cleaner (F&B Establishment)",
      mainJobTitle: "MJT",
      mainJobDuties: "MJD",
      occupationGroup: "3   Associate Professionals and Technicians",
      typeOfEmployee: "Trainee",
      jobType: "Full-Time",
      department: "Finance",
      standard_hr_wrk: "33",
      actual_hr_wrk: "23",
      totalWorkingDaysofMonth: "22",
      actualWorkingDaysofMonth: "20",
      paymentMode: "Month",
      basicWage: "2000.00",
      grossWage: "2500.00",
      annualLeaves: "100.00",
      premiseType: "Branch",
      postalCode: "544123",
      streetName: "Sample",
      dateLeft: "20260531",
      modeOfLeaving: "Retirements"
    }
  ]
};

// 🔐 SHA-256 hash of { payload: <object> }
function sha256Hash(payloadObject) {
  const payloadString = JSON.stringify({ payload: payloadObject });
  fs.writeFileSync('payload.json', payloadString); // ✅ Save to payload.json for Postman testing
  return crypto.createHash('sha256').update(payloadString).digest('hex');
}

// ✅ Generate or Load Keys
const PRIVATE_JWK_FILE = './private-jwk.json';
const PUBLIC_JWK_FILE = './public-jwk.json';
let privateJwk, publicJwk;

async function initializeKeys() {
  if (fs.existsSync(PRIVATE_JWK_FILE) && fs.existsSync(PUBLIC_JWK_FILE)) {
    privateJwk = JSON.parse(fs.readFileSync(PRIVATE_JWK_FILE));
    publicJwk = JSON.parse(fs.readFileSync(PUBLIC_JWK_FILE)).keys[0];
  } else {
    const { publicKey, privateKey } = await jose.generateKeyPair('ES256');

    const pubJwk = await jose.exportJWK(publicKey);
    const privJwk = await jose.exportJWK(privateKey);

    const kid = crypto.randomUUID();
    pubJwk.kid = privJwk.kid = kid;
    pubJwk.alg = privJwk.alg = 'ES256';
    pubJwk.use = privJwk.use = 'sig';

    fs.writeFileSync(PUBLIC_JWK_FILE, JSON.stringify({ keys: [pubJwk] }, null, 2));
    fs.writeFileSync(PRIVATE_JWK_FILE, JSON.stringify(privJwk, null, 2));

    privateJwk = privJwk;
    publicJwk = pubJwk;
  }
}

// 🔓 Serve JWKS
app.get('/.well-known/jwks.json', (req, res) => {
  if (!publicJwk) return res.status(503).json({ error: 'JWKS not ready yet' });
  res.json({ keys: [publicJwk] });
});

// 🔐 Sign JWT using jose
app.get('/get-jwt', async (req, res) => {
  const payloadHash = sha256Hash(payloadData);
  const privateKey = await jose.importJWK(privateJwk, 'ES256');

  const jwt = await new jose.SignJWT({
    data: payloadHash,
    jti: uuidv4()
  })
    .setProtectedHeader({
      alg: 'ES256',
      kid: privateJwk.kid,
      typ: 'JWT'
    })
    .setIssuedAt()
    .setExpirationTime('180s')
    .setIssuer('c66446db-9221-4b84-9632-2abd5781a250')
    .setSubject('POST')
    .setAudience('https://sandbox.api.gov.sg/mom/oed/jwt/lssp/ez/laboursurvey/prc/v2/Submission')
    .sign(privateKey);

  res.json({ token: jwt });
});

initializeKeys().then(() => {
  app.listen(port, () => {
    console.log(`✅ Server running at http://localhost:${port}`);
  });
});
