const express = require('express');
const { generateKeyPair, exportJWK, SignJWT } = require('jose');

const app = express();
const port = 3000;

// ✅ Fixed key ID (random UUID you generated) , key in terminal to create >>>>> node -e "console.log(require('crypto').randomUUID())"
const keyId = '988b13d8-64f2-4799-bc20-6448e6efa090';

let publicJwk;
let privateKey;

(async () => {
  const { publicKey, privateKey: privKey } = await generateKeyPair('ES256');
  privateKey = privKey;

  // 👇 Export public key and manually inject kid, alg, use
  publicJwk = {
    ...(await exportJWK(publicKey)),
    kid: keyId,
    alg: 'ES256',
    use: 'sig',
  };
})();

app.get('/.well-known/jwks.json', (req, res) => {
  if (!publicJwk) {
    return res.status(503).json({ error: 'JWKS not ready yet' });
  }
  res.json({ keys: [publicJwk] });
});

app.get('/get-jwt', async (req, res) => {
  const jwt = await new SignJWT({ sub: '7368ddc6-1fd0-4456-8b2b-0c3fc39ba40f' }) // sub usually same as iss
    .setProtectedHeader({ alg: 'ES256', kid: keyId })
    .setIssuedAt()
    .setIssuer('7368ddc6-1fd0-4456-8b2b-0c3fc39ba40f')
    .setAudience('https://sandbox.api.gov.sg/mom/oed/jwt/lssp/ez/laboursurvey/prc/v2/Submission')
    .setExpirationTime('5m')
    .sign(privateKey);

  res.json({ token: jwt });
});


const fs = require('fs');

(async () => {
  const { publicKey, privateKey: privKey } = await generateKeyPair('ES256');
  privateKey = privKey;
  publicJwk = {
    ...(await exportJWK(publicKey)),
    kid: keyId,
    alg: 'ES256',
    use: 'sig',
  };

  // Save JWKS to file
  const jwksJson = JSON.stringify({ keys: [publicJwk] }, null, 2);
  fs.writeFileSync('./jwks.json', jwksJson);
})();



app.listen(port, () => {
  console.log(`Server running at http://localhost:${port}`);
});
