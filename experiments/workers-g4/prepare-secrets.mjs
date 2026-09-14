// Usage: node prepare-secrets.mjs /private/path/g4-secrets.json
// Creates once, never prints secret values. Dedicated qualification resources only.
import fs from 'node:fs';
import crypto from 'node:crypto';
const path=process.argv[2];if(!path)throw new Error('Private output path required');
const {privateKey}=crypto.generateKeyPairSync('rsa',{modulusLength:2048});
fs.writeFileSync(path,JSON.stringify({
 PROOF_KEY:crypto.randomBytes(32).toString('base64url'),
 SIGNING_KEY:crypto.randomBytes(32).toString('base64url'),
 TOKEN_PEPPER:crypto.randomBytes(32).toString('base64url'),
 OAUTH_KEY:crypto.randomBytes(16).toString('hex'),
 IDP_JWK:JSON.stringify(privateKey.export({format:'jwk'})),
 OIDC_SECRET:crypto.randomBytes(32).toString('base64url'),
}),{flag:'wx',mode:0o600});
