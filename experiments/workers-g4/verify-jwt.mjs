// Qualification only: secret-bearing input stays on stdin and is never logged.
import {readFileSync} from 'node:fs';
import {createPublicKey, verify} from 'node:crypto';
const {token,jwk}=JSON.parse(readFileSync(0,'utf8'));
const [header,payload,signature,...rest]=token.split('.');
if(rest.length || JSON.parse(Buffer.from(header,'base64url')).alg!=='RS256') process.exit(1);
const key=createPublicKey({key:jwk,format:'jwk'});
if(!verify('RSA-SHA256',Buffer.from(header+'.'+payload),key,Buffer.from(signature,'base64url'))) process.exit(1);
