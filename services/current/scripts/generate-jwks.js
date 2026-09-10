import { writeFile } from 'node:fs/promises';
import { randomUUID } from 'node:crypto';
import { generateKeyPair, exportJWK } from 'jose';

const path = process.argv[2];
if (!path) throw new Error('Usage: node scripts/generate-jwks.js /private/path/jwks.json');
const { privateKey } = await generateKeyPair('RS256', { extractable: true });
const jwks = { keys: [{ ...await exportJWK(privateKey), use: 'sig', alg: 'RS256', kid: randomUUID() }] };
// Never overwrite a key by accident. Explicit key rotation is a separate operation.
await writeFile(path, JSON.stringify(jwks), { mode: 0o600, flag: 'wx' });
console.log('Created an RS256 signing key. Keep this file private.');
