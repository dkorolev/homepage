import http from 'node:http';
import { once } from 'node:events';
import { mkdtemp, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import express from 'express';
import { generateKeyPair, exportJWK, SignJWT } from 'jose';
import { createHash } from 'node:crypto';
import { createApp } from '../src/app.js';
import { random } from '../src/memory.js';

export async function listen(app, hostname = '127.0.0.1') {
  const server = http.createServer(app);
  server.listen(0, hostname);
  await once(server, 'listening');
  return { server, origin: `http://${hostname}:${server.address().port}`, close: () => new Promise(resolve => { server.close(resolve); server.closeAllConnections(); }) };
}

// A test-only upstream identity provider. It has its own RSA key and implements
// the wire exchange independently of the provider used by the application.
export async function fixture() {
  const key = await generateKeyPair('RS256', { extractable: true });
  const wrongKey = await generateKeyPair('RS256');
  const jwk = { ...await exportJWK(key.publicKey), alg: 'RS256', kid: 'upstream-test' };
  const google = express();
  google.use(express.urlencoded({ extended: false }));
  const upstream = await listen(google);
  const codes = new Map();
  const control = { tamper: null, calls: 0 };
  google.get('/.well-known/openid-configuration', (_req, res) => res.json({
    issuer: upstream.origin, authorization_endpoint: `${upstream.origin}/authorize`, token_endpoint: `${upstream.origin}/token`,
    jwks_uri: `${upstream.origin}/jwks`, userinfo_endpoint: `${upstream.origin}/userinfo`,
    response_types_supported: ['code'], subject_types_supported: ['public'], id_token_signing_alg_values_supported: ['RS256'],
    token_endpoint_auth_methods_supported: ['client_secret_post'], code_challenge_methods_supported: ['S256'],
  }));
  google.get('/jwks', (_req, res) => res.json({ keys: [jwk] }));
  google.get('/authorize', (req, res) => {
    const code = random();
    codes.set(code, req.query);
    const callback = new URL(req.query.redirect_uri);
    callback.searchParams.set('code', code);
    callback.searchParams.set('state', req.query.state);
    control.calls++;
    res.redirect(callback.href);
  });
  google.post('/token', async (req, res) => {
    const params = codes.get(req.body.code);
    codes.delete(req.body.code);
    if (!params || req.body.client_id !== 'test-google' || req.body.client_secret !== 'test-secret' || req.body.redirect_uri !== params.redirect_uri || createHash('sha256').update(req.body.code_verifier).digest('base64url') !== params.code_challenge) return res.status(400).json({ error: 'invalid_grant' });
    const now = Math.floor(Date.now() / 1000);
    const claims = { iss: upstream.origin, sub: 'google-user-123', aud: 'test-google', iat: now, exp: now + 600, nonce: params.nonce };
    if (control.tamper === 'issuer') claims.iss = 'https://wrong.example';
    if (control.tamper === 'audience') claims.aud = 'wrong-client';
    if (control.tamper === 'nonce') claims.nonce = 'wrong-nonce';
    if (control.tamper === 'expiry') claims.exp = now - 600;
    const id_token = await new SignJWT(claims).setProtectedHeader({ alg: 'RS256', kid: jwk.kid }).sign(control.tamper === 'signature' ? wrongKey.privateKey : key.privateKey);
    res.json({ access_token: 'test-profile-token', token_type: 'Bearer', expires_in: 600, id_token });
  });
  google.get('/userinfo', (req, res) => {
    if (req.get('authorization') !== 'Bearer test-profile-token') return res.status(401).end();
    res.json({ sub: control.tamper === 'subject' ? 'other-user' : 'google-user-123', name: 'Demo Person', email: 'demo@example.com', email_verified: true });
  });
  const host = await listen(undefined, '0.0.0.0');
  const port = host.server.address().port;
  const origin = `http://127.0.0.1:${port}`;
  const directory = await mkdtemp(join(tmpdir(), 'current-clients-'));
  const clientsFile = join(directory, 'clients.json');
  await writeFile(clientsFile, JSON.stringify([{
    client_id: 'external-test-client', client_secret: 'test-client-secret-for-local-fixtures-only',
    client_name: 'External service', application_type: 'web',
    redirect_uris: [`http://localhost:${port}/service-callback`],
    response_types: ['code'], grant_types: ['authorization_code', 'refresh_token'],
    token_endpoint_auth_method: 'client_secret_basic',
  }]), { mode: 0o600 });
  const settings = {
    development: true, currentOrigin: origin, dimaOrigin: `http://localhost:${port}`,
    googleIssuer: upstream.origin, googleId: 'test-google', googleSecret: 'test-secret', registrationToken: random(),
    githubId: 'test-github', githubSecret: 'github-secret',
    clientsFile,
  };
  let service;
  try { service = await createApp(settings); }
  catch (error) { await host.close(); await upstream.close(); await rm(directory, { recursive: true, force: true }); throw error; }
  host.server.on('request', service.app);
  return { ...service, origin, settings, control, close: async () => { await host.close(); await upstream.close(); await rm(directory, { recursive: true, force: true }); } };
}
