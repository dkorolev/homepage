import * as oidc from 'openid-client';
import { beginFlow, finishFlow, csrf } from './sessions.js';
import { random } from './memory.js';
import { page, escape, form } from './views.js';

export function clientOptions(settings, fetchImpl) {
  return {
    [oidc.customFetch]: fetchImpl,
    execute: [oidc.enableNonRepudiationChecks, ...(settings.development ? [oidc.allowInsecureRequests] : [])],
    timeout: 15,
  };
}

export function mountClients(app, settings, accounts, providerData, fetchImpl) {
  const configs = new Map();
  async function configFor(type) {
    if (configs.has(type)) return configs.get(type);
    let config;
    const options = clientOptions(settings, fetchImpl);
    if (type === 'github') {
      if (!settings.githubId || !settings.githubSecret) throw Object.assign(new Error('GitHub sign-in needs a client ID and secret. See setup.'), { status: 503 });
      config = new oidc.Configuration({
        issuer: 'https://github.com', authorization_endpoint: 'https://github.com/login/oauth/authorize',
        token_endpoint: 'https://github.com/login/oauth/access_token',
      }, settings.githubId, settings.githubSecret, oidc.ClientSecretPost(settings.githubSecret));
    } else if (type === 'google' || type === 'enterprise') {
      const enterprise = type === 'enterprise';
      const id = enterprise ? settings.enterpriseId : settings.googleId;
      const secret = enterprise ? settings.enterpriseSecret : settings.googleSecret;
      if (!id || !secret) throw Object.assign(new Error(`${enterprise ? 'Enterprise OIDC' : 'Google'} sign-in needs configuration. See setup.`), { status: 503 });
      config = await oidc.discovery(new URL(enterprise ? settings.enterpriseIssuer : settings.googleIssuer), id, secret, oidc.ClientSecretPost(secret), options);
    } else {
      const metadata = providerData.clients.find(c => c.client_id === `current-${type}-demo`);
      if (!metadata) throw Object.assign(new Error('Unknown sign-in demo.'), { status: 404 });
      config = await oidc.discovery(new URL(settings.currentOrigin), metadata.client_id, metadata, oidc.ClientSecretBasic(metadata.client_secret), options);
    }
    config[oidc.customFetch] = fetchImpl;
    if (settings.development) oidc.allowInsecureRequests(config);
    if (type !== 'github' && type !== 'oauth') oidc.enableNonRepudiationChecks(config);
    configs.set(type, config);
    return config;
  }

  async function start(req, res, type, callback, returnTo = '/account') {
    const config = await configFor(type);
    const verifier = oidc.randomPKCECodeVerifier();
    const nonce = ['oauth', 'github'].includes(type) ? undefined : random();
    const state = beginFlow(req, { type, verifier, nonce, returnTo, callback });
    const scope = type === 'github' ? 'read:user' : type === 'oauth' ? 'profile' : 'openid profile email';
    const params = {
      redirect_uri: callback, scope, state,
      code_challenge: await oidc.calculatePKCECodeChallenge(verifier), code_challenge_method: 'S256',
    };
    if (nonce) params.nonce = nonce;
    if (type === 'google') params.prompt = 'select_account';
    res.redirect(303, oidc.buildAuthorizationUrl(config, params).href);
  }

  async function finish(req, res, type) {
    const pending = finishFlow(req, type);
    const config = await configFor(type);
    const url = new URL(req.originalUrl, req.demoOrigin);
    // The expected redirect URL comes from the server-side flow, never Host/query input.
    if (url.origin + url.pathname !== pending.callback) throw Object.assign(new Error('Wrong sign-in callback.'), { status: 400 });
    const tokens = await oidc.authorizationCodeGrant(config, url, {
      pkceCodeVerifier: pending.verifier, expectedState: req.query.state, expectedNonce: pending.nonce,
      idTokenExpected: !!pending.nonce,
    });
    let profile;
    if (type === 'github') {
      const headers = { Authorization: `Bearer ${tokens.access_token}`, Accept: 'application/vnd.github+json', 'User-Agent': 'Current-Demos', 'X-GitHub-Api-Version': '2022-11-28' };
      const response = await fetchImpl('https://api.github.com/user', { headers });
      if (!response.ok) throw new Error('GitHub profile request failed.');
      const data = await response.json();
      if (!Number.isSafeInteger(data.id) || data.id <= 0 || typeof data.login !== 'string') throw new Error('GitHub returned an invalid profile.');
      profile = { sub: String(data.id), name: data.name || data.login, login: data.login };
      req.demoSession.github = profile;
    } else if (type === 'oauth') {
      const response = await fetchImpl(`${settings.currentOrigin}/api/identity`, { headers: { Authorization: `Bearer ${tokens.access_token}` } });
      if (!response.ok) throw new Error('Current profile request failed.');
      profile = await response.json();
    } else {
      const claims = tokens.claims();
      profile = await oidc.fetchUserInfo(config, tokens.access_token, claims.sub);
      if (type === 'google') {
        const account = accounts.fromGoogle(profile);
        req.demoSession.accountId = account.sub;
        req.demoSession.authTime = Math.floor(Date.now() / 1000);
        req.demoSession.authInteraction = pending.returnTo.startsWith('/interaction/') ? pending.returnTo.split('/').pop() : undefined;
      }
    }
    req.demoSession.result = {
      type, profile, claims: tokens.claims() || null,
      checks: pending.nonce ? ['State', 'PKCE S256', 'Issuer', 'Audience', 'Expiry', 'Nonce', 'JWKS signature', 'UserInfo subject'] : ['State', 'PKCE S256', 'Authorization code exchange'],
    };
    // Tokens stay on the server and are discarded after this demonstration.
    req.rotateSession();
    res.redirect(303, pending.returnTo);
  }

  for (const type of ['google', 'github', 'enterprise']) {
    app.get(`/auth/${type}`, async (req, res) => {
      let returnTo = '/account';
      if (type === 'google' && typeof req.query.return_to === 'string' && /^\/interaction\/[A-Za-z0-9_-]+$/.test(req.query.return_to)) returnTo = req.query.return_to;
      await start(req, res, type, `${settings.currentOrigin}/auth/${type}/callback`, returnTo);
    });
    app.get(`/auth/${type}/callback`, (req, res) => finish(req, res, type));
  }
  for (const type of ['oauth', 'oidc']) {
    app.get(`/demo/${type}`, (req, res) => start(req, res, type, `${settings.currentOrigin}/demo/${type}/callback`, '/account'));
    app.get(`/demo/${type}/callback`, (req, res) => finish(req, res, type));
  }

  return {
    mountDima(dima) {
      dima.get('/current-demo', (req, res) => {
        const result = req.demoSession.result;
        res.send(page('Sign in with Current', `<p class="eyebrow">DIMA.AI / RELYING PARTY</p><h1>One identity.<br>Another service.</h1><p>This page is on dima.ai. Sign in through Current to see your identity verified here.</p><a class="chamfer btn btn--cyan button" href="/current-demo/login"><span>Sign in with Current →</span></a>${result ? `<h2>Verified by dima.ai</h2><pre>${escape(JSON.stringify(result, null, 2))}</pre>${form('/current-demo/logout', req.demoSession.csrf, '<button class="chamfer btn btn--cyan"><span>Clear this session</span></button>')}` : ''}<p><a href="${settings.currentOrigin}">Back to Current demos</a></p>`, settings.currentOrigin));
      });
      dima.get('/current-demo/login', (req, res) => start(req, res, 'dima', `${settings.dimaOrigin}/current-demo/callback`, '/current-demo'));
      dima.get('/current-demo/callback', (req, res) => finish(req, res, 'dima'));
      dima.post('/current-demo/logout', csrf, (req, res) => { delete req.demoSession.result; req.rotateSession(); res.redirect(303, '/current-demo'); });
    },
  };
}
