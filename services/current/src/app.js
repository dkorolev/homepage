import express from 'express';
import { rateLimit } from 'express-rate-limit';
import { fileURLToPath } from 'node:url';
import { Accounts } from './memory.js';
import { sessions, csrf } from './sessions.js';
import { createProvider } from './provider.js';
import { mountClients } from './clients.js';
import { colorBoard, mountMcp } from './mcp.js';
import { page, escape, form } from './views.js';
import { loadPrnuiCss } from './prnui.js';

export async function createApp(settings) {
  for (const value of [settings.currentOrigin, settings.dimaOrigin]) {
    const url = new URL(value);
    if (url.origin !== value || (url.protocol !== 'https:' && !(settings.development && ['127.0.0.1', 'localhost'].includes(url.hostname)))) throw new Error('Demo origins must be HTTPS origins (or loopback in development).');
  }
  const prnuiCss = await loadPrnuiCss();
  const accounts = new Accounts();
  const board = colorBoard();
  const providerData = await createProvider(settings, accounts);
  const { provider } = providerData;
  const app = express();
  app.disable('x-powered-by');
  app.set('trust proxy', 'loopback');
  const jsonBody = express.json({ limit: '32kb' });
  const formBody = express.urlencoded({ extended: false, limit: '16kb' });
  const limiter = rateLimit({ windowMs: 60000, limit: 120, standardHeaders: 'draft-8', legacyHeaders: false });
  const authLimiter = rateLimit({ windowMs: 60000, limit: 40, standardHeaders: 'draft-8', legacyHeaders: false });
  const fetchImpl = async (input, init = {}) => {
    const url = new URL(input instanceof Request ? input.url : input);
    const headers = new Headers(init.headers);
    // Only our own configured issuer uses this back channel. Forwarded headers
    // are created here and at the Rust ingress, never copied from visitors.
    if (settings.backchannel && url.origin === settings.currentOrigin) {
      headers.set('host', url.host);
      headers.set('x-forwarded-proto', url.protocol.slice(0, -1));
      headers.set('x-forwarded-host', url.host);
      const destination = new URL(settings.backchannel);
      url.protocol = destination.protocol;
      url.host = destination.host;
    }
    return fetch(url, { ...init, headers, signal: init.signal || AbortSignal.timeout(15000), redirect: 'error' });
  };
  app.use((req, res, next) => {
    const host = req.get('host');
    const origin = `${req.protocol}://${host}`;
    if (![settings.currentOrigin, settings.dimaOrigin].includes(origin)) return res.status(421).send('Unknown host.');
    req.demoOrigin = origin;
    if (settings.development && origin.startsWith('http:')) {
      // HTTP loopback cannot use SameSite=None. Apply the development fallback
      // to cookies from both provider routes and interactionFinished responses.
      // HTTPS retains Secure + SameSite=None for cross-site authorization POSTs.
      const writeHead = res.writeHead;
      res.writeHead = function (...args) {
        const value = this.getHeader('Set-Cookie');
        if (value) {
          const convert = cookie => cookie.replace(/SameSite=None/gi, 'SameSite=Lax');
          this.setHeader('Set-Cookie', Array.isArray(value) ? value.map(convert) : convert(String(value)));
        }
        return writeHead.apply(this, args);
      };
    }
    res.set({ 'Cache-Control': 'no-store', 'Referrer-Policy': 'same-origin', 'X-Content-Type-Options': 'nosniff', 'X-Frame-Options': 'DENY' });
    // The OIDC library sets its own policy for auto-submitting form_post/logout.
    if (!req.path.startsWith('/oauth/')) res.set('Content-Security-Policy', `default-src 'self'; script-src 'self'; style-src 'self' ${settings.currentOrigin}; connect-src 'self'; img-src 'self' data:; frame-ancestors 'none'; base-uri 'none'; form-action 'self'`);
    next();
  });
  app.get('/static/favicon.svg', (_req, res) => res.sendFile(fileURLToPath(new URL('../../../static/favicon.svg', import.meta.url))));
  const current = express.Router();
  const dima = express.Router();
  app.use((req, res, next) => (req.demoOrigin === settings.currentOrigin ? current : dima)(req, res, next));

  current.get('/healthz', (_req, res) => res.json({ ok: true, service: 'current-demos' }));
  current.get('/assets/prnui.css', (_req, res) => res.type('css').send(prnuiCss));
  current.use('/assets', express.static(fileURLToPath(new URL('../public', import.meta.url)), { index: false, maxAge: 0 }));
  current.get('/', (_req, res) => res.sendFile(fileURLToPath(new URL('../public/index.html', import.meta.url))));
  current.get('/api/colors', (_req, res) => res.json({ latest: board.latest() }));
  mountMcp(current, board, settings.currentOrigin, jsonBody, limiter);
  current.get('/api/identity', async (req, res) => {
    const bearer = /^Bearer ([A-Za-z0-9._~-]+)$/i.exec(req.get('authorization') || '');
    const token = bearer && await provider.AccessToken.find(bearer[1]);
    const grant = token?.grantId && await provider.Grant.find(token.grantId);
    const account = token && accounts.bySub.get(token.accountId);
    if (!token || token.isExpired || !grant || !account) return res.set('WWW-Authenticate', 'Bearer error="invalid_token"').status(401).json({ error: 'invalid_token' });
    if (!token.scope?.split(' ').includes('profile')) return res.set('WWW-Authenticate', 'Bearer error="insufficient_scope", scope="profile"').status(403).json({ error: 'insufficient_scope' });
    res.json({ sub: account.sub, name: account.name, current_id: account.current_id });
  });

  current.get('/privacy', (_req, res) => res.send(page('Privacy', '<h1>A small, temporary demo.</h1><p>Google sign-in shares your name, email address, and provider identity with Current. GitHub sign-in shares your public profile. We keep accounts, login sessions, registered clients, tokens, and color assignments in server memory; restarting the demos service clears them. Sessions and grants expire after an hour. Registered clients expire after a day.</p><p>Names submitted to the color tool are public. Only the latest five submissions are shown. Do not submit private information. Google and GitHub have their own data policies.</p><p>We do not request access to your inbox or repositories. The demos do not use analytics or third-party scripts. Ordinary server infrastructure may log request metadata. Contact <a href="mailto:dima@current.ai">dima@current.ai</a>.</p>')));
  current.get('/terms', (_req, res) => res.send(page('Demo terms', '<h1>Experiment, explore, reset.</h1><p>These are public protocol demonstrations. Accounts and integrations are temporary, may disappear on restart, and should not be used to secure important data. Submit only names you are happy to make public. Please do not abuse the shared service.</p>')));
  current.get('/setup', (_req, res) => res.send(page('Build with Current', setupHtml(settings))));

  // Protocol endpoints stay stateless at this layer. Browser sessions are only
  // allocated for pages and actions that actually need a browser identity.
  const session = sessions();
  // This event follows the provider's CSRF check and fires even when logout
  // redirects to a client. Cancellation also emits it, without params.logout.
  provider.on('end_session.success', ctx => {
    if (ctx.oidc.params.logout) session.destroy(ctx.req, ctx.res);
  });
  current.use(['/auth', '/interaction', '/account', '/clients', '/demo', '/api/session'], session.middleware, formBody);
  dima.use('/current-demo', session.middleware, formBody);
  current.use('/auth', authLimiter);
  current.use('/clients', authLimiter);
  const clients = mountClients(current, settings, accounts, providerData, fetchImpl);
  clients.mountDima(dima);

  current.get('/api/session', (req, res) => res.json({
    account: accounts.bySub.get(req.demoSession.accountId) || null,
    google: !!(settings.googleId && settings.googleSecret), github: !!(settings.githubId && settings.githubSecret),
    enterprise: !!(settings.enterpriseIssuer && settings.enterpriseId && settings.enterpriseSecret),
    dima_url: `${settings.dimaOrigin}/current-demo`,
  }));
  current.get('/account', (req, res) => {
    const account = accounts.bySub.get(req.demoSession.accountId);
    res.send(page('Your demo session', `<p class="eyebrow">IDENTITY / IN MEMORY</p><h1>${account ? `Current ${escape(account.current_id)}` : 'Your demo session'}</h1>${account ? `<p>Signed in as ${escape(account.name)}. This ID lasts until the service restarts.</p><div class="actions"><a class="chamfer btn btn--cyan button" href="${settings.dimaOrigin}/current-demo"><span>Try it on dima.ai →</span></a><a class="chamfer btn btn--muted button secondary" href="/clients"><span>Register a service</span></a></div>${form('/account/logout', req.demoSession.csrf, '<button class="text-button">Sign out of Current</button>')}` : '<p>Create a Current account with Google to try the identity provider.</p><a class="chamfer btn btn--cyan button" href="/auth/google"><span>Continue with Google →</span></a>'}${req.demoSession.result ? `<h2>Last verified sign-in</h2><pre>${escape(JSON.stringify(req.demoSession.result, null, 2))}</pre>` : ''}`));
  });
  current.post('/account/logout', csrf, (_req, res) => res.redirect(303, '/oauth/logout'));

  async function interaction(req, res) {
    const details = await provider.interactionDetails(req, res);
    if (details.uid !== req.params.uid) throw Object.assign(new Error('Wrong interaction.'), { status: 400 });
    const callbackOrigin = new URL(details.params.redirect_uri).origin;
    res.set('Content-Security-Policy', res.get('Content-Security-Policy').replace("form-action 'self'", `form-action 'self' ${callbackOrigin}`));
    return details;
  }
  function canLogin(req, details) {
    if (!accounts.bySub.has(req.demoSession.accountId)) return false;
    const force = details.params.prompt?.split(' ').includes('login') || details.params.max_age !== undefined;
    return !force || req.demoSession.authInteraction === details.uid;
  }
  current.get('/interaction/:uid', async (req, res) => {
    const details = await interaction(req, res);
    // Browsers apply form-action to the redirect chain too. Permit only the
    // callback origin that the provider has already matched to this client.
    const client = await provider.Client.find(details.params.client_id);
    const account = accounts.bySub.get(details.prompt.name === 'consent' ? details.session?.accountId : req.demoSession.accountId);
    const ready = details.prompt.name === 'consent' ? !!account : canLogin(req, details);
    const body = ready ? form(`/interaction/${details.uid}`, req.demoSession.csrf,
      `<p>Continue as <strong>${escape(account.name)}</strong> · Current <strong>${escape(account.current_id)}</strong>.</p><p>Requested access: <strong>${escape(details.params.scope)}</strong>.</p><p>Return to <code>${escape(new URL(details.params.redirect_uri).origin)}</code>.</p><button class="chamfer btn btn--cyan" name="action" value="approve"><span>${details.prompt.name === 'consent' ? 'Allow access' : 'Continue'} →</span></button> <button class="chamfer btn btn--muted secondary" name="action" value="deny"><span>Cancel</span></button>`) :
      `<p>${account ? 'This service requires a fresh sign-in. Continue with Google again.' : 'Use your Google account to create a temporary Current identity, then continue to this service.'}</p><a class="chamfer btn btn--cyan button" href="/auth/google?return_to=${encodeURIComponent(`/interaction/${details.uid}`)}"><span>Continue with Google →</span></a>${form(`/interaction/${details.uid}`, req.demoSession.csrf, '<button class="text-button" name="action" value="deny">Cancel sign-in</button>')}`;
    res.send(page('Sign in with Current', `<p class="eyebrow">CURRENT / IDENTITY PROVIDER</p><h1>${escape(client.clientName || client.clientId)}<br>wants to connect.</h1>${body}`));
  });
  current.post('/interaction/:uid', csrf, async (req, res) => {
    const details = await interaction(req, res);
    if (req.body.action === 'deny') return provider.interactionFinished(req, res, { error: 'access_denied', error_description: 'The user declined the request.' }, { mergeWithLastSubmission: false });
    if (req.body.action !== 'approve') return res.status(400).send('Choose an action.');
    if (details.prompt.name === 'login') {
      if (!canLogin(req, details)) return res.status(403).send('Sign in with Google first.');
      return provider.interactionFinished(req, res, { login: { accountId: req.demoSession.accountId, ts: req.demoSession.authTime } }, { mergeWithLastSubmission: false });
    }
    if (details.prompt.name !== 'consent' || !accounts.bySub.has(details.session?.accountId)) return res.status(400).send('Sign-in expired.');
    const grant = details.grantId ? await provider.Grant.find(details.grantId) : new provider.Grant({ accountId: details.session.accountId, clientId: details.params.client_id });
    if (!grant) return res.status(400).send('Grant expired.');
    const missing = details.prompt.details;
    if (missing.missingOIDCScope) grant.addOIDCScope(missing.missingOIDCScope.join(' '));
    if (missing.missingOIDCClaims) grant.addOIDCClaims(missing.missingOIDCClaims);
    for (const [resource, scopes] of Object.entries(missing.missingResourceScopes || {})) grant.addResourceScope(resource, scopes.join(' '));
    const grantId = await grant.save();
    return provider.interactionFinished(req, res, { consent: { grantId } }, { mergeWithLastSubmission: true });
  });

  const registrations = new Map();
  current.get('/clients', (req, res) => {
    if (!accounts.bySub.has(req.demoSession.accountId)) return res.redirect(303, '/account');
    res.send(page('Register a service', `<p class="eyebrow">OAUTH 2.0 / OPENID CONNECT</p><h1>Add “Sign in<br>with Current”.</h1><p>Register an exact HTTPS callback URL. Your client credentials expire after 24 hours and disappear on restart. Use authorization code flow with S256 PKCE.</p>${form('/clients', req.demoSession.csrf, '<label>Service name<span class="chamfer field-control"><input class="field-input" name="name" required maxlength="80" placeholder="My service"></span></label><label>Callback URL<span class="chamfer field-control"><input class="field-input" type="url" name="redirect_uri" required maxlength="2048" placeholder="https://example.com/auth/callback"></span></label><button class="chamfer btn btn--cyan"><span>Create client →</span></button>')}`));
  });
  current.post('/clients', csrf, async (req, res) => {
    const owner = req.demoSession.accountId;
    if (!accounts.bySub.has(owner)) return res.status(401).send('Sign in with Google first.');
    const name = req.body.name;
    const redirect = typeof req.body.redirect_uri === 'string' && URL.parse(req.body.redirect_uri);
    if (typeof name !== 'string' || !name.trim() || name.length > 80 || !redirect || redirect.href.length > 2048 || redirect.hash || redirect.username || redirect.password || redirect.protocol !== 'https:') return res.status(400).send('Enter a service name and an exact HTTPS callback URL without a fragment or credentials.');
    const count = registrations.get(owner) || 0;
    if (count >= 10) return res.status(429).send('Ten clients per account are allowed in this demo.');
    const response = await fetchImpl(`${settings.currentOrigin}/oauth/register`, {
      method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${providerData.registrationToken}` },
      body: JSON.stringify({ client_name: name.trim(), redirect_uris: [redirect.href], response_types: ['code'], grant_types: ['authorization_code', 'refresh_token'], token_endpoint_auth_method: 'client_secret_basic' }),
    });
    if (!response.ok) throw new Error('Client registration failed.');
    const result = await response.json();
    registrations.set(owner, count + 1);
    const credentials = { issuer: settings.currentOrigin, client_id: result.client_id, client_secret: result.client_secret, redirect_uri: redirect.href, token_endpoint_auth_method: result.token_endpoint_auth_method };
    res.send(page('Client created', `<h1>Your service is ready.</h1><p>Save this secret in your server configuration. It is shown once. Keep it out of browser code.</p><pre>${escape(JSON.stringify(credentials, null, 2))}</pre><p>Discovery: <a href="/.well-known/openid-configuration">OpenID configuration</a>. Request <code>openid profile email</code>. The <code>sub</code> claim is the identity; <code>current_id</code> is its six-digit display ID.</p><a href="/clients">Register another service</a>`));
  });

  current.use(provider.callback());
  app.use((_req, res) => res.status(404).send(page('Page not found', '<h1>Page not found.</h1><a href="/">Back to the demos</a>')));
  app.use((err, _req, res, _next) => {
    console.error('Demo request failed:', err.name, err.code || '');
    if (res.headersSent) return res.end();
    const status = err.status || (['ClientError', 'AuthorizationResponseError', 'ResponseBodyError'].includes(err.constructor.name) ? 400 : 500);
    res.status(status).send(page('Could not continue', `<h1>Could not continue.</h1><p>${escape(status < 500 || status === 503 ? err.message : 'The sign-in service could not complete this request. Please start again.')}</p><p><a href="/">Back to Current</a> · <a href="/setup">Configuration guide</a></p>`));
  });
  return { app, provider, accounts, board, clients: providerData.clients };
}

function setupHtml(settings) {
  return `<p class="eyebrow">DEVELOPER NOTES</p><h1>Small demos.<br>Real protocols.</h1>
  <h2>Use Current as your identity provider</h2><p>Issuer: <code>${escape(settings.currentOrigin)}</code><br>Discovery: <a href="/.well-known/openid-configuration">/.well-known/openid-configuration</a><br>OAuth metadata: <a href="/.well-known/oauth-authorization-server">/.well-known/oauth-authorization-server</a></p><p><a href="/clients">Register your service</a>, then use authorization code flow with S256 PKCE. Request <code>openid profile email</code> for OIDC, or <code>profile</code> for the OAuth-only demo. Use <code>sub</code> as the user identity, not the six-digit display ID. Tokens expire after ten minutes; sessions and refresh tokens after one hour.</p>
  <h2>Google Console</h2><ol><li>Open <a href="https://console.cloud.google.com/auth/overview">Google Auth Platform</a> in the project owning the OAuth credentials.</li><li>In Branding, use Current, add <code>current.ai</code> as an authorized domain, and set the homepage to <code>https://current.ai</code>, privacy policy to <code>https://current.ai/privacy</code>, and terms to <code>https://current.ai/terms</code>. Provide the support and developer contact emails.</li><li>In Audience, choose External. While Testing, add your Google account under Test users. Publish when you want other users to sign in.</li><li>In Data Access, select only <code>openid</code>, <code>.../auth/userinfo.email</code>, and <code>.../auth/userinfo.profile</code>. No Gmail API or inbox permission is needed.</li><li>In Clients, edit or create a Web application. Add the authorized redirect URI <code>${escape(settings.currentOrigin)}/auth/google/callback</code>. Keep existing dima.ai redirects. This server redirect flow needs no JavaScript origin setting.</li><li>Configure <code>GOOGLE_CLIENT_ID</code> and <code>GOOGLE_CLIENT_SECRET</code> on the demos service, then restart it.</li></ol>
  <h2>GitHub</h2><p>Create an OAuth App in GitHub Settings → Developer settings → OAuth Apps. Homepage: <code>https://current.ai</code>. Authorization callback: <code>${escape(settings.currentOrigin)}/auth/github/callback</code>. Set <code>GITHUB_CLIENT_ID</code> and <code>GITHUB_CLIENT_SECRET</code>. A separate app preserves the existing dima.ai callback. The demo requests the read:user profile scope; it does not request repository access.</p>
  <h2>Okta or another OIDC provider</h2><p>The built-in OIDC client runs against Current. To also connect an external provider, register a Web OIDC application there with callback <code>${escape(settings.currentOrigin)}/auth/enterprise/callback</code>, and set <code>ENTERPRISE_OIDC_ISSUER</code>, <code>ENTERPRISE_OIDC_CLIENT_ID</code>, and <code>ENTERPRISE_OIDC_CLIENT_SECRET</code>. Use authorization code flow and client_secret_post authentication. The client discovers endpoints and validates state, PKCE, nonce, issuer, audience, expiry, the ID-token signature, and the UserInfo subject.</p>
  <h2>Connect an MCP client</h2><p>Streamable HTTP endpoint: <code>${escape(settings.currentOrigin)}/mcp</code>. No auth. Tools: <code>assign_color</code> with a <code>name</code>, and <code>latest_colors</code>. Resource: <code>current://colors/latest</code>. All submissions are public; the latest five are retained.</p><pre>${escape(JSON.stringify({ mcpServers: { 'current-colors': { url: `${settings.currentOrigin}/mcp` } } }, null, 2))}</pre>
  <h2>Standards and verification</h2><p>The server uses <a href="https://github.com/panva/node-oidc-provider">oidc-provider</a>, an OpenID Certified implementation, configured for authorization code flow, discovery, JWKS, UserInfo, registration, revocation, introspection, refresh tokens, and RP-initiated logout. The client uses <a href="https://github.com/panva/openid-client">openid-client</a>. Current's deployment has not itself been OpenID certified. See the repository verification guide for local interoperability tests and how to run the OpenID Foundation conformance suite.</p>`;
}
