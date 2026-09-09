import { readFile } from 'node:fs/promises';
import Provider from 'oidc-provider';
import { generateKeyPair, exportJWK } from 'jose';
import { memoryAdapter, random } from './memory.js';
import { escape, page } from './views.js';

export async function createProvider(settings, accounts) {
  let jwks;
  if (settings.jwksFile) jwks = JSON.parse(await readFile(settings.jwksFile, 'utf8'));
  else {
    const { privateKey } = await generateKeyPair('RS256', { extractable: true });
    jwks = { keys: [{ ...await exportJWK(privateKey), kid: random(), alg: 'RS256', use: 'sig' }] };
  }
  const clients = ['oauth', 'oidc', 'dima'].map(name => ({
    client_id: `current-${name}-demo`, client_secret: random(),
    client_name: name === 'dima' ? 'dima.ai' : `Current ${name.toUpperCase()} demo`,
    redirect_uris: [name === 'dima' ? `${settings.dimaOrigin}/current-demo/callback` : `${settings.currentOrigin}/demo/${name}/callback`],
    post_logout_redirect_uris: [name === 'dima' ? `${settings.dimaOrigin}/current-demo` : `${settings.currentOrigin}/`],
    response_types: ['code'], grant_types: ['authorization_code', 'refresh_token'],
    token_endpoint_auth_method: 'client_secret_basic',
  }));
  // Persistent registrations are ordinary client metadata supplied privately by the operator.
  if (settings.clientsFile) {
    const contents = await readFile(settings.clientsFile, 'utf8');
    let registered;
    try { registered = JSON.parse(contents); }
    catch { throw new Error('CURRENT_CLIENTS_FILE must contain a JSON array of client registrations'); }
    if (!Array.isArray(registered)) throw new Error('CURRENT_CLIENTS_FILE must contain a JSON array of client registrations');
    clients.push(...registered);
  }
  const registrationToken = settings.registrationToken || random();
  const provider = new Provider(settings.currentOrigin, {
    adapter: memoryAdapter(), clients, jwks,
    cookies: { keys: [random()], short: { sameSite: 'lax' }, long: { sameSite: 'none' } },
    claims: { openid: ['sub'], profile: ['name', 'current_id'], email: ['email', 'email_verified'] },
    scopes: ['openid', 'profile', 'email', 'offline_access'],
    subjectTypes: ['public'],
    // A complete authorization-code provider. Implicit/hybrid profiles are not advertised.
    responseTypes: ['code'],
    enableHttpPostMethods: true,
    features: {
      devInteractions: { enabled: false },
      registration: { enabled: true, initialAccessToken: registrationToken },
      registrationManagement: { enabled: true },
      revocation: { enabled: true, allowedPolicy: (_ctx, client, token) => token.clientId === client.clientId },
      introspection: { enabled: true, allowedPolicy: (_ctx, client, token) => token.clientId === client.clientId },
      claimsParameter: { enabled: true },
      backchannelLogout: { enabled: true },
      rpInitiatedLogout: {
        enabled: true,
        logoutSource: async (ctx, logoutForm) => {
          // Keep the library's form, action, and CSRF token intact.
          ctx.body = page('Sign out of Current', `<p class="eyebrow">CURRENT / SIGN OUT</p><h1>End this sign-in?</h1><p>Sign out of Current on this browser.</p>${logoutForm}<div class="actions"><button class="chamfer btn btn--cyan" autofocus type="submit" form="op.logoutForm" value="yes" name="logout"><span>Yes, sign me out</span></button><button class="chamfer btn btn--muted" type="submit" form="op.logoutForm"><span>No, stay signed in</span></button></div>`);
        },
        postLogoutSuccessSource: async ctx => {
          ctx.body = page('Signed out', '<p class="eyebrow">CURRENT / SIGN OUT</p><h1>Sign-out complete.</h1><p>You can sign in again whenever you want to try another connection.</p><a class="chamfer btn btn--cyan" href="/"><span>Back to the demos →</span></a>');
        },
      },
    },
    rotateRefreshToken: () => true,
    ttl: {
      AccessToken: 600, AuthorizationCode: 60, IdToken: 600,
      RefreshToken: ctx => ctx?.oidc?.entities.RotatedRefreshToken?.remainingTTL ?? 3600,
      Session: 3600, Interaction: 600, Grant: 3600,
    },
    interactions: { url: (_ctx, interaction) => `/interaction/${interaction.uid}` },
    routes: {
      authorization: '/oauth/authorize', token: '/oauth/token', jwks: '/oauth/jwks',
      userinfo: '/oauth/userinfo', registration: '/oauth/register',
      revocation: '/oauth/revoke', introspection: '/oauth/introspect', end_session: '/oauth/logout',
    },
    clientBasedCORS: (_ctx, origin, client) => client.redirectUris.some(uri => new URL(uri).origin === origin),
    findAccount: async (_ctx, id) => {
      const account = accounts.bySub.get(id);
      if (!account) return undefined;
      return { accountId: id, claims: async () => ({ ...account }) };
    },
    renderError: async (ctx, out) => {
      ctx.type = 'html';
      ctx.body = page('Sign-in could not continue', `<h1>Sign-in could not continue.</h1><p>${escape(out.error)}: ${escape(out.error_description)}</p><p>Return to the service and start again.</p><a href="/">Current demos</a>`);
    },
  });
  provider.proxy = true;
  // Never log authorization codes, tokens, or provider response bodies.
  provider.on('server_error', (_ctx, err) => console.error('OIDC server error:', err.name));
  // Report delivery failures without logging callback URLs, account IDs, or signed logout tokens.
  provider.on('backchannel.error', () => console.error('OIDC back-channel logout delivery failed'));
  return { provider, clients, registrationToken };
}
