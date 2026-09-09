# Current demos

`current.ai` is an OAuth client, an OAuth/OpenID Connect provider, and a public MCP server. `dima.ai/current-demo` is a separate relying party. Rust terminates HTTPS and proxies Current (except ACME challenges) and the dima demo path to this loopback Node service. Other dima.ai routes retain their existing behavior.

## Run locally

Use Node 24 LTS or newer supported LTS:

```sh
git submodule update --init --checkout -- vendor/prnui
cd services/current
npm ci
npm start
```

Open `http://127.0.0.1:3100`. The separate relying party is `http://localhost:3100/current-demo`. Google requires a Web client with `http://127.0.0.1:3100/auth/google/callback` registered for local testing. Export the credentials before starting (or use Node's `--env-file`); `.env` is not loaded automatically. The no-auth MCP/color demo works without credentials. Plain HTTP loopback uses a SameSite=Lax development cookie fallback. Use HTTPS to exercise the production SameSite=None SSO policy, including cross-site authorization POST requests.

## Shared PRN UI

Current's homepage, account and consent screens, setup guide, and dima relying-party demo use the PRN design system. At startup, the service reads the stylesheet directly from `vendor/prnui/prnui.html` and serves it as `/assets/prnui.css`. The upstream submodule owns the colors, typography, chamfers, cards, buttons, and fields. `public/style.css` contains Current's layouts and responsive adjustments; the specimen's JavaScript is not needed for Current's own interactions.

Follow the repository's [deployment instructions](../../AGENTS.md): update the submodule from upstream `main`, test, and commit any changed gitlink before every deployment. Initialize that recorded revision on the server before restarting Current. A service restart loads any updated upstream styles. The standalone `/prn` specimen still comes from the Rust binary and requires rebuilding when its upstream HTML changes.

## Provider setup

The live `/setup` page contains the configuration guide. On Google Auth Platform:

1. **Branding:** Current; homepage `https://current.ai`; privacy `https://current.ai/privacy`; terms `https://current.ai/terms`; authorized domain `current.ai`; support/developer email addresses.
2. **Audience:** External. Add test users during Testing, then publish for general access.
3. **Data Access:** `openid`, `https://www.googleapis.com/auth/userinfo.email`, `https://www.googleapis.com/auth/userinfo.profile`. No Gmail API or Gmail scopes are required.
4. **Clients:** Web application. Add **`https://current.ai/auth/google/callback`** to authorized redirect URIs, retaining existing dima.ai callbacks. Server redirects do not require authorized JavaScript origins.
5. Set `GOOGLE_CLIENT_ID` and `GOOGLE_CLIENT_SECRET` in the service environment and restart.

For GitHub, create a separate OAuth App to preserve the older dima.ai login: homepage `https://current.ai`, callback **`https://current.ai/auth/github/callback`**. Set `GITHUB_CLIENT_ID` and `GITHUB_CLIENT_SECRET`. GitHub profiles demonstrate OAuth login but do not create Current provider accounts; only verified Google identities do that.

For Okta or another external OIDC provider, register a Web app with authorization code flow, `client_secret_post` authentication, scopes `openid profile email`, and callback **`https://current.ai/auth/enterprise/callback`**. Set `ENTERPRISE_OIDC_ISSUER`, `ENTERPRISE_OIDC_CLIENT_ID`, and `ENTERPRISE_OIDC_CLIENT_SECRET`. The built-in OIDC demo already uses Current as its issuer.

Official references: [Google](https://developers.google.com/identity/openid-connect/openid-connect), [GitHub OAuth](https://docs.github.com/en/apps/oauth-apps/building-oauth-apps/authorizing-oauth-apps), [OpenID Connect](https://openid.net/specs/openid-connect-core-1_0.html).

## Endpoints and state

Persistent clients are loaded from the private JSON file named by `CURRENT_CLIENTS_FILE`. It contains an array of standard OIDC client registrations, including each client's ID, secret, exact `redirect_uris` allowlist, grant types, and token authentication method. Keep this file outside Git with mode `0600`; credentials survive deployments and restarts. Without it, only the built-in demo clients are configured. Browser-created registrations remain temporary.

This repository treats external services as opaque OAuth/OIDC clients. Their implementation, configuration, admission rules, and deployment belong elsewhere.

| Endpoint | Purpose |
| --- | --- |
| `/.well-known/openid-configuration` | OIDC discovery; issuer `https://current.ai` |
| `/.well-known/oauth-authorization-server` | OAuth authorization server metadata |
| `/oauth/authorize`, `/oauth/token` | Authorization code and refresh grants |
| `/oauth/jwks`, `/oauth/userinfo` | Public signing keys and OIDC claims |
| `/oauth/introspect`, `/oauth/revoke` | Authenticated token inspection and revocation |
| `/oauth/logout` | RP-initiated logout |
| `/oauth/register` | Standard dynamic registration; requires an initial access token |
| `/clients` | Google-authenticated service registration with CSRF protection |
| `/api/identity` | OAuth-only protected profile; requires `profile` scope |
| `/demo/oauth`, `/demo/oidc` | End-to-end Current client demonstrations |
| `/auth/enterprise` | Optional external OIDC sign-in |
| `/mcp` | Stateless Streamable HTTP, official MCP SDK |
| `/api/colors` | Latest five public assignments |

MCP tools: `assign_color({"name":"Ada"})` and `latest_colors({})`. Resource: `current://colors/latest`. GET and DELETE on `/mcp` return 405, as permitted for a stateless JSON-response transport. Notifications return 202. The browser uses the same MCP wire protocol as an external client. Names are bounded to 60 printable characters and rendered as text. Foreign browser origins are rejected; native MCP clients require no auth or Origin header.

Accounts, six-digit IDs, grants, browser-registered clients, sessions, and colors are **in memory**. Accounts remain until restart; browser sessions, grants, and refresh tokens expire after one hour. Access/ID tokens last ten minutes, codes one minute, pending sign-ins ten minutes, and browser-registered clients 24 hours. Configured client registrations are restored from the private clients file after restart. Storage has hard capacity limits and expirations. A random opaque `sub` prevents recycled six-digit IDs from identifying another account after restart. Integrations must use `sub`, not `current_id`, as their identity key. The durable signing key contains no user data.

Authorization accepts both GET and POST. Dynamic client management supports authenticated read, update, and deletion.

Open `/oauth/logout` directly or choose **Sign out of Current** on `/account` to sign out of this browser. Completed logout clears both Current's account session and its provider SSO session, including pending sign-ins. It also sends signed OIDC back-channel logout notifications to participating relying parties. Canceling the confirmation preserves the Current sign-in and sends no global logout notifications. Google and applications without a registered logout receiver retain their own sessions; sign out there separately if needed.

To participate, add `backchannel_logout_uri` (the application's exact HTTPS receiver URL) and `backchannel_logout_session_required: true` to its standard client registration in `CURRENT_CLIENTS_FILE`, preserving its existing credentials and callback allowlist. Restart the service to load persistent registration edits. Authenticated dynamic registration/management accepts these fields too. Discovery advertises `backchannel_logout_supported` and `backchannel_logout_session_supported`; subsequent ID tokens include the client-specific `sid`. Existing application sessions established before registration must sign in again.

The library sends an `application/x-www-form-urlencoded` POST containing `logout_token`, signed with Current's signing key. Receivers must validate the signature, issuer, audience, issuance time, logout event, absence of nonce, and session ID before ending the matching session. Other browser sessions remain independent. Delivery failures produce a token-free server log message; they do not prevent local Current logout, and this in-memory provider does not queue durable retries. Applications should retain finite local session lifetimes. See [OIDC Back-Channel Logout](https://openid.net/specs/openid-connect-backchannel-1_0.html).

The implementation uses pinned `oidc-provider` and `openid-client` versions. It supports the OIDC **authorization code** profile, RS256 ID tokens, discovery, UserInfo, claims requests, consent, refresh, revocation, introspection, DCR, and RP-initiated logout. It does not advertise implicit/hybrid flows. Native clients require PKCE; all built-in clients use S256 PKCE. Google/OIDC callbacks check browser-bound state, nonce, issuer, audience, expiration, signature, and matching UserInfo subject. Access tokens and secrets are never displayed in demo results or request logs.

## Deploy

The server needs Node 24 LTS under `/home/ec2-user/.local/current-node`. Download its official Linux x64 archive from nodejs.org and verify it against `SHASUMS256.txt` before extraction. Install production dependencies with that runtime on PATH:

```sh
cd /home/ec2-user/website/services/current
PATH=/home/ec2-user/.local/current-node/bin:$PATH npm ci --omit=dev
/home/ec2-user/.local/current-node/bin/node scripts/generate-jwks.js /home/ec2-user/.config/current-demos-jwks.json
```

Run the key-generation command **once**, using the installed Node binary or PATH above. Create `/home/ec2-user/.config/current-demos.env` from `.env.example`, mode 0600, outside the repository. Install `config/current-demos.service` in `/etc/systemd/system/`, then:

```sh
sudo systemctl daemon-reload
sudo systemctl enable --now current-demos.service
curl -fsS http://127.0.0.1:3100/healthz -H 'Host: current.ai' -H 'X-Forwarded-Proto: https'
```

Build the Rust ingress with `cargo build --profile fast-release -p homepage`. Its default upstream is `http://127.0.0.1:3100`, overridable through `CURRENT_DEMOS_UPSTREAM` (loopback only). Restart `website.service` after the demos health check succeeds. For subsequent updates, `npm ci --omit=dev`, restart `current-demos.service`, then restart the rebuilt ingress if it changed. Expect in-memory state to reset.

Before replacing a running Rust executable, copy it to a rollback filename. If checks fail, restore the previous executable and restart `website.service`; stop the demos service if it was newly introduced. Preserve deployment-only `static/pad.html` and `static/pad.js`.

## Verification

See the [deployment verification record](VERIFICATION.md) for measured results, OpenID Foundation suite outcomes, and remaining external provider configuration.

```sh
npm ci
npx playwright install chromium
npm test
# Or, with Google Chrome already installed:
PLAYWRIGHT_CHANNEL=chrome npm test
```

The tests use a test-only upstream issuer with an independent RSA implementation. They drive real browsers through Google-backed account creation, consent, Current OAuth/OIDC and dima sign-in; validate ID tokens independently with JOSE; exercise refresh/revocation/replay and wrong PKCE/redirects; reject malicious issuer/audience/nonce/expiry/signature/UserInfo subject; check CSRF, cancellation, browser session isolation, official MCP SDK interoperability, cleanup, input validation, and mobile layout. Tests shut down browsers, servers, and transports in teardown. No fake-login route exists in the running service. `cargo test -p homepage` covers ingress behavior, including POST bodies, redirect preservation, cookie forwarding, and forged proxy headers.

The OpenID Certified libraries' certification does not automatically certify this deployment. To run the [OpenID Foundation suite](https://gitlab.com/openid/conformance-suite), use its Config OP and Basic OP plans against `https://current.ai/.well-known/openid-configuration`. Create the suite's client registrations through `/clients` or set a private `CURRENT_REGISTRATION_TOKEN` for authenticated DCR. Use a real Google-backed Current account for interactive cases. The local test fixture can also be served behind HTTPS for automated protocol tests without live Google credentials. Include both client_secret_basic and client_secret_post variants. Record skipped/manual cases separately from passes; do not claim certification without completing the Foundation's process. After a local Docker run, remove that run's containers/network/volumes with its exact Compose project name and `down --volumes`.
