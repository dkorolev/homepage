# Deployment verification — 2026-09-05 UTC

Application commit: `cb4806d`. The Rust ingress and `current-demos.service` were deployed to the existing dima.ai host. Production runs Node 24.20.0 LTS.

## Results

| Check | Result |
| --- | --- |
| Rust ingress tests | 10 passed |
| Browser, OAuth/OIDC, MCP, and storage integration tests | 12 passed |
| Production dependency audit | No reported vulnerabilities |
| Live Current HTTPS, health, discovery, and dima relying-party page | Passed |
| Existing dima.ai pad script | Still served |
| Live official MCP SDK initialize/list/call and public color board | Passed |
| OpenID Foundation Config OP profile against **live current.ai** | Passed |
| OpenID Foundation Basic OP profile against an HTTPS local copy | 26 passed, 6 skipped, 2 warnings, 4 review, **0 failures** |

The [live discovery result](verification/oidf-discovery-live.json) and [38-module Basic result](verification/oidf-basic.json) retain the exact outcomes. The Basic tests use the application provider with a **test-only upstream Google substitute** and an independent RSA signer. They exercise the production HTTPS cookie policy, not the HTTP development fallback. Production exposes no fake-login endpoint.

The official suite image was `registry.gitlab.com/openid/conformance-suite@sha256:a849feeba1b88a81f9da8e79ce1421c9e64452e8ad4b588a51f8d1562fc7b578`. Suite source/API instructions were inspected at commit `3e09b13b896fce95d78c2c0f931feee9614e9452`. Tests were driven through the suite's local API and a real Chrome browser. Initial findings led to enabling authenticated client management and authorization-endpoint POST support; the complete Basic profile was then rerun.

## Interpretation

Six tests were skipped because the provider does not advertise unsigned ID tokens, address/phone scope data, unsigned request objects, or request-URI support. Those optional features are not implemented.

Two warnings remain:

- `scope=profile` does not return every optional profile field, such as gender, birthdate, website, and timezone. The demo has a name and a Current ID; it does not manufacture other personal data.
- The provider does not return an `acr` authentication-context claim in response to an `acr_values` preference. It does not assert a particular assurance class for the upstream Google login.

Four cases require screenshot review in the suite. The captured screens were inspected and show the expected behavior; the suite's **REVIEW** status is retained:

- [Explicit fresh login](verification/oidcc-prompt-login.png).
- [Fresh login after max_age expiry](verification/oidcc-max-age-1.png).
- [Reject an unregistered redirect URI](verification/oidcc-ensure-registered-redirect-uri.png).
- [Reject an unregistered redirect URI with a request object](verification/oidcc-ensure-request-object-with-redirect-uri.png).

This is not an OpenID certification claim. The provider's Basic profile and the live Config profile were run; the client has application-level positive and negative interoperability tests, not a separate Foundation RP certification run. Certification would require the Foundation's review/process and testing the real production identity journey after its external OAuth settings are complete.

## External configuration still needed

The deployed Google flow was exercised and returned **`redirect_uri_mismatch`**. Add `https://current.ai/auth/google/callback` to the existing Google Web OAuth client's authorized redirect URIs. Preserve existing dima.ai callbacks. Use the `openid`, email, and profile scopes; no Gmail API is needed. The full instructions are in the [setup guide](README.md#provider-setup) and at [current.ai/setup](https://current.ai/setup).

GitHub currently uses the existing app branded dima.ai. Register a separate Current OAuth App with callback `https://current.ai/auth/github/callback` and update the demos service environment to preserve the older dima.ai login. A complete real-user GitHub authorization was not performed.

The optional external Okta/OIDC connection needs its own issuer, client ID, and secret. Current's own OIDC client and dima.ai relying party are already implemented; their complete sign-in journeys were verified with the test upstream.

Local browsers, fixture servers, and the temporary OpenID conformance containers were shut down after testing. The production services remain running, and the previous Rust executable was retained as `/home/ec2-user/homepage-before-current-demos` for rollback.
