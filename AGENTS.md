# Deployment instructions

- Treat external OAuth/OIDC services as opaque clients. Keep their implementation, configuration, and deployment details outside this repository; Current needs only ordinary client registrations and exact callback URL allowlists.

- `vendor/prnui` is a Git submodule tracking `main` in `https://github.com/dkorolev/prnui.git`. That repository is the single source of truth for PRN UI. Do not copy or edit its HTML in homepage; make UI changes upstream first.
- Before **every deployment**, including deployments of unrelated homepage changes, fetch the latest PRN UI with `git submodule update --init --remote --checkout -- vendor/prnui`. This is the submodule equivalent of pulling upstream `main`. Preserve any local submodule edits; resolve them before updating.
- Run `node --test vendor/prnui/test/prnui.test.mjs` and `cargo test -p homepage`. Commit any changed `vendor/prnui` gitlink in the deployment branch, so the deployed version is recorded in homepage history.
- After merging that branch on the server, run `git submodule update --init --checkout -- vendor/prnui` before building. This installs the exact upstream commit just reviewed and recorded. `/prn` and `/prn/` embed the unmodified page in the Rust binary; updating the submodule alone does not update the live page.
- Current consumes the same submodule's CSS at service startup through `/assets/prnui.css`. Keep shared component changes upstream; `services/current/public/style.css` owns only Current's layout and application adjustments. Restart `current-demos.service` after a submodule or Current server change to load the updated styles.
- Follow the full deployment and rollback commands in [README.md](README.md). Preserve the production-only `static/pad.html` and `static/pad.js`. Never print environment files or credential-bearing launch scripts while inspecting deployment configuration.
