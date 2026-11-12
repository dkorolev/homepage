# homepage

A simple personal page.

Created primarily to gain experience on finding freelance designers with help of Quora. :-)

Extended quite a bit for my personal tasks since.

## Redeploy

Before **every deployment**, fetch the latest PRN UI and offline-speech from their upstream `main`, even if the homepage change is unrelated:

```sh
git submodule update --init --remote --checkout -- vendor/prnui vendor/offline-speech
node --test vendor/prnui/test/prnui.test.mjs
(cd vendor/offline-speech && npm run test:unit)
cargo test -p homepage
```

If a submodule commit changed, include its gitlink in the deployment branch's commit and push it with the other changes. Keep any local submodule edits safe before updating. The PRN UI source belongs in [dkorolev/prnui](https://github.com/dkorolev/prnui), and the TTS app in [dimacurrentai/offline-speech](https://github.com/dimacurrentai/offline-speech); make changes there first.

The prepared branch must contain both upstream homepage history and the deployed
history. If they diverge, merge them locally and resolve the submodule pins to the
reviewed upstream versions before deployment; do not reset production to upstream
or replace its newer speech pin with an older one. The server merge below must
remain a fast-forward.

On the production server, merge the prepared branch and initialize the recorded submodule version before compiling:

```sh
(
set -e
cd /home/ec2-user/website
git merge --ff-only dev
git submodule update --init --checkout -- vendor/prnui vendor/offline-speech
# Rebuild /tts/ only when offline-speech changed. The disk is small, so remove the old build first
# (/tts/ answers 404 until the new one is ready) and drop the raw downloads (~190 MB, including ~68 MB of source archives) afterwards.
NODE=/home/ec2-user/.local/current-node/bin/node
TTS_COMMIT=$(git -C vendor/offline-speech rev-parse HEAD)
if [ "$(cat vendor/offline-speech/dist/.homepage-built-commit 2>/dev/null)" != "$TTS_COMMIT" ]; then
  rm -rf vendor/offline-speech/dist
  $NODE vendor/offline-speech/scripts/download-assets.mjs
  $NODE vendor/offline-speech/scripts/build-hosted.mjs
  rm -rf vendor/offline-speech/models vendor/offline-speech/vendor
  echo "$TTS_COMMIT" > vendor/offline-speech/dist/.homepage-built-commit
fi
cp target/fast-release/homepage /home/ec2-user/homepage-before-deploy
cargo build --profile fast-release -p homepage
sudo systemctl restart website.service
curl -fsS https://dima.ai/prn -o /dev/null
)
```

Stop if any command fails. If the new service fails its live checks, restore the saved executable and restart:

```sh
cp /home/ec2-user/homepage-before-deploy target/fast-release/homepage.rollback
mv target/fast-release/homepage.rollback target/fast-release/homepage
sudo systemctl restart website.service
```

## TTS

[dima.ai/tts/](https://dima.ai/tts/) serves the offline-speech browser text-to-speech app, linked from the `?debug` view. Speech runs on the visitor's device: the server serves only static files, and text and audio never leave the browser. `/tts` redirects to `/tts/`, so the app's relative URLs and service-worker scope resolve. Like `/static/`, its files carry `Cache-Control: no-cache` and an ETag, so the HTTP cache revalidates them. The app's service worker separately manages saved files and open-tab updates; these headers do not invalidate its Cache Storage.

`vendor/offline-speech` is a Git submodule of the public [dimacurrentai/offline-speech](https://github.com/dimacurrentai/offline-speech), tracking `main`, fetched over plain HTTPS with no credentials. The homepage serves `vendor/offline-speech/dist/hosted/` unchanged; without that build, startup logs a warning and `/tts/` answers 404. offline-speech's own code is GPL-3.0-or-later, and its build bundles eSpeak NG under the same license; the app's page links its license and dependency notices, and `/tts/source/` serves the corresponding source archives. The debug view links the deployed offline-speech commit under the TTS row.

## PRN UI

[dima.ai/prn](https://dima.ai/prn) serves the public PRN UI specimen; `/prn/` works too. No account is required. Its self-contained HTML, CSS, and JavaScript run in each visitor's browser, with synthetic demo data and no shared backend state.

`vendor/prnui` is a Git submodule of [dkorolev/prnui](https://github.com/dkorolev/prnui), tracking `main`. The Rust binary embeds `prnui.html` unchanged, and browsers revalidate the page on reload. Only the page is served; the submodule's Git metadata and other repository files are not exposed through `/prn`.

For a fresh clone, run `git submodule update --init --checkout -- vendor/prnui` before compiling (or use `git clone --recurse-submodules`). Follow the update step above on every deployment. Use the upstream [verification checklist](vendor/prnui/FEATURE-DEMO.md) for desktop, mobile, keyboard, and pointer checks.

## Certificates

The server takes one certificate directory, and its last path component is the FQDN. In production `run.sh` points it at a copy the service user owns, not at `/etc/letsencrypt` (which is root-only):

```
--letsencrypt /home/ec2-user/.ssl/dima.ai
```

Every sibling directory that also holds `fullchain.pem` and `privkey.pem` is loaded at startup and served by SNI under its own name, so `/home/ec2-user/.ssl/current.ai/` makes `https://current.ai` present the `current.ai` certificate. A sibling that fails to load is logged and skipped, and the startup log lists each one picked up as `SNI cert: <name>`. Restart the service after adding or refreshing one.

ACME HTTP-01 tokens are served from `static/.well-known/acme-challenge/` on every hostname, so certbot's webroot mode works while the server keeps running. With DNS for the new name pointing at this host and the current build deployed:

```
sudo certbot certonly --webroot -w /home/ec2-user/website/static \
  -d current.ai -d www.current.ai --cert-name current.ai \
  --deploy-hook 'systemctl restart website.service'
```

Then copy the result next to the `dima.ai` one and restart:

```
mkdir -p ~/.ssl/current.ai
sudo cp -L /etc/letsencrypt/live/current.ai/{fullchain,privkey}.pem ~/.ssl/current.ai/
sudo chown ec2-user:ec2-user ~/.ssl/current.ai/*.pem
chmod 600 ~/.ssl/current.ai/privkey.pem
sudo systemctl restart website.service
```

Certbot renews into `/etc/letsencrypt` and its hook restarts the service, but nothing refreshes the `~/.ssl` copies: repeat the copy after a renewal, for `dima.ai` as well.

`https://current.ai` serves the OAuth, OpenID Connect, and MCP playground through the loopback demos service. `https://dima.ai/current-demo` demonstrates signing in through Current. See [the demos setup and deployment guide](services/current/README.md), including Google Console configuration. Plain HTTP redirects to HTTPS, and `www.current.ai` (or any other subdomain) redirects to `current.ai`, keeping the path. ACME challenges still reach the certificate webroot. `zoom.dima.ai` redirects to Zoom on both listeners.

## Setup

```
$ systemctl show -p FragmentPath website.service
```

```
FragmentPath=/etc/systemd/system/website.service
```

```
$ cat /etc/systemd/system/website.service
```

```
# /etc/systemd/system/website.service
[Unit]
Description=Website (Rust)
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=/home/ec2-user/run.sh
User=ec2-user
Group=ec2-user

AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
NoNewPrivileges=true

Restart=always
RestartSec=2

[Install]
WantedBy=multi-user.target
```

## Logs

```
journalctl -u website.service -f
```
