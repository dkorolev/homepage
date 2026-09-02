# homepage

A simple personal page.

Created primarily to gain experience on finding freelance designers with help of Quora. :-)

Extended quite a bit for my personal tasks since.

## Redeploy

```
(cd ~/website; git merge --ff-only dev && cargo build --profile fast-release -p homepage && sudo systemctl restart website.service && echo OK)
```

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

`https://current.ai` serves a landing page pointing at https://github.com/c5t/current that moves on to https://dima.ai after three seconds; every path gets that page. Plain HTTP redirects to HTTPS, and `www.current.ai` (or any other subdomain) redirects to `current.ai`, keeping the path. `zoom.dima.ai` redirects to Zoom on both listeners. The hostname the caller asked for decides.

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
