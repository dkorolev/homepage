# homepage

A simple personal page.

Created primarily to gain experience on finding freelance designers with help of Quora. :-)

Extended quite a bit for my personal tasks since.

## Redeploy

```
(cd ~/website; git merge --ff-only dev && cargo build --profile fast-release -p homepage && sudo systemctl restart website.service && echo OK)
```

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
