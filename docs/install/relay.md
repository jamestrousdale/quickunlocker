# Install the Pi relay

Run the relay on a Linux host with Docker Compose and IPv4 access to the PC's
wired network. The published container supports `linux/arm64` and `linux/amd64`.
Compose uses Linux host networking so the relay can send Wake-on-LAN broadcasts.

## Choose a hostname and origin

Pick a hostname under a domain you control, such as `unlock.home.example.com`.
Add a local DNS record pointing it to the Pi's LAN address. Pi-hole can provide
this record. Traefik uses Cloudflare DNS-01 for the certificate, so the hostname
can resolve exclusively on your LAN.

Create a Cloudflare API token scoped to DNS editing for the selected zone. Fill
in `CF_DNS_API_TOKEN` and `ACME_EMAIL` in the local environment file. Restrict
`LAN_CIDR` to the subnet that should reach Traefik.

Use `https://unlock.home.example.com` as the origin on the PC and the phone. If
another service owns port 443, set both `HTTPS_PORT=8443` and
`UNLOCK_ORIGIN=https://unlock.home.example.com:8443`. The port is part of the
origin. The WebAuthn relying party ID is the hostname alone.

If you plan to use an independent gateway, follow the
[gateway setup](gateway.md) when choosing the Pi's backend hostname and access
policy.

## Deploy the container

Download `docker-compose.yml`, `.env.example`, and `SHA256SUMS` from the same
[GitHub release](https://github.com/jamestrousdale/quickunlocker/releases).
Check both files against their entries in `SHA256SUMS` before editing them. For
a source build, open the repository's `relay/` directory instead.

Run these commands from the directory containing `docker-compose.yml`.

```sh
cp .env.example .env
chmod 600 .env
mkdir -p data letsencrypt
sudo chown 10001:10001 data
```

Fill in `.env` and start the services.

```sh
docker compose config --quiet
docker compose up -d
docker compose ps
docker compose logs --tail=100 traefik
```

From a source checkout, use `docker compose up -d --build`. The release Compose
file pulls the image by digest.

Verify HTTPS from another LAN device using the configured origin.

```sh
curl --fail https://unlock.home.example.com/healthz
```

The response should be `{"ok":true}`. Then open the same origin in Safari. If
the connection fails, check [troubleshooting](../operate/troubleshooting.md).

## What to keep

The `data/` directory holds public keys and registered PC records. Traefik keeps
its certificate state in `letsencrypt/`. Keep those directories and the
environment file when upgrading the Compose assets. See
[maintenance](../operate/maintenance.md) for backup and restore.
