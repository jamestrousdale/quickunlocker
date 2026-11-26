# Install an independent HTTPS gateway

Use a separate trusted host to serve the phone app when you want pairing to
remain trustworthy if the Pi is compromised. The gateway serves its own copy of
the web app and forwards a fixed set of JSON API routes to the Pi. Windows and
the phone use the gateway's HTTPS origin for registration and unlock.

## Plan TLS and DNS

Choose distinct hostnames. For example, use `unlock.home.example.com` for the
gateway and `pi-backend.example.net` for the Pi. Make both names resolve to
their correct LAN addresses through DNS you trust. Use a fresh gateway hostname
if the Pi previously served the web app. The new hostname gets separate browser
storage and a new RP ID, so enroll again.

The gateway needs `fullchain.pem` and `privkey.pem` for its hostname. Keep its
TLS private key and any DNS or certificate issuance credentials off the Pi. If
the Pi obtains its own certificate through Cloudflare DNS-01, scope its token to
a separate backend DNS zone that cannot authorize issuance for the gateway name.

## Configure the Pi backend

With the example addresses below, only the gateway at `192.168.1.30` can reach
the Pi backend.

```dotenv
UNLOCK_HOST=pi-backend.example.net
UNLOCK_RP_ID=unlock.home.example.com
UNLOCK_ORIGIN=https://unlock.home.example.com
LAN_CIDR=192.168.1.30/32
```

Keep the Pi's certificate settings for the backend hostname. Apply the changes
with `docker compose up -d` on the Pi. From the gateway host, confirm that
`https://pi-backend.example.net/healthz` returns `{"ok":true}` over
certificate-validated HTTPS. If its port differs from 443, use the actual
backend port in the URL and in `GATEWAY_BACKEND`.

## Start the gateway

Place the release's `docker-compose.gateway.yml` on the trusted host. Verify it
against the release checksums. Put the certificate and key in a directory the
container's UID `10001` can read. The mount is read-only inside the container.
Restrict access to the key on the host.

```sh
export GATEWAY_BACKEND=https://pi-backend.example.net
export GATEWAY_LISTEN=192.168.1.30
export GATEWAY_TLS_DIR=./tls
docker compose -f docker-compose.gateway.yml config --quiet
docker compose -f docker-compose.gateway.yml up -d
```

For a source build, run from `relay/` and add `--build` to the last command. If
the gateway publishes a port other than 443, set `GATEWAY_PORT` and include that
port in the Pi's `UNLOCK_ORIGIN` and in the origin given to Windows.

Open the gateway origin on the phone and verify the JSON connection from a LAN
client.

```sh
curl --fail https://unlock.home.example.com/api/pcs
```

A fresh setup returns `[]`. Configure Windows with the gateway origin and
[enroll the phone](phone.md).
