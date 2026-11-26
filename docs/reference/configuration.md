# Configuration reference

## Pi Compose environment

Set these in the relay's `.env`. Docker Compose reads the file from the
deployment directory.

| Setting            | Default or example        | Purpose                                                                              |
| ------------------ | ------------------------- | ------------------------------------------------------------------------------------ |
| `UNLOCK_HOST`      | `unlock.home.example.com` | Hostname Traefik serves on the Pi. Use the backend hostname with a gateway.          |
| `UNLOCK_ORIGIN`    | `https://<RP ID>`         | Exact browser and Windows origin. Set an explicit non-default port.                  |
| `UNLOCK_RP_ID`     | Value of `UNLOCK_HOST`    | Passkey RP ID. With a gateway, set its hostname.                                     |
| `HTTPS_PORT`       | `443`                     | Port Traefik binds on the Pi.                                                        |
| `CF_DNS_API_TOKEN` | Your zone-scoped token    | Authorizes Cloudflare DNS-01 certificate validation.                                 |
| `ACME_EMAIL`       | Your ACME contact email   | Contact for Traefik's ACME certificate resolver.                                     |
| `LAN_CIDR`         | Example `192.168.1.0/24`  | Allowed client addresses at Traefik. Use the gateway's IP and `/32` when applicable. |
| `WAKE_BROADCAST`   | `255.255.255.255`         | IPv4 destination for UDP port 9 Wake-on-LAN broadcasts.                              |

The relay container listens on the Pi's loopback port `8000` behind Traefik. Its
`/data` mount contains `credentials.json`. When running the Python app directly,
it reads `RP_ID`, `ORIGIN`, `RP_NAME`, `DATA_DIR`, `REQUEST_TTL` and
`WAKE_BROADCAST` from the environment. The default unlock TTL is 90 seconds. The
Compose file maps the deployment settings to those app settings and sets the
display name to **PC Unlock**.

## Gateway environment

Set these on the independent host when running
`docker compose -f docker-compose.gateway.yml`.

| Setting           | Default or example               | Purpose                                                           |
| ----------------- | -------------------------------- | ----------------------------------------------------------------- |
| `GATEWAY_BACKEND` | `https://pi-backend.example.net` | Fixed HTTPS origin of the Pi relay. Include any non-default port. |
| `GATEWAY_LISTEN`  | `192.168.1.30`                   | Gateway host's LAN address to bind.                               |
| `GATEWAY_PORT`    | `443`                            | Published HTTPS port on the gateway.                              |
| `GATEWAY_TLS_DIR` | `./tls`                          | Directory containing `fullchain.pem` and `privkey.pem`.           |

## Windows and simulator

Windows setup stores the configured account identity and SID, origin, RP ID, PC
name, and public key pins in the 64-bit HKLM key `HKLM\SOFTWARE\quickunlocker`.
It separately stores the Windows password in an LSA private-data secret
associated with the SID. Use the
[setup commands](../install/windows.md#setup-commands) for updates.

The Python simulator uses `PIN_FILE` for its local pins, defaulting to
`~/.pc-unlock-pinned.json`. Pass the HTTPS origin with `--relay`. For
enrollment, supply the PC name and a colon-delimited Ethernet MAC. For unlock,
use the same PC name. The simulator's `--timeout` defaults to 90 seconds.
