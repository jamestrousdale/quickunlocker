# quickunlocker

[![CI](https://github.com/jamestrousdale/quickunlocker/actions/workflows/ci-checks.yaml/badge.svg?branch=master)](https://github.com/jamestrousdale/quickunlocker/actions/workflows/ci-checks.yaml)
[![Python coverage](https://raw.githubusercontent.com/jamestrousdale/quickunlocker/mustard-badges/badge.svg)](https://github.com/jamestrousdale/quickunlocker/actions/workflows/ci-checks.yaml?query=branch%3Amaster)
[![Windows C++ coverage](https://raw.githubusercontent.com/jamestrousdale/quickunlocker/mustard-badges-3-cpp/badge.svg)](https://github.com/jamestrousdale/quickunlocker/actions/workflows/ci-checks.yaml?query=branch%3Amaster)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

Unlock a locked Windows PC (e.g. during Steam Remote Play) with a passkey on
your iPhone — Face ID via 1Password or iCloud Keychain — instead of
mouse-fumbling a PIN.

```
iPhone (PWA)  ──passkey assertion──▶  relay on Raspberry Pi  ◀──long-poll──  Windows lock screen
 Face ID                               (Traefik + this app)                    credential provider
                                                                                verifies + unlocks
```

[Documentation](https://jamestrousdale.github.io/quickunlocker/) ·
[Documentation source](docs/index.md)

## Security model

- **The PC trusts nothing but its pinned public key.** It generates a fresh
  32-byte challenge each time and verifies the assertion itself: challenge,
  origin, rpIdHash, user-presence + user-verification flags, and the ES256
  signature.
- **The relay is a messenger.** It stores public keys and enrollment metadata.
  If it's compromised, the attacker can block unlocks but can't create one. (It
  also verifies assertions, as a second check.)
- **The phone holds the private key** in 1Password / iCloud Keychain, usable
  only after Face ID.
- **LAN only:** reachable only through Pi-hole DNS, with Traefik's IP allowlist
  on top.
- **Approve only unlocks you started.** The PWA shows which PC is asking and how
  long ago. Someone at the physical PC can trigger a request, but it only works
  if you approve it.

## Setup (Pi)

1. Pick a hostname on your Cloudflare domain, e.g. `unlock.home.example.com`.
   Add a **Pi-hole Local DNS record** pointing it at the Pi's LAN IP. No public
   DNS record is needed — Traefik gets the cert via the Cloudflare DNS-01
   challenge.
2. Create a Cloudflare API token with **Zone → DNS → Edit** for that zone.
3. In a source checkout, run `cd relay`. For a release install, put its
   `docker-compose.yml` and `.env.example` in a directory. Copy `.env.example`
   to `.env` and fill in the values. If Pi-hole's web UI is already on 443, set
   `HTTPS_PORT=8443` and `UNLOCK_ORIGIN=https://unlock.home.example.com:8443`.
4. Create the persistent directories with `mkdir -p data letsencrypt`, then run
   `sudo chown 10001:10001 data` for the relay user. For a source checkout, run
   `docker compose up -d --build`. For release assets, run
   `docker compose up -d`. Check `docker compose logs traefik` for the cert.

## Enroll your phone

Start enrollment from the PC simulator. Use the PC's name and the MAC address of
its wired Ethernet adapter.

```sh
pip install httpx cryptography
python pc-sim/unlock_client.py --relay https://unlock.home.example.com enroll \
  --pc-name gaming-pc --mac 02:00:00:00:00:01
```

Open the short-lived link on the iPhone, create a passkey, then enter the
fingerprint shown on the phone in the PC prompt. The PC independently computes
its fingerprint from the public key before saving it. Enroll while you trust the
Pi, which serves the enrollment page. An attacker who controls the Pi during
pairing can alter that page. Previously pinned keys are verified locally.

To use the same passkey on another PC, start enrollment from that PC and open
its link on the phone using the browser or Home Screen app where you created the
passkey. Choose **Use existing passkey** and confirm the fingerprint on the new
PC. The phone keeps the computed fingerprint in its browser storage so it can
show it again during enrollment.

To test an unlock, open the relay home page in Safari and optionally add it to
the Home Screen. Run the simulator and approve the request on the phone.

```sh
python pc-sim/unlock_client.py --relay https://unlock.home.example.com unlock --pc-name gaming-pc
```

The simulator prints `VERIFIED` after it validates the assertion locally.

## Development

```sh
mise install
mise run python:uv-sync
mise run ci-checks
```

The tests use a software ES256 authenticator in place of the phone. They cover
enrollment, the full unlock flow, the long-poll wake-up, and the attacks the PC
must reject: replayed challenge, unpinned key, key swapped under a pinned ID,
missing UV flag, wrong origin or RP, and a tampered signature.

CI reports the Python relay and gateway coverage and the Windows C++ coverage
through Mustard. The Windows report measures the native CTest runs, including
the verifier, the credential provider's COM entry points and the setup tool's
enrollment checks. Secure-desktop sign-in and hardware behavior still require a
Windows VM and a wired PC. Mustard publishes the coverage badges after a
successful run on the default branch.

## API

| Method | Path                                  | Who      | Purpose                                                          |
| ------ | ------------------------------------- | -------- | ---------------------------------------------------------------- |
| POST   | `/api/enroll/sessions`                | PC setup | `{pc_name, mac}` → `{session_id, enroll_url, expires_in}`        |
| GET    | `/enroll?s=…`                         | phone    | open enrollment from the link                                    |
| POST   | `/api/enroll/options`                 | phone    | start ES256 passkey registration for the link                    |
| POST   | `/api/enroll/verify`                  | phone    | submit and verify the new passkey once                           |
| POST   | `/api/enroll/reuse`                   | phone    | prove possession and enroll an existing passkey                  |
| GET    | `/api/enroll/sessions/{id}?wait=25`   | PC setup | wait for the credential ID, SPKI DER (base64url) and fingerprint |
| GET    | `/api/pcs`                            | phone    | list enrolled PCs                                                |
| POST   | `/api/pcs/{name}/wake`                | phone    | send a rate-limited LAN magic packet                             |
| POST   | `/api/unlock-requests`                | PC       | `{pc_name, challenge}` → `{id}`                                  |
| GET    | `/api/unlock-requests/pending`        | phone    | pending requests and WebAuthn options                            |
| POST   | `/api/unlock-requests/{id}/assertion` | phone    | submit the passkey assertion                                     |
| GET    | `/api/unlock-requests/{id}?wait=25`   | PC       | long-poll for the raw assertion                                  |

## Run the enrollment gateway independently of the Pi

Use a separate gateway when the Pi is outside your trust boundary. The gateway
serves the phone UI from its image and forwards only the Quickunlocker JSON API
to the Pi. It ignores upstream response headers and rejects redirects, HTML and
oversized responses. Windows and the phone both use the gateway's HTTPS origin.

1. Point the gateway hostname at the gateway's LAN address. Keep its TLS
   certificate, private key and DNS or certificate issuance credentials off the
   Pi. If the Pi uses Cloudflare DNS-01, give it a token for a separate backend
   DNS zone without permission to validate the gateway hostname.
2. In the Pi's relay environment, set `UNLOCK_HOST` to the backend hostname and
   `LAN_CIDR` to the gateway IP with a `/32` prefix. Set `UNLOCK_ORIGIN` to the
   gateway's full HTTPS origin and `UNLOCK_RP_ID` to its hostname. Restart the
   Pi relay.
3. On the gateway host, put `fullchain.pem` and `privkey.pem` in a directory
   readable by the container's UID 10001. Copy the release's
   `docker-compose.gateway.yml` beside that directory and start it:

   ```sh
   export GATEWAY_BACKEND=https://pi-backend.example.net
   export GATEWAY_LISTEN=192.168.1.30
   export GATEWAY_TLS_DIR=./tls
   docker compose -f docker-compose.gateway.yml up -d
   ```

   From a source checkout, run the command in `relay/` with `--build`. Set
   `GATEWAY_PORT` if the published HTTPS port will differ from 443.
4. Configure Windows with the gateway's HTTPS origin and enroll the phone using
   that origin. Use a fresh gateway hostname if the Pi previously served the
   browser UI. The new hostname gives the gateway its own site data and RP ID.

## Set up Windows

Use a Windows x64 VM snapshot for the first trial. Keep a working Windows
password or PIN and a separate administrator account for recovery. This software
is supplied as-is. Verify the EXE and DLL against the release's SHA256
checksums. The Windows integration requires a real password. Microsoft accounts
in passwordless mode cannot be used.

Place the x64 setup EXE and DLL in the same directory. In an elevated terminal,
run these commands. For a local account, enter your username as `.\username`
when prompted. Connect Ethernet during enrollment.

```powershell
.\quickunlocker-setup.exe configure
.\quickunlocker-setup.exe register
```

Scan the QR code from the setup tool, then enter the phone's fingerprint to
finish pinning. A direct Pi deployment requires trusting that Pi during
enrollment. The setup tool keeps Windows passwords in an LSA private-data secret
and stores the account SID, relay origin and RP ID, and pinned keys in
`HKLM\SOFTWARE\quickunlocker`.

Lock the screen, open the relay home page on the phone, and select **Unlock**
for the PC. Windows may show its own sign-in confirmation. The setup tool
supports `enroll` for another phone, `list` to identify pinned keys, `revoke ID`
to revoke a key locally, and `password` to update the LSA secret after changing
the Windows password. Run `unregister` from an elevated terminal to remove the
provider registration and clear the local pins and password.

Build and run the verifier tests with MSVC from the repository root.

```powershell
cmake -S windows -B windows/build -A x64
cmake --build windows/build --config Release
ctest --test-dir windows/build -C Release --output-on-failure
```

## Wake-on-LAN

The phone shows Wake for each enrolled PC without a pending lock-screen request.
It switches to Unlock when the PC posts a challenge. The Pi and PC should share
a LAN that carries IPv4 broadcasts. Enable Wake-on-LAN in the BIOS or UEFI and
in the wired adapter's settings, including Wake on Magic Packet and permission
for the adapter to wake the computer. Disable Windows Fast Startup if you need
wake from full shutdown and the hardware supports it.

The Compose deployment uses Linux host networking. Traefik terminates HTTPS and
applies the LAN allowlist. The relay listens on host loopback port 8000. Set
`WAKE_BROADCAST` to your subnet broadcast address if the default broadcast does
not reach the PC.
