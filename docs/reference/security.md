# Security model

## Pairing and local pins

The PC initiates pairing. The relay creates a short-lived session with separate
capabilities for the phone and for the PC's polling endpoint. The phone creates
an ES256 passkey with user verification required. The PC pins its public key
only after the fingerprints agree. The phone stores the private key in its
passkey manager.

A Pi that serves the phone app can control what the browser displays during
pairing. When the Pi is outside your trust boundary, use the
[independent gateway](../install/gateway.md) for the browser UI, TLS and origin.
The gateway forwards only allowlisted API routes and reconstructs bounded JSON
responses using its own headers. The Pi still controls relay data and
availability. Approve sign-in requests that you started.

Reusing a passkey signs a 33-byte enrollment challenge. This verification is
separate from the 32-byte challenge that Windows generates for unlock. Every PC
keeps its own local pins.

## Unlock verification

Windows generates a fresh 32-byte random challenge and sets a local deadline. It
accepts an assertion only after the local verifier checks:

- The credential ID maps to a public key pinned on that PC.
- The WebAuthn operation is `webauthn.get`, the challenge and exact HTTPS origin
  match, and the assertion is same-origin.
- The authenticator data has the SHA-256 hash of the expected RP ID and both
  user-presence and user-verification flags.
- The pinned key is P-256 and the ES256 signature verifies over the
  authenticator data and the hash of the original client data.

The relay's approval state has no authority to sign in to Windows. After
verification, the provider releases a single Windows sign-in attempt for the
configured account. Failed verification leaves normal Windows sign-in available.
The local LSA secret lets the provider submit the existing Windows account's
credentials. Users with administrative access to the PC are part of the Windows
trust boundary.

## LAN exposure and sensitive data

Restrict the relay and gateway to the LAN. Wake-on-LAN has no passkey prompt and
is rate-limited. The relay stores public keys, PC names and MAC addresses. Keep
DNS tokens, ACME state, gateway keys and Windows credentials private. Treat
enrollment and polling URLs as temporary capabilities and redact them from issue
reports.
