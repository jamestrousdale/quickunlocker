# Relay API

The Windows tool and phone app use HTTPS and JSON. This API is intended for a
LAN deployment behind Traefik's allowlist, optionally with an independent
gateway. The gateway serves the phone pages locally and forwards only the
supported JSON API routes.

## Enrollment

| Method and path                 | Request and result                                                                             |
| ------------------------------- | ---------------------------------------------------------------------------------------------- |
| `POST /api/enroll/sessions`     | Accepts `pc_name` and `mac`. Returns `session_id`, `enroll_url`, and `expires_in`.             |
| `GET /enroll?s=…`               | Opens the browser enrollment page using the phone's capability.                                |
| `POST /api/enroll/options`      | Accepts the phone capability as `session`. Returns the registration and reuse options.         |
| `POST /api/enroll/verify`       | Accepts `session` and a WebAuthn registration object as `credential`. Completes the session.   |
| `POST /api/enroll/reuse`        | Accepts `session` and the existing passkey's assertion as `credential`. Completes the session. |
| `GET /api/enroll/sessions/{id}` | Polls with the PC capability. Optional `wait` is in seconds, up to 30.                         |

The enrollment poll returns `pending`, `expired`, or `complete` in `status`. The
completion response includes `credential_id`, `spki_der` and `fingerprint`. The
credential ID and DER SPKI are encoded in base64url. Completion is delivered
once. A later poll returns `expired`. Sessions expire after five minutes.

## Wake and unlock

| Method and path                            | Request and result                                                                                       |
| ------------------------------------------ | -------------------------------------------------------------------------------------------------------- |
| `GET /api/pcs`                             | Lists enrolled `pc_name` values.                                                                         |
| `POST /api/pcs/{name}/wake`                | Sends the selected PC's magic packet and returns HTTP 202 on success. Use a JSON object for the gateway. |
| `POST /api/unlock-requests`                | Accepts `pc_name` and a base64url challenge. Returns `id` and `expires_in`.                              |
| `GET /api/unlock-requests/pending`         | Lists pending requests with their passkey options.                                                       |
| `POST /api/unlock-requests/{id}/assertion` | Accepts the phone's WebAuthn assertion response to the challenge.                                        |
| `GET /api/unlock-requests/{id}`            | Polls for `pending`, `expired`, or `approved`. Optional `wait` is in seconds, capped at 30.              |
| `GET /healthz`                             | Returns `{"ok":true}` from the Pi relay. The gateway does not proxy this path.                           |

A new request replaces a previous request for the same PC. An approved poll
returns an `assertion` object once with the base64url `credential_id`,
`authenticator_data`, `client_data_json` and `signature` fields. The PC verifies
those values locally. The relay defaults to a 90-second lifetime for an unlock
request.

Wake requests are limited to one every 10 seconds per PC and one per second
across the relay. A rate limit returns HTTP 429. Unknown targets return
HTTP 404. An invalid or mismatched passkey assertion can return HTTP 403. The
relay may also reject invalid JSON or schema fields before processing a request.
