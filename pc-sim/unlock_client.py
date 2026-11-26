#!/usr/bin/env python3
"""Stand-in for the Windows credential provider.

Does exactly what the C++ credential provider will do, so you can test the
whole flow end to end before touching the lock screen:

  enroll  open a short-lived phone enrollment and pin the confirmed key
  unlock  generate a fresh challenge, post it, long-poll, then verify the
          passkey assertion LOCALLY against the pinned key. Never trusts the relay.

Usage:
  python unlock_client.py --relay https://unlock.home.example.com enroll --pc-name gaming-pc --mac 02:00:00:00:00:01
  python unlock_client.py --relay https://unlock.home.example.com unlock --pc-name gaming-pc
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import sys
import time
from pathlib import Path
from urllib.parse import urlparse

import httpx
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

PIN_FILE = Path(os.environ.get('PIN_FILE', Path.home() / '.pc-unlock-pinned.json'))
FLAG_UP, FLAG_UV = 0x01, 0x04


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode()


def b64url_decode(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + '=' * (-len(s) % 4))


class VerifyError(Exception):
    pass


def verify_assertion(assertion: dict, *, challenge: bytes, rp_id: str, origin: str, pinned: dict[str, bytes]) -> str:
    """Verify a WebAuthn assertion. Returns the credential id on success.

    This is the security-critical function; the C++ port must do every check here.
    """
    cred_id = assertion.get('credential_id', '')
    spki = pinned.get(cred_id)
    if spki is None:
        raise VerifyError('credential is not pinned on this PC')

    cdj_raw = b64url_decode(assertion['client_data_json'])
    auth_data = b64url_decode(assertion['authenticator_data'])
    sig = b64url_decode(assertion['signature'])

    _check_client_data(cdj_raw, challenge, origin)
    _check_authenticator_data(auth_data, rp_id)

    # 3. Signature over authenticatorData || SHA256(clientDataJSON), ES256.
    key = serialization.load_der_public_key(spki)
    if not isinstance(key, ec.EllipticCurvePublicKey) or key.curve.name != 'secp256r1':
        raise VerifyError('pinned key is not P-256')
    try:
        key.verify(sig, auth_data + hashlib.sha256(cdj_raw).digest(), ec.ECDSA(hashes.SHA256()))
    except InvalidSignature as e:
        raise VerifyError('bad signature') from e
    return cred_id


def _check_client_data(cdj_raw: bytes, challenge: bytes, origin: str) -> None:
    # 1. clientDataJSON: right ceremony, OUR challenge, expected origin.
    cdj = json.loads(cdj_raw)
    if cdj.get('type') != 'webauthn.get':
        raise VerifyError('wrong ceremony type')
    if cdj.get('challenge') != b64url(challenge):
        raise VerifyError('challenge mismatch (replay or wrong request)')
    if cdj.get('origin') != origin:
        raise VerifyError(f'origin mismatch: {cdj.get("origin")}')
    if cdj.get('crossOrigin'):
        raise VerifyError('cross-origin assertion')


def _check_authenticator_data(auth_data: bytes, rp_id: str) -> None:
    if len(auth_data) < 37:
        raise VerifyError('authenticatorData too short')
    if auth_data[:32] != hashlib.sha256(rp_id.encode()).digest():
        raise VerifyError('rpIdHash mismatch')
    flags = auth_data[32]
    if not flags & FLAG_UP or not flags & FLAG_UV:
        raise VerifyError('user presence/verification flag not set')


def load_pins() -> dict:
    return json.loads(PIN_FILE.read_text(encoding='utf-8')) if PIN_FILE.exists() else {}


def cmd_enroll(args: argparse.Namespace, client: httpx.Client) -> int:
    location = urlparse(args.relay)
    rp_id = location.hostname
    origin = args.relay.rstrip('/')
    if location.scheme != 'https' or not rp_id or location.netloc != location.netloc.lower():
        print("Use the relay's canonical HTTPS origin.", file=sys.stderr)
        return 1
    pins = load_pins()
    if pins.get('credentials') and (pins['origin'], pins['rp_id']) != (origin, rp_id):
        print('The existing pin file belongs to a different relay origin or RP ID.', file=sys.stderr)
        return 1

    start = (
        client.post(
            '/api/enroll/sessions',
            json={'pc_name': args.pc_name, 'mac': args.mac},
        )
        .raise_for_status()
        .json()
    )
    enroll_url = urlparse(start['enroll_url'])
    if (enroll_url.scheme, enroll_url.netloc, enroll_url.path) != ('https', location.netloc, '/enroll'):
        print('The relay returned an unexpected enrollment URL.', file=sys.stderr)
        return 1
    print(f'Open this link on your phone: {start["enroll_url"]}', flush=True)
    result = _wait_for_enrollment(start['session_id'], client)
    if result is None:
        print('Enrollment expired.')
        return 1
    return _confirm_pin(result, pins, origin, rp_id)


def _wait_for_enrollment(session_id: str, client: httpx.Client) -> dict | None:
    deadline = time.monotonic() + 300
    while time.monotonic() < deadline:
        result = (
            client.get(f'/api/enroll/sessions/{session_id}', params={'wait': 25}, timeout=35).raise_for_status().json()
        )
        if result['status'] == 'pending':
            continue
        if result['status'] == 'complete' and time.monotonic() < deadline:
            return result
        break
    return None


def _confirm_pin(result: dict, pins: dict, origin: str, rp_id: str) -> int:
    spki = b64url_decode(result['spki_der'])
    key = serialization.load_der_public_key(spki)
    if not isinstance(key, ec.EllipticCurvePublicKey) or key.curve.name != 'secp256r1':
        print('Enrollment returned a key that is not P-256.', file=sys.stderr)
        return 1
    digest = hashlib.sha256(spki).hexdigest()[:20].upper()
    fingerprint = '-'.join(digest[i : i + 4] for i in range(0, 20, 4))
    answer = input(f'Type the fingerprint shown on your phone to pin {fingerprint}: ')
    if answer.strip().upper() != fingerprint:
        print('Fingerprint mismatch.')
        return 1
    credentials = pins.setdefault('credentials', {})
    credential_id = result['credential_id']
    if credential_id in credentials and credentials[credential_id] != result['spki_der']:
        print('Credential ID is already pinned to another key.')
        return 1
    credentials[credential_id] = result['spki_der']
    pins.update(rp_id=rp_id, origin=origin)
    PIN_FILE.write_text(json.dumps(pins, indent=2), encoding='utf-8')
    print(f'Saved {len(credentials)} pinned key(s) to {PIN_FILE}')
    return 0


def cmd_unlock(args: argparse.Namespace, client: httpx.Client) -> int:
    pins = load_pins()
    if not pins.get('credentials'):
        print('Nothing pinned. Run `enroll` first.')
        return 1
    pinned = {k: b64url_decode(v) for k, v in pins['credentials'].items()}
    challenge = os.urandom(32)
    rid = (
        client.post('/api/unlock-requests', json={'pc_name': args.pc_name, 'challenge': b64url(challenge)})
        .raise_for_status()
        .json()['id']
    )
    print(f'Waiting for approval on your phone (request {rid})…')
    deadline = time.time() + args.timeout
    while time.time() < deadline:
        r = client.get(f'/api/unlock-requests/{rid}', params={'wait': 25}, timeout=35).json()
        if r['status'] == 'approved':
            try:
                cid = verify_assertion(
                    r['assertion'],
                    challenge=challenge,
                    rp_id=pins['rp_id'],
                    origin=pins['origin'],
                    pinned=pinned,
                )
            except VerifyError as e:
                print(f'REJECTED: {e}')
                return 2
            print(f'VERIFIED with credential {cid[:12]}… — the real provider would unlock now.')
            return 0
        if r['status'] == 'expired':
            break
    print('Timed out.')
    return 1


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument('--relay', required=True, help='e.g. https://unlock.home.example.com')
    sub = p.add_subparsers(dest='cmd', required=True)
    enroll = sub.add_parser('enroll')
    enroll.add_argument('--pc-name', default='gaming-pc')
    enroll.add_argument('--mac', required=True, help='Wired adapter MAC address, separated by colons')
    u = sub.add_parser('unlock')
    u.add_argument('--pc-name', default='gaming-pc')
    u.add_argument('--timeout', type=int, default=90)
    args = p.parse_args()
    with httpx.Client(base_url=args.relay, timeout=10) as client:
        return {'enroll': cmd_enroll, 'unlock': cmd_unlock}[args.cmd](args, client)


if __name__ == '__main__':
    sys.exit(main())
