"""WebAuthn verification and public key encoding for the relay."""

import base64
import hashlib
from typing import Any

from cryptography.hazmat.primitives import serialization
from fastapi import HTTPException
from webauthn import verify_authentication_response
from webauthn.helpers import decode_credential_public_key, decoded_public_key_to_cryptography


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode()


def b64url_decode(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + '=' * (-len(s) % 4))


def spki_from_cose(cose: bytes) -> bytes:
    key = decoded_public_key_to_cryptography(decode_credential_public_key(cose))
    return key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)


def fingerprint(spki_der: bytes) -> str:
    h = hashlib.sha256(spki_der).hexdigest()[:20].upper()
    return '-'.join(h[i : i + 4] for i in range(0, 20, 4))


def check_authentication(
    credential: dict[str, Any], challenge: bytes, public_key: str, *, rp_id: str, origin: str
) -> None:
    try:
        verify_authentication_response(
            credential=credential,
            expected_challenge=challenge,
            expected_rp_id=rp_id,
            expected_origin=origin,
            credential_public_key=b64url_decode(public_key),
            credential_current_sign_count=0,
            require_user_verification=True,
        )
    except Exception as e:
        raise HTTPException(403, 'Passkey assertion rejected.') from e
