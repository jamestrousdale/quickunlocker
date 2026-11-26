"""End-to-end test with a software authenticator standing in for the iPhone.

Covers enrollment, the full unlock flow, and the attacks the PC-side verifier
must reject (wrong challenge, wrong origin, no Face ID flag, unpinned key,
tampered signature, relay-forged assertion).
"""

import asyncio
import base64
import hashlib
import importlib
import json
import os
from urllib.parse import parse_qs, urlsplit

import cbor2
import httpx
import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from fastapi.testclient import TestClient
from gateway import create_app as create_gateway

RP_ID = 'unlock.home.example.com'
ORIGIN = f'https://{RP_ID}'
PC = {'pc_name': 'gaming-pc', 'mac': '02:00:00:00:00:01'}


def b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b'=').decode()


def b64u_d(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + '=' * (-len(s) % 4))


class SoftAuthenticator:
    """Minimal ES256 platform authenticator (like iCloud Keychain / 1Password)."""

    def __init__(self, rp_id=RP_ID):
        self.key = ec.generate_private_key(ec.SECP256R1())
        self.cred_id = os.urandom(16)
        self.rp_hash = hashlib.sha256(rp_id.encode()).digest()

    def _cose(self) -> bytes:
        n = self.key.public_key().public_numbers()
        return cbor2.dumps({1: 2, 3: -7, -1: 1, -2: n.x.to_bytes(32, 'big'), -3: n.y.to_bytes(32, 'big')})

    def create(self, options: dict, origin=ORIGIN) -> dict:
        cdj = json.dumps({'type': 'webauthn.create', 'challenge': options['challenge'], 'origin': origin}).encode()
        attested = bytes(16) + len(self.cred_id).to_bytes(2, 'big') + self.cred_id + self._cose()
        auth_data = self.rp_hash + bytes([0x45]) + (0).to_bytes(4, 'big') + attested  # UP|UV|AT
        att_obj = cbor2.dumps({'fmt': 'none', 'attStmt': {}, 'authData': auth_data})
        return {
            'id': b64u(self.cred_id),
            'rawId': b64u(self.cred_id),
            'type': 'public-key',
            'response': {'clientDataJSON': b64u(cdj), 'attestationObject': b64u(att_obj)},
            'clientExtensionResults': {},
        }

    def get(self, options: dict, origin=ORIGIN, flags=0x05) -> dict:
        cdj = json.dumps({'type': 'webauthn.get', 'challenge': options['challenge'], 'origin': origin}).encode()
        auth_data = self.rp_hash + bytes([flags]) + (0).to_bytes(4, 'big')
        sig = self.key.sign(auth_data + hashlib.sha256(cdj).digest(), ec.ECDSA(hashes.SHA256()))
        return {
            'id': b64u(self.cred_id),
            'rawId': b64u(self.cred_id),
            'type': 'public-key',
            'response': {
                'authenticatorData': b64u(auth_data),
                'clientDataJSON': b64u(cdj),
                'signature': b64u(sig),
                'userHandle': None,
            },
            'clientExtensionResults': {},
        }


@pytest.fixture
def env(tmp_path, monkeypatch):
    monkeypatch.setenv('RP_ID', RP_ID)
    monkeypatch.setenv('ORIGIN', ORIGIN)
    monkeypatch.setenv('DATA_DIR', str(tmp_path))
    import main

    importlib.reload(main)
    import unlock_client

    return TestClient(main.app), unlock_client


def new_enrollment(client, pc=PC):
    response = client.post('/api/enroll/sessions', json=pc)
    assert response.status_code == 201, response.text
    session = response.json()
    assert session['enroll_url'].startswith(f'{ORIGIN}/enroll?s=')
    phone_id = parse_qs(urlsplit(session['enroll_url']).query)['s'][0]
    poll_path = f'/api/enroll/sessions/{session["session_id"]}'
    return phone_id, poll_path


def enroll(client, auth, pc=PC):
    phone_id, poll_path = new_enrollment(client, pc)
    start = client.post('/api/enroll/options', json={'session': phone_id}).json()
    response = client.post(
        '/api/enroll/verify',
        json={
            'session': phone_id,
            'credential': auth.create(start['options']),
        },
    )
    assert response.status_code == 200, response.text
    result = client.get(poll_path).json()
    assert result['status'] == 'complete'
    return result


def start_unlock(client):
    challenge = os.urandom(32)
    rid = client.post('/api/unlock-requests', json={'pc_name': 'gaming-pc', 'challenge': b64u(challenge)}).json()['id']
    pending = client.get('/api/unlock-requests/pending').json()
    assert pending[0]['id'] == rid
    return challenge, rid, pending[0]['options']


# ------------------------------------------------------------------ happy path


@pytest.mark.parametrize('via_gateway', [False, True], ids=['direct', 'gateway'])
def test_full_flow(env, via_gateway):
    client, pc = env
    if via_gateway:
        transport = httpx.ASGITransport(app=client.app)
        client = TestClient(create_gateway('https://pi.example.com:8443', transport=transport), base_url=ORIGIN)
    auth = SoftAuthenticator()
    result = enroll(client, auth)
    spki = auth.key.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    import main

    assert result['fingerprint'] == main.fingerprint(spki)
    assert b64u_d(result['spki_der']) == spki
    pinned = {result['credential_id']: spki}

    challenge, rid, opts = start_unlock(client)
    assert opts['rpId'] == RP_ID
    assert opts['userVerification'] == 'required'
    assert client.post(f'/api/unlock-requests/{rid}/assertion', json=auth.get(opts)).status_code == 200

    r = client.get(f'/api/unlock-requests/{rid}').json()
    assert r['status'] == 'approved'
    cid = pc.verify_assertion(r['assertion'], challenge=challenge, rp_id=RP_ID, origin=ORIGIN, pinned=pinned)
    assert cid == b64u(auth.cred_id)
    # Assertion is handed out once only.
    assert client.get(f'/api/unlock-requests/{rid}').json()['status'] == 'expired'


# ------------------------------------------------------------------ relay rejects


def test_enrollment_scopes_and_single_use(env):
    client, _ = env
    phone_id, poll_path = new_enrollment(client)
    assert client.get(f'/enroll?s={phone_id}').status_code == 200
    assert client.get(poll_path).json() == {'status': 'pending'}
    assert client.get(f'/api/enroll/sessions/{phone_id}').json() == {'status': 'expired'}
    assert client.post('/api/enroll/options', json={'session': poll_path.split('/')[-1]}).status_code == 404

    options = client.post('/api/enroll/options', json={'session': phone_id}).json()['options']
    assert options == client.post('/api/enroll/options', json={'session': phone_id}).json()['options']
    body = {'session': phone_id, 'credential': SoftAuthenticator().create(options)}
    assert client.post('/api/enroll/verify', json=body).status_code == 200
    assert client.post('/api/enroll/verify', json=body).status_code == 404
    assert client.get(poll_path).json()['status'] == 'complete'
    assert client.get(poll_path).json() == {'status': 'expired'}


def test_enrollment_expiry(env, monkeypatch):
    client, _ = env
    import main

    monkeypatch.setattr(main, 'ENROLL_TTL', 0)
    phone_id, poll_path = new_enrollment(client)
    assert client.get(f'/enroll?s={phone_id}').status_code == 404
    assert client.post('/api/enroll/options', json={'session': phone_id}).status_code == 404
    assert client.get(poll_path, params={'wait': 25}).json() == {'status': 'expired'}


def test_enrollment_wakes_waiter_and_only_one_receives_result(env):
    client, _ = env
    auth = SoftAuthenticator()

    async def exercise():
        transport = httpx.ASGITransport(app=client.app)
        async with httpx.AsyncClient(transport=transport, base_url=ORIGIN) as api:
            session = (await api.post('/api/enroll/sessions', json=PC)).json()
            phone_id = parse_qs(urlsplit(session['enroll_url']).query)['s'][0]
            poll_path = f'/api/enroll/sessions/{session["session_id"]}'
            options = (await api.post('/api/enroll/options', json={'session': phone_id})).json()['options']
            polls = [asyncio.create_task(api.get(poll_path, params={'wait': 25})) for _ in range(2)]
            await asyncio.sleep(0.01)
            assert all(not poll.done() for poll in polls)
            response = await api.post(
                '/api/enroll/verify',
                json={
                    'session': phone_id,
                    'credential': auth.create(options),
                },
            )
            assert response.status_code == 200
            results = await asyncio.wait_for(asyncio.gather(*polls), timeout=3)
            assert sorted(result.json()['status'] for result in results) == ['complete', 'expired']

    asyncio.run(exercise())


def test_relay_rejects_unknown_key(env):
    client, _ = env
    enroll(client, SoftAuthenticator())
    _, rid, opts = start_unlock(client)
    assert client.post(f'/api/unlock-requests/{rid}/assertion', json=SoftAuthenticator().get(opts)).status_code == 403


def test_relay_rejects_no_face_id(env):
    client, _ = env
    auth = SoftAuthenticator()
    enroll(client, auth)
    _, rid, opts = start_unlock(client)
    assert client.post(f'/api/unlock-requests/{rid}/assertion', json=auth.get(opts, flags=0x01)).status_code == 403


def test_relay_rejects_wrong_origin(env):
    client, _ = env
    auth = SoftAuthenticator()
    enroll(client, auth)
    _, rid, opts = start_unlock(client)
    bad = auth.get(opts, origin='https://evil.example.com')
    assert client.post(f'/api/unlock-requests/{rid}/assertion', json=bad).status_code == 403


def test_challenge_size_enforced(env):
    client, _ = env
    r = client.post('/api/unlock-requests', json={'pc_name': 'x', 'challenge': b64u(b'short')})
    assert r.status_code == 400


# ------------------------------------------------------------------ PC verifier rejects
# These model a compromised relay: it hands the PC whatever it wants.


def _assertion(auth, challenge, **kw):
    a = auth.get({'challenge': b64u(challenge)}, **kw)
    r = a['response']
    return {
        'credential_id': a['id'],
        'authenticator_data': r['authenticatorData'],
        'client_data_json': r['clientDataJSON'],
        'signature': r['signature'],
    }


@pytest.fixture
def verifier(env):
    _, pc = env
    auth = SoftAuthenticator()
    spki = auth.key.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    pinned = {b64u(auth.cred_id): spki}

    def check(assertion, challenge):
        return pc.verify_assertion(assertion, challenge=challenge, rp_id=RP_ID, origin=ORIGIN, pinned=pinned)

    return auth, check, pc.VerifyError


def test_pc_accepts_valid(verifier):
    auth, check, _ = verifier
    ch = os.urandom(32)
    assert check(_assertion(auth, ch), ch)


def test_pc_rejects_replay_of_old_challenge(verifier):
    auth, check, err = verifier
    old = _assertion(auth, os.urandom(32))
    with pytest.raises(err, match='challenge'):
        check(old, os.urandom(32))


def test_pc_rejects_unpinned_key(verifier):
    _, check, err = verifier
    ch = os.urandom(32)
    with pytest.raises(err, match='not pinned'):
        check(_assertion(SoftAuthenticator(), ch), ch)


def test_pc_rejects_key_swapped_under_pinned_id(verifier):
    """Relay forges an assertion with its own key but claims the pinned credential id."""
    auth, check, err = verifier
    ch = os.urandom(32)
    forged = _assertion(SoftAuthenticator(), ch)
    forged['credential_id'] = b64u(auth.cred_id)
    with pytest.raises(err, match='signature'):
        check(forged, ch)


def test_pc_rejects_no_uv(verifier):
    auth, check, err = verifier
    ch = os.urandom(32)
    with pytest.raises(err, match='verification'):
        check(_assertion(auth, ch, flags=0x01), ch)


def test_pc_rejects_wrong_origin(verifier):
    auth, check, err = verifier
    ch = os.urandom(32)
    with pytest.raises(err, match='origin'):
        check(_assertion(auth, ch, origin='https://evil.example.com'), ch)


def test_pc_rejects_wrong_rp(verifier):
    _, check, err = verifier
    other = SoftAuthenticator(rp_id='evil.example.com')
    # Pin it so we get past the pin check and hit the rpIdHash check.
    ch = os.urandom(32)
    a = _assertion(other, ch)
    with pytest.raises(err):
        check(a, ch)


def test_pc_rejects_tampered_signature(verifier):
    auth, check, err = verifier
    ch = os.urandom(32)
    a = _assertion(auth, ch)
    sig = bytearray(b64u_d(a['signature']))
    sig[-1] ^= 0xFF
    a['signature'] = b64u(bytes(sig))
    with pytest.raises(err):
        check(a, ch)


def test_long_poll_wakes_on_approval(env):
    """Exercise a concurrent poll and approval over a real loopback socket."""
    import socket

    import uvicorn

    client, _ = env
    auth = SoftAuthenticator()
    enroll(client, auth)
    _, rid, opts = start_unlock(client)

    async def exercise():
        with socket.socket() as sock:
            sock.bind(('127.0.0.1', 0))
            port = sock.getsockname()[1]
            started = asyncio.Event()

            class TestServer(uvicorn.Server):
                async def startup(self, sockets=None):
                    await super().startup(sockets=sockets)
                    started.set()

            server = TestServer(uvicorn.Config(client.app, log_level='warning'))
            serving = asyncio.create_task(server.serve(sockets=[sock]))
            try:
                await asyncio.wait_for(started.wait(), timeout=5)
                assert server.started
                async with httpx.AsyncClient(base_url=f'http://127.0.0.1:{port}') as api:
                    path = f'/api/unlock-requests/{rid}'
                    poll = asyncio.create_task(api.get(path, params={'wait': 10}))
                    await asyncio.sleep(0.05)
                    assert not poll.done()
                    approval = await api.post(f'{path}/assertion', json=auth.get(opts))
                    assert approval.status_code == 200
                    response = await asyncio.wait_for(poll, timeout=5)
                    assert response.json()['status'] == 'approved'
            finally:
                server.should_exit = True
                await asyncio.wait_for(serving, timeout=5)

    asyncio.run(exercise())


def test_enrolled_pc_survives_restart_and_wake_is_limited(env, monkeypatch):
    client, _ = env
    import main

    assert client.get('/api/pcs').json() == []
    enroll(client, SoftAuthenticator())
    enroll(client, SoftAuthenticator(), {'pc_name': 'other-pc', 'mac': '02:00:00:00:00:02'})
    client = TestClient(main.create_app())
    assert client.get('/api/pcs').json() == [{'pc_name': 'gaming-pc'}, {'pc_name': 'other-pc'}]

    sent = []
    monkeypatch.setattr(main, 'send_magic_packet', sent.append)
    wake_path = '/api/pcs/gaming-pc/wake'
    assert client.post('/api/pcs/missing/wake').status_code == 404
    assert client.post(wake_path, headers={'Origin': 'https://example.net'}).status_code == 403
    assert client.post(wake_path).status_code == 202
    assert client.post('/api/pcs/other-pc/wake').status_code == 429
    monkeypatch.setattr(main, 'WAKE_GLOBAL_COOLDOWN', 0)
    assert client.post(wake_path).status_code == 429
    assert client.post('/api/pcs/other-pc/wake').status_code == 202
    assert sent == [PC['mac'], '02:00:00:00:00:02']


def test_magic_packet_bytes(env, monkeypatch):
    from unittest.mock import MagicMock

    import main

    socket_factory = MagicMock()
    sock = socket_factory.return_value.__enter__.return_value
    monkeypatch.setattr(main.socket, 'socket', socket_factory)

    main.send_magic_packet(PC['mac'])

    socket_factory.assert_called_once_with(main.socket.AF_INET, main.socket.SOCK_DGRAM)
    sock.setsockopt.assert_called_once_with(main.socket.SOL_SOCKET, main.socket.SO_BROADCAST, 1)
    sock.sendto.assert_called_once_with(
        bytes.fromhex('ffffffffffff') + bytes.fromhex('020000000001') * 16,
        (main.WAKE_BROADCAST, 9),
    )


@pytest.mark.parametrize('mac', ['bad', '00:00:00:00:00:00', 'ff:ff:ff:ff:ff:ff'])
def test_enrollment_rejects_invalid_wake_address(env, mac):
    client, _ = env
    assert client.post('/api/enroll/sessions', json={**PC, 'mac': mac}).status_code == 422


def test_legacy_credential_remains_usable(env):
    client, _ = env
    import main

    auth = SoftAuthenticator()
    result = enroll(client, auth)
    path = main.DATA_DIR / 'credentials.json'
    records = json.loads(path.read_text())
    del records[0]['pcs']
    path.write_text(json.dumps(records))
    client = TestClient(main.create_app())

    assert client.get('/api/pcs').json() == []
    _, rid, options = start_unlock(client)
    assert options['allowCredentials'] == [{'type': 'public-key', 'id': result['credential_id']}]
    assert client.post(f'/api/unlock-requests/{rid}/assertion', json=auth.get(options)).status_code == 200


def test_reuse_passkey_across_pcs(env):
    client, pc = env
    auth = SoftAuthenticator()
    first = enroll(client, auth)
    phone_id, poll_path = new_enrollment(client, {'pc_name': 'other-pc', 'mac': '02:00:00:00:00:02'})
    options = client.post('/api/enroll/options', json={'session': phone_id}).json()
    reuse = options['reuse']
    assert len(b64u_d(reuse['challenge'])) == 33

    proof_path = '/api/enroll/reuse'
    assert (
        client.post(proof_path, json={'session': phone_id, 'credential': auth.get(options['options'])}).status_code
        == 403
    )
    assert client.post(proof_path, json={'session': phone_id, 'credential': auth.get(reuse)}).status_code == 200
    assert client.get(poll_path).json() == first
    assert client.get('/api/pcs').json() == [{'pc_name': 'gaming-pc'}, {'pc_name': 'other-pc'}]

    challenge = os.urandom(32)
    body = {'pc_name': 'other-pc', 'challenge': b64u(challenge)}
    request_id = client.post('/api/unlock-requests', json=body).json()['id']
    unlock = client.get('/api/unlock-requests/pending').json()[0]['options']
    assert unlock['allowCredentials'] == [{'type': 'public-key', 'id': first['credential_id']}]
    endpoint = f'/api/unlock-requests/{request_id}'
    assert client.post(f'{endpoint}/assertion', json=auth.get(reuse)).status_code == 403
    assert client.post(f'{endpoint}/assertion', json=auth.get(unlock)).status_code == 200
    assertion = client.get(endpoint).json()['assertion']
    pinned = {first['credential_id']: b64u_d(first['spki_der'])}
    assert (
        pc.verify_assertion(assertion, challenge=challenge, rp_id=RP_ID, origin=ORIGIN, pinned=pinned)
        == first['credential_id']
    )
