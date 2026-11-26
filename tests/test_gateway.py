"""Exercise the independent origin against an untrusted relay."""

import httpx
import pytest
from gateway import MAX_BODY, create_app
from starlette.testclient import TestClient

ORIGIN = 'https://unlock.example.com'
BACKEND = 'https://pi.example.com:8443'


def test_gateway_serves_local_enrollment_and_treats_relay_as_data():
    def reply(request):
        assert str(request.url) == f'{BACKEND}/api/enroll/sessions'
        assert request.headers['origin'] == ORIGIN
        assert 'cookie' not in request.headers
        assert 'authorization' not in request.headers
        assert request.content == b'{}'
        return httpx.Response(
            201,
            json={'enroll_url': f'{ORIGIN}/enroll?s=qr-id'},
            headers={
                'set-cookie': 'session=relay-controlled',
                'refresh': '0; url=https://evil.example.com',
                'service-worker-allowed': '/',
                'clear-site-data': '"storage"',
                'content-security-policy': 'default-src *',
            },
        )

    client = TestClient(create_app(BACKEND, transport=httpx.MockTransport(reply)), base_url=ORIGIN)
    page = client.get('/enroll?s=qr-id')
    assert page.status_code == 200
    assert 'src="/app.js"' in page.text
    assert "frame-ancestors 'none'" in page.headers['content-security-policy']
    assert client.get('/app.js').status_code == 200

    result = client.post(
        '/api/enroll/sessions',
        json={},
        headers={'origin': ORIGIN, 'cookie': 'local=1', 'authorization': 'example'},
    )
    assert result.status_code == 201
    assert result.json() == {'enroll_url': f'{ORIGIN}/enroll?s=qr-id'}
    for header in ['set-cookie', 'refresh', 'service-worker-allowed', 'clear-site-data']:
        assert header not in result.headers
    assert result.headers['content-security-policy'] == "default-src 'none'; sandbox"
    assert result.headers['x-content-type-options'] == 'nosniff'


@pytest.mark.parametrize(
    ('status', 'headers', 'payload'),
    [
        (302, {'location': '/app.js'}, b''),
        (200, {'content-type': 'text/html'}, b'<script>alert(1)</script>'),
        (200, {'content-type': 'application/json'}, b'not JSON'),
        (200, {'content-type': 'application/json'}, b'[' + b' ' * MAX_BODY + b']'),
        (200, {'content-type': 'application/json', 'content-encoding': 'gzip'}, b'{"x": 1}'),
    ],
)
def test_gateway_rejects_unsafe_upstream_responses(status, headers, payload):
    transport = httpx.MockTransport(lambda _: httpx.Response(status, headers=headers, content=payload))
    client = TestClient(create_app(BACKEND, transport=transport), base_url=ORIGIN)
    response = client.get('/api/pcs')
    assert response.status_code == 502
    assert response.headers['content-type'] == 'application/json'
    assert 'location' not in response.headers


def test_gateway_only_forwards_the_known_api():
    def unexpected(_):
        pytest.fail('A local route or invalid request reached the relay.')

    client = TestClient(create_app(BACKEND, transport=httpx.MockTransport(unexpected)), base_url=ORIGIN)
    assert client.get('/api/custom.js').status_code == 404
    assert client.get('/secret-file').status_code == 404
    assert client.put('/api/enroll/sessions', json={}).status_code == 405
    assert client.post('/api/pcs/game-pc/wake', data={'wake': '1'}).status_code == 415
    assert client.post('/api/enroll/options', json={'session': 'a' * MAX_BODY}).status_code == 413


@pytest.mark.parametrize(
    'backend', ['http://pi.example.com', 'https://pi.example.com/?a=b', 'https://foo@pi.example.com']
)
def test_gateway_requires_a_fixed_https_backend(backend):
    with pytest.raises(ValueError, match='GATEWAY_BACKEND'):
        create_app(backend)
