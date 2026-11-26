"""Serve the phone UI from a trusted host and read only JSON from the Pi."""

from __future__ import annotations

import asyncio
import json
import os
import re
from pathlib import Path
from typing import TYPE_CHECKING

import httpx
from starlette.applications import Starlette
from starlette.responses import FileResponse, JSONResponse, Response
from starlette.routing import Route

if TYPE_CHECKING:
    from collections.abc import AsyncIterator

    from starlette.requests import Request

STATIC_DIR = Path(__file__).parent / 'static'
STATIC_FILES = {
    '/': 'index.html',
    '/enroll': 'enroll.html',
    '/app.js': 'app.js',
    '/style.css': 'style.css',
    '/manifest.webmanifest': 'manifest.webmanifest',
    '/icon.svg': 'icon.svg',
}
API_PATHS = {
    'GET': re.compile(r'/api/(?:pcs|enroll/sessions/[\w-]{32,64}|unlock-requests/(?:pending|[\w-]{16,64}))', re.ASCII),
    'POST': re.compile(
        r'/api/(?:enroll/(?:sessions|options|verify|reuse)'
        r'|pcs/[A-Za-z0-9][A-Za-z0-9_.-]{0,39}/wake'
        r'|unlock-requests(?:/[\w-]{16,64}/assertion)?)',
        re.ASCII,
    ),
}
MAX_BODY = 128 * 1024
SECURITY_HEADERS = {
    'Cache-Control': 'no-store',
    'X-Content-Type-Options': 'nosniff',
    'Referrer-Policy': 'no-referrer',
}
STATIC_HEADERS = {
    **SECURITY_HEADERS,
    'Content-Security-Policy': (
        "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
        "frame-ancestors 'none'; base-uri 'none'; form-action 'none'; object-src 'none'"
    ),
}
API_HEADERS = {**SECURITY_HEADERS, 'Content-Security-Policy': "default-src 'none'; sandbox"}


def gateway_error(status: int, message: str) -> JSONResponse:
    return JSONResponse({'error': message}, status_code=status, headers=API_HEADERS)


def backend_origin(value: str) -> httpx.URL:
    url = httpx.URL(value)
    if url.scheme != 'https' or not url.host or url.userinfo or url.raw_path != b'/' or url.fragment:
        msg = 'GATEWAY_BACKEND must be an HTTPS origin with no credentials, path, query, or fragment.'
        raise ValueError(msg)
    return url


async def bounded_body(stream: AsyncIterator[bytes]) -> bytes | None:
    body = bytearray()
    async for chunk in stream:
        if len(body) + len(chunk) > MAX_BODY:
            return None
        body.extend(chunk)
    return bytes(body)


def api_headers(request: Request) -> dict[str, str]:
    headers = {'Accept': 'application/json', 'Accept-Encoding': 'identity'}
    if request.method == 'POST':
        headers['Content-Type'] = 'application/json'
        if origin := request.headers.get('origin'):
            headers['Origin'] = origin
    return headers


async def relay_json(
    client: httpx.AsyncClient,
    request: Request,
    destination: httpx.URL,
    body: bytes,
) -> JSONResponse:
    async with client.stream(request.method, destination, content=body, headers=api_headers(request)) as upstream:
        media_type = upstream.headers.get('content-type', '').partition(';')[0].strip().lower()
        if media_type != 'application/json' or not (upstream.is_success or upstream.is_client_error):
            return gateway_error(502, 'The relay did not return an API response.')
        if upstream.headers.get('content-encoding', 'identity').lower() != 'identity':
            return gateway_error(502, 'The relay returned unexpected content encoding.')

        data = await bounded_body(upstream.aiter_bytes())
    if data is None:
        return gateway_error(502, 'The relay response was too large.')
    payload = json.loads(data)
    if not isinstance(payload, (dict, list)):
        return gateway_error(502, 'The relay returned an invalid API response.')
    return JSONResponse(payload, status_code=upstream.status_code, headers=API_HEADERS)


async def static(request: Request) -> Response:
    filename = STATIC_FILES.get(request.url.path)
    if filename is None:
        return Response(status_code=404, headers=STATIC_HEADERS)
    return FileResponse(STATIC_DIR / filename, headers=STATIC_HEADERS)


def create_app(backend: str | None = None, *, transport: httpx.AsyncBaseTransport | None = None) -> Starlette:
    origin = backend_origin(backend or os.environ.get('GATEWAY_BACKEND', ''))

    async def api(request: Request) -> JSONResponse:
        path = request.url.path
        if (allowed := API_PATHS.get(request.method)) is None or not allowed.fullmatch(path):
            return gateway_error(404, 'Unknown API endpoint.')
        if (
            request.method == 'POST'
            and request.headers.get('content-type', '').partition(';')[0] != 'application/json'
        ):
            return gateway_error(415, 'Expected application/json.')
        body = await bounded_body(request.stream())
        if body is None:
            return gateway_error(413, 'Request was too large.')
        destination = origin.copy_with(path=path, query=request.scope['query_string'] or None)
        try:
            async with (
                asyncio.timeout(40),
                httpx.AsyncClient(
                    transport=transport,
                    follow_redirects=False,
                    trust_env=False,
                    timeout=httpx.Timeout(35, connect=5),
                ) as client,
            ):
                return await relay_json(client, request, destination, body)
        except (httpx.HTTPError, ValueError, RecursionError, TimeoutError):
            return gateway_error(502, 'The relay API is unavailable.')

    return Starlette(
        routes=[
            Route('/api/{path:path}', api, methods=['GET', 'POST', 'HEAD']),
            Route('/{path:path}', static, methods=['GET', 'HEAD']),
        ]
    )
