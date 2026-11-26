"""Persistent public keys and their associated PCs."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from pathlib import Path


class CredentialStore:
    """Credentials are public keys only — nothing here is secret."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._creds: list[dict[str, Any]] = (
            json.loads(self.path.read_text(encoding='utf-8')) if self.path.exists() else []
        )

    def all(self) -> list[dict[str, Any]]:
        return list(self._creds)

    def get(self, cred_id: str) -> dict[str, Any] | None:
        return next((c for c in self._creds if c['id'] == cred_id), None)

    def pcs(self) -> dict[str, str]:
        pcs: dict[str, str] = {}
        for credential in self._creds:
            pcs.update(self.credential_pcs(credential))
        return pcs

    @staticmethod
    def credential_pcs(credential: dict[str, Any]) -> dict[str, str]:
        if 'pcs' in credential:
            return credential['pcs']
        if 'pc_name' in credential and 'mac' in credential:
            return {credential['pc_name']: credential['mac']}
        return {}

    def save(self, cred: dict[str, Any]) -> None:
        updated = [c for c in self._creds if c['id'] != cred['id']]
        updated.append(cred)
        tmp = self.path.with_suffix('.tmp')
        tmp.write_text(json.dumps(updated, indent=2), encoding='utf-8')
        tmp.replace(self.path)
        self._creds = updated


def matches_pc(credential: dict[str, Any], name: str) -> bool:
    pcs = CredentialStore.credential_pcs(credential)
    return bool(credential.get('legacy_global')) or not pcs or name in pcs
