"""
models.py
Server registration model + simple JSON-file-backed store.

SECURITY NOTE: credentials (including the SFTP password) are stored in
plaintext in servers.json for simplicity, matching how the previous
version of this app already handled SFTP credentials per-request. This
is designed as a local, single-user ops tool. If you deploy this
anywhere multi-user or network-reachable, swap this for real secret
storage (env vars per server, a vault, OS keychain, SSH keys instead of
passwords, etc.) before pointing it at real credentials.
"""

import datetime as _dt
import json
import os
import threading
import uuid
from dataclasses import asdict, dataclass
from typing import List, Optional

STORE_PATH = os.environ.get("SERVERS_STORE_PATH", "servers.json")
_LOCK = threading.Lock()


@dataclass
class Server:
    id: str
    name: str
    host: str
    port: int
    username: str
    password: str
    log_path: str  # the actively-written log file to tail
    auth_method: str = "password"  # "password" or "key"
    key_path: str = ""  # used when auth_method == "key"
    created_at: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


class ServerStore:
    """Simple JSON-file-backed CRUD store for Server records. Good enough
    for a local single-user tool; swap for a real DB if this needs to
    support concurrent users."""

    def __init__(self, path: str = STORE_PATH):
        self.path = path
        self._servers = {}
        self._load()

    def _load(self):
        if not os.path.exists(self.path):
            return
        try:
            with open(self.path, "r") as f:
                raw = json.load(f)
            for sid, data in raw.items():
                self._servers[sid] = Server(**data)
        except (json.JSONDecodeError, TypeError, ValueError):
            # Corrupt or old-format store — start fresh rather than crash
            # the whole app on boot.
            self._servers = {}

    def _save(self):
        with _LOCK:
            tmp_path = self.path + ".tmp"
            with open(tmp_path, "w") as f:
                json.dump({sid: s.to_dict() for sid, s in self._servers.items()}, f, indent=2)
            os.replace(tmp_path, self.path)

    def add(
        self,
        name: str,
        host: str,
        port: int,
        username: str,
        password: str,
        log_path: str,
        auth_method: str = "password",
        key_path: str = "",
    ) -> Server:
        sid = uuid.uuid4().hex[:12]
        server = Server(
            id=sid,
            name=name,
            host=host,
            port=port,
            username=username,
            password=password,
            log_path=log_path,
            auth_method=auth_method,
            key_path=key_path,
            created_at=_dt.datetime.utcnow().isoformat(),
        )
        self._servers[sid] = server
        self._save()
        return server

    def get(self, server_id: str) -> Optional[Server]:
        return self._servers.get(server_id)

    def list(self) -> List[Server]:
        return sorted(self._servers.values(), key=lambda s: s.created_at)

    def delete(self, server_id: str) -> None:
        if server_id in self._servers:
            del self._servers[server_id]
            self._save()
