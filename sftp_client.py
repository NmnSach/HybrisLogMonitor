"""
sftp_client.py
Thin paramiko wrappers used by the live poller and historical-file views.

Every function opens its own short-lived Transport/SFTPClient and closes
it when done, rather than holding one long-lived connection open for the
whole monitoring session. That costs a bit of reconnect overhead each
poll cycle, but it's much simpler to reason about and far more robust
against a connection silently dying between polls (which, over a
long-running monitoring session against a real ops box, will happen).
"""

import contextlib
import os
from typing import Iterator, List, Tuple

import paramiko


@contextlib.contextmanager
def _sftp_session(server):
    transport = paramiko.Transport((server.host, int(server.port or 22)))
    sftp = None
    try:
        if server.auth_method == "key" and server.key_path:
            pkey = _load_private_key(server.key_path)
            transport.connect(username=server.username, pkey=pkey)
        else:
            transport.connect(username=server.username, password=server.password)
        sftp = paramiko.SFTPClient.from_transport(transport)
        yield sftp
    finally:
        if sftp is not None:
            sftp.close()
        transport.close()


def _load_private_key(key_path: str):
    """Load a private key file, auto-detecting its type (RSA / Ed25519 /
    ECDSA / DSA) rather than assuming RSA, and supporting an optional
    passphrase via the SFTP_KEY_PASSPHRASE env var (there's nowhere in
    the current /new form to collect a per-server passphrase — if you
    need per-server passphrases, extend Server with a passphrase field
    and thread it through here instead of a single shared env var)."""
    expanded = os.path.expanduser(key_path)
    passphrase = os.environ.get("SFTP_KEY_PASSPHRASE") or None

    key_loaders = [
        paramiko.Ed25519Key.from_private_key_file,
        paramiko.RSAKey.from_private_key_file,
        paramiko.ECDSAKey.from_private_key_file,
    ]
    # DSSKey (DSA keys) was removed in newer paramiko releases — DSA is
    # obsolete and most servers refuse it anyway, but fall back to it
    # here if it happens to be present, rather than hard-coding a
    # reference that breaks on paramiko versions where it's gone.
    if hasattr(paramiko, "DSSKey"):
        key_loaders.append(paramiko.DSSKey.from_private_key_file)
    last_error = None
    for loader in key_loaders:
        try:
            return loader(expanded, password=passphrase)
        except paramiko.ssh_exception.SSHException as exc:
            last_error = exc
            continue
        except FileNotFoundError:
            raise
    raise ValueError(
        f"Could not load private key at {expanded} as any of "
        f"Ed25519/RSA/ECDSA/DSS: {last_error}"
    )


def stat_size(server, remote_path: str) -> int:
    with _sftp_session(server) as sftp:
        return sftp.stat(remote_path).st_size


def read_range(server, remote_path: str, offset: int) -> Tuple[bytes, int]:
    """Read everything from `offset` to the current end of file. Returns
    (new_bytes, new_total_size). Uses a random-access seek+read instead of
    downloading the whole file each time, so tailing a multi-GB log costs
    O(new data) per poll, not O(file size)."""
    with _sftp_session(server) as sftp:
        size = sftp.stat(remote_path).st_size
        if size <= offset:
            return b"", size
        with sftp.open(remote_path, "rb") as f:
            f.seek(offset)
            data = f.read(size - offset)
        return data, size


def iter_full_text_chunks(server, remote_path: str, chunk_size: int = 1024 * 1024) -> Iterator[str]:
    """Stream a file from the start, in decoded text chunks, so we never
    hold the whole thing in memory at once. Used for (a) the initial
    backlog parse when a server is first added / on app startup, and
    (b) one-off historical file views."""
    with _sftp_session(server) as sftp:
        with sftp.open(remote_path, "rb") as f:
            f.set_pipelined()
            while True:
                chunk = f.read(chunk_size)
                if not chunk:
                    break
                yield chunk.decode("utf-8", errors="replace")


def list_log_dir(server, dir_path: str) -> List[Tuple[str, int]]:
    """List files in a directory (typically the one containing the
    live-tailed log) for the historical-file picker. Returns
    [(filename, size_bytes), ...] sorted by filename."""
    with _sftp_session(server) as sftp:
        entries = sftp.listdir_attr(dir_path)
    files = [(e.filename, e.st_size) for e in entries if not e.filename.startswith(".")]
    return sorted(files)


def test_connection(server) -> Tuple[bool, str]:
    """Used by /new to validate credentials + log_path before saving the
    server record and starting a poller for it."""
    try:
        with _sftp_session(server) as sftp:
            sftp.stat(server.log_path)
        return True, "OK"
    except Exception as exc:  # noqa: BLE001
        return False, str(exc)
