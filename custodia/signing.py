"""Detached signatures over a manifest's canonical bytes.

Two options, both dependency-light:

- **HMAC** (stdlib): shared-secret integrity. Anyone holding the key can verify —
  good for internal / consortium integrity, *not* third-party attestation.
- **SSH signatures** (via ``ssh-keygen``, if present): asymmetric, publicly
  verifiable detached signatures (SSHSIG) over the exact canonical bytes — real
  third-party attestation with a tool almost every system already has.

You sign ``Manifest.canonical_bytes()`` so the signature is over a deterministic,
reproducible representation of the whole attested corpus.
"""
from __future__ import annotations

import hashlib
import hmac
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Union

PathLike = Union[str, Path]


# --- HMAC (symmetric, stdlib) -------------------------------------------------

def sign_hmac(data: bytes, key: bytes) -> str:
    """Shared-secret HMAC-SHA256 over data. Hex digest."""
    return hmac.new(key, data, hashlib.sha256).hexdigest()


def verify_hmac(data: bytes, key: bytes, signature: str) -> bool:
    return hmac.compare_digest(sign_hmac(data, key), signature)


# --- SSH signatures (asymmetric, via ssh-keygen) ------------------------------

def ssh_available() -> bool:
    return shutil.which("ssh-keygen") is not None


def sign_ssh(data: bytes, private_key_path: PathLike, *, namespace: str = "custodia") -> str:
    """Detached SSH signature (SSHSIG) over data. Returns the armored signature text.

    Requires ``ssh-keygen``. Publicly verifiable with the corresponding public key.
    """
    if not ssh_available():
        raise RuntimeError("ssh-keygen not found; SSH signing unavailable")
    with tempfile.TemporaryDirectory() as d:
        msg = Path(d) / "m"
        msg.write_bytes(data)
        subprocess.run(
            ["ssh-keygen", "-Y", "sign", "-f", str(private_key_path), "-n", namespace, str(msg)],
            check=True,
            capture_output=True,
        )
        return Path(str(msg) + ".sig").read_text()


def verify_ssh(data: bytes, signature: str, *, identity: str, public_key: str, namespace: str = "custodia") -> bool:
    """Verify a detached SSH signature over data against a public key + identity."""
    if not ssh_available():
        raise RuntimeError("ssh-keygen not found; SSH verification unavailable")
    with tempfile.TemporaryDirectory() as d:
        sig = Path(d) / "m.sig"
        sig.write_text(signature)
        allowed = Path(d) / "allowed_signers"
        allowed.write_text(f"{identity} {public_key.strip()}\n")
        r = subprocess.run(
            ["ssh-keygen", "-Y", "verify", "-f", str(allowed), "-I", identity, "-n", namespace, "-s", str(sig)],
            input=data,
            capture_output=True,
        )
        return r.returncode == 0
