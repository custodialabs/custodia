"""Sealing and verification.

Two explicit guarantees:
  - seal_bytes(): fetch-time custody — hash raw bytes AT ACQUISITION + metadata.
  - seal_file(): at-rest integrity seal — hash stored content now (tamper-evidence
    going forward). It does NOT claim to match the original fetch.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Optional, Union

from .record import ProvenanceRecord, hash_bytes, now_utc

PathLike = Union[str, Path]


def seal_bytes(
    data: bytes,
    origin: str = "",
    *,
    fetcher: Optional[str] = None,
    fetcher_version: Optional[str] = None,
    fetch_date: Optional[str] = None,
    note: str = "",
) -> ProvenanceRecord:
    """Fetch-time custody: seal the raw bytes exactly as acquired."""
    return ProvenanceRecord(
        sha256=hash_bytes(data),
        origin=origin,
        size=len(data),
        fetch_date=fetch_date or now_utc(),
        fetcher=fetcher,
        fetcher_version=fetcher_version,
        sealed_at=now_utc(),
        note=note,
    )


def seal_file(path: PathLike, *, note: str = "") -> ProvenanceRecord:
    """At-rest integrity seal of a file's current content."""
    p = Path(path)
    data = p.read_bytes()
    return ProvenanceRecord(sha256=hash_bytes(data), origin=str(p), size=len(data), sealed_at=now_utc(), note=note)


@dataclass
class VerifyResult:
    ok: bool
    origin: str
    expected: str
    actual: str
    reason: str = ""

    def __bool__(self) -> bool:
        return self.ok


def verify_bytes(data: bytes, record: ProvenanceRecord) -> VerifyResult:
    actual = hash_bytes(data)
    ok = actual == record.sha256
    return VerifyResult(
        ok=ok,
        origin=record.origin,
        expected=record.sha256,
        actual=actual,
        reason="" if ok else "content hash mismatch (tampered or changed since seal)",
    )


def verify_file(path: PathLike, record: ProvenanceRecord) -> VerifyResult:
    p = Path(path)
    if not p.exists():
        return VerifyResult(ok=False, origin=str(p), expected=record.sha256, actual="", reason="file missing")
    return verify_bytes(p.read_bytes(), record)
