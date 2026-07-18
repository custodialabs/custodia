"""Provenance record: the small, explicit unit of custody metadata."""
from __future__ import annotations

import hashlib
import time
from dataclasses import asdict, dataclass
from typing import Optional

ALGO = "sha256"


def now_utc() -> str:
    """ISO-8601 UTC timestamp, second precision."""
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def hash_bytes(data: bytes) -> str:
    """SHA-256 hex digest of raw bytes."""
    return hashlib.sha256(data).hexdigest()


@dataclass
class ProvenanceRecord:
    """One source's custody record.

    `fetch_date`/`fetcher*` describe fetch-time custody (raw bytes at acquisition).
    `sealed_at` describes when the at-rest integrity seal was taken. Both may be
    present; neither is invented — an at-rest seal never claims fetch-time custody.
    """

    sha256: str
    origin: str = ""
    size: int = 0
    algo: str = ALGO
    fetch_date: Optional[str] = None
    fetcher: Optional[str] = None
    fetcher_version: Optional[str] = None
    sealed_at: Optional[str] = None
    note: str = ""

    def to_dict(self) -> dict:
        return {k: v for k, v in asdict(self).items() if v not in (None, "", 0) or k == "size"}

    @classmethod
    def from_dict(cls, d: dict) -> "ProvenanceRecord":
        fields = cls.__dataclass_fields__
        return cls(**{k: d[k] for k in fields if k in d})
