"""Fetch-time custody: seal raw bytes + acquisition metadata at the moment of fetch.

This is the *true* chain of custody — it can only be captured when the source is
acquired, never reconstructed later. The network call and the sealing are kept
separate so the sealing logic is testable and reusable with any fetcher.
"""
from __future__ import annotations

import urllib.request
from typing import Optional, Tuple

from .record import ProvenanceRecord, hash_bytes, now_utc

DEFAULT_UA = "custodia/0.1 (+https://github.com/custodialabs/custodia)"


def seal_fetched(
    origin: str,
    data: bytes,
    *,
    fetcher: str = "custodia.fetch",
    fetcher_version: Optional[str] = None,
    fetch_date: Optional[str] = None,
    status: Optional[int] = None,
    content_type: Optional[str] = None,
    note: str = "",
) -> ProvenanceRecord:
    """Build a fetch-time custody record from already-acquired bytes + metadata.

    Use this when you fetch with your own tooling and want a custody record for
    the exact bytes you received.
    """
    meta = [
        p
        for p in (
            f"status={status}" if status is not None else None,
            f"content-type={content_type}" if content_type else None,
            note or None,
        )
        if p
    ]
    return ProvenanceRecord(
        sha256=hash_bytes(data),
        origin=origin,
        size=len(data),
        fetch_date=fetch_date or now_utc(),
        fetcher=fetcher,
        fetcher_version=fetcher_version,
        sealed_at=now_utc(),
        note="; ".join(meta),
    )


def fetch(url: str, *, timeout: float = 30.0, user_agent: str = DEFAULT_UA, note: str = "") -> Tuple[bytes, ProvenanceRecord]:
    """Fetch a URL and seal the raw response bytes with acquisition metadata.

    Returns (data, ProvenanceRecord). The record proves *this is exactly what the
    source served, when we got it* — genuine chain of custody.
    """
    req = urllib.request.Request(url, headers={"User-Agent": user_agent})
    with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 (URL is caller-provided by design)
        data = resp.read()
        status = getattr(resp, "status", None) or resp.getcode()
        content_type = resp.headers.get("Content-Type")
    rec = seal_fetched(url, data, fetcher="custodia.fetch", status=status, content_type=content_type, note=note)
    return data, rec
