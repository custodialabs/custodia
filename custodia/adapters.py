"""Storage adapters: seal/verify over a directory of files or a SQLite table.

The SQLite adapter mirrors the production pattern this library was generalized
from: one row = one source, content in a column, hash sealed per row.
"""
from __future__ import annotations

import re
import sqlite3
from pathlib import Path
from typing import List, Union

from .manifest import Manifest
from .record import ProvenanceRecord, hash_bytes, now_utc
from .seal import VerifyResult, seal_file, verify_file

PathLike = Union[str, Path]
_IDENT = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")


def _ident(name: str) -> str:
    if not _IDENT.fullmatch(name):
        raise ValueError(f"unsafe SQL identifier: {name!r}")
    return name


def seal_directory(root: PathLike, *, pattern: str = "**/*", label: str = "") -> Manifest:
    root = Path(root)
    m = Manifest(label=label or str(root))
    for p in sorted(root.glob(pattern)):
        if p.is_file():
            rec = seal_file(p)
            rec.origin = str(p.relative_to(root))
            m.add(rec)
    return m


def verify_directory(root: PathLike, manifest: Manifest) -> List[VerifyResult]:
    root = Path(root)
    return [verify_file(root / rec.origin, rec) for rec in manifest.records]


def seal_sqlite(db_path: PathLike, table: str, id_col: str, content_col: str, *, label: str = "") -> Manifest:
    table, id_col, content_col = _ident(table), _ident(id_col), _ident(content_col)
    m = Manifest(label=label or f"{db_path}:{table}")
    conn = sqlite3.connect(str(db_path))
    try:
        q = f"SELECT {id_col}, {content_col} FROM {table} WHERE {content_col} IS NOT NULL"
        for sid, content in conn.execute(q):
            data = content.encode("utf-8", "replace") if isinstance(content, str) else (content or b"")
            m.add(ProvenanceRecord(sha256=hash_bytes(data), origin=str(sid), size=len(data), sealed_at=now_utc()))
    finally:
        conn.close()
    return m
