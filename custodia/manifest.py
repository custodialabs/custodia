"""Corpus manifest: an ordered set of provenance records + a Merkle root.

The manifest is the tamper-evident attestation over a whole corpus. Serializes to
plain JSON so it can be published, signed, or diffed with any tooling.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Union

from .merkle import Proof, inclusion_proof, merkle_root, verify_inclusion
from .record import ProvenanceRecord, now_utc

VERSION = "custodia/1"
PathLike = Union[str, Path]


@dataclass
class Manifest:
    records: List[ProvenanceRecord] = field(default_factory=list)
    created_at: str = field(default_factory=now_utc)
    label: str = ""

    def add(self, record: ProvenanceRecord) -> None:
        self.records.append(record)

    def leaf_hexes(self) -> List[str]:
        return [r.sha256 for r in self.records]

    def root(self) -> str:
        return merkle_root(self.leaf_hexes())

    def proof_for(self, index: int) -> Proof:
        return inclusion_proof(self.leaf_hexes(), index)

    def verify_root(self, expected_root: str) -> bool:
        return self.root() == expected_root

    def to_dict(self) -> dict:
        return {
            "version": VERSION,
            "label": self.label,
            "created_at": self.created_at,
            "algo": "sha256",
            "count": len(self.records),
            "merkle_root": self.root(),
            "records": [r.to_dict() for r in self.records],
        }

    def canonical_bytes(self) -> bytes:
        """Deterministic serialization — the exact bytes to sign / attest / diff."""
        return json.dumps(self.to_dict(), sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")

    def save(self, path: PathLike) -> None:
        Path(path).write_text(json.dumps(self.to_dict(), ensure_ascii=False, indent=2), encoding="utf-8")

    @classmethod
    def load(cls, path: PathLike) -> "Manifest":
        d = json.loads(Path(path).read_text(encoding="utf-8"))
        return cls(
            records=[ProvenanceRecord.from_dict(r) for r in d.get("records", [])],
            created_at=d.get("created_at", now_utc()),
            label=d.get("label", ""),
        )


__all__ = ["Manifest", "VERSION", "inclusion_proof", "verify_inclusion"]
