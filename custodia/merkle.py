"""Minimal binary Merkle tree over content hashes, with domain separation.

Lets a whole corpus be attested by a single root, and any member proven to be
included without re-hashing the rest. Standard SHA-256; last node duplicated on
odd levels. Domain-separation prefixes prevent leaf/internal second-preimage.
"""
from __future__ import annotations

import hashlib
from typing import List, Tuple

_LEAF = b"\x00"
_NODE = b"\x01"

Proof = List[Tuple[str, str]]  # (sibling_hex, 'L'|'R')


def _h(*parts: bytes) -> bytes:
    m = hashlib.sha256()
    for p in parts:
        m.update(p)
    return m.digest()


def _leaf(hexdigest: str) -> bytes:
    return _h(_LEAF, bytes.fromhex(hexdigest))


def merkle_root(leaf_hexes: List[str]) -> str:
    if not leaf_hexes:
        return hashlib.sha256(b"").hexdigest()
    level = [_leaf(h) for h in leaf_hexes]
    while len(level) > 1:
        nxt = []
        for i in range(0, len(level), 2):
            left = level[i]
            right = level[i + 1] if i + 1 < len(level) else left
            nxt.append(_h(_NODE, left, right))
        level = nxt
    return level[0].hex()


def inclusion_proof(leaf_hexes: List[str], index: int) -> Proof:
    if not (0 <= index < len(leaf_hexes)):
        raise IndexError("leaf index out of range")
    level = [_leaf(h) for h in leaf_hexes]
    idx = index
    proof: Proof = []
    while len(level) > 1:
        nxt = []
        for i in range(0, len(level), 2):
            left = level[i]
            right = level[i + 1] if i + 1 < len(level) else left
            if i == idx:  # target is the left child -> sibling is right
                proof.append((right.hex(), "R"))
            elif i + 1 == idx:  # target is the right child -> sibling is left
                proof.append((left.hex(), "L"))
            nxt.append(_h(_NODE, left, right))
        idx //= 2
        level = nxt
    return proof


def verify_inclusion(leaf_hex: str, proof: Proof, root: str) -> bool:
    cur = _leaf(leaf_hex)
    for sib_hex, side in proof:
        sib = bytes.fromhex(sib_hex)
        cur = _h(_NODE, sib, cur) if side == "L" else _h(_NODE, cur, sib)
    return cur.hex() == root
