"""Quickstart: seal a corpus, attest it with one root, verify, prove inclusion."""
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from custodia import Manifest, seal_bytes, verify_bytes

# 1. Fetch-time custody: seal each source exactly as acquired.
sources = {
    "https://example.org/a": b"first source content",
    "https://example.org/b": b"second source content",
    "https://example.org/c": b"third source content",
}

m = Manifest(label="demo-corpus")
for url, data in sources.items():
    m.add(seal_bytes(data, origin=url, fetcher="example-fetcher", fetcher_version="1.0"))

print(f"corpus of {len(m.records)} sources")
print(f"merkle root (attests the whole corpus): {m.root()}")

# 2. Verify a source against its seal.
rec = m.records[0]
print(f"verify unchanged: {verify_bytes(b'first source content', rec).ok}")
print(f"verify tampered:  {verify_bytes(b'FIRST source content', rec).ok}")

# 3. Prove one source is included in the attested corpus, without the others.
proof = m.proof_for(1)
from custodia import verify_inclusion

print(f"inclusion proof for source 1 valid: {verify_inclusion(m.records[1].sha256, proof, m.root())}")
