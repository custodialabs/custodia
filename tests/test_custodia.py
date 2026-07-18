"""Basic correctness tests. Run: python -m pytest  (or python tests/test_custodia.py)."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from custodia import Manifest, seal_bytes, verify_bytes  # noqa: E402
from custodia.merkle import inclusion_proof, merkle_root, verify_inclusion  # noqa: E402


def test_seal_verify_roundtrip():
    rec = seal_bytes(b"hello world", origin="doc-1", fetcher="curl", fetcher_version="8.0")
    assert verify_bytes(b"hello world", rec).ok
    tampered = verify_bytes(b"hello w0rld", rec)
    assert not tampered.ok and "mismatch" in tampered.reason


def test_merkle_inclusion_all_indices():
    leaves = [seal_bytes(f"s{i}".encode(), origin=str(i)).sha256 for i in range(7)]  # odd count
    root = merkle_root(leaves)
    for i, lh in enumerate(leaves):
        assert verify_inclusion(lh, inclusion_proof(leaves, i), root)
    # a foreign leaf must not verify against the root
    foreign = seal_bytes(b"not-in-set", origin="x").sha256
    assert not verify_inclusion(foreign, inclusion_proof(leaves, 0), root)


def test_manifest_roundtrip(tmp_path=None):
    import tempfile

    d = tmp_path or tempfile.mkdtemp()
    m = Manifest(label="corpus")
    for i in range(5):
        m.add(seal_bytes(f"record-{i}".encode(), origin=f"r{i}"))
    root = m.root()
    p = os.path.join(str(d), "m.json")
    m.save(p)
    m2 = Manifest.load(p)
    assert m2.root() == root
    assert m2.verify_root(root)
    assert len(m2.records) == 5


if __name__ == "__main__":
    test_seal_verify_roundtrip()
    test_merkle_inclusion_all_indices()
    test_manifest_roundtrip()
    print("all tests passed")
