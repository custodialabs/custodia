"""custodia — tamper-evident provenance & custody for source corpora."""
from .adapters import seal_directory, seal_sqlite, verify_directory
from .fetch import fetch, seal_fetched
from .manifest import Manifest
from .merkle import inclusion_proof, merkle_root, verify_inclusion
from .record import ProvenanceRecord, hash_bytes, now_utc
from .seal import VerifyResult, seal_bytes, seal_file, verify_bytes, verify_file
from .signing import sign_hmac, sign_ssh, ssh_available, verify_hmac, verify_ssh

__version__ = "0.1.0"
__all__ = [
    "ProvenanceRecord",
    "hash_bytes",
    "now_utc",
    "seal_bytes",
    "seal_file",
    "verify_bytes",
    "verify_file",
    "VerifyResult",
    "fetch",
    "seal_fetched",
    "merkle_root",
    "inclusion_proof",
    "verify_inclusion",
    "Manifest",
    "seal_directory",
    "verify_directory",
    "seal_sqlite",
    "sign_hmac",
    "verify_hmac",
    "sign_ssh",
    "verify_ssh",
    "ssh_available",
]
