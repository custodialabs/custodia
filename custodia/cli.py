"""custodia command-line interface: seal / verify / root."""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .adapters import seal_directory, verify_directory
from .manifest import Manifest
from .seal import seal_file


def _seal_single(path: Path) -> Manifest:
    m = Manifest(label=str(path))
    rec = seal_file(path)
    rec.origin = path.name
    m.add(rec)
    return m


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="custodia", description="Tamper-evident provenance & custody for source corpora.")
    sub = ap.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("seal", help="seal a file or directory into a manifest")
    s.add_argument("path")
    s.add_argument("-o", "--out", default="custodia.manifest.json")

    v = sub.add_parser("verify", help="verify a directory against a manifest")
    v.add_argument("path")
    v.add_argument("manifest")

    r = sub.add_parser("root", help="print the merkle root of a manifest")
    r.add_argument("manifest")

    args = ap.parse_args(argv)

    if args.cmd == "seal":
        p = Path(args.path)
        m = seal_directory(p) if p.is_dir() else _seal_single(p)
        m.save(args.out)
        print(f"sealed {len(m.records)} source(s) -> {args.out}")
        print(f"merkle_root: {m.root()}")
        return 0

    if args.cmd == "verify":
        m = Manifest.load(args.manifest)
        results = verify_directory(args.path, m)
        bad = [x for x in results if not x.ok]
        for x in bad:
            print(f"FAIL {x.origin}: {x.reason}")
        print(f"{len(results) - len(bad)}/{len(results)} OK")
        return 1 if bad else 0

    if args.cmd == "root":
        print(Manifest.load(args.manifest).root())
        return 0

    return 2


if __name__ == "__main__":
    sys.exit(main())
