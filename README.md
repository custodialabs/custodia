# custodia

**Tamper-evident provenance & custody for source corpora.**

`custodia` is a small, storage-agnostic library for establishing and verifying the
integrity and provenance of collections of sources — documents, web fetches,
records, evidence. It answers one hard question honestly: *can you prove this
source has not been altered since you obtained it, and show where it came from?*

It is built for anyone who has to stand behind their data: investigative
journalists, researchers, legal/evidence workflows, knowledge graphs, and any
ingestion pipeline that needs an auditable chain of custody rather than a vague
"trust us."

> Status: **v0 (early)**. The model here is generalized from production use in a
> large knowledge-graph system where it seals **1.1M+ sources** across two
> databases. This repository re-implements that model as a clean, dependency-light,
> reusable tool.

## The honest custody model

Most "integrity" tooling conflates two very different guarantees. `custodia`
keeps them explicit, because the difference is the whole point:

1. **Fetch-time custody** *(true chain of custody)* — hash the **raw bytes at the
   moment of acquisition**, together with acquisition metadata (source URL,
   timestamp, fetch tool/version, response headers). This is what lets you claim
   "this is exactly what the source served, when we got it." It must be captured
   at fetch time; it cannot be reconstructed later.
2. **At-rest integrity seal** *(tamper-evidence going forward)* — periodically
   re-hash stored content and compare against the recorded seal. This detects any
   change **after** the seal point. It does **not** prove the content matches the
   original fetch if the seal was taken after ingestion — and `custodia` says so,
   rather than pretending otherwise.

A provenance record in `custodia` carries a small, explicit set of fields:

| field | meaning |
|---|---|
| `sha256` | content hash (fetch-time bytes and/or at-rest content) |
| `fetch_date` | when the source was acquired |
| `fetcher` / `fetcher_version` | tool that acquired it |
| `origin` | URL / path / identifier of the source |
| `sealed_at` | when the at-rest seal was taken |
| `note` | free-form provenance note |

## What it does

- **Seal** a source or a whole corpus (content hash + provenance record).
- **Verify** a source/corpus against its seals and report any drift or tampering.
- **Manifest** — build a tamper-evident manifest over a corpus, with an optional
  Merkle root so a large corpus can be attested (and individual members proven)
  without re-hashing everything.
- **Adapters** — work over a directory of files, a SQLite table, or a custom
  pipeline hook. Storage-agnostic by design; no lock-in.

## Design principles

- **Standard crypto only** (SHA-256, Merkle trees) — nothing exotic to trust.
- **Honest guarantees** — never claim fetch-time custody for an at-rest seal.
- **Dependency-light**, embeddable in an existing pipeline in a few lines.
- **Open** — Apache-2.0, all outputs openly licensed.

## Roadmap

- [ ] `custodia.seal` / `custodia.verify` core (files + SQLite adapters)
- [ ] Corpus manifest + Merkle root + inclusion proofs
- [ ] Fetch-time custody hook (capture raw bytes + metadata at acquisition)
- [ ] Signed manifests (detached signatures) for third-party attestation
- [ ] CLI (`custodia seal` / `custodia verify` / `custodia manifest`)

## License

Apache License 2.0. See [`LICENSE`](./LICENSE).

## Contributing

Issues and proposals welcome. The goal is a small, auditable, boring-in-a-good-way
integrity primitive that other projects can depend on.
