# ProofGraph Security IR v1 / Evidence Adapter v1

Input schema URI: `proofgraph.security-ir/v1`. Result schema URI: `proofgraph.result/v1`. These are project-local identifiers, not IANA registrations. Downstream tools may submit *new* adapters only after their own output is normalized into this deliberately strict contract. No existing HeaderLens/ReconDiff/SurfaceMap/ScopeGuard/PentestEvidence/JSMap/ParamMiner/AuthMatrix wire formats are claimed compatible; separate adapters, schema migration and conformance tests are **UNTESTED**.

`Node` has `id`, `type` (`asset|identity|service|control|finding`) and mandatory `scope_id`. `Edge` has typed `from`, `to`, `kind`, `state` (`observed|confirmed|inferred|hypothesis|disproven`), cited `evidence_ids`, RFC3339 `observed_at`, and an optional `verified_by` **only** when `state=confirmed`. Human identity is not authenticated. `Evidence` carries strictly base64-encoded bytes; its input body is never emitted. Output includes deterministic `sha256:` digests, snapshot, graph findings, negative evidence, explicit contradictory relationships, bounds and limitations.

An AI suggestion must be imported as `inferred` or `hypothesis` with evidence and must never set `confirmed`, change authorization scope, or silently erase disproven/negative observations. RC1 does not implement an AI interface; this is the proposed boundary for future adapters.

All declared JSON member names must match the contract exactly, including case. `encoding/json` legacy case-insensitive member matching is not accepted by the strict validation layer.

Input `input_sha256` is SHA-256 of the exact input bytes, not RFC 8785 normalized JSON. Report `sha256` is SHA-256 of compact `encoding/json` serialization of the report with its `sha256` field cleared, and is verifiable only as an unkeyed integrity check. Replay additionally recalculates all output from source. These hash contracts are versioned and must not be altered without a schema bump.

## Required member presence (RC5)

`proofgraph.result/v1` requires every listed top-level report member to be
present, including arrays/maps with no observations. A missing member is never
interchangeable with an explicit empty array/map or a Go `nil`/`null` value.
`verify` enforces this property even if the report author recomputes the plain
SHA-256 checksum. This is schema validation only, **not** cryptographic source
or human-identity authentication; `replay` remains necessary to compare results
against the supplied original input.

## RC8 derived metric integrity boundary

Derived result claims (`graph_cuts`, `blast_radius`, `information_gain`, `contradictions`, `negative_evidence`, `missing_links`) are now subject to referential and bounded consistency checks; these checks do **not** imply a source was genuine. `replay` with independently trusted original input must be used to verify actual derivation. No schema identifiers, hash algorithm or accepted valid-result serialization changed.
