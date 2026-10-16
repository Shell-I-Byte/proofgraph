> Current public release and Mac validation status: [README](../README.md) and [MACOS_QUALIFICATION.md](MACOS_QUALIFICATION.md). Historical run references in this technical document do not describe the current publication status.

# RC12 — Strict RFC 3339 timestamps and native CI coverage

Fix BUG-PG-194-001. In RC11, authorization, snapshot, edge observation and result-verifier timestamp checks used Go's permissive `time.Parse(time.RFC3339, ...)`, which accepts invalid RFC 3339 strings including one-digit hours, comma fractions and `+24:00`/`+00:60` offsets. The RC12 parser enforces RFC 3339 section 5.6 and delegates civil-date validation to Go. Invalid old input can now be rejected; the published v1 wire schemas and valid report bytes are unchanged. A self-rehashed report with invalid snapshot is rejected even when its SHA-256 is internally consistent.

The native CI matrix now includes `ubuntu-24.04-arm`, `macos-15` and `windows-2025` and explicitly runs native race/shuffle, vet, build and module verification. These are **configuration checks only**. No GitHub Actions run was executed, and Go 1.27.2, Staticcheck and Govulncheck remain unavailable locally. This is a release candidate, not stable v1.

# RC11 — Linux input-ancestor symlink hardening

Fix BUG-PG-181-001: Linux input opens previously rejected only final-component symlinks. RC10 accepted a stable symlink in an input ancestor; this bypassed the documented no-symlink invariant. RC11 uses descriptor-relative `openat` and `O_NOFOLLOW` for every input component and rejects lexical `..`. Added synthetic positive/negative Go regression and black-box atomic rename-exchange probe. No versioned Security IR/result changes. Native macOS/Windows runtime, supported Go, static analyzers, CI, provenance and adapters remain open/blocked.

# RC10 — Linux output-ancestor race hardening

Fix BUG-PG-168-001. A local synthetic test demonstrated that a symlink-exchange
attack on an intermediate output-directory component caused RC9 to write valid
reports into an unintended directory. Linux RC10 resolves each component
descriptor-relatively with `O_NOFOLLOW` before exclusive creation. Positive,
negative and race regressions are included. Stable v1 still blocked by
supported Go/analyzers, CI/native platform evidence, permanent module identity,
publisher provenance and ProofGraph adapter completeness. No change to v1
Security IR/results or trusted evidence claims.

# RC9 — Linux output-directory race hardening

Linux output files now use a pinned final parent directory descriptor, `openat`
and `O_NOFOLLOW` to reject symlink substitution. The existing scope, evidence
contracts and valid JSON are unchanged. This fix addresses one reproducible
local release-candidate vulnerability in RC8; it does **not** authenticate the
actor controlling the input or defeat privileged ancestor/mount replacement.
Supported Go, Staticcheck, Govulncheck, CI, native macOS/Windows tests, module
identity and publisher signatures remain OPEN/BLOCKED. Do not ship stable v1.
