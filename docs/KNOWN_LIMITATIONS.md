> Current public release and Mac validation status: [README](../README.md) and [MACOS_QUALIFICATION.md](MACOS_QUALIFICATION.md). Historical run references in this technical document do not describe the current publication status.

- RC12 rejects Go's non-RFC3339 date/time extensions; valid output bytes remain unchanged, but previously accepted invalid timestamp source records are now refused. Lower-case `t`/`z` remain unsupported by this project's uppercase-profile parser, as permitted by RFC 3339 section 5.6.
- Native Linux ARM64, macOS ARM64 and Windows AMD64 CI jobs are configured but have **not** executed; cross-compilation is not native qualification.
# Known limitations (release gates)

- Go 1.23.2 is unsupported and is the only natively executed Go toolchain in the current local runtime.
- Go 1.26.9/1.27.2, Staticcheck v0.8.1, Govulncheck v1.9.0, GitHub Actions and native macOS/Windows have not yet been proven green.
- Repository module path is provisional (`example.com/...`).
- Human identity and authorization are self-asserted and **not cryptographically verified**.
- No complete RFC 8785 JSON canonicalization; deterministic Go JSON serialization is used for a fixed schema.
- No genuine temporal comparison across multiple snapshots, cryptographic signatures, signed replay log, persistent storage, multi-user authorization or AI adapter.
- Attack paths are one shortest claimed-confirmed route for each entry-target pair, max eight edges. Cycles and alternate equal-length paths are not enumerated. Graph cuts are reachability counterfactuals, not global minimum cuts.
- File/path replacement is checked before and after opening. On Linux, the RC11 input and RC10 output path walkers use descriptor-relative `openat` for ancestor components; this does not prevent privileged mounts or all parent rename attacks. On non-Linux platforms, input/output ancestor guarantees remain UNTESTED and Windows opens require native adversarial validation. Avoid attacker-writable parent directories.
- Crosscompiled binaries have not been executed on macOS/Windows.

- Run069 exact JSON member-name checks prevent legacy `encoding/json` casefolding; this is not full RFC 8785 canonicalization, nor any cryptographic identity check.

- Run094: IR v1 now consistently rejects explicit `null` and verification properties on non-confirmed edges. That closes a schema-shape discrepancy, not cryptographic identity authentication.
- Historical edge `observed_at` preceding authorization `valid_from` is allowed under the currently published snapshot-only interval policy; deciding whether historical collection evidence should instead require separate provenance is an explicit future versioned-policy design gate, not silently changed in rc4.

- RC5 adds strict presence checks for required v1 JSON report properties; this
  does **not** turn unkeyed report SHA-256 into trustworthy publisher identity.
  An attacker able to forge all data and recompute the digest still requires
  separate source provenance, signature and human verification gates.

- RC6: The result verifier now checks schema-constrained nested node/evidence/reference members even when a caller recomputes a valid report digest. This **still is not an authenticated signature**: a forged but schema-valid report could retain an internally consistent checksum. Only replay against a trusted original input binds the result to those input bytes, and it does not authenticate the source/author.

- RC7: Result integrity checks detect specific cross-field inconsistencies but cannot prove completeness or authenticity. A self-rehashed, internally consistent forged result may pass `verify`. The `replay` command checks derivation against the supplied source only; signatures, trusted publisher identities and independently authenticated human attestations remain OUT OF SCOPE/OPEN.

- RC8 verifies structural consistency and boundedness of derived impact fields but cannot recompute their true reachability counts without the original input. `replay` recomputes against supplied input; an untrusted author could forge BOTH source and report. These numbers are not independently authenticated factual, risk or remediation impact assessments.

- RC10 Linux output directory-chain traversal rejects symlinked ancestors and `..`
  components and creates the report from a pinned directory descriptor. It
  does not prohibit privileged mount changes, directory moves, namespace tricks
  or hostile filesystem behavior. The macOS/Windows fallback has not been
  hardened or native-tested against equivalent races.

- RC11: Linux input ancestors now use no-follow descriptor-relative resolution and refuse lexical `..` paths. Native macOS/Windows input-ancestor races, privileged mounts, and untrusted directory renames remain unqualified.
