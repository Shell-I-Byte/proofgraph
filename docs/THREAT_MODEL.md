> Current public release and Mac validation status: [README](../README.md) and [MACOS_QUALIFICATION.md](MACOS_QUALIFICATION.md). Historical run references in this technical document do not describe the current publication status.

# Architecture and threat model

## Trust boundaries

1. The source JSON can be fully malicious. The parser caps size, requires UTF-8, rejects duplicate keys, unknown fields and trailing data, validates timestamps and strict IDs. It hashes decoded evidence bytes but does not independently establish whether a source was truly obtained lawfully.
2. The local operator controls input files and the directory for output. The CLI refuses file symlinks and overwrite, uses mode 0600, and does not embed raw source bytes in results. The CLI compares the opened file inode to the initial and subsequent path checks; attacker-writable parent-directory rename races remain a documented limitation.
3. `verified_by` is not cryptographically authenticated; asserted confirmations are not independently factual. Never treat a path as a tested exploit path.
4. External AI is not in the trusted computing base. There is no AI code or interface in RC1. Future adapters must not mutate provenance, authorization or confirmation states.
5. Report digest SHA-256 detects accidental or uninformed tampering; it is unkeyed, not a signature. Replay is deterministic only for the same source bytes and graph implementation; schema migrations need separately defined semantics.

## Runtime architecture

`cmd/proofgraph` CLI -> `internal/graph` strict parser/scope validator -> evidence hashing -> typed graph analyzer -> deterministic JSON renderer -> integrity/replay validator. No external libraries, network functions, plugin loading or shell execution. The graph algorithm uses bounded BFS over confirmed edges, with graph-cut and information-gain counterfactual simulation.

## Resource assumptions

Max 8 MiB JSON input; decoded evidence bounded per item and in aggregate, max 256 nodes, max 512 edges, max four entries/targets. Graph traversal bounded by one BFS per origin, rather than combinatorial path enumeration. No production performance benchmark is claimed.

## RC9 local filesystem race boundary

A local attacker replacing the *final* output parent with a symlink could in
RC8 redirect the report outside the checked parent. RC9 pins the Linux parent
inode and creates the output relative to that descriptor. The parent directory
precheck is race-detecting but not proof of containment against ancestor
mutations; treat hostile/mount-controlled paths as out of trust scope.

## RC10 output-ancestor symlink exchange boundary

The full Linux output directory chain is walked using no-follow directory
file descriptors, starting from `/` or the process cwd. Unlike RC9, no
intermediate pathname component can be replaced by a symlink and followed
during the write. This prevents the reproduced ancestor redirect while leaving
mountpoints, privileged attackers, mutable directory placement, non-Linux
implementation and **input-file** ancestor confinement outside the guarantee.

## RC11 input-ancestor boundary

A local attacker could provide a symlink in a parent directory while keeping the final input filename regular. RC10 would accept that path, circumventing its no-symlink contract. Linux RC11 uses `openat` from pinned descriptors and `O_NOFOLLOW` on each component for input. Paths containing lexical `..` are rejected. This does not prove trusted evidence provenance, prohibit privileged mounts/renames or extend to native macOS/Windows.
