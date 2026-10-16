> Current public release and Mac validation status: [README](../README.md) and [MACOS_QUALIFICATION.md](MACOS_QUALIFICATION.md). Historical run references in this technical document do not describe the current publication status.

# Scope and authorization contract

`authorization.scope_id` is mandatory and exactly matches every node's scope. `authorization.granted_by` is mandatory, as are RFC3339 `valid_from` and `valid_until` dates around the chosen `snapshot`. Edge observations after the snapshot are rejected. There are no remote input URLs or scanning options. This protects against accidental mixed-scope analysis, but **does not authenticate the grantor**. A malicious or untrusted author can forge the input. Operators must retain signed permission or contract evidence outside ProofGraph and must only submit evidence they have permission to process.
