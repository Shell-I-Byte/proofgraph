# ProofGraph

I’m publishing ProofGraph as a bounded evidence-graph CLI. It brings observations, relationships, and verification states into one inspectable result, with separate verification and replay commands.

Analyze, verify, and replay bounded evidence graphs with explicit verification states.

## Get started

Download the **macOS ARM64** archive from [Releases](https://github.com/Shell-I-Byte/proofgraph/releases), or build from source with a supported Go toolchain. This release was tested with **Go 1.27.2 and Go 1.26.9** on native Apple Silicon macOS. I recommend Go 1.27.2.

```sh
git clone https://github.com/Shell-I-Byte/proofgraph.git
cd proofgraph
go build -trimpath -buildvcs=false -o proofgraph ./cmd/proofgraph
```

Try the included example:

```sh
./proofgraph analyze --input examples/public/proofgraph.json --output report.json
./proofgraph verify --input report.json
./proofgraph replay --input examples/public/proofgraph.json --report report.json
```

The bundled examples are synthetic.

## What I’m shipping

- Source, tests, schemas, technical documentation, and synthetic examples.
- A locally built and tested macOS ARM64 binary, with SHA-256 checksums.
- Strict input handling and explicit limits rather than an automatic vulnerability verdict.

This is **v0.1.0-rc12**, a release candidate. The [qualification record](docs/MACOS_QUALIFICATION.md) explains exactly what was tested and how the public source snapshot relates to the local qualification. Public binaries are rebuilt from this repository’s canonical Go module path and tested again before release.

## Validation

```sh
go test -count=1 ./...
go test -race -count=1 ./...
go test -shuffle=on -count=2 ./...
go vet ./...
go mod verify
go run honnef.co/go/tools/cmd/staticcheck@v0.8.2 ./...
go run golang.org/x/vuln/cmd/govulncheck@v1.9.0 ./...
```

The native Mac checks pass, including positive and negative CLI cases. Historical local results are not GitHub Actions results. Workflow configuration is included; hosted Actions is disabled for this initial publication. No Linux or Windows native release is claimed here.

## Boundaries

This release does not implement signed replay, persistent storage, multi-user authorization, a full temporal-diff engine, or AI adapters.

Use physical directory paths for hardened Mac file operations: symlinked parents are rejected. The protection covers the tested symlink substitutions; it is not a filesystem snapshot and does not defend against privileged mount changes or a compromised user account. Mac binaries are ad-hoc linker-signed, **not Developer ID signed or notarized**. Do not disable operating-system protections to run them.

Please read [SECURITY.md](SECURITY.md) and the technical documentation in `docs/` before using real data. The bundled dependency notices and existing copyright notices are retained.

## License

MIT. See [LICENSE](LICENSE).
