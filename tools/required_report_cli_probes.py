#!/usr/bin/env python3
"""Independent local report-shape tampering probes for BUG-PG-108-001."""
import argparse
import hashlib
import json
import subprocess
import tempfile
from pathlib import Path

REQUIRED = ["nodes", "evidence", "findings", "attack_paths", "negative_evidence",
            "contradictions", "missing_links", "information_gain", "blast_radius",
            "graph_cuts", "limitations"]

def run(binary, *args):
    return subprocess.run([binary, *args], text=True, capture_output=True, timeout=15)

def main():
    p = argparse.ArgumentParser()
    p.add_argument('binary')
    p.add_argument('--fixture', default='testdata/lab.json')
    args = p.parse_args()
    exe = str(Path(args.binary).resolve())
    fixture = str(Path(args.fixture).resolve())
    assertions = 0
    with tempfile.TemporaryDirectory() as td:
        good = Path(td) / 'good.json'
        result = run(exe, 'analyze', '--input', fixture, '--output', str(good))
        assert result.returncode == 0, (result.returncode, result.stderr)
        assertions += 1
        assert run(exe, 'verify', '--input', str(good)).returncode == 0
        assertions += 1
        assert run(exe, 'replay', '--input', fixture, '--report', str(good)).returncode == 0
        assertions += 1
        obj = json.loads(good.read_bytes())
        for name in REQUIRED:
            # Rehash the document as Go would see it: the missing required
            # slice/map becomes null in its zero-value struct representation.
            source = dict(obj)
            source[name] = None
            source['sha256'] = ''
            stable = json.dumps(source, separators=(',', ':'), ensure_ascii=False).encode()
            forged = dict(obj)
            forged.pop(name)
            forged['sha256'] = 'sha256:' + hashlib.sha256(stable).hexdigest()
            candidate = Path(td) / f'missing-{name}.json'
            candidate.write_text(json.dumps(forged, separators=(',', ':')))
            outcome = run(exe, 'verify', '--input', str(candidate))
            assert outcome.returncode == 3, (name, outcome.returncode, outcome.stdout, outcome.stderr)
            assertions += 1
            replay = run(exe, 'replay', '--input', fixture, '--report', str(candidate))
            assert replay.returncode == 3, (name, replay.returncode, replay.stdout, replay.stderr)
            assertions += 1
        changed = dict(obj); changed['scope_id']='tampered'
        candidate=Path(td)/'tampered.json'; candidate.write_text(json.dumps(changed))
        assert run(exe, 'verify', '--input', str(candidate)).returncode == 3
        assertions += 1
    print(f'PASS {assertions}/{assertions} independent CLI assertions')

if __name__ == '__main__':
    main()
