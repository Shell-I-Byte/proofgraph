#!/usr/bin/env python3
"""Independent local falsification of cross-field ProofGraph result inconsistencies.

These are consistency checks, never proof of publisher identity or genuine
human verification. All targets are local fixture files; no network traffic.
"""
import copy
import hashlib
import json
import pathlib
import subprocess
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[1]


def invoke(binary, *args):
    return subprocess.run([str(binary), *map(str, args)], capture_output=True, timeout=15)


def main():
    if len(sys.argv) != 2:
        raise SystemExit('usage: result_consistency_cli_probes.py /path/to/proofgraph')
    exe = pathlib.Path(sys.argv[1]).resolve()
    checked = 0
    with tempfile.TemporaryDirectory(prefix='proofgraph-consistency-') as td:
        root = pathlib.Path(td)
        source = ROOT / 'testdata/lab.json'
        report = root / 'valid.json'
        a = invoke(exe, 'analyze', '--input', source, '--output', report)
        assert a.returncode == 0, ('analyze', a.stderr)
        v = invoke(exe, 'verify', '--input', report)
        assert v.returncode == 0, ('valid verify', v.stderr)
        checked += 1
        replay = invoke(exe, 'replay', '--input', source, '--report', report)
        assert replay.returncode == 0, ('valid replay', replay.stderr)
        checked += 1
        baseline = json.loads(report.read_text())
        changes = {
            'cross-scope-node': lambda r: r['nodes'][0].__setitem__('scope_id', 'other-scope'),
            'unknown-finding-state': lambda r: r['findings'][0].__setitem__('state', 'secretly_confirmed'),
            'false-human-verification': lambda r: next(f for f in r['findings'] if f['state']=='hypothesis').__setitem__('human_assertion', True),
            'unknown-evidence-in-finding': lambda r: r['findings'][0].__setitem__('evidence_ids', ['ghost-ev']),
            'ghost-edge-in-attack-path': lambda r: r['attack_paths'][0].__setitem__('edge_ids', ['ghost-edge']),
            'confirmed-edge-as-negative': lambda r: r.__setitem__('negative_evidence', ['edge1']),
        }
        for name, mutation in changes.items():
            obj = copy.deepcopy(baseline)
            mutation(obj)
            obj['sha256'] = ''
            unsealed = json.dumps(obj, ensure_ascii=False, separators=(',', ':')).encode('utf-8')
            obj['sha256'] = 'sha256:' + hashlib.sha256(unsealed).hexdigest()
            path = root / (name + '.json')
            path.write_text(json.dumps(obj, ensure_ascii=False, separators=(',', ':'))+'\n')
            outcome = invoke(exe, 'verify', '--input', path)
            assert outcome.returncode == 3, (name, outcome.returncode, outcome.stdout, outcome.stderr)
            checked += 1
    print(f'PASS {checked}/{checked} independent synthetic consistency assertions')


if __name__ == '__main__':
    try:
        main()
    except (AssertionError, OSError, subprocess.TimeoutExpired) as exc:
        print('FAIL', repr(exc), file=sys.stderr)
        sys.exit(1)
