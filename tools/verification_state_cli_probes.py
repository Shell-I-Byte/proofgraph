#!/usr/bin/env python3
"""Independent, offline CLI checks for versioned IR verification presence."""
import copy
import json
import pathlib
import subprocess
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
BINARY = pathlib.Path(sys.argv[1]).resolve() if len(sys.argv) == 2 else None


def main():
    if BINARY is None or not BINARY.is_file():
        raise ValueError("pass compiled ProofGraph binary")
    source = json.loads((ROOT / 'testdata/lab.json').read_text())
    cases = [('valid original', None, 0)]
    for state in ('hypothesis', 'observed', 'disproven', 'inferred'):
        for value, label in ((None, 'null'), ('', 'empty')):
            data = copy.deepcopy(source)
            edge = next(x for x in data['edges'] if x['state'] == 'hypothesis')
            edge['state'] = state
            edge['verified_by'] = value
            cases.append((f'{state} verification {label}', data, 2))
    confirmed = copy.deepcopy(source)
    next(x for x in confirmed['edges'] if x['state'] == 'confirmed')['verified_by'] = None
    cases.append(('confirmed verification null', confirmed, 2))
    with tempfile.TemporaryDirectory(prefix='pg094_') as tmp:
        path = pathlib.Path(tmp) / 'input.json'
        for name, data, expected_exit in cases:
            path.write_text(json.dumps(source if data is None else data))
            p = subprocess.run([str(BINARY), 'analyze', '--input', str(path)], capture_output=True, timeout=12)
            if p.returncode != expected_exit:
                raise AssertionError(f'{name}: expected exit {expected_exit}, received {p.returncode}')
            if b'private token' in p.stdout or b'private token' in p.stderr:
                raise AssertionError(f'{name}: unexpected secret in output')
            print(f'PASS {name}: exit={p.returncode}')
    print(f'PASS {len(cases)}/{len(cases)} independent CLI cases')


if __name__ == '__main__':
    try:
        main()
    except (AssertionError, ValueError, subprocess.TimeoutExpired) as exc:
        print(f'FAIL {exc}', file=sys.stderr)
        sys.exit(1)
