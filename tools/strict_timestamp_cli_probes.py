#!/usr/bin/env python3
"""Independent offline CLI acceptance for RFC3339 temporal authorization gates."""
import argparse
import hashlib
import json
import pathlib
import subprocess
import sys
import tempfile

BASE = pathlib.Path(__file__).resolve().parents[1] / 'testdata/lab.json'

NEGATIVE = [
    ('snapshot_hour_width', ('snapshot',), '2026-10-09T6:00:00Z'),
    ('snapshot_decimal_comma', ('snapshot',), '2026-10-09T06:00:00,125Z'),
    ('snapshot_offset_hour_24', ('snapshot',), '2026-10-09T06:00:00+24:00'),
    ('snapshot_offset_minute_60', ('snapshot',), '2026-10-09T06:00:00+00:60'),
    ('snapshot_negative_offset_hour_24', ('snapshot',), '2026-10-09T06:00:00-24:00'),
    ('authorization_start_offset_minute_60', ('authorization', 'valid_from'), '2026-10-01T00:00:00+01:60'),
    ('authorization_end_offset_hour_24', ('authorization', 'valid_until'), '2026-10-31T00:00:00+24:00'),
    ('edge_observed_hour_width', ('edges', 0, 'observed_at'), '2026-10-08T0:00:00Z'),
    ('edge_observed_decimal_comma', ('edges', 0, 'observed_at'), '2026-10-08T00:00:00,500Z'),
    ('edge_observed_offset_minute_60', ('edges', 0, 'observed_at'), '2026-10-08T00:00:00+01:60'),
]
POSITIVE = [
    ('canonical_utc', '2026-10-09T06:00:00Z'),
    ('dot_fraction', '2026-10-09T06:00:00.125Z'),
    ('positive_offset', '2026-10-09T06:00:00+01:30'),
    ('negative_offset', '2026-10-09T06:00:00-01:30'),
    ('max_zone_offset', '2026-10-09T06:00:00+23:59'),
]

def put(data, keypath, value):
    ref = data
    for key in keypath[:-1]:
        ref = ref[key]
    ref[keypath[-1]] = value

def run(*args):
    return subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=15)

def ensure(condition, name, extra=''):
    if not condition:
        raise AssertionError(f'{name}: {extra}')

def main(binary):
    source = json.loads(BASE.read_text())
    successes = 0
    with tempfile.TemporaryDirectory(prefix='proofgraph-time-') as temp:
        root = pathlib.Path(temp)
        for name, path, value in NEGATIVE:
            x = json.loads(json.dumps(source))
            put(x, path, value)
            input_path = root / f'{name}.json'
            input_path.write_text(json.dumps(x))
            call = run(str(binary), 'analyze', '--input', str(input_path))
            ensure(call.returncode == 2, name, f'expected exit2; got {call.returncode} stdout={call.stdout[:100]!r} stderr={call.stderr[:100]!r}')
            successes += 1
        for name, value in POSITIVE:
            x = json.loads(json.dumps(source))
            put(x, ('snapshot',), value)
            input_path = root / f'{name}.json'
            input_path.write_text(json.dumps(x))
            call = run(str(binary), 'analyze', '--input', str(input_path))
            ensure(call.returncode == 0, name, f'expected success; got {call.returncode} stderr={call.stderr[:100]!r}')
            report_path = root / f'{name}-report.json'
            report_path.write_bytes(call.stdout)
            checked = run(str(binary), 'verify', '--input', str(report_path))
            ensure(checked.returncode == 0, name + '-verify', f'exit {checked.returncode}')
            replay = run(str(binary), 'replay', '--input', str(input_path), '--report', str(report_path))
            ensure(replay.returncode == 0, name + '-replay', f'exit {replay.returncode}')
            successes += 3
        # A forged-but-self-rehashed malformed report must fail before digest
        # validation. For this synthetic fixture, Python's JSON compact form
        # reproduces the Go stdlib's compact encoding byte-for-byte.
        source_path = root / 'original.json'
        source_path.write_text(json.dumps(source))
        orig = run(str(binary), 'analyze', '--input', str(source_path))
        ensure(orig.returncode == 0, 'baseline')
        for name, value in [('hour-width', '2026-10-09T6:00:00Z'),
                            ('fraction-comma','2026-10-09T06:00:00,125Z'),
                            ('offset24','2026-10-09T06:00:00+24:00'),
                            ('offset-minute60','2026-10-09T06:00:00+00:60')]:
            report = json.loads(orig.stdout)
            report['snapshot'] = value
            report['sha256'] = ''
            packed = json.dumps(report, separators=(',', ':'), ensure_ascii=False).encode('utf-8')
            report['sha256'] = 'sha256:' + hashlib.sha256(packed).hexdigest()
            p = root / ('forged-' + name + '.json')
            p.write_text(json.dumps(report))
            result = run(str(binary), 'verify', '--input', str(p))
            ensure(result.returncode == 3, name + '-self-rehashed-verifier', f'expected exit3; got {result.returncode}')
            successes += 1
        ensure(b'c3ludGhldGljIGV2aWRlbmNl' not in orig.stdout, 'privacy-base64-leak')
        ensure(b'synthetic evidence' not in orig.stdout, 'privacy-raw-leak')
        successes += 2
    print(f'PASS {successes}/{successes} offline RFC3339, replay, tampering, privacy CLI assertions')

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('binary', type=pathlib.Path)
    args = parser.parse_args()
    try:
        main(args.binary.resolve())
    except (AssertionError, subprocess.TimeoutExpired, OSError, ValueError) as ex:
        print(f'FAIL {ex}', file=sys.stderr)
        sys.exit(1)
