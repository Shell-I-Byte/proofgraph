#!/usr/bin/env python3
"""Linux-only synthetic test: input ancestor symlink/dotdot and rename-exchange.
Only local JSON files are used; no network, external target or privileged mount.
"""
import argparse
import base64
import ctypes
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import threading

p = argparse.ArgumentParser()
p.add_argument('binary')
p.add_argument('--count', type=int, default=120)
a = p.parse_args()
binary = str(Path(a.binary).resolve())
fixture = Path(__file__).resolve().parents[1] / 'testdata' / 'lab.json'
original = fixture.read_bytes()
external = json.loads(original)
external['evidence'][0]['data_base64'] = base64.b64encode(b'different-synthetic-outside-evidence').decode()
external_raw = json.dumps(external, separators=(',', ':')).encode()
outside_hash = 'sha256:' + hashlib.sha256(external_raw).hexdigest()

with tempfile.TemporaryDirectory(prefix='proofgraph-input-ancestor-') as name:
    root = Path(name)
    trusted = root / 'trusted'
    outside = root / 'outside'
    trusted.mkdir()
    outside.mkdir()
    (trusted / 'input.json').write_bytes(original)
    (outside / 'input.json').write_bytes(external_raw)
    alias = root / 'alias'
    alias.symlink_to(outside, target_is_directory=True)

    def invoke(path):
        return subprocess.run([binary, 'analyze', '--input', str(path)],
                              capture_output=True, timeout=5)

    good = invoke(trusted / 'input.json')
    assert good.returncode == 0, ('valid input rejected', good.stderr)
    assert json.loads(good.stdout)['schema'] == 'proofgraph.result/v1'
    for label, path in [('ancestor_symlink', alias / 'input.json'),
                        ('lexical_dotdot', str(trusted) + '/../outside/input.json')]:
        result = invoke(path)
        assert result.returncode == 4, (label, result.returncode, result.stderr)
    direct = root / 'input-symlink.json'
    direct.symlink_to(outside / 'input.json')
    assert invoke(direct).returncode == 4

    # Two pathname positions atomically swap between a real directory and a
    # symlink to a different synthetically generated evidence file.
    alternate = root / 'alternate'
    alternate.symlink_to(outside, target_is_directory=True)
    libc = ctypes.CDLL(None, use_errno=True)
    renameat2 = libc.renameat2
    renameat2.argtypes = [ctypes.c_int, ctypes.c_char_p,
                          ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
    renameat2.restype = ctypes.c_int
    stop = threading.Event()
    errors = []
    swaps = [0]
    def swaptree():
        while not stop.is_set():
            if renameat2(-100, os.fsencode(trusted), -100,
                         os.fsencode(alternate), 2) != 0:
                errors.append(ctypes.get_errno())
                break
            swaps[0] += 1

    thread = threading.Thread(target=swaptree, daemon=True)
    thread.start()
    counts = {'pass_original': 0, 'rejected': 0, 'outside_read': 0, 'unexpected': 0}
    try:
        for _ in range(a.count):
            r = invoke(trusted / 'input.json')
            if r.returncode == 0:
                try:
                    parsed = json.loads(r.stdout)
                    if parsed['input_sha256'] == outside_hash:
                        counts['outside_read'] += 1
                    elif parsed['input_sha256'] == 'sha256:' + hashlib.sha256(original).hexdigest():
                        counts['pass_original'] += 1
                    else:
                        counts['unexpected'] += 1
                except (KeyError, ValueError):
                    counts['unexpected'] += 1
            elif r.returncode == 4:
                counts['rejected'] += 1
            else:
                counts['unexpected'] += 1
    finally:
        stop.set()
        thread.join(timeout=5)

    payload = {'attempts': a.count, 'swaps': swaps[0], 'counts': counts,
               'swap_errors': errors, 'static_controls': '4/4 PASS'}
    print(json.dumps(payload, sort_keys=True))
    if errors or counts['outside_read'] or counts['unexpected'] or sum(counts.values()) != a.count:
        raise SystemExit(1)
