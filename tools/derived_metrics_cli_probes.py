#!/usr/bin/env python3
"""Offline, synthetic positive/negative/falsification probe for derived result/v1 semantics."""
import copy
import hashlib
import json
import subprocess
import sys
import tempfile
from pathlib import Path

BIN = str(Path(sys.argv[1]).resolve()) if len(sys.argv) > 1 else None
ROOT = Path(__file__).resolve().parents[1]
if not BIN:
    raise SystemExit('usage: derived_metrics_cli_probes.py /absolute/path/to/proofgraph')

def call(*args):
    return subprocess.run([BIN, *map(str, args)], text=True, capture_output=True, timeout=8)

def write_case(path, report, do_rehash=True):
    r=copy.deepcopy(report)
    if do_rehash:
        r['sha256']=''
        canonical=json.dumps(r, separators=(',', ':'), ensure_ascii=False).encode('utf8')
        r['sha256']='sha256:'+hashlib.sha256(canonical).hexdigest()
    path.write_text(json.dumps(r, ensure_ascii=False), encoding='utf8')

cases={
'unknown_graph_cut_edge':lambda x:x.__setitem__('graph_cuts',[{'removed_edge':'ghost-edge','disconnected_targets':1}]),
'nonconfirmed_graph_cut_edge':lambda x:x.__setitem__('graph_cuts',[{'removed_edge':'edge3','disconnected_targets':1}]),
'overstated_graph_cut_impact':lambda x:x.__setitem__('graph_cuts',[{'removed_edge':'edge2','disconnected_targets':999}]),
'unknown_information_gain':lambda x:x.__setitem__('information_gain',[{'edge_id':'ghost-edge','possible_new_paths':1}]),
'confirmed_information_gain':lambda x:x.__setitem__('information_gain',[{'edge_id':'edge1','possible_new_paths':1}]),
'negative_blast_radius':lambda x:x['blast_radius'].__setitem__('origin',-1),
'unknown_blast_radius_node':lambda x:x['blast_radius'].__setitem__('ghost-node',1),
'bogus_contradiction':lambda x:x.__setitem__('contradictions',[['edge1','edge3']]),
'missing_negative_evidence':lambda x:x.__setitem__('negative_evidence',[]),
'missing_hypothesis_link':lambda x:x.__setitem__('missing_links',[]),
'missing_contradiction':lambda x:x.__setitem__('contradictions',[]),
}
with tempfile.TemporaryDirectory() as td:
    td=Path(td); output=td/'baseline.json'
    r=call('analyze','-input',ROOT/'testdata/lab.json','-output',output)
    if r.returncode: raise RuntimeError(f'analyze failed: exit={r.returncode} {r.stderr[:200]}')
    baseline=json.loads(output.read_text())
    if call('verify','-input',output).returncode!=0: raise RuntimeError('valid baseline rejected')
    if call('replay','-input',ROOT/'testdata/lab.json','-report',output).returncode!=0: raise RuntimeError('valid replay rejected')
    count=3
    for name,mutate in cases.items():
        forged=copy.deepcopy(baseline);mutate(forged)
        path=td/(name+'.json');write_case(path,forged)
        result=call('verify','-input',path)
        if result.returncode!=3:
            raise AssertionError(f'{name} expected rejection exit3, got exit{result.returncode}, stdout={result.stdout!r}')
        print('PASS rejected rehashed:', name)
        count+=1
    altered=copy.deepcopy(baseline);altered['scope_id']='bad-scope'
    path=td/'tamper_without_rehash.json';write_case(path,altered,False)
    if call('verify','-input',path).returncode!=3:raise AssertionError('raw tamper not rejected')
    count+=1
    print(f'PASS {count}/{count} synthetic CLI controls (positive, rehashed negative, tampered)')
