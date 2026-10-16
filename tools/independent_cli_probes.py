#!/usr/bin/env python3
"""Independent positive/negative CLI checks. Uses local synthetic JSON only."""
import base64
import copy
import hashlib
import json
import os
import pathlib
import subprocess
import sys
import tempfile
from concurrent.futures import ThreadPoolExecutor

ROOT=pathlib.Path(__file__).resolve().parents[1]
GO=os.environ.get('GO','go')
TESTS=0

def check(cond,label):
 global TESTS
 TESTS+=1
 if not cond: raise AssertionError(label)

def run(binary,*args):
 return subprocess.run([str(binary),*map(str,args)],stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=15)

def dump(path,obj): path.write_text(json.dumps(obj,ensure_ascii=False,sort_keys=True))

def main():
 with tempfile.TemporaryDirectory(prefix='proofgraph-probes-') as td:
  d=pathlib.Path(td);binary=d/'proofgraph'
  env=dict(os.environ,GOPROXY='off',GOSUMDB='off',GOTOOLCHAIN='local')
  subprocess.run([GO,'build','-o',str(binary),'./cmd/proofgraph'],cwd=ROOT,env=env,check=True,timeout=120)
  source=ROOT/'testdata/lab.json';data=json.loads(source.read_text());r=run(binary,'version');check(r.returncode==0 and b'v0.1.0-rc12' in r.stdout,'version')
  report=d/'report.json';r=run(binary,'analyze','--input',source,'--output',report);check(r.returncode==0,'valid analyze')
  doc=json.loads(report.read_text());check(doc['schema']=='proofgraph.result/v1','schema')
  check(len(doc['attack_paths'])==1 and doc['attack_paths'][0]['to']=='vault','bounded confirmed paths')
  check(len(doc['negative_evidence'])==1 and len(doc['contradictions'])==1,'contradiction and negative evidence')
  check(len(doc['graph_cuts'])==2 and len(doc['information_gain'])==1,'graph counterfactuals')
  check(doc['information_gain'][0]['possible_new_paths']==1,'conservative information gain')
  check('synthetic evidence' not in report.read_text() and 'data_base64' not in report.read_text(),'raw evidence redaction')
  check(run(binary,'verify','--input',report).returncode==0,'integrity verify')
  check(run(binary,'replay','--input',source,'--report',report).returncode==0,'deterministic replay')
  check(run(binary,'analyze','--input',source,'--output',report).returncode==4,'existing output no overwrite')
  r=run(binary,'analyze','--input',source);check(r.returncode==0 and r.stdout.startswith(b'{'),'stdout analyze')
  check(r.stdout.rstrip(b'\n')==report.read_bytes().rstrip(b'\n'),'byte identical output')
  check(run(binary,'verify','--input',source).returncode==3,'invalid report rejected')
  wrong=d/'tampered.json';wrong.write_bytes(report.read_bytes().replace(b'"lab-1"',b'"lab-2"',1));check(run(binary,'verify','--input',wrong).returncode==3,'tamper detected')
  mutated=copy.deepcopy(data);mutated['nodes'][0]['id']='new-origin';new=d/'modified.json';dump(new,mutated);check(run(binary,'replay','--input',new,'--report',report).returncode!=0,'modified source fails replay')
  mutants={
   'authorization-expired':lambda v:v['authorization'].__setitem__('valid_until','2026-10-08T00:00:00Z'),
   'out-of-scope':lambda v:v['nodes'][0].__setitem__('scope_id','other'),
   'unknown-node':lambda v:v['edges'][0].__setitem__('to','not-in-graph'),
   'no-evidence':lambda v:v['edges'][0].__setitem__('evidence_ids',[]),
   'unverified-confirmed':lambda v:v['edges'][0].pop('verified_by'),
   'AI-verification':lambda v:v['edges'][2].__setitem__('verified_by','ai'),
   'invalid-state':lambda v:v['edges'][0].__setitem__('state','rooted'),
   'bad-evidence-base64':lambda v:v['evidence'][0].__setitem__('data_base64','!!!'),
   'bad-node-id':lambda v:v['nodes'][0].__setitem__('id','origin\nspoof'),
   'extra-field':lambda v:v.__setitem__('new_field',{}),
   'future-edge':lambda v:v['edges'][0].__setitem__('observed_at','2027-01-01T00:00:00Z'),
   'bad-scope-grantor':lambda v:v['authorization'].__setitem__('granted_by',''),
   'wrong-schema':lambda v:v.__setitem__('schema','proofgraph.security-ir/v2'),
   'duplicate-edge':lambda v:v['edges'].append(copy.deepcopy(v['edges'][0])),
   'duplicate-node':lambda v:v['nodes'].append(copy.deepcopy(v['nodes'][0])),
   'unknown-entry':lambda v:v['entry_nodes'].append('foreign'),
   'too-many-entries':lambda v:v.__setitem__('entry_nodes',['origin','web','vault','vault2','origin']),
  }
  for name,change in mutants.items():
   obj=copy.deepcopy(data);change(obj);p=d/(name+'.json');dump(p,obj);r=run(binary,'analyze','--input',p)
   check(r.returncode==2 and len(r.stderr)<256,name)
  invalid={
   'duplicate-key':b'{"schema":"a","schema":"b"}',
   'duplicate-nested':source.read_bytes().replace(b'"scope_id":"lab-1"',b'"scope_id":"lab-1","scope_id":"other"',1),
   'trailing-document':source.read_bytes()+b' {}',
   'invalid-utf8':source.read_bytes()+b'\xff',
   'null':b'null',
   'invalid-json':b'{',
   'oversized':b'A'*((8<<20)+1),
  }
  for name,raw in invalid.items():
   p=d/(name+'.json');p.write_bytes(raw);r=run(binary,'analyze','--input',p)
   check(r.returncode in (2,4),name)
  # Run-069 confirmation/authorization case confusion falsification controls.
  case_mutants={
   'case-root':lambda v:v.__setitem__('Schema','proofgraph.security-ir/v1'),
   'case-auth-scope':lambda v:v['authorization'].__setitem__('Scope_ID','lab-1'),
   'case-auth-grant':lambda v:v['authorization'].__setitem__('Granted_By','attacker'),
   'case-edge-state':lambda v:v['edges'][2].__setitem__('State','confirmed'),
   'case-edge-verification':lambda v:v['edges'][2].__setitem__('Verified_By','AI'),
   'case-node-type':lambda v:v['nodes'][0].__setitem__('Type','identity'),
   'case-evidence-data':lambda v:v['evidence'][0].__setitem__('Data_Base64','c3ludGhldGljIGV2aWRlbmNl'),
  }
  for name,change in case_mutants.items():
   obj=copy.deepcopy(data);change(obj);p=d/(name+'.json');dump(p,obj)
   r=run(binary,'analyze','--input',p)
   check(r.returncode==2 and not r.stdout and len(r.stderr)<256,name)
  # Positive negative-control: correctly cased, authorized, attested extra edge.
  valid=copy.deepcopy(data);valid['edges'][2]['state']='confirmed';valid['edges'][2]['verified_by']='analyst'
  p=d/'valid-confirmed.json';dump(p,valid);r=run(binary,'analyze','--input',p)
  check(r.returncode==0 and any(x['to']=='vault2' for x in json.loads(r.stdout)['attack_paths']),'legitimate confirmed edge remains functional')
  altered=d/'case-report.json';altered.write_bytes(report.read_bytes().replace(b'"scope_id":',b'"Scope_ID":',1))
  check(run(binary,'verify','--input',altered).returncode==3,'report case variant refused')
  check(run(binary,'replay','--input',source,'--report',altered).returncode==3,'replay case variant refused')
  x=d/'sym';x.symlink_to(source);check(run(binary,'analyze','--input',x).returncode==4,'input symlink refusal')
  check(run(binary,'analyze','--input',d).returncode==4,'input directory refusal')
  check(run(binary,'analyze','--input',source,'--output',x).returncode==4,'output symlink refusal')
  hostile='--fake\x1b[31m\nLOG-INJECTED'
  r=run(binary,'analyze',hostile);check(r.returncode==2 and b'LOG-INJECTED' not in r.stderr,'flag error sanitized')
  # Concurrent independently launched processes must agree byte-for-byte.
  def invocation(_):return run(binary,'analyze','--input',source)
  with ThreadPoolExecutor(max_workers=8) as pool:
   outputs=list(pool.map(invocation,range(16)))
  check(all(x.returncode==0 for x in outputs),'concurrent cli exit statuses')
  check(all(x.stdout==outputs[0].stdout for x in outputs),'concurrent deterministic CLI')
  # Valid unknown evidence bytes must be hashed, never written back to stdout.
  secret=copy.deepcopy(data);raw_secret=b'private token 123456789';secret['evidence'][0]['data_base64']=base64.b64encode(raw_secret).decode();sec=d/'secret.json';dump(sec,secret)
  r=run(binary,'analyze','--input',sec);check(r.returncode==0 and raw_secret not in r.stdout and secret['evidence'][0]['data_base64'].encode() not in r.stdout,'secret redaction')
  check(('sha256:'+hashlib.sha256(raw_secret).hexdigest()).encode() in r.stdout,'actual evidence hash')
  print('PASS: %d independent local CLI assertions' % TESTS)

if __name__=='__main__':
 try:main()
 except (AssertionError,subprocess.CalledProcessError,subprocess.TimeoutExpired) as e:
  print('FAIL:',repr(e),file=sys.stderr);sys.exit(1)
