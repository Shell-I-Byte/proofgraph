#!/usr/bin/env python3
"""Independent RED/GREEN for self-rehashed malformed result/v1 properties."""
import copy,hashlib,json,pathlib,subprocess,sys,tempfile

def run(exe,*args):return subprocess.run([str(exe),*map(str,args)],capture_output=True,text=True,timeout=15)

def main():
    if len(sys.argv)!=2:raise SystemExit('usage: result_schema_cli_probes.py binary')
    exe=pathlib.Path(sys.argv[1]).resolve()
    src=pathlib.Path(__file__).resolve().parents[1]/'testdata/lab.json'
    counts=0
    with tempfile.TemporaryDirectory() as td:
        good=pathlib.Path(td)/'good.json'
        assert run(exe,'analyze','--input',src,'--output',good).returncode==0
        doc=json.loads(good.read_text())
        assert run(exe,'verify','--input',good).returncode==0
        assert run(exe,'replay','--input',src,'--report',good).returncode==0
        counts+=3
        cases={
          'invalid-node-type':lambda d:d['nodes'][0].__setitem__('type','UNKNOWN'),
          'negative-evidence-length':lambda d:d['evidence'][0].__setitem__('bytes',-1),
          'evidence-too-large':lambda d:d['evidence'][0].__setitem__('bytes',2097153),
          'invalid-evidence-sha':lambda d:d['evidence'][0].__setitem__('sha256','x'),
          'invalid-node-id':lambda d:d['nodes'][0].__setitem__('id','bad id'),
          'invalid-node-scope':lambda d:d['nodes'][0].__setitem__('scope_id','bad scope'),
          'invalid-input-sha':lambda d:d.__setitem__('input_sha256','x'),
          'invalid-snapshot':lambda d:d.__setitem__('snapshot','bad'),
          'invalid-scope-id':lambda d:d.__setitem__('scope_id','bad scope'),
          'invalid-negative-edge-ref':lambda d:d.__setitem__('negative_evidence',['bad id']),
          'invalid-missing-edge-ref':lambda d:d.__setitem__('missing_links',['bad id']),
        }
        for name,mutate in cases.items():
            doc2=copy.deepcopy(doc);mutate(doc2);doc2['sha256']=''
            canonical=json.dumps(doc2,ensure_ascii=False,separators=(',',':')).encode()
            doc2['sha256']='sha256:'+hashlib.sha256(canonical).hexdigest()
            candidate=pathlib.Path(td)/(name+'.json')
            candidate.write_text(json.dumps(doc2,ensure_ascii=False))
            verified=run(exe,'verify','--input',candidate)
            assert verified.returncode==3, (name,'verify',verified.returncode,verified.stdout,verified.stderr)
            counts+=1
            replayed=run(exe,'replay','--input',src,'--report',candidate)
            assert replayed.returncode==3, (name,'replay',replayed.returncode)
            counts+=1
            print('PASS reject self-rehashed malformed',name)
    print(f'PASS {counts}/{counts} independent schema CLI checks')

if __name__=='__main__':main()
