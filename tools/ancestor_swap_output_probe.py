#!/usr/bin/env python3
import argparse,ctypes,json,os,pathlib,subprocess,tempfile,threading
p=argparse.ArgumentParser();p.add_argument('binary');p.add_argument('--count',type=int,default=150);a=p.parse_args(); a.fixture=str(pathlib.Path(__file__).resolve().parent.parent/'testdata/lab.json')
libc=ctypes.CDLL(None,use_errno=True)
libc.renameat2.argtypes=[ctypes.c_int,ctypes.c_char_p,ctypes.c_int,ctypes.c_char_p,ctypes.c_uint]
libc.renameat2.restype=ctypes.c_int
with tempfile.TemporaryDirectory(prefix='proofgraph-ancestor-race-') as tmp:
 root=pathlib.Path(tmp);trusted=root/'trusted';alt=root/'alternate';outside=root/'outside'
 (trusted/'reports').mkdir(parents=True);(outside/'reports').mkdir(parents=True);alt.symlink_to(outside,target_is_directory=True)
 stop=threading.Event(); flips=[0];errors=[]
 def flip():
  aa=os.fsencode(trusted);bb=os.fsencode(alt)
  while not stop.is_set():
   if libc.renameat2(-100,aa,-100,bb,2)!=0:errors.append(ctypes.get_errno());return
   flips[0]+=1
 t=threading.Thread(target=flip,daemon=True);t.start();ret={}
 try:
  for i in range(a.count):
   q=subprocess.run([a.binary,'analyze','--input',a.fixture,'--output',str(trusted/'reports'/f'report_{i}.json')],capture_output=True,timeout=5)
   ret[str(q.returncode)]=ret.get(str(q.returncode),0)+1
 finally:stop.set();t.join(timeout=4)
 leaked=sorted((outside/'reports').glob('*.json'))
 # A valid JSON result in external directory confirms the redirection.
 valid=sum(json.loads(x.read_text()).get('schema') == 'proofgraph.result/v1' for x in leaked)
 print(json.dumps({'attempts':a.count,'flips':flips[0],'exitcodes':ret,'external_reports':len(leaked),'external_valid_results':valid,'flip_errors':errors},sort_keys=True))
 if errors:return_code=3
 elif valid:return_code=1
 elif flips[0]<100:return_code=2
 else:return_code=0
 raise SystemExit(return_code)
