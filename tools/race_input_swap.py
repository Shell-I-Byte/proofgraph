#!/usr/bin/env python3
"""Local-only adversarial input file/FIFO atomic-swap CLI regression."""
import argparse, ctypes, json, os, pathlib, shutil, subprocess, tempfile, threading, time
p=argparse.ArgumentParser();p.add_argument('binary');p.add_argument('--iterations',type=int,default=100);p.add_argument('--timeout',type=float,default=.25);p.add_argument('--require-no-hangs', action='store_true');args=p.parse_args()
libc=ctypes.CDLL(None,use_errno=True)
renameat2=libc.renameat2
renameat2.argtypes=[ctypes.c_int,ctypes.c_char_p,ctypes.c_int,ctypes.c_char_p,ctypes.c_uint];renameat2.restype=ctypes.c_int
AT_FDCWD=-100; RENAME_EXCHANGE=2
source=pathlib.Path(__file__).parents[1]/'testdata/lab.json'
with tempfile.TemporaryDirectory(prefix='proofgraph-fifo-swap-') as d:
    a=pathlib.Path(d)/'input.json';b=pathlib.Path(d)/'pipe';shutil.copyfile(source,a);os.mkfifo(b)
    count=[0]; errors=[];stop=threading.Event()
    ab=os.fsencode(a);bb=os.fsencode(b)
    def swap():
      while not stop.is_set():
        rc=renameat2(AT_FDCWD,ab,AT_FDCWD,bb,RENAME_EXCHANGE)
        if rc!=0:
          errors.append(ctypes.get_errno());break
        count[0]+=1
    t=threading.Thread(target=swap,daemon=True);t.start();results={'0':0,'2':0,'3':0,'4':0,'other':0,'hang':0}
    for i in range(args.iterations):
      try:
       r=subprocess.run([str(pathlib.Path(args.binary).resolve()),'analyze','-input',str(a)],stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=args.timeout)
       if str(r.returncode) in results:results[str(r.returncode)]+=1
       else:results['other']+=1
       if r.returncode==0:
        try:
         if json.loads(r.stdout)['schema'] != 'proofgraph.result/v1':results['other']+=1
        except Exception:results['other']+=1
      except subprocess.TimeoutExpired:results['hang']+=1
      if errors:break
    stop.set();t.join(timeout=2)
    print(json.dumps({'total':sum(results.values()),'exchanges':count[0],'results':results,'swap_errors':errors},sort_keys=True))
    if args.require_no_hangs and (results['hang'] or results['other'] or errors):raise SystemExit(1)
