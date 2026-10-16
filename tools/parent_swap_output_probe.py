#!/usr/bin/env python3
"""Linux-only synthetic proofgraph output-parent rename/symlink race; no network."""
import argparse, ctypes, json, os, pathlib, subprocess, tempfile, threading

def main():
    p=argparse.ArgumentParser(); p.add_argument('binary'); p.add_argument('--count',type=int,default=350)
    a=p.parse_args(); binary=str(pathlib.Path(a.binary).resolve())
    if os.uname().sysname!='Linux': print('SKIP non-Linux'); return 77
    if not (1 <= a.count <= 2500): return 2
    libc=ctypes.CDLL(None, use_errno=True)
    libc.renameat2.argtypes=[ctypes.c_int,ctypes.c_char_p,ctypes.c_int,ctypes.c_char_p,ctypes.c_uint]
    libc.renameat2.restype=ctypes.c_int
    with tempfile.TemporaryDirectory(prefix='proofgraph-out-swap-') as tmp:
        r=pathlib.Path(tmp); parent=r/'parent'; alt=r/'alternate'; outside=r/'outside'
        parent.mkdir(); outside.mkdir(); alt.symlink_to(outside,target_is_directory=True)
        src=r/'source.json'; src.write_bytes((pathlib.Path(__file__).resolve().parent.parent/'testdata/lab.json').read_bytes())
        stop=threading.Event(); errors=[]; flips=[0]
        def toggler():
            a=os.fsencode(parent); b=os.fsencode(alt)
            while not stop.is_set():
                if libc.renameat2(-100,a,-100,b,2)!=0:
                    errors.append(ctypes.get_errno());break
                flips[0]+=1
        th=threading.Thread(target=toggler,daemon=True); th.start()
        returncodes={}; succeeds=0
        try:
            for i in range(a.count):
                q=subprocess.run([binary,'analyze','--input',str(src),'--output',str(parent/f'result_{i}.json')],capture_output=True,timeout=5)
                returncodes[str(q.returncode)]=returncodes.get(str(q.returncode),0)+1
                if q.returncode==0: succeeds+=1
                elif q.returncode not in (4,):
                    print('unexpected returncode',q.returncode,'stderr=',q.stderr.decode(errors='replace')[:200]);return 3
        finally:
            stop.set();th.join(timeout=5)
        leaked=sorted(x.name for x in outside.iterdir())
        report={'attempts':a.count,'exchanges':flips[0],'successes':succeeds,'returncodes':returncodes,'outside_reports':len(leaked),'examples':leaked[:6],'swap_errors':errors}
        print(json.dumps(report,sort_keys=True))
        if leaked:return 1
        if flips[0] < 100 or succeeds < 1 or errors:return 2
        return 0
if __name__=='__main__':raise SystemExit(main())
