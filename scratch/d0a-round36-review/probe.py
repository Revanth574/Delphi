#!/usr/bin/env python3
"""Pinned round-36 acceptance counterexamples; originals remain untouched."""
import contextlib, importlib.util, io, os, pathlib, re, shutil, subprocess, tempfile
ROOT = pathlib.Path(__file__).resolve().parents[2]
def module(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
    return m
la = module(ROOT/'scripts/lane-accept.py', 'la')
def rewrite(p, text):
    st=p.stat(); p.write_text(text); os.utime(p, ns=(st.st_atime_ns, st.st_mtime_ns))
with tempfile.TemporaryDirectory(prefix='d0a-r36-') as td:
    td=pathlib.Path(td)
    original=ROOT/'scratch/lane-run-23'
    cases = {
        'restored run 23': lambda d: None,
        'positive verdict Topology and failed test': lambda d: rewrite(d/'part-b-control.txt', (d/'part-b-control.txt').read_text().replace('verdict: Reached','verdict: Topology').replace('test result: ok. 1 passed; 0 failed','test result: FAILED. 0 passed; 1 failed')),
        'positive Reached but later assertion fails': lambda d: rewrite(d/'part-b-control.txt', (d/'part-b-control.txt').read_text().replace('test result: ok. 1 passed; 0 failed','test result: FAILED. 0 passed; 1 failed')),
        'root identities empty, old membership summary': lambda d: rewrite(d/'root-identities.txt', ''),
        'unpriv identity multiplicity changed': lambda d: rewrite(d/'unpriv-identities.txt', (d/'unpriv-identities.txt').read_text().replace('1\t','2\t',1)),
        'empty root transcript': lambda d: rewrite(d/'root-run.log',''),
        'failed rebuild, hashes unchanged': lambda d: rewrite(d/'rebuild.log','error: could not compile delphi-runtime\n'),
        '17 copies of one producer': lambda d: rewrite(d/'root-run23.status',(d/'root-run23.status').read_text().splitlines()[0]+'\n'+((d/'root-run23.status').read_text().splitlines()[0]+'\n')*16),
    }
    for label, mutate in cases.items():
        d=td/'lane-run-23'; shutil.copytree(original,d); mutate(d)
        ok, report=la.accept(d)
        print(f'{label}: {"ACCEPTED" if ok else "REFUSED"}')
        if not ok: print('\n'.join(report))
        shutil.rmtree(d)
    # Freeze the verifier clock to prove collisions without timing luck.
    d=td/'lane-run-23'; shutil.copytree(original,d)
    import sys
    old_args=sys.argv; sys.argv=['lane-accept.py',str(d)]
    old_stamp=la.time.strftime; la.time.strftime=lambda *a:'20000101T000000Z'
    try:
        with contextlib.redirect_stdout(io.StringIO()): rc1=la.main()
        capture=d/'acceptance-reverified-20000101T000000Z.txt'; first=capture.read_text()
        rewrite(d/'root-run23.status','1\tfailed\n'*17)
        with contextlib.redirect_stdout(io.StringIO()): rc2=la.main()
        print(f'same-second re-verification: rc {rc1} -> {rc2}; previous capture overwritten={first != capture.read_text()}; captures={len(list(d.glob("acceptance-reverified-*")))}')
    finally: sys.argv=old_args; la.time.strftime=old_stamp

# Recompute historical multisets independently.
from collections import Counter
for n in (23,24,25):
    d=ROOT/f'scratch/lane-run-{n}'; c=Counter(); target=None
    for line in (d/'root-run.log').read_text().splitlines():
        if line.startswith('### '): target=pathlib.Path(line[4:]).name.rsplit('-',1)[0]
        m=re.match(r'^test (\S+) \.\.\. ',line)
        if m: c[f'{target}::{m[1]}']+=1
    def read_ids(name):
        ans=Counter()
        for line in (d/name).read_text().splitlines():
            count,key=line.split('\t'); ans[key]+=int(count)
        return ans
    root,unpriv=read_ids('root-identities.txt'),read_ids('unpriv-identities.txt')
    print(f'run {n}: derived={sum(c.values())}, root={sum(root.values())}, unpriv={sum(unpriv.values())}, derived==root={c==root}, root==unpriv={root==unpriv}')
