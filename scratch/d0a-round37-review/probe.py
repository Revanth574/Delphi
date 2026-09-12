#!/usr/bin/env python3
import contextlib, importlib.util, io, os, pathlib, re, shutil, subprocess, tempfile
ROOT=pathlib.Path(__file__).resolve().parents[2]
def module(path,name):
 s=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
la=module(ROOT/'scripts/lane-accept.py','la')
g=module(ROOT/'scripts/lane-accept.test.py','g')
def rewrite(p,text):
 st=p.stat();p.write_text(text);os.utime(p,ns=(st.st_atime_ns,st.st_mtime_ns))
with tempfile.TemporaryDirectory(prefix='r37-probe-') as td:
 td=pathlib.Path(td)
 for label,mutate in [
  ('restored run 23',lambda d:None),
  ('different unpriv identity, same total',lambda d:rewrite(d/'unpriv-identities.txt',(d/'unpriv-identities.txt').read_text().replace('::','::wrong_',1))),
  ('positive invocation exited 101',lambda d:(d/'part-b-control.status').write_text('101\n')),
  ('root summary changed to failure',lambda d:rewrite(d/'root-run.log',(d/'root-run.log').read_text().replace('test result: ok.','test result: FAILED.',1))),
 ]:
  d=td/'lane-run-23';shutil.copytree(ROOT/'scratch/lane-run-23',d);mutate(d)
  ok,report=la.accept(d);print(f'{label}: {"ACCEPTED" if ok else "REFUSED"}')
  if not ok:print('\n'.join(report))
  shutil.rmtree(d)
 d=g.fixture();r=td/'lane-run-26';shutil.move(d,r)
 (r/'run-start.txt').write_text('start\n');os.utime(r/'run-start.txt',(1000025,1000025))
 ok,_=la.accept(r);print(f'current run 26 fixture: {ok}')
 (r/'rebuild.status').unlink();ok,report=la.accept(r)
 print('run 26 without rebuild.status: '+str(ok));print('\n'.join(x for x in report if 'REFUSE' in x))
 r.rename(td/'review-copy');ok,_=la.accept(td/'review-copy');print(f'same evidence in directory without run number: {ok}')
 procedure=(ROOT/'scratch/lane-run-7-procedure.md').read_text()
 print('procedure mentions rebuild.status: '+str('rebuild.status' in procedure))
 # Run actual contract guard against temporary files; do not change working implementation.
 for label,proc in [('restored contract',procedure),('positive control artifact omitted everywhere',procedure.replace('part-b-control.txt','discarded-positive.txt')),('acceptance invocation commented out',procedure.replace('scripts/lane-accept.py "scratch/lane-run-$RUN"','\x23 scripts/lane-accept.py "scratch/lane-run-$RUN"'))]:
  repo=td/'contract';(repo/'scripts').mkdir(parents=True,exist_ok=True);(repo/'scratch').mkdir(exist_ok=True)
  (repo/'scripts/lane-accept.py').write_text((ROOT/'scripts/lane-accept.py').read_text())
  (repo/'scratch/lane-run-7-procedure.md').write_text(proc)
  g.REPO=repo
  try:
   with contextlib.redirect_stdout(io.StringIO()):g.guard_the_procedure_produces_what_the_verifier_requires()
  except AssertionError as e:print(f'{label}: GUARD FAILED {e}')
  else:print(f'{label}: GUARD PASSED')
