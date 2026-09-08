#!/usr/bin/env python3
"""Run actual shutdown unit tests against a mutant that reports Terminated but never kills.
All edits are temporary. Adopt and reap the leaked sleepers after observing them.
"""
from pathlib import Path
import ctypes, json, os, signal, subprocess, tempfile
ROOT=Path(__file__).resolve().parents[2]
ctypes.CDLL(None).prctl(36,1,0,0,0)
meta=subprocess.run(['cargo','metadata','--format-version','1','--no-deps'],cwd=ROOT,capture_output=True,text=True,check=True)
deps=Path(json.loads(meta.stdout)['target_directory'])/'debug/deps'
nix=sorted(deps.glob('libnix-*.rlib'))[0]
with tempfile.TemporaryDirectory(prefix='r31-shutdown-mutant-') as td:
    p=Path(td);(p/'bin').mkdir()
    source=(ROOT/'runtime/src/shutdown.rs').read_text()
    anchor='Waited::Timeout => {}'
    assert source.count(anchor)==1
    (p/'shutdown.rs').write_text(source.replace(anchor,'Waited::Timeout => return ChildOutcome::Terminated,'))
    (p/'bin/delphi-runtimed.rs').write_text((ROOT/'runtime/src/bin/delphi-runtimed.rs').read_text())
    (p/'probe.rs').write_text('#[path="shutdown.rs"] mod shutdown;\n')
    subprocess.run(['rustc','--edition=2024','--test',str(p/'probe.rs'),'--extern',f'nix={nix}','-L',f'dependency={deps}','-o',str(p/'probe')],check=True)
    test=subprocess.Popen([str(p/'probe'),'--nocapture'],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,start_new_session=True)
    try:
        out,err=test.communicate(timeout=15)
        print(out,end='');print(err,end='')
        print('mutant test exit:',test.returncode)
        children=Path(f'/proc/{os.getpid()}/task/{os.getpid()}/children').read_text().split()
        print('live orphan sleepers adopted after passing suite:',len(children))
    finally:
        try: os.killpg(test.pid,signal.SIGKILL)
        except ProcessLookupError: pass
        if test.poll() is None: test.communicate(timeout=5)
        while True:
            try: os.waitpid(-1,0)
            except ChildProcessError: break
