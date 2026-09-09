#!/usr/bin/env python3
"""Run the 77 pinned self-checks in a disposable Git repository and private TMPDIR."""
import ast
import os
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]
old = ast.parse((ROOT/'scratch/d0a-round33-review/campaign-guards.py').read_text())
files = next(ast.literal_eval(n.value) for n in old.body if isinstance(n,ast.Assign)
             and any(isinstance(t,ast.Name) and t.id=='FILES' for t in n.targets))
with tempfile.TemporaryDirectory(prefix='d0a-r34-suite-') as tmp:
    td=Path(tmp)
    repo=td/'repo'
    for rel in files:
        p=repo/rel
        p.parent.mkdir(parents=True,exist_ok=True)
        p.write_bytes(subprocess.check_output(['git','show','d94875d:'+rel],cwd=ROOT))
    def git(*args):
        return subprocess.run(['git','-c','core.hooksPath=/dev/null',*args],cwd=repo,
                              capture_output=True,check=True)
    git('init','-q'); git('add','.')
    git('-c','user.name=Review','-c','user.email=review@example.invalid','commit','-qm','pinned fixtures')
    scratch=td/'tmp'; scratch.mkdir()
    env=dict(os.environ,TMPDIR=str(scratch))
    result=subprocess.run(['python3',str(repo/'scripts/mutation-campaign.test.py')],
                          cwd=repo,env=env,timeout=90)
    assert result.returncode==0
    assert not list(scratch.glob('delphi-mutation-wt-*'))
