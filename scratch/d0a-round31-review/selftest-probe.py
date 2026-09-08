#!/usr/bin/env python3
"""Run all 31 guards with signal registration replaced by a no-op, in a temporary Git repo."""
import importlib.util, pathlib, shutil, subprocess, tempfile
root=pathlib.Path(__file__).resolve().parents[2]
with tempfile.TemporaryDirectory(prefix='r31-selftest-') as td:
    repo=pathlib.Path(td)
    for rel in ['scripts/mutation-campaign.py','scripts/mutation-campaign.test.py','scripts/check-stale-test-sessions.sh','installer/pam/delphi-runtime','runtime/src/wire.rs']:
        (repo/rel).parent.mkdir(parents=True,exist_ok=True)
        shutil.copy(root/rel,repo/rel)
    def git(*args):
        subprocess.run(['git','-c','core.hooksPath=/dev/null',*args],cwd=repo,check=True,capture_output=True)
    git('init','-q');git('add','.')
    git('-c','user.name=Review','-c','user.email=review@example.invalid','commit','-qm','fixture')
    spec=importlib.util.spec_from_file_location('campaign_test',repo/'scripts/mutation-campaign.test.py')
    t=importlib.util.module_from_spec(spec);spec.loader.exec_module(t)
    t.mc._install_signal_handlers=lambda: None
    print('MUTATION: signal installer replaced with a no-op')
    print('selftest return:',t.main())
