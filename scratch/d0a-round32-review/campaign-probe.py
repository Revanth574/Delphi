#!/usr/bin/env python3
"""Pinned harness probes in disposable Git repos; never mutate the user's checkout."""
import ctypes, importlib.util, json, os, pathlib, signal, subprocess, tempfile
root=pathlib.Path(__file__).resolve().parents[2]
assert ctypes.CDLL(None).prctl(36,1,0,0,0)==0
files=['scripts/mutation-campaign.py','scripts/mutation-campaign.test.py','scripts/check-stale-test-sessions.sh','runtime/src/shutdown.rs','runtime/src/wire.rs','runtime/src/execute.rs','runtime/src/sandbox.rs','runtime/src/action.rs','runtime/src/service.rs','runtime/src/test_child_guard.rs','installer/pam/delphi-runtime','Cargo.lock']
def make(repo):
    for rel in files:
        p=repo/rel; p.parent.mkdir(parents=True,exist_ok=True)
        p.write_bytes(subprocess.check_output(['git','show','4a0a0b1:'+rel],cwd=root))
    def git(*args): return subprocess.check_output(['git','-c','core.hooksPath=/dev/null',*args],cwd=repo,stderr=subprocess.DEVNULL,text=True).strip()
    git('init','-q'); git('add','.'); git('-c','user.name=Review','-c','user.email=review@example.invalid','commit','-qm','pinned fixture')
    return git
with tempfile.TemporaryDirectory(prefix='r32-campaign-') as td:
    repo=pathlib.Path(td)/'repo'; repo.mkdir(); git=make(repo)
    script=repo/'scripts/mutation-campaign.py'; original=script.read_text()
    # No-op only the killer; registration/restoration remain the actual implementation.
    start=original.index('def _kill_active_child_group()')
    end=original.index('\ndef suite_cmd(',start)
    script.write_text(original[:start]+'def _kill_active_child_group() -> None:\n    pass\n\n'+original[end:])
    spec=importlib.util.spec_from_file_location('campaign_test',repo/'scripts/mutation-campaign.test.py')
    t=importlib.util.module_from_spec(spec); spec.loader.exec_module(t)
    print('MUTANT: only _kill_active_child_group is a no-op',flush=True)
    t.guard_real_signal_during_a_real_campaign()
    print('REAL SIGNAL GUARD PASSED with no cancellation kill',flush=True)
    # Extend only the fast command fixture with a long-lived grandchild whose pipes are closed.
    # This gives the same real-signal guard an actual survivor to observe after the shell exits.
    test_path=repo/'scripts/mutation-campaign.test.py'
    test_src=test_path.read_text().replace('sleep 6', 'sleep 60 >/dev/null 2>&1 & sleep 6')
    exec(compile(test_src,str(test_path),'exec'), t.__dict__)
    print('LONG GRANDCHILD FIXTURE, same no-op killer:',flush=True)
    t.guard_real_signal_during_a_real_campaign()
    adopted=pathlib.Path(f'/proc/{os.getpid()}/task/{os.getpid()}/children').read_text().split()
    live=[]
    for pid in adopted:
        fields=pathlib.Path(f'/proc/{pid}/stat').read_bytes().rsplit(b')',1)[1].split()
        if fields[0] != b'Z': live.append((int(pid),int(fields[2])))
    print(f'REAL SIGNAL GUARD PASSED with live adopted descendants (pid,pgid): {live}',flush=True)
    assert live
    for pid,_ in live: os.kill(pid,signal.SIGKILL)
    while True:
        try: os.waitpid(-1,0)
        except ChildProcessError: break
    # Dirty executing instrument: empty mutation inventory, but recorded commit has full one.
    script.write_text(original.replace('if __name__ == "__main__":','MUTATIONS = []  # UNCOMMITTED REVIEW MUTATION\n\nif __name__ == "__main__":'))
    out=pathlib.Path(td)/'out'
    env=dict(os.environ, DELPHI_MUTATION_TEST_CMD='printf "test result: ok. 1 passed\\n"')
    r=subprocess.run(['python3',str(script),'--out',str(out)],cwd=repo,env=env,capture_output=True,text=True,timeout=30)
    result=json.loads((out/'results.json').read_text())
    print(f'DIRTY INSTRUMENT: exit={r.returncode}; mutations={len(result["results"])}; attributed_to_commit={result["lane"]["commit"]==git("rev-parse","HEAD")}; dirty_warning={"NOT included" in r.stderr}',flush=True)
    assert r.returncode==0 and len(result['results'])==0
    # Baseline failure cleanup path.
    script.write_text(original)
    out2=pathlib.Path(td)/'bad-baseline'
    env['DELPHI_MUTATION_TEST_CMD']='false'
    r=subprocess.run(['python3',str(script),'--out',str(out2)],cwd=repo,env=env,capture_output=True,text=True,timeout=30)
    lane=json.loads((out2/'lane.json').read_text())
    work=pathlib.Path(lane['isolated_checkout'])
    print(f'BASELINE FAILURE: exit={r.returncode}; worktree_still_exists={work.exists()}; still_registered={str(work) in git("worktree","list")}',flush=True)
    assert r.returncode==2 and work.exists()
    git('worktree','remove','--force',str(work)); work.parent.rmdir()
    # Collect any orphan fixture workers; none can escape this probe's subreaper.
    while True:
        try: os.waitpid(-1,0)
        except ChildProcessError: break
