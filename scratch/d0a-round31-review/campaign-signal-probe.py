#!/usr/bin/env python3
"""Exercise the actual campaign in temporary Git repositories with a fake Cargo tree."""
from pathlib import Path
import os, signal, subprocess, sys, tempfile, time, ctypes, json
ROOT=Path(__file__).resolve().parents[2]
# Adopt orphan fake build workers and reap them; never leave probe processes behind.
ctypes.CDLL(None).prctl(36,1,0,0,0) # PR_SET_CHILD_SUBREAPER

def git(repo,*args):
    return subprocess.run(['git','-c','core.hooksPath=/dev/null',*args],cwd=repo,capture_output=True,text=True,check=True)

for sig in (signal.SIGTERM, signal.SIGKILL):
    with tempfile.TemporaryDirectory(prefix='r31-campaign-') as td:
        repo=Path(td)
        for name in ('scripts','runtime/src','bin'): (repo/name).mkdir(parents=True)
        (repo/'scripts/mutation-campaign.py').write_text((ROOT/'scripts/mutation-campaign.py').read_text())
        original='    for arg in action.argv.iter().skip(1) {\n'
        victim=repo/'runtime/src/execute.rs'
        victim.write_text(original)
        git(repo,'init','-q'); git(repo,'add','.')
        git(repo,'-c','user.name=Review','-c','user.email=review@example.invalid','commit','-qm','fixture')
        cargo=repo/'bin/cargo'
        cargo.write_text('''#!/usr/bin/env python3
import os,pathlib,subprocess,sys,time
if '--version' in sys.argv: print('fake cargo')
elif '--no-run' in sys.argv:
    worker=subprocess.Popen(['sleep','60'])
    pathlib.Path('worker.pid').write_text(str(worker.pid))
    worker.wait()
else: print('test result: ok. 1 passed; 0 failed')
''')
        cargo.chmod(0o755)
        env={**os.environ,'PATH':str(repo/'bin')+os.pathsep+os.environ['PATH']}
        p=subprocess.Popen([sys.executable,'scripts/mutation-campaign.py','--out','artifacts'],cwd=repo,env=env,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,start_new_session=True)
        try:
            deadline=time.monotonic()+10
            while not (repo/'worker.pid').exists():
                if p.poll() is not None: raise RuntimeError(p.communicate())
                if time.monotonic()>deadline: raise TimeoutError('build not started')
                time.sleep(.01)
            worker=int((repo/'worker.pid').read_text())
            os.kill(p.pid,sig) # Kill ONLY harness, as timeout/cancellation of a process does.
            p.wait(timeout=5)
            print(sig.name,'harness exit:',p.returncode,'source restored:',victim.read_text()==original)
            print(sig.name,'journal:',[json.loads(l)['outcome'] for l in (repo/'artifacts/results.jsonl').read_text().splitlines()])
            stat=Path(f'/proc/{worker}/stat').read_text().split(') ',1)[1].split()[0]
            print(sig.name,'fake build worker state after harness exited:',stat)
        finally:
            # Session belongs only to this probe and still contains its fake build worker.
            try: os.killpg(p.pid,signal.SIGKILL)
            except ProcessLookupError: pass
            p.communicate(timeout=5)
            while True:
                try: os.waitpid(-1,0)
                except ChildProcessError: break
