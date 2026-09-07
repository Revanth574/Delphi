#!/usr/bin/env python3
"""Retained probes; mutations confined to temporary Git repositories, never the workspace."""
import importlib.util, os, pathlib, shutil, signal, subprocess, sys, tempfile, time, types
ROOT = pathlib.Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('mc', ROOT / 'scripts/mutation-campaign.py')
mc = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mc)
original_sh = mc.sh
stdout = '''running 1 test
test fixture::test ... FAILED
failures:
---- fixture::test stdout ----
thread 'fixture::test' panicked at runtime/src/test_child_guard.rs:124:5:
PRECONDITION FAILED before this test ran — a session is live on tty1.
failures:
    fixture::test

test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out
'''
mc.sh = lambda *a, **kw: types.SimpleNamespace(returncode=101, stdout=stdout, stderr='')
print('stale-session precondition classification:', mc.run_suite()[0])
mc.sh = original_sh

def git(repo, *args):
    return subprocess.run(['git', '-c', 'core.hooksPath=/dev/null', *args], cwd=repo, check=True, capture_output=True, text=True)

with tempfile.TemporaryDirectory(prefix='d0a-r30-harness-') as td:
    repo = pathlib.Path(td)
    for name in ['scripts', 'runtime/src', 'installer/pam', 'bin']:
        (repo / name).mkdir(parents=True)
    shutil.copy(ROOT / 'scripts/mutation-campaign.py', repo / 'scripts/mutation-campaign.py')
    code = '    for arg in action.argv.iter().skip(1) {\n'
    (repo / 'runtime/src/execute.rs').write_text(code)
    (repo / 'installer/pam/delphi-runtime').write_text('original fixture\n')
    git(repo, 'init', '-q')
    git(repo, 'add', '.')
    git(repo, '-c', 'user.name=Review probe', '-c', 'user.email=probe@example.invalid', 'commit', '-qm', 'fixture')
    (repo / 'installer/pam/delphi-runtime').write_text('modified fixture\n')
    mc.REPO = repo
    print('dirty installer fixture admitted:', mc.inputs_are_clean()[0])
    git(repo, 'restore', 'installer/pam/delphi-runtime')
    cargo = repo / 'bin/cargo'
    cargo.write_text('''#!/usr/bin/env python3
import pathlib, sys, time
if '--version' in sys.argv:
    print('cargo fixture')
elif '--no-run' in sys.argv:
    pathlib.Path('build-started').touch()
    time.sleep(30)
else:
    print('test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out')
''')
    cargo.chmod(0o755)
    env = {**os.environ, 'PATH': str(repo / 'bin') + os.pathsep + os.environ['PATH']}
    proc = subprocess.Popen([sys.executable, str(repo / 'scripts/mutation-campaign.py'), '--out', str(repo / 'artifacts')], cwd=repo, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, start_new_session=True)
    try:
        deadline = time.monotonic() + 10
        while not (repo / 'build-started').exists():
            if proc.poll() is not None:
                raise RuntimeError(proc.communicate())
            if time.monotonic() > deadline:
                raise TimeoutError('fake build not reached')
            time.sleep(.01)
        os.killpg(proc.pid, signal.SIGTERM)
        out, err = proc.communicate(timeout=5)
        print('SIGTERM returncode:', proc.returncode)
        print('source restored after SIGTERM:', (repo / 'runtime/src/execute.rs').read_text() == code)
        print('JSONL after SIGTERM:', repr((repo / 'artifacts/results.jsonl').read_text()))
    finally:
        if proc.poll() is None:
            os.killpg(proc.pid, signal.SIGKILL)
            proc.communicate()

with tempfile.TemporaryDirectory(prefix='d0a-r30-selftest-') as td:
    repo = pathlib.Path(td)
    (repo / 'scripts').mkdir()
    (repo / 'runtime/src').mkdir(parents=True)
    (repo / 'runtime/src/wire.rs').write_text('// fixture\n')
    shutil.copy(ROOT / 'scripts/mutation-campaign.test.py', repo / 'scripts/mutation-campaign.test.py')
    (repo / 'scripts/mutation-campaign.py').write_text(
        (ROOT / 'scripts/mutation-campaign.py').read_text() + '\nfile_matches_head = lambda rel: False\n')
    p = subprocess.run([sys.executable, 'scripts/mutation-campaign.test.py'], cwd=repo, capture_output=True, text=True)
    print('self-test with always-false restore verifier: exit', p.returncode)
    for line in p.stdout.splitlines():
        if 'FAIL' in line: print(line)
