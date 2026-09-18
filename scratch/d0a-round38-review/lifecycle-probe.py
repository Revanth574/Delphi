#!/usr/bin/env python3
import importlib.util
import json
import os
import pathlib
import signal
import subprocess
import sys
import tempfile
import time

ROOT = pathlib.Path(__file__).resolve().parents[2]
OUT = pathlib.Path(__file__).resolve().parent
d = pathlib.Path(tempfile.mkdtemp(prefix="d0a-r38-lifetime-"))
spec = importlib.util.spec_from_file_location("wd", ROOT / "scripts/weaken-driver.py")
wd = importlib.util.module_from_spec(spec)
spec.loader.exec_module(wd)
t = d / "subject.py"
t.write_text("FLAG = True\n")
suite = d / "suite.py"
suite.write_text('''import os, pathlib, subprocess, sys
d = pathlib.Path(__file__).parent
p = subprocess.run([sys.executable, str(d/'subject.py')], capture_output=True, text=True)
with (d/'subject-outcomes.log').open('a') as f:
    f.write(f'exit={p.returncode}\\nstdout={p.stdout}\\nstderr={p.stderr}\\n')
if p.returncode != 0:
    pathlib.Path(os.environ['DELPHI_GUARD_FAILURE_REPORT']).write_text('expected\\n')
    raise AssertionError('expected: subject must execute successfully')
''')
v, ev = wd.drive(t, "True", "MISSING_NAME", [sys.executable, str(suite)], "expected")
result = {"verdict": v, "evidence": ev,
          "subject_outcomes": (d / "subject-outcomes.log").read_text()}
(OUT / "nameerror.json").write_text(json.dumps(result, indent=2) + "\n")
print("nameerror: " + json.dumps(result))

suite.write_text('''import pathlib, time
d = pathlib.Path(__file__).parent
if 'False' in (d/'subject.py').read_text():
    (d/'started').touch()
    time.sleep(20)
''')
p = subprocess.Popen([sys.executable, str(ROOT / "scripts/weaken-driver.py"),
                      "--target", str(t), "--anchor", "True", "--replacement", "False",
                      "--expect", "expected", "--", sys.executable, str(suite)],
                     stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                     start_new_session=True)
try:
    deadline = time.monotonic() + 5
    while not (d / "started").exists():
        assert p.poll() is None
        assert time.monotonic() < deadline
        time.sleep(.01)
    p.terminate()
    rc = p.wait(timeout=5)
    after = t.read_text()
finally:
    # Collect the whole PROBE session; the driver does not do this itself.
    try:
        os.killpg(p.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
stdout, stderr = p.communicate(timeout=5)
result = {"driver_exit": rc, "after_termination": after, "stdout": stdout, "stderr": stderr}
(OUT / "sigterm.json").write_text(json.dumps(result, indent=2) + "\n")
print("sigterm: " + json.dumps(result))

env = {**os.environ, "DELPHI_FAILURE_SNAPSHOT_DIR": str(d)}
cmd = ["sudo", "-n", "-u", str(os.getuid()), "/usr/bin/python3", "-c",
       "import os; print(repr(os.environ.get('DELPHI_FAILURE_SNAPSHOT_DIR')))"]
# sudo uses '#uid' for numeric users.
cmd[3] = "#" + str(os.getuid())
p = subprocess.run(cmd, env=env, capture_output=True, text=True)
result = {"cmd": cmd, "parent_value": str(d), "exit": p.returncode,
          "stdout": p.stdout, "stderr": p.stderr}
(OUT / "sudo-environment.json").write_text(json.dumps(result, indent=2) + "\n")
print("sudo-environment: " + json.dumps(result))
