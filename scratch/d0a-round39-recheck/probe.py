#!/usr/bin/env python3
"""Reproduce round-39 findings using pinned sources and temporary targets only."""
import importlib.util
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time

REPO = Path(__file__).resolve().parents[2]
OUT = Path(__file__).resolve().parent
PIN = "c560cae"
TMP = Path(tempfile.mkdtemp(prefix="d0a-r39-"))
source = subprocess.check_output(["git", "show", f"{PIN}:scripts/weaken-driver.py"], cwd=REPO)
driver = TMP / "weaken-driver.py"
driver.write_bytes(source)
spec = importlib.util.spec_from_file_location("wd", driver)
wd = importlib.util.module_from_spec(spec)
spec.loader.exec_module(wd)


def save(name, value):
    (OUT / f"{name}.json").write_text(json.dumps(value, indent=2) + "\n")
    print(name, json.dumps(value), flush=True)


def make(name, original, suite_source):
    d = TMP / name
    d.mkdir()
    target, suite = d / "subject.py", d / "suite.py"
    target.write_text(original)
    suite.write_text(suite_source)
    return d, target, [sys.executable, str(suite), str(target)]


# Equal-length, same-second mutation. Validation imports cached original bytecode,
# while direct execution in the suite correctly observes the invalid source.
while time.time() % 1 > .1:
    time.sleep(.01)
d, target, suite = make("cached-invalid", "FLAG = 1\n", '''import os,subprocess,sys
p = subprocess.run([sys.executable, sys.argv[1]], capture_output=True, text=True)
open(sys.argv[1] + '.last-stderr', 'w').write(p.stderr)
if p.returncode:
    open(os.environ['DELPHI_GUARD_FAILURE_REPORT'], 'a').write('subject-imports-clean\\n')
    sys.exit(1)
''')
started = time.time()
v, ev = wd.drive(target, "FLAG = 1", "FLAG = X", suite, "subject-imports-clean", timeout=5)
target.write_text("FLAG = X\n")
actual = subprocess.run([sys.executable, str(target)], capture_output=True, text=True)
save("cached-invalid", dict(verdict=v, evidence=ev, duration=time.time()-started,
                            direct_mutant_exit=actual.returncode, direct_mutant_stderr=actual.stderr))

# The suite remains in its ordinary group: no setsid escape is used.
d, target, suite = make("signal-survivor", "FLAG = True\n", '''import os,pathlib,sys,time
p = pathlib.Path(sys.argv[1])
if 'FLAG = False' in p.read_text():
    p.with_suffix('.ready').write_text(str(os.getpid()))
    time.sleep(1.0)
    p.write_text('CLOBBERED BY ACTIVE SUITE\\n')
''')
cmd = [sys.executable, str(driver), "--target", str(target), "--anchor", "True",
       "--replacement", "False", "--expect", "x", *suite]
proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
deadline = time.monotonic() + 10
while not target.with_suffix('.ready').exists():
    if time.monotonic() > deadline:
        raise RuntimeError("suite never entered mutant window")
    time.sleep(.01)
child_pid = int(target.with_suffix('.ready').read_text())
group = os.getpgid(child_pid)
proc.terminate()
stdout, stderr = proc.communicate(timeout=5)
immediate = target.read_text()
time.sleep(1.3)
save("signal-survivor", dict(command=cmd, driver_exit=proc.returncode, stdout=stdout,
                            stderr=stderr, child_pid=child_pid, child_pgid=group,
                            immediate=immediate, later=target.read_text(),
                            backup_exists=wd._backup_path(target).exists()))

# Validation executes new top-level code, but uses subprocess.run without group
# collection. Its ordinary child can write after RED_PROVEN and backup deletion.
d, target, suite = make("validation-survivor", "FLAG = True\n", '''import os,pathlib,sys
if 'FLAG = False' in pathlib.Path(sys.argv[1]).read_text():
    open(os.environ['DELPHI_GUARD_FAILURE_REPORT'], 'a').write('flag-must-be-true\\n')
    sys.exit(1)
''')
child_code = "import pathlib,sys,time;time.sleep(1);pathlib.Path(sys.argv[1]).write_text('CLOBBERED BY VALIDATION\\n')"
replacement = ("FLAG = False\nimport subprocess,sys\n"
               f"subprocess.Popen([sys.executable, '-c', {child_code!r}, __file__], "
               "stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)\n")
v, ev = wd.drive(target, "FLAG = True\n", replacement, suite, "flag-must-be-true", timeout=5)
immediate = target.read_text()
time.sleep(1.3)
save("validation-survivor", dict(verdict=v, evidence=ev, immediate=immediate,
                                later=target.read_text(), backup_exists=wd._backup_path(target).exists(),
                                replacement=replacement))
save("locations", dict(pin=PIN, temporary_directory=str(TMP)))
