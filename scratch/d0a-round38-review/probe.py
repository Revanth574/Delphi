#!/usr/bin/env python3
"""Round 38 reproductions. All subjects and mutants live in temporary directories."""
import importlib.util
import json
import os
import pathlib
import shlex
import shutil
import subprocess
import sys
import tempfile
import time

ROOT = pathlib.Path(__file__).resolve().parents[2]
OUT = pathlib.Path(__file__).resolve().parent
TMP = pathlib.Path(tempfile.mkdtemp(prefix="d0a-r38-"))


def module(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


wd = module(ROOT / "scripts/weaken-driver.py", "wd")
mc = module(ROOT / "scripts/mutation-campaign.py", "mc")
lg = module(ROOT / "scripts/lane-accept.test.py", "lg")
real_run = subprocess.run
observations = []


def observed_run(cmd, **kwargs):
    # Spy only: delegate unchanged, retain the actual exit and complete output.
    try:
        p = real_run(cmd, **kwargs)
    except subprocess.TimeoutExpired as e:
        observations.append({"cmd": cmd, "timeout": e.timeout,
                             "stdout": str(e.stdout), "stderr": str(e.stderr)})
        raise
    observations.append({"cmd": cmd, "exit": p.returncode,
                         "stdout": p.stdout, "stderr": p.stderr})
    return p


subprocess.run = observed_run
real_sh = mc.sh


def observed_sh(cmd, **kwargs):
    # The campaign uses Popen internally, so observe its command boundary too.
    p = real_sh(cmd, **kwargs)
    observations.append({"cmd": cmd, "exit": p.returncode,
                         "stdout": p.stdout, "stderr": p.stderr})
    return p


mc.sh = observed_sh


def record(name, value):
    (OUT / (name + ".json")).write_text(json.dumps(value, indent=2, default=str) + "\n")
    print(name + ": " + json.dumps(value, default=str))


def fixture(name, body, crlf=False):
    d = TMP / name
    d.mkdir()
    target = d / "subject.py"
    target.write_bytes(b"FLAG = True\r\n" if crlf else b"FLAG = True\n")
    suite = d / "suite.py"
    suite.write_text("import os, pathlib, subprocess, sys, time\n"
                     "d = pathlib.Path(__file__).parent\n"
                     "target = d / 'subject.py'\n"
                     "report = pathlib.Path(os.environ['DELPHI_GUARD_FAILURE_REPORT'])\n"
                     + body)
    return d, target, [sys.executable, str(suite)]


simple = """if 'False' in target.read_text():
    report.write_text('expected\\n')
    print('actual expected guard failed', flush=True)
    sys.exit(1)
print('guard passed', flush=True)
"""

# A real CRLF round-trip makes the supposedly unreachable check fire.
d, t, cmd = fixture("crlf", simple, True)
before = t.read_bytes()
v, ev = wd.drive(t, "True", "False", cmd, "expected")
record("crlf", {"verdict": v, "evidence": ev, "before": repr(before),
                "after": repr(t.read_bytes())})
d, t, cmd = fixture("missing-anchor-crlf", simple, True)
v, ev = wd.drive(t, "MISSING", "", cmd, "expected")
record("missing-anchor-crlf", {"verdict": v, "evidence": ev,
                               "after": repr(t.read_bytes())})

# Delete ONLY the allegedly unreachable digest predicate in a temporary driver.
mutrepo = TMP / "mutant-repo"
(mutrepo / "scripts").mkdir(parents=True)
src = (ROOT / "scripts/weaken-driver.py").read_text()
needle = '    if ev["digest_restored"] != before:\n        return RESTORE_FAILED, ev\n'
assert src.count(needle) == 1
(mutrepo / "scripts/weaken-driver.py").write_text(src.replace(needle, ""))
shutil.copy2(ROOT / "scripts/weaken-driver.test.py", mutrepo / "scripts")
p = subprocess.run([sys.executable, str(mutrepo / "scripts/weaken-driver.test.py")],
                   capture_output=True, text=True)
(OUT / "weakened-driver-suite.stdout").write_text(p.stdout)
(OUT / "weakened-driver-suite.stderr").write_text(p.stderr)
mut = module(mutrepo / "scripts/weaken-driver.py", "mut")
d, t, cmd = fixture("mutant-crlf", simple, True)
v, ev = mut.drive(t, "True", "False", cmd, "expected")
record("surviving-weaken", {"suite_exit": p.returncode,
                            "suite_last_line": p.stdout.splitlines()[-1],
                            "verdict": v, "evidence": ev})

# A trusted reporting child from baseline survives and writes during the mutant.
d, t, cmd = fixture("late-report", """if 'False' not in target.read_text():
    if not (d / 'spawned').exists():
        (d / 'spawned').touch()
        subprocess.Popen([sys.executable, str(d / 'late.py')],
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    print('baseline/restored parent passed', flush=True)
else:
    (d / 'go').touch()
    deadline = time.monotonic() + 5
    while not (d / 'done').exists():
        assert time.monotonic() < deadline
        time.sleep(.01)
    print('mutant failed WITHOUT reporting any guard', flush=True)
    sys.exit(1)
""")
(d / "late.py").write_text("""import os, pathlib, time
d = pathlib.Path(__file__).parent
deadline = time.monotonic() + 5
while not (d / 'go').exists():
    assert time.monotonic() < deadline
    time.sleep(.01)
pathlib.Path(os.environ['DELPHI_GUARD_FAILURE_REPORT']).write_text('expected\\n')
(d / 'done').touch()
""")
v, ev = wd.drive(t, "True", "False", cmd, "expected")
record("late-report", {"verdict": v, "evidence": ev})

# Timeout kills the suite leader, but its real child can overwrite the restore.
d, t, cmd = fixture("timeout-child", """if 'False' in target.read_text():
    subprocess.Popen([sys.executable, str(d / 'child.py')],
                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    print('mutant started writer child', flush=True)
    time.sleep(20)
print('baseline passed', flush=True)
""")
(d / "child.py").write_text("""import pathlib, time
d = pathlib.Path(__file__).parent
time.sleep(2)
(d / 'subject.py').write_text('FLAG = False\\n')
(d / 'done').touch()
""")
v, ev = wd.drive(t, "True", "False", cmd, "expected", timeout=1)
immediate = t.read_text()
deadline = time.monotonic() + 5
while not (d / "done").exists():
    assert time.monotonic() < deadline
    time.sleep(.02)
record("timeout-child", {"verdict": v, "evidence": ev,
                         "immediate": immediate, "after_child": t.read_text()})

# A real signal is numerically indistinguishable from the timeout sentinel.
d, t, cmd = fixture("sighup", "import signal\nos.kill(os.getpid(), signal.SIGHUP)\n")
v, ev = wd.drive(t, "True", "False", cmd, "expected")
record("sighup", {"verdict": v, "evidence": ev})

# Real Cargo: passing library followed by failing integration test.
crate = TMP / "crate"
(crate / "src").mkdir(parents=True)
(crate / "tests").mkdir()
(crate / "Cargo.toml").write_text(
    '[package]\nname="delphi-runtime"\nversion="0.0.0"\nedition="2024"\n[workspace]\n')
(crate / "src/lib.rs").write_text('#[test] fn library_passes() {}\n')
(crate / "tests/fail.rs").write_text('#[test] fn actual_failure() { assert!(false); }\n')
os.environ["CARGO_TARGET_DIR"] = str(crate / "target")
mc._WORKER_PUBLISH["path"] = str(crate / "worker.json")
outcome, ev = mc.run_suite(cwd=crate)
record("multi-binary", {"outcome": outcome, "evidence": ev})

# A real failing enumeration must not waive identity checking. The subject exits
# itself after writing a fictitious failure (there is no such test in the binary).
(crate / "tests/fail.rs").unlink()
(crate / "src/lib.rs").write_text('''#[test] fn exits_without_a_guard_failure() {
 use std::io::Write;
 std::io::stdout().write_all(b"\\ntest result: FAILED. 0 passed; 1 failed\\nfailures:\\n    fabricated_name\\n").unwrap();
 std::process::exit(1);
}
''')
wrapper = crate / "cargo_wrapper.py"
wrapper.write_text("""import os, signal, sys
if '--list' in sys.argv:
    os.kill(os.getpid(), signal.SIGTERM)
os.execvp('cargo', ['cargo', 'test', '-p', 'delphi-runtime', '--lib', '--tests'])
""")
os.environ["DELPHI_MUTATION_TEST_CMD"] = shlex.join([sys.executable, str(wrapper)])
outcome, ev = mc.run_suite(cwd=crate)
record("failed-enumeration", {"outcome": outcome, "evidence": ev})
os.environ.pop("DELPHI_MUTATION_TEST_CMD")

# Dictionary assignment silently loses multiplicity in an identity-count file.
d = lg.fixture()
try:
    baseline, _ = lg.la.accept(d)
    p = d / "unpriv-identities.txt"
    text = p.read_text()
    p.write_text(text + text.splitlines()[0] + "\n")
    ok, report = lg.la.accept(d)
    record("duplicate-membership", {"baseline": baseline, "accepted": ok,
                                    "report": report, "unpriv": p.read_text()})
finally:
    shutil.rmtree(d.parent)

(OUT / "process-observations.json").write_text(json.dumps(observations, indent=2) + "\n")
print("Temporary subjects retained at " + str(TMP))
