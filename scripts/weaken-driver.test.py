#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Guards for `scripts/weaken-driver.py` — the tool that decides what RED-proven means.

Every verdict gets a DISCRIMINATING case. A driver that collapsed two of them would turn a
non-measurement into a proof, which is the failure it was built to stop, so the positive
control (`RED_PROVEN` on a chain that genuinely holds) comes first: a driver that returned a
refusal for everything would pass every negative guard below and be useless.

The subject and suite are MINIATURE and self-contained. Driving the real suites would make
these guards slow, and — worse — would couple the driver's proof to whatever those suites
happen to contain today.
"""
from __future__ import annotations

import importlib.util
import json
import os
import pathlib
import re
import shutil
import subprocess
import sys
import time
import tempfile

REPO = pathlib.Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location("wd", REPO / "scripts" / "weaken-driver.py")
wd = importlib.util.module_from_spec(spec)
spec.loader.exec_module(wd)

PASSED = 0


def check(label: str, condition: bool, detail: str = "") -> None:
    global PASSED
    if not condition:
        # Report to the side channel, like every other suite here, so THIS suite can be
        # driven by the driver it guards (D0A-R38-06's weaken proofs are run that way).
        report = os.environ.get("DELPHI_GUARD_FAILURE_REPORT")
        if report:
            with open(report, "a") as f:
                f.write(label + "\n")
        raise AssertionError(f"GUARD FAILED: {label}{(' — ' + detail) if detail else ''}")
    print(f"  [OK ] {label}")
    PASSED += 1


SUBJECT = '''
def verdict(n):
    if n != 1:
        return "REFUSE"
    return "OK"
'''

# A suite in the shape of this project's: `check()` enforces AND reports its failing label to
# the side channel the driver names.
SUITE = '''
import importlib.util, os, pathlib, sys
spec = importlib.util.spec_from_file_location("subject", sys.argv[1] if len(sys.argv) > 1
                                              else "SUBJECT_PATH")
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)

def check(label, condition):
    if not condition:
        report = os.environ.get("DELPHI_GUARD_FAILURE_REPORT")
        if report:
            with open(report, "a") as f:
                f.write(label + "\\n")
        raise AssertionError("GUARD FAILED: " + label)
    print("  [OK ] " + label)

check("a nonconforming value is REFUSED", m.verdict(2) == "REFUSE")
check("a conforming value is OK", m.verdict(1) == "OK")
print("2 guards held")
'''


def fixture() -> tuple[pathlib.Path, pathlib.Path, list[str]]:
    d = pathlib.Path(tempfile.mkdtemp(prefix="weaken-driver-fixture-"))
    subject = d / "subject.py"
    subject.write_text(SUBJECT)
    suite_py = d / "suite.py"
    suite_py.write_text(SUITE.replace("SUBJECT_PATH", str(subject)))
    return d, subject, [sys.executable, str(suite_py), str(subject)]


def crlf_fixture() -> tuple[pathlib.Path, pathlib.Path, list[str]]:
    """The same fixture with CRLF line endings. D0A-R38-06: the driver used to read and write
    this through `str`, which translates newlines, so it rewrote the target as LF."""
    d, subject, suite = fixture()
    subject.write_bytes(SUBJECT.replace("\n", "\r\n").encode())
    return d, subject, suite


def drive(subject: pathlib.Path, suite: list[str], anchor: str, repl: str,
          expect: str = "a nonconforming value is REFUSED") -> tuple[str, dict]:
    return wd.drive(subject, anchor, repl, suite, expect, timeout=60)


def main() -> int:
    # POSITIVE CONTROL FIRST.
    d, subject, suite = fixture()
    try:
        v, ev = drive(subject, suite, '    if n != 1:', '    if False:')
        check("a chain that HOLDS is RED_PROVEN", v == wd.RED_PROVEN, f"{v}: {ev}")
        check("...and the target is restored byte-identical",
              ev["digest_restored"] == ev["digest_before"])
        check("...and the suite is green again afterwards", ev["restored_exit"] == 0)
        check("...and the failing guard is named from the SIDE CHANNEL, not from text",
              ev["failing_guards"] == ["a nonconforming value is REFUSED"],
              f"{ev['failing_guards']}")
    finally:
        shutil.rmtree(d, ignore_errors=True)

    # MUTATION_NOT_APPLIED — the silent `str.replace` no-op that has shipped twice in this repo.
    d, subject, suite = fixture()
    try:
        v, ev = drive(subject, suite, 'ANCHOR THAT DOES NOT OCCUR', 'x')
        check("a missing anchor is MUTATION_NOT_APPLIED, never RED_PROVEN",
              v == wd.MUTATION_NOT_APPLIED, v)
        v, ev = drive(subject, suite, '    if n != 1:', '    if n != 1:')
        check("a replacement identical to the anchor is MUTATION_NOT_APPLIED",
              v == wd.MUTATION_NOT_APPLIED, f"{v}: the file was byte-identical afterwards")
    finally:
        shutil.rmtree(d, ignore_errors=True)

    # MUTATION_INVALID — the R36-06 shape: a weaken that dies for its own reason.
    d, subject, suite = fixture()
    try:
        v, _ = drive(subject, suite, '    if n != 1:', '    if n != 1 INVALID SYNTAX:')
        check("a weaken that does not parse is MUTATION_INVALID, not RED_PROVEN",
              v == wd.MUTATION_INVALID, v)
    finally:
        shutil.rmtree(d, ignore_errors=True)

    # NOT_CAUGHT — the R36-04 shape: the suite still passes, so nothing was proven.
    d, subject, suite = fixture()
    try:
        v, ev = drive(subject, suite, '    return "OK"', '    return "OK"  # inert edit')
        check("a weaken that changes nothing is NOT_CAUGHT", v == wd.NOT_CAUGHT, v)
        check("...and it says the ambiguity rather than resolving it",
              "58" in ev.get("reason", ""), ev.get("reason"))
    finally:
        shutil.rmtree(d, ignore_errors=True)

    # WRONG_GUARD — something failed, but not the one the weaken targets.
    d, subject, suite = fixture()
    try:
        v, ev = drive(subject, suite, '    return "OK"', '    return "WRONG"')
        check("a weaken failing a DIFFERENT guard is WRONG_GUARD", v == wd.WRONG_GUARD, v)
        check("...and it names what actually failed",
              ev["failing_guards"] == ["a conforming value is OK"], f"{ev['failing_guards']}")
    finally:
        shutil.rmtree(d, ignore_errors=True)

    # UNVERIFIABLE — the REFUSAL that makes this a mechanism rather than a convention. A suite
    # that fails without reporting a label cannot be attributed except by reading text.
    d, subject, suite = fixture()
    try:
        (d / "suite.py").write_text(
            "import sys\nprint('GUARD FAILED: a nonconforming value is REFUSED')\n"
            "sys.exit(1)\n")
        silent = [sys.executable, str(d / "suite.py")]
        # Baseline must be green for the chain to reach attribution, so the silent suite is
        # introduced only for the weakened run.
        v, ev = wd.drive(subject, '    if n != 1:', '    if False:', silent,
                         "a nonconforming value is REFUSED", timeout=60)
        check("a suite that fails BEFORE the weaken is BASELINE_NOT_GREEN",
              v == wd.BASELINE_NOT_GREEN, v)
    finally:
        shutil.rmtree(d, ignore_errors=True)

    d, subject, suite = fixture()
    try:
        # A suite that is green at baseline, fails under the weaken, and reports NO label.
        (d / "suite.py").write_text(
            "import importlib.util, sys\n"
            f"spec = importlib.util.spec_from_file_location('s', {str(subject)!r})\n"
            "m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)\n"
            "if m.verdict(2) != 'REFUSE':\n"
            "    print('GUARD FAILED: a nonconforming value is REFUSED')\n"
            "    sys.exit(1)\n"
            "print('ok')\n")
        mute = [sys.executable, str(d / "suite.py")]
        v, ev = wd.drive(subject, '    if n != 1:', '    if False:', mute,
                         "a nonconforming value is REFUSED", timeout=60)
        check("a failure with NO structured label is UNVERIFIABLE, never RED_PROVEN",
              v == wd.UNVERIFIABLE, f"{v}: {ev.get('reason')}")
        check("...and the refusal says why text is not an acceptable substitute",
              "read text" in ev.get("reason", ""), ev.get("reason"))
    finally:
        shutil.rmtree(d, ignore_errors=True)

    # RESTORE_FAILED — the tree came back but the suite did not. Constructed with a suite that
    # counts its invocations and fails on the THIRD, which is the post-restore run: the driver
    # must not call a weaken proven when the tree it left behind is broken.
    d, subject, suite = fixture()
    try:
        counter = d / "invocations"
        (d / "suite.py").write_text(
            "import os, pathlib, sys\n"
            f"c = pathlib.Path({str(counter)!r})\n"
            "n = int(c.read_text()) + 1 if c.exists() else 1\n"
            "c.write_text(str(n))\n"
            "if n == 2:\n"
            "    report = os.environ.get('DELPHI_GUARD_FAILURE_REPORT')\n"
            "    if report:\n"
            "        open(report, 'a').write('a nonconforming value is REFUSED\\n')\n"
            "    sys.exit(1)\n"
            "if n >= 3:\n"
            "    sys.exit(1)\n"
            "print('ok')\n")
        v, ev = wd.drive(subject, '    if n != 1:', '    if False:',
                         [sys.executable, str(d / "suite.py")],
                         "a nonconforming value is REFUSED", timeout=60)
        check("a suite still red AFTER restoration is RESTORE_FAILED, not RED_PROVEN",
              v == wd.RESTORE_FAILED, f"{v}: {ev}")
        check("...and the restore digest still matches, so the file came back",
              ev["digest_restored"] == ev["digest_before"])
    finally:
        shutil.rmtree(d, ignore_errors=True)

    # TIMEOUT — distinct from a failure, because a hang attributes nothing.
    d, subject, suite = fixture()
    try:
        (d / "suite.py").write_text("import time\ntime.sleep(30)\n")
        v, _ = wd.drive(subject, '    if n != 1:', '    if False:',
                        [sys.executable, str(d / "suite.py")],
                        "a nonconforming value is REFUSED", timeout=2)
        check("a hanging suite is TIMEOUT, not a pass or a failure", v == wd.TIMEOUT, v)
    finally:
        shutil.rmtree(d, ignore_errors=True)

    # ── D0A-R38-06 ──────────────────────────────────────────────────────────────────────
    # Both checks below were committed with a written argument for why they needed no test:
    # the anchor check "redundant with the digest comparison", the restore-digest check
    # "unreachable". BOTH WERE FALSE and the round-38 review demonstrated both. The argument
    # is not replaced with a better argument; it is replaced with these guards.

    # A CRLF target must survive the whole chain byte-for-byte.
    d, subject, suite = crlf_fixture()
    try:
        raw = subject.read_bytes()
        v, ev = drive(subject, suite, '    if n != 1:', '    if False:')
        check("a CRLF target still reaches RED_PROVEN", v == wd.RED_PROVEN, f"{v}: {ev}")
        check("...and comes back byte-identical, CRLF intact",
              subject.read_bytes() == raw and b"\r\n" in subject.read_bytes())
    finally:
        shutil.rmtree(d, ignore_errors=True)

    # ...and a path that mutates NOTHING must not rewrite it either. This returned
    # MUTATION_NOT_APPLIED while silently converting the file to LF (class 16).
    d, subject, suite = crlf_fixture()
    try:
        raw = subject.read_bytes()
        v, ev = drive(subject, suite, 'ANCHOR THAT DOES NOT OCCUR', 'x')
        check("a refusing path leaves a CRLF target untouched", subject.read_bytes() == raw,
              f"{v}: {subject.read_bytes()[:40]!r}")
        check("...and the restore digest it recorded actually matches",
              ev["digest_restored"] == ev["digest_before"])
    finally:
        shutil.rmtree(d, ignore_errors=True)

    # The anchor predicate's OWN discriminating case: it is the thing that attributes the
    # no-op to the anchor. Delete it and the cause recorded changes.
    d, subject, suite = fixture()
    try:
        _, ev = drive(subject, suite, 'ANCHOR THAT DOES NOT OCCUR', 'x')
        check("a missing anchor is attributed to the ANCHOR, not to unchanged bytes",
              ev["not_applied_because"] == "anchor-absent", str(ev.get("not_applied_because")))
        _, ev = drive(subject, suite, '    if n != 1:', '    if n != 1:')
        check("a replacement equal to the anchor is attributed to unchanged BYTES",
              ev["not_applied_because"] == "bytes-unchanged", str(ev.get("not_applied_because")))
    finally:
        shutil.rmtree(d, ignore_errors=True)

    # RESTORE_FAILED's digest path, reachable through the one fault it models: a restore
    # write that reports success without landing.
    d, subject, suite = fixture()
    try:
        v, ev = wd.drive(subject, '    if n != 1:', '    if False:', suite,
                         "a nonconforming value is REFUSED", timeout=60,
                         _restore=lambda b: subject.write_bytes(b + b"# not the original\n"))
        check("a restore that does not land is RESTORE_FAILED, not RED_PROVEN",
              v == wd.RESTORE_FAILED, f"{v}: {ev}")
        check("...and it says what the verdict would otherwise have been",
              ev["verdict_before_restore_check"] == wd.RED_PROVEN)
    finally:
        shutil.rmtree(d, ignore_errors=True)

    # ...and the same check runs on a path that never reached the success branch at all.
    d, subject, suite = fixture()
    try:
        v, ev = wd.drive(subject, 'ANCHOR THAT DOES NOT OCCUR', 'x', suite,
                         "a nonconforming value is REFUSED", timeout=60,
                         _restore=lambda b: subject.write_bytes(b + b"# not the original\n"))
        check("restoration is verified on EVERY terminal path, not just the proven one",
              v == wd.RESTORE_FAILED, f"{v}: {ev}")
        check("...and the refused verdict it replaced is retained",
              ev["verdict_before_restore_check"] == wd.MUTATION_NOT_APPLIED)
    finally:
        shutil.rmtree(d, ignore_errors=True)

    # ── D0A-R38-09 ──────────────────────────────────────────────────────────────────────
    # Death by signal is its own observation. SIGHUP is signal 1, and a process killed by it
    # has returncode -1 — the value the timeout sentinel used.
    d, subject, suite = fixture()
    try:
        (d / "suite.py").write_text(
            "import os,sys,signal,importlib.util\n"
            "spec = importlib.util.spec_from_file_location('s', sys.argv[1])\n"
            "m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)\n"
            "if m.verdict(2) != 'REFUSE':\n"
            "    os.kill(os.getpid(), signal.SIGHUP)\n")
        v, ev = drive(subject, suite, '    if n != 1:', '    if False:')
        check("a suite killed by SIGHUP is not TIMEOUT", v != wd.TIMEOUT, v)
        check("...it is UNVERIFIABLE, because a killed run judged nothing",
              v == wd.UNVERIFIABLE, v)
        check("...and the signal is recorded as a signal, not as an exit code",
              ev["weakened"]["outcome"] == wd.SIGNALLED and ev["weakened"]["signal"] == 1,
              f"{ev['weakened']}")
    finally:
        shutil.rmtree(d, ignore_errors=True)

    # ── D0A-R38-03 ──────────────────────────────────────────────────────────────────────
    # `compile()` proves syntax. A mutant that compiles and dies at import is an INVALID
    # experiment; crediting its fallout is the R36-06 misreading this driver forecloses.
    d = pathlib.Path(tempfile.mkdtemp(prefix="weaken-driver-loadfail-"))
    try:
        subject = d / "subject.py"
        subject.write_text("FLAG = True\n")
        runner = d / "run_subject.py"
        runner.write_text("import importlib.util,sys\n"
                          "spec = importlib.util.spec_from_file_location('s', sys.argv[1])\n"
                          "m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)\n")
        suite_py = d / "suite.py"
        # The guard checks COMMAND SUCCESS — the shape that made the NameError look like a
        # detection, because a guard did fail and did report itself.
        suite_py.write_text(
            "import os,subprocess,sys\n"
            "def check(label, cond):\n"
            "    if not cond:\n"
            "        r = os.environ.get('DELPHI_GUARD_FAILURE_REPORT')\n"
            "        if r: open(r,'a').write(label + chr(10))\n"
            "        sys.exit(1)\n"
            f"p = subprocess.run([sys.executable, r'{runner}', r'{subject}'], capture_output=True)\n"
            "check('subject-imports-clean', p.returncode == 0)\n")
        suite = [sys.executable, str(suite_py)]
        v, ev = wd.drive(subject, "True", "MISSING_NAME", suite, "subject-imports-clean",
                         timeout=60)
        check("a mutant that COMPILES but fails to import is MUTATION_INVALID",
              v == wd.MUTATION_INVALID, f"{v}: {ev.get('reason')}")
        check("...never RED_PROVEN, however loudly a guard reported itself",
              v != wd.RED_PROVEN, v)
        check("...and the ORIGINAL loading is the control that makes that attributable",
              ev["original_loads"] is True and ev["mutant_loads"] is False)
        # ...and the control has teeth: a target that does not load UNMUTATED is a broken
        # experiment, not a finding about the mutation.
        subject.write_text("BROKEN = ALSO_MISSING\n")
        v, ev = wd.drive(subject, "BROKEN", "X", suite, "subject-imports-clean", timeout=60)
        check("a target that does not load unmutated is BASELINE_NOT_GREEN",
              v == wd.BASELINE_NOT_GREEN and ev["original_loads"] is False, v)
    finally:
        shutil.rmtree(d, ignore_errors=True)

    # ── D0A-R38-01 ──────────────────────────────────────────────────────────────────────
    # The three stages shared one report path. A process left behind by the BASELINE wrote the
    # expected label during the MUTANT's window and the driver credited it — RED_PROVEN from a
    # suite that reported nothing of its own.
    d, subject, suite = fixture()
    try:
        (d / "suite.py").write_text(
            "import os,sys,time,subprocess,importlib.util\n"
            "spec = importlib.util.spec_from_file_location('s', sys.argv[1])\n"
            "m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)\n"
            "r = os.environ['DELPHI_GUARD_FAILURE_REPORT']\n"
            "if m.verdict(2) == 'REFUSE':\n"
            # Detached stdio, so the parent's capture pipes do not hold this run open: the
            # child genuinely outlives the baseline stage.
            "    subprocess.Popen([sys.executable,'-c','import time,sys;time.sleep(1.5);"
            "open(sys.argv[1],\"a\").write(\"a nonconforming value is REFUSED\" + chr(10))', r],"
            " start_new_session=True, stdin=subprocess.DEVNULL,"
            " stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)\n"
            "    sys.exit(0)\n"
            "time.sleep(3.0)\n"
            "sys.exit(1)\n")
        v, ev = drive(subject, suite, '    if n != 1:', '    if False:')
        check("a label from a SURVIVING baseline child is not the mutant's report",
              v != wd.RED_PROVEN, f"{v}: {ev.get('failing_guards')}")
        check("...the honest verdict is UNVERIFIABLE", v == wd.UNVERIFIABLE, v)
        check("...and each invocation was given a report path of its own",
              ev["baseline"]["report"] != ev["weakened"]["report"],
              f"{ev['baseline']['report']} vs {ev['weakened']['report']}")
    finally:
        shutil.rmtree(d, ignore_errors=True)

    # ── D0A-R38-02 ──────────────────────────────────────────────────────────────────────
    # A tool that mutates the tree owes the tree its lifetime, and the `finally` alone does not
    # provide it: SIGTERM does not raise, and a detached grandchild outlives a timeout.

    # (a) A REAL SIGTERM during the window in which the target is mutated.
    d, subject, suite = fixture()
    try:
        # D0A-R39-02: the suite WRITES THE TARGET a second after the driver is signalled. The
        # first version of this guard observed only the immediate bytes, so it passed while the
        # still-running suite overwrote the restore a second later — and the handler had
        # already deleted the backup.
        (d / "suite.py").write_text(
            "import sys,time,pathlib,importlib.util\n"
            "spec = importlib.util.spec_from_file_location('s', sys.argv[1])\n"
            "m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)\n"
            "if m.verdict(2) != 'REFUSE':\n"
            f"    pathlib.Path(r'{d / 'ready'}').write_text('mutated')\n"
            "    time.sleep(1.0)\n"
            "    open(sys.argv[1],'w').write('CLOBBERED BY ACTIVE SUITE')\n"
            "    time.sleep(30)\n")
        raw = subject.read_bytes()
        proc = subprocess.Popen(
            [sys.executable, str(REPO / "scripts" / "weaken-driver.py"),
             "--target", str(subject), "--anchor", "    if n != 1:",
             "--replacement", "    if False:", "--expect", "x",
             sys.executable, str(d / "suite.py"), str(subject)],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        ready = d / "ready"
        for _ in range(300):
            if ready.exists():
                break
            time.sleep(0.05)
        check("the target IS mutated while the suite runs (the window is real)", ready.exists())
        proc.terminate()
        proc.wait(timeout=20)
        check("a SIGTERM'd driver still restores the target", subject.read_bytes() == raw,
              subject.read_bytes().decode()[:60])
        check("...and removes its backup on the way out",
              not (d / "subject.py.weaken-backup").exists())
        time.sleep(2.5)          # past the moment the suite would have written
        check("...and the suite is collected, so it cannot overwrite the restore afterwards",
              subject.read_bytes() == raw, subject.read_bytes().decode()[:60])
    finally:
        shutil.rmtree(d, ignore_errors=True)

    # (b) A grandchild that outlives a TIMEOUT must not come back and rewrite the target.
    d, subject, suite = fixture()
    try:
        (d / "suite.py").write_text(
            "import os,subprocess,sys,time,importlib.util\n"
            "spec = importlib.util.spec_from_file_location('s', sys.argv[1])\n"
            "m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)\n"
            "if m.verdict(2) != 'REFUSE':\n"
            # Detached STDIO so it does not hold the parent's capture pipes open, but NOT a new
            # session: it stays in the suite's process group, which is the ordinary shape of a
            # leftover.
            "    subprocess.Popen([sys.executable,'-c','import time,sys;time.sleep(3);"
            "open(sys.argv[1],\"w\").write(\"CLOBBERED\")', sys.argv[1]],"
            " stdin=subprocess.DEVNULL,"
            " stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)\n"
            "    time.sleep(60)\n")
        raw = subject.read_bytes()
        v, ev = wd.drive(subject, '    if n != 1:', '    if False:',
                         [sys.executable, str(d / "suite.py"), str(subject)], "x", timeout=2)
        check("a hanging suite is still TIMEOUT", v == wd.TIMEOUT, v)
        time.sleep(4.0)          # past the moment the grandchild would have woken
        check("a grandchild that outlived the timeout was collected with the group",
              subject.read_bytes() == raw, subject.read_bytes().decode()[:40])
    finally:
        shutil.rmtree(d, ignore_errors=True)

    # (b2) THE LIMIT, PINNED RATHER THAN CLAIMED CLOSED. A descendant that calls `setsid`
    # leaves the group, and no `killpg` can reach it. Process-group management is not a
    # guarantee about the tree; it is a guarantee about the group. This guard asserts the hole
    # so that closing it later FAILS here and forces the record to be updated.
    d, subject, suite = fixture()
    try:
        (d / "suite.py").write_text(
            "import os,subprocess,sys,time,importlib.util\n"
            "spec = importlib.util.spec_from_file_location('s', sys.argv[1])\n"
            "m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)\n"
            "if m.verdict(2) != 'REFUSE':\n"
            "    subprocess.Popen([sys.executable,'-c','import time,sys;time.sleep(3);"
            "open(sys.argv[1],\"w\").write(\"CLOBBERED\")', sys.argv[1]],"
            " start_new_session=True, stdin=subprocess.DEVNULL,"
            " stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)\n"
            "    time.sleep(60)\n")
        raw = subject.read_bytes()
        wd.drive(subject, '    if n != 1:', '    if False:',
                 [sys.executable, str(d / "suite.py"), str(subject)], "x", timeout=2)
        time.sleep(4.0)
        check("KNOWN LIMIT: a descendant that calls setsid escapes the group and can still "
              "write the target",
              subject.read_bytes() != raw,
              "the escape was closed — update the register and delete this guard")
    finally:
        shutil.rmtree(d, ignore_errors=True)

    # (c) The backup is a REFUSAL, not a convenience: one left behind means an experiment
    # ended without restoring, and the next run must not overwrite that record.
    d, subject, suite = fixture()
    try:
        (d / "subject.py.weaken-backup").write_bytes(b"an earlier run's original\n")
        try:
            drive(subject, suite, '    if n != 1:', '    if False:')
            check("a stale backup refuses the run", False, "no Refusal was raised")
        except wd.Refusal as e:
            check("a stale backup refuses the run", "weaken-backup" in str(e), str(e))
    finally:
        shutil.rmtree(d, ignore_errors=True)

    # (d) ...and a restore that did not land RETAINS it, because that is when it is needed.
    d, subject, suite = fixture()
    try:
        v, ev = wd.drive(subject, '    if n != 1:', '    if False:', suite, "x", timeout=60,
                         _restore=lambda b: subject.write_bytes(b + b"# not the original\n"))
        check("a failed restore retains the backup", v == wd.RESTORE_FAILED
              and pathlib.Path(ev["backup_retained"]).read_bytes() == SUBJECT.encode(),
              f"{v}: {ev.get('backup_retained')}")
    finally:
        shutil.rmtree(d, ignore_errors=True)

    # ── D0A-R39-01 ──────────────────────────────────────────────────────────────────────
    # THREE ROUNDS, THREE PROXIES FOR "the mutant is valid": text (R36-06), compilation
    # (R38-03), an import that can resolve elsewhere (R39-01). Validity is now bound to the
    # bytes on disk, and these guards construct the cache deterministically with `os.utime`
    # rather than racing a timestamp second.
    d = pathlib.Path(tempfile.mkdtemp(prefix="weaken-driver-cache-"))
    try:
        tgt = d / "subject.py"
        VALID, INVALID = b"FLAG = 1\n", b"FLAG = (\n"      # same size, second is a SyntaxError
        check("the cache fixture's two bodies are the same size", len(VALID) == len(INVALID))
        tgt.write_bytes(VALID)
        # Create a real bytecode cache for the VALID bytes...
        subprocess.run([sys.executable, "-c",
                        "import importlib.util,sys\n"
                        "spec = importlib.util.spec_from_file_location('s', sys.argv[1])\n"
                        "m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)\n",
                        str(tgt)], capture_output=True)
        pycs = list((d / "__pycache__").glob("subject.*.pyc")) if (d / "__pycache__").is_dir() else []
        check("the cache fixture actually produced a .pyc", len(pycs) == 1, str(pycs))
        mtime = tgt.stat().st_mtime
        # ...then swap in the INVALID bytes and restore the mtime. The pyc header records the
        # source mtime truncated to SECONDS and its size, so the cache is now live for bytes
        # that do not compile.
        tgt.write_bytes(INVALID)
        os.utime(tgt, (mtime, mtime))
        probe = subprocess.run([sys.executable, "-c",
                                "import importlib.util,sys\n"
                                "spec = importlib.util.spec_from_file_location('s', sys.argv[1])\n"
                                "m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)\n",
                                str(tgt)], capture_output=True)
        check("CONTROL: an IMPORT of the invalid bytes succeeds from the stale cache",
              probe.returncode == 0,
              "the cache was not live, so the guard below would prove nothing")
        digest = wd._digest(tgt)
        status, detail, _obs = wd._loads(wd._validation_cmd(tgt, digest), 60)
        check("validation reads the BYTES, so the invalid mutant does not load",
              status == wd.LOAD_FAILED, f"{status}: {detail}")

        # ...and the digest binds validation to what the driver measured.
        status, _, _obs = wd._loads(wd._validation_cmd(tgt, "0" * 64), 60)
        check("a target whose bytes are not the measured bytes is DIGEST_MISMATCH",
              status == wd.DIGEST_MISMATCH, status)
        tgt.write_bytes(VALID)
        status, detail, _obs = wd._loads(wd._validation_cmd(tgt, wd._digest(tgt)), 60)
        check("...and valid bytes with their own digest still load", status == wd.LOADED,
              f"{status}: {detail}")
    finally:
        shutil.rmtree(d, ignore_errors=True)

    # The SUITE may import the target even though validation does not, so a stale cache would
    # let it judge the ORIGINAL while the mutant sat on disk — NOT_CAUGHT for a weaken that
    # would have bitten. The mutant's compiled form must not outlive the write.
    d = pathlib.Path(tempfile.mkdtemp(prefix="weaken-driver-purge-"))
    try:
        tgt = d / "subject.py"
        tgt.write_bytes(b"FLAG = 1\n")
        cache = d / "__pycache__"
        cache.mkdir()
        stale = cache / "subject.cpython-999.pyc"
        stale.write_bytes(b"stale")
        wd._purge_bytecode(tgt)
        check("a stale compiled form of the target is purged", not stale.exists())
        check("...and the cache directory itself is left alone", cache.is_dir())
        suite_py = d / "suite.py"
        suite_py.write_text(
            "import importlib.util,os,sys\n"
            "def check(label, cond):\n"
            "    if not cond:\n"
            "        r = os.environ.get('DELPHI_GUARD_FAILURE_REPORT')\n"
            "        if r: open(r,'a').write(label + chr(10))\n"
            "        sys.exit(1)\n"
            "spec = importlib.util.spec_from_file_location('s', sys.argv[1])\n"
            "m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)\n"
            "check('flag-is-one', m.FLAG == 1)\n")
        v, ev = wd.drive(tgt, "1", "2", [sys.executable, str(suite_py), str(tgt)],
                         "flag-is-one", timeout=60)
        # REGRESSION GUARD, NOT THE DISCRIMINATING CASE, and said so because the difference
        # matters. With the purge in place this is stable (5/5 RED_PROVEN); with the purge
        # REMOVED it is intermittent (measured 4 NOT_CAUGHT / 1 RED_PROVEN in 5), because
        # whether the stale cache stays valid depends on the run crossing a timestamp second.
        # An intermittent discriminator is Iron Law 15 clause 2's third worthless case, so the
        # purge is proven by the deterministic unit guard above, not by this one.
        check("a same-size weaken is still CAUGHT by a suite that IMPORTS the target",
              v == wd.RED_PROVEN, f"{v}: {ev.get('reason')}")
        # A .pyc for the RESTORED bytes is expected — the post-restore green run imports the
        # target again. What must not survive is a compiled form of the MUTANT, so the
        # property is what a fresh import now observes.
        after = subprocess.run(
            [sys.executable, "-c",
             "import importlib.util,sys\n"
             "spec = importlib.util.spec_from_file_location('s', sys.argv[1])\n"
             "m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)\n"
             "print(m.FLAG)\n", str(tgt)], capture_output=True, text=True)
        check("...and a fresh import afterwards observes the RESTORED value, not the mutant",
              after.stdout.strip() == "1", f"{after.stdout.strip()!r} {after.stderr[-200:]}")
    finally:
        shutil.rmtree(d, ignore_errors=True)

    # ── D0A-R39-03 ──────────────────────────────────────────────────────────────────────
    # Validation EXECUTES target code, so it can leave children behind. It was added by
    # R38-03's fix and ran through plain `subprocess.run`, outside every group R38-02's fix
    # manages — two fixes from one round that did not compose.
    d = pathlib.Path(tempfile.mkdtemp(prefix="weaken-driver-validchild-"))
    try:
        subject = d / "subject.py"
        subject.write_bytes(b"MODE = 'plain'\n")
        suite_py = d / "suite.py"
        suite_py.write_text(
            "import importlib.util,os,sys\n"
            "def check(label, cond):\n"
            "    if not cond:\n"
            "        r = os.environ.get('DELPHI_GUARD_FAILURE_REPORT')\n"
            "        if r: open(r,'a').write(label + chr(10))\n"
            "        sys.exit(1)\n"
            "spec = importlib.util.spec_from_file_location('s', sys.argv[1])\n"
            "m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)\n"
            "check('mode-is-plain', m.MODE == 'plain')\n")
        # A perfectly VALID mutant that spawns an ordinary child at import — no setsid, so
        # this is not the pinned group escape; it was simply never in a managed group.
        repl = ("'spawned'\nimport subprocess as _s, sys as _sys\n"
                "_s.Popen([_sys.executable,'-c','import time,sys;time.sleep(1.0);"
                "open(sys.argv[1],\"w\").write(\"CLOBBERED BY VALIDATION\")', __file__],"
                " stdin=-3, stdout=-3, stderr=-3)\n")
        raw = subject.read_bytes()
        v, ev = wd.drive(subject, "'plain'", repl, [sys.executable, str(suite_py), str(subject)],
                         "mode-is-plain", timeout=60)
        check("a validation-phase child cannot outlive the run", v == wd.RED_PROVEN, str(v))
        time.sleep(2.5)
        check("...and the target still holds the restored bytes after its deadline",
              subject.read_bytes() == raw, subject.read_bytes().decode()[:60])
    finally:
        shutil.rmtree(d, ignore_errors=True)

    # ── D0A-R41-02 ──────────────────────────────────────────────────────────────────────
    # `git hash-object -- <path>` applies filters. Two exposure levels, tested separately:
    # eol normalisation (live in this repo, `.gitattributes` sets `text auto, eol lf`) and
    # clean filters running arbitrary commands (latent — none configured here).
    d = pathlib.Path(tempfile.mkdtemp(prefix="weaken-driver-filters-"))
    try:
        subprocess.run(["git", "init", "-q", str(d)], check=True, capture_output=True)
        for k, v in (("user.email", "t@t"), ("user.name", "t")):
            subprocess.run(["git", "-C", str(d), "config", k, v], check=True)
        (d / ".gitattributes").write_text("* text eol=lf\n")
        crlf = d / "crlf.py"
        crlf.write_bytes(b"x = 1\r\n")
        subprocess.run(["git", "-C", str(d), "add", "-A"], check=True, capture_output=True)
        subprocess.run(["git", "-C", str(d), "commit", "-qm", "seed"], check=True,
                       capture_output=True)
        ref = wd._source_ref(crlf)
        check("a CRLF source's digest is of its REAL bytes",
              ref["sha256"] == wd._digest_bytes(crlf.read_bytes()))
        if ref.get("git_blob"):
            blob = subprocess.run(["git", "-C", str(d), "cat-file", "blob", ref["git_blob"]],
                                  capture_output=True).stdout
            check("...and any git_blob it records holds exactly those bytes",
                  wd._digest_bytes(blob) == ref["sha256"],
                  "the reference binds bytes that are not the bytes measured")
        else:
            check("...and with no matching object git_blob is not claimed, so content travels",
                  ref.get("content") is not None)

        # A clean filter is an arbitrary command. Binding a source must not run one.
        sentinel = d / "FILTER-RAN"
        subprocess.run(["git", "-C", str(d), "config", "filter.evil.clean",
                        f"sh -c 'touch {sentinel}; cat'"], check=True)
        (d / ".gitattributes").write_text("* filter=evil\n")
        wd._source_ref(crlf)
        check("binding a source runs NO clean filter", not sentinel.exists(),
              "a filter executed against the working tree while recording evidence")
    finally:
        shutil.rmtree(d, ignore_errors=True)

    src_now = (REPO / "scripts" / "weaken-driver.py").read_text().splitlines()
    filtering = [l.strip() for l in src_now
                 if "hash-object" in l and not l.lstrip().startswith("#")
                 and not l.lstrip().startswith("*") and '"""' not in l
                 and "D0A-R41-02" not in l and "the target during" not in l]
    check("no code path invokes `git hash-object`", not filtering, str(filtering))

    # Structural: there is ONE way to start a process here. A second path is how validation
    # ended up outside lifetime management in the first place.
    src = (REPO / "scripts" / "weaken-driver.py").read_text().splitlines()
    direct = [l.strip() for l in src
              if "subprocess.run(" in l and not l.lstrip().startswith("#")]
    check("every subprocess goes through the managed primitive", not direct, str(direct))

    # ── D0A-R39: THE RECORD ─────────────────────────────────────────────────────────────
    # The ID is content-addressed, so the canonical body must EXCLUDE the id itself. A
    # self-referential hash that works on the first record and breaks on the second is the
    # kind of thing that ships.
    base = {"schema": wd.SCHEMA, "verdict": "RED_PROVEN", "expectation": {"guard": "g"},
            "limits": wd.RECORD_LIMITS}
    rid = wd.record_id(base)
    check("the id is stable when the body is unchanged", wd.record_id(base) == rid)
    check("...and an id already present does not feed its own hash",
          wd.record_id({**base, "id": rid}) == rid and
          wd.record_id({**base, "id": "0" * 16}) == rid)
    check("...and a different body gives a different id",
          wd.record_id({**base, "verdict": "NOT_CAUGHT"}) != rid)
    check("the id is 16 hex characters", re.fullmatch(r"[0-9a-f]{16}", rid) is not None, rid)

    d, subject, suite = fixture()
    rec_dir = pathlib.Path(tempfile.mkdtemp(prefix="weaken-records-"))
    try:
        v, ev = drive(subject, suite, '    if n != 1:', '    if False:')
        body = wd.build_record(subject, '    if n != 1:', '    if False:', suite,
                               "a nonconforming value is REFUSED", v, ev)
        path = wd.write_record(rec_dir, body)
        on_disk = json.loads(path.read_text())
        check("a record written by the driver verifies against its own bytes",
              wd.record_id(on_disk) == on_disk["id"] == body["id"], str(body["id"]))
        check("the record names the file it was filed under", path.name == body["id"] + ".json")

        # The disagreement test: could a reader re-open this?
        check("the expectation is registered BEFORE any invocation",
              body["expectation"]["registered_at"] == 0.0
              and all(p["started_at"] >= 0.0 for p in body["phases"]))
        check("every phase carries a duration, not only an outcome",
              all("duration_s" in p for p in body["phases"]),
              str([p["name"] for p in body["phases"] if "duration_s" not in p]))
        check("the phases cover baseline, validation, observation and restoration",
              {"validate-original", "baseline", "validate-mutant", "observe", "restore",
               "restored"} <= {p["name"] for p in body["phases"]},
              str([p["name"] for p in body["phases"]]))
        check("the instrument and the subject are DISTINCT fields",
              body["instrument"]["digest_executing"] != body["subject"]["digest_before"]
              and body["subject"]["is_the_instrument_file"] is False)
        check("...and the subject's three digests are all recorded",
              all(body["subject"][k] for k in
                  ("digest_before", "digest_mutant", "digest_restored")))
        # ── D0A-R40-01: THE EVIDENCE CONTRACT ───────────────────────────────────────────
        # The consumer checked a hash and a declared verdict, so a record with no experiment
        # in it was accepted. Both sides now answer to REQUIRED_PATHS, and this iterates that
        # same list against a REAL producer record — so a path added to the contract is
        # covered here without anyone remembering to add a case.
        check("a real producer record satisfies the contract",
              wd.validate_record(on_disk) == [], str(wd.validate_record(on_disk)))
        survived = []
        for path in wd.REQUIRED_PATHS:
            maimed = json.loads(json.dumps(on_disk))
            node, *rest = path.split(".")
            if rest:
                maimed.get(node, {}).pop(rest[0], None)
            else:
                maimed.pop(node, None)
            # Re-seal so the ONLY defect is the missing field — except when the missing
            # field IS the id, where re-sealing would put it back.
            if path != "id":
                maimed["id"] = wd.record_id(maimed)
            if not wd.validate_record(maimed):
                survived.append(path)
        check("removing ANY required field is rejected", not survived, str(survived))

        # A verdict is a claim about an experiment; these are the observations it needs.
        for label, mangle in (
            ("the expected guard is not among the observed failures",
             lambda r: r["observations"].update(failing_guards=["something else"])),
            ("the mutant never loaded",
             lambda r: r["observations"].update(mutant_validation="load-failed")),
            ("restoration was not verified",
             lambda r: r["subject"].update(digest_restored="0" * 64)),
            ("a phase that would show it is absent",
             lambda r: r.update(phases=[p for p in r["phases"] if p["name"] != "observe"])),
        ):
            bad = json.loads(json.dumps(on_disk))
            mangle(bad)
            bad["id"] = wd.record_id(bad)
            check(f"RED_PROVEN is rejected when {label}", wd.validate_record(bad),
                  "the contract accepted a verdict its own record does not support")

        # ── D0A-R41-01 / D0A-R42-01 / D0A-R42-04 ────────────────────────────────────────
        # THREE ITERATIONS OF ONE MISTAKE, each a level down: R40-01 required no evidence,
        # R41-01 required containers, R42-01 required containers whose contents could
        # CONTRADICT the claim. And R42-04 is the same defect on this side — my fixture
        # deleted `outcome` and `streams` TOGETHER, so neither was individually load-bearing,
        # and I tested only ABSENT invocations, never invalid ones. Three weakens of the
        # contract survived with all 141 guards passing.
        #
        # So: ONE MUTATION PER OBLIGATION, varying one field at a time. A fixture that moves
        # several things at once cannot discriminate any of them.
        def mangled(fn):
            bad = json.loads(json.dumps(on_disk))
            fn(bad)
            bad["id"] = wd.record_id(bad)
            return bad

        def phase(rec, name):
            return next(p for p in rec["phases"] if p["name"] == name)

        for name, key, want_green in wd._INVOCATIONS:
            obligations = [
                (f"phase {name!r} without its outcome",
                 lambda b, n=name: phase(b, n).pop("outcome", None)),
                (f"phase {name!r} without its streams",
                 lambda b, n=name: phase(b, n).pop("streams", None)),
                (f"phase {name!r} disagreeing with the summary that cites it",
                 lambda b, n=name: phase(b, n).update(outcome="signalled")),
                (f"the {key} invocation absent",
                 lambda b, k=key: b["observations"].pop(k, None)),
                (f"the {key} invocation not having EXITED",
                 lambda b, k=key: b["observations"][k].update(outcome="timed-out")),
                (f"the {key} invocation's exit code contradicting RED_PROVEN",
                 lambda b, k=key, g=want_green: b["observations"][k].update(
                     code=(7 if g else 0))),
            ]
            for label, fn in obligations:
                check(f"rejected: {label}", wd.validate_record(mangled(fn)),
                      "this obligation has no mutation that fails it alone")

        for name, key in wd._VALIDATIONS:
            obligations = [
                (f"phase {name!r} without any validation evidence",
                 lambda b, n=name: phase(b, n).pop("validation", None)),
                (f"phase {name!r} running validation but recording no argv",
                 lambda b, n=name: phase(b, n)["validation"].pop("argv", None)),
                (f"phase {name!r} running validation but recording no exit",
                 lambda b, n=name: phase(b, n)["validation"].pop("exit", None)),
                (f"phase {name!r} exiting nonzero while {key} says it loaded",
                 lambda b, n=name: phase(b, n)["validation"].update(exit=1)),
                (f"phase {name!r} not saying whether validation ran",
                 lambda b, n=name: phase(b, n).update(validation={"reason": "silent"})),
            ]
            for label, fn in obligations:
                check(f"rejected: {label}", wd.validate_record(mangled(fn)),
                      "this obligation has no mutation that fails it alone")
            # ...and a target with NO validation command is a real case, not a defect.
            ok = mangled(lambda b, n=name: phase(b, n).update(
                validation={"ran": False, "reason": "no validation command"}))
            check(f"accepted: {name!r} saying validation did not run",
                  not wd.validate_record(ok), str(wd.validate_record(ok)[:2]))

        # A reference that NAMES bytes is not a reference that BINDS them.
        for where, mangle in (
            ("inputs.subject_original", lambda r: r["inputs"].update(subject_original={"path": "x"})),
            ("inputs.instrument", lambda r: r["inputs"].update(instrument={"path": "x"})),
            ("suite.sources[0]", lambda r: r["suite"]["sources"].__setitem__(0, {"path": "x"})),
        ):
            check(f"a path-only placeholder at {where} is rejected",
                  wd.validate_record(mangled(mangle)), "a placeholder satisfied the contract")

        # The summary is not the observation.
        check("the weakened invocation's OWN report must name the expected guard",
              wd.validate_record(mangled(lambda b: b["observations"]["weakened"].update(labels=[]))),
              "`failing_guards` alone satisfied a claim about what the run observed")

        # `{"path": ...}` fails BOTH halves of a source reference, so it cannot discriminate
        # either — weakening the sha256 requirement against it returned NOT_CAUGHT. Each half
        # needs a case only IT refuses.
        bad = json.loads(json.dumps(on_disk))
        ref = dict(bad["inputs"]["subject_original"]); ref.pop("sha256")
        bad["inputs"]["subject_original"] = ref
        bad["id"] = wd.record_id(bad)
        check("a reference carrying content but NO sha256 is rejected", wd.validate_record(bad),
              "content without a digest binds nothing: the bytes name themselves")
        bad = json.loads(json.dumps(on_disk))
        ref = dict(bad["inputs"]["subject_original"]); ref.pop("content")
        bad["inputs"]["subject_original"] = ref
        bad["id"] = wd.record_id(bad)
        check("a reference carrying a sha256 but NOTHING to resolve it is rejected",
              wd.validate_record(bad), "a digest alone cannot recover an untracked file")

        # The summary is not the observation.
        bad = json.loads(json.dumps(on_disk))
        bad["observations"]["weakened"]["labels"] = []
        bad["id"] = wd.record_id(bad)
        check("the weakened invocation's OWN report must name the expected guard",
              wd.validate_record(bad),
              "`failing_guards` alone satisfied a claim about what the run observed")

        # The producer answers to the contract too: a record that could not be accepted
        # should never be written.
        try:
            wd.write_record(rec_dir, {"id": "x", "verdict": "RED_PROVEN"})
            check("the producer refuses to write a record that fails the contract", False,
                  "it wrote one")
        except wd.Refusal as e:
            check("the producer refuses to write a record that fails the contract",
                  "evidence contract" in str(e), str(e)[:120])

        check("the record carries its own limits, so a citation cannot shed them",
              body["limits"] == wd.RECORD_LIMITS and len(body["limits"]) >= 5)
        check("the suite argv and cwd are recorded, so the run is reconstructable",
              body["suite"]["argv"] == suite and body["suite"]["cwd"])
        # The comment above this field once read "retained whole" over a field that retained
        # nothing. The streams are where a reader spots "it never reached the gate".
        ran = [p for p in body["phases"] if "streams" in p]
        check("the subject's own output is RETAINED on the phases that produced it",
              len(ran) == 3, str([p["name"] for p in body["phases"]]))
        check("...and it is the real output, not a placeholder",
              any("guards held" in p["streams"]["stdout"] or p["streams"]["stdout"].strip()
                  for p in ran), str(ran[0]["streams"])[:120])
        big = wd._streams(wd.Invocation(wd.EXITED, stdout="x" * (wd.STREAM_CAP + 10)))
        # `.get`, not `[...]`: indexing evaluates BEFORE `check` is called, so under a weaken
        # that removes the key the guard raises KeyError and reports NOTHING — the driver
        # returned UNVERIFIABLE for exactly that, which is the honest verdict for an assertion
        # that cannot reach its own side channel.
        check("a capped stream SAYS it was capped",
              big.get("stdout_truncated_from") == wd.STREAM_CAP + 10
              and len(big.get("stdout", "")) == wd.STREAM_CAP, str(list(big)))
        check("...and an uncapped one carries no truncation marker",
              "stdout_truncated_from" not in wd._streams(wd.Invocation(wd.EXITED, stdout="ok")))

        # ── D0A-R40-02 ──────────────────────────────────────────────────────────────────
        # a7c6e196 and 7dc26d27 are identical in instrument, subject, suite and expectation
        # and carry different verdicts, because the SUITE FILE's bytes decided and nothing
        # recorded them. Binding argv binds nothing.
        refs = {r["path"]: r for r in body["suite"]["sources"]}
        suite_files = [a for a in suite if pathlib.Path(a).is_file()]
        check("every suite argv element that is a file is bound by content",
              set(refs) == set(suite_files), f"{sorted(refs)} vs {sorted(suite_files)}")
        check("...by sha256, and by a git blob or the bytes themselves",
              all(r.get("sha256") and (r.get("git_blob") or r.get("content") is not None)
                  for r in refs.values()), str(list(refs.values()))[:200])
        check("the subject's ORIGINAL bytes travel with the record",
              body["inputs"]["subject_original"]["sha256"] == body["subject"]["digest_before"]
              and body["inputs"]["subject_original"]["content"],
              str(body["inputs"]["subject_original"])[:160])
        check("the driver's working state stays out of the printed evidence",
              all(not k.startswith("_") for k in body.get("observations", {})),
              str([k for k in body.get("observations", {}) if k.startswith("_")]))
        check("the execution settings that shaped the run are recorded",
              body["execution"]["timeout_s"] and body["execution"]["interpreter"]
              and body["execution"]["python"], str(body["execution"]))

        # ── D0A-R40-03 ──────────────────────────────────────────────────────────────────
        val = [p for p in body["phases"] if p["name"].startswith("validate-")]
        check("validation phases carry a process observation, not only timing",
              len(val) == 2 and all("validation" in p for p in val),
              str([sorted(p) for p in val]))
        check("...including exit, streams and the argv that produced them",
              all(p["validation"].get("ran") and "streams" in p["validation"]
                  and p["validation"].get("exit") == 0 and p["validation"].get("argv")
                  for p in val), str(val[0]["validation"])[:200])
    finally:
        shutil.rmtree(d, ignore_errors=True)
        shutil.rmtree(rec_dir, ignore_errors=True)

    # A TIMED-OUT invocation must not drop what `_managed_run` already collected.
    d, subject, suite = fixture()
    try:
        (d / "suite.py").write_text(
            "import sys,time\nprint('BEFORE THE HANG', flush=True)\n"
            "sys.stderr.write('ON STDERR\\n'); sys.stderr.flush()\ntime.sleep(30)\n")
        v, ev = wd.drive(subject, '    if n != 1:', '    if False:',
                         [sys.executable, str(d / "suite.py")], "x", timeout=2)
        check("a TIMEOUT is still a TIMEOUT", v == wd.TIMEOUT, v)
        base = ev["baseline"]
        check("...and it retains the streams the subject produced before hanging",
              "BEFORE THE HANG" in base["stdout"] and "ON STDERR" in base["stderr"],
              f"{base['stdout']!r} {base['stderr']!r}")
    finally:
        shutil.rmtree(d, ignore_errors=True)
        shutil.rmtree(rec_dir, ignore_errors=True)

    # And the self-weaken case the record exists for: when the driver is its OWN subject,
    # the executing bytes and the mutated bytes are different things.
    body = wd.build_record(pathlib.Path(wd.__file__), "a", "b", ["x"], "g", "RED_PROVEN",
                           {"digest_before": "deadbeef"})
    check("a self-weaken is marked as one", body["subject"]["is_the_instrument_file"] is True)
    check("...and the EXECUTING digest is still reported separately from the subject's",
          body["instrument"]["digest_executing"] != body["subject"]["digest_before"])

    # ── D0A-R40: THE CLAIM INVENTORY IS CHECKED, NOT READ ───────────────────────────────
    # A register note is quarantine, not disposition. The failure mode of a prose inventory is
    # that it reads as complete when it is not, so the inventory is joined to `git log` here:
    # a commit in the covered range that carries a RED-proof claim and is absent from the
    # table fails this guard.
    inv = (REPO / "docs" / "PROOF_CLAIM_INVENTORY.md").read_text()
    m = re.search(r"\*\*Covered range:\*\* `([0-9a-f]+)\.\.([0-9a-f]+)`", inv)
    check("the inventory declares its covered range", m is not None)
    rows = re.findall(r"^\| `([0-9a-f]{7,40})` \| (.+?) \| `([^`]+)` \|$", inv, re.M)
    check("the inventory has rows", len(rows) >= 20, str(len(rows)))
    allowed = {"withdrawn", "narrative"}
    bad = [d for _, _, d in rows if d not in allowed and not d.startswith("record:")]
    check("every row carries one of the three dispositions", not bad, str(bad))

    ledger = REPO / "scratch" / "weaken-records"
    missing = [d.split(":", 1)[1] for _, _, d in rows if d.startswith("record:")
               if not (ledger / f"{d.split(':', 1)[1]}.json").exists()]
    check("every cited record resolves in the ledger", not missing, str(missing))

    # A `record:` disposition that points at a record the CONSUMER would refuse is not a
    # disposition. This is no longer vacuous — 17 rows cite one.
    cited_ids = [d.split(":", 1)[1] for _, _, d in rows if d.startswith("record:")]
    check("the inventory cites records at all, so the checks below are not empty",
          len(cited_ids) >= 1, "no row cites a record")
    invalid = []
    for rid in cited_ids:
        path = ledger / f"{rid}.json"
        if path.exists() and wd.validate_record(json.loads(path.read_text())):
            invalid.append(rid)
    check("every record cited as a disposition satisfies the evidence contract",
          not invalid, f"cited but would be refused: {invalid}")
    # ...and a withdrawn row must NOT be silently backed by a valid record either: the
    # historical ones are withdrawn because their records predate the contract.
    check("the inventory's own guard set covers both dispositions",
          any(d == "withdrawn" for _, _, d in rows) and cited_ids)

    # The guard above is VACUOUS while no row cites a record — it passes because there is
    # nothing to check, which is DEFECT_CLASSES 50's shape. This one never is: the table's
    # own summary line has to match the table.
    tally = {"withdrawn": 0, "narrative": 0, "record": 0}
    for _, _, d in rows:
        tally["record" if d.startswith("record:") else d] += 1
    claimed = re.search(r"\*\*(\d+) withdrawn, (\d+) with records?, (\d+) narrative\.\*\*", inv)
    check("the inventory states its own counts", claimed is not None)
    check("...and the stated counts match the rows",
          (int(claimed.group(1)), int(claimed.group(2)), int(claimed.group(3)))
          == (tally["withdrawn"], tally["record"], tally["narrative"]),
          f"stated {claimed.groups()} vs counted "
          f"{(tally['withdrawn'], tally['record'], tally['narrative'])}")

    rng = subprocess.run(["git", "-C", str(REPO), "log", "--format=%h %H",
                          f"{m.group(1)}..{m.group(2)}"], capture_output=True, text=True)
    check("the covered range resolves in git", rng.returncode == 0, rng.stderr[-200:])
    claiming = []
    for line in rng.stdout.split("\n"):
        if not line.strip():
            continue
        short, full = line.split()
        body = subprocess.run(["git", "-C", str(REPO), "log", "-1", "--format=%B", full],
                              capture_output=True, text=True).stdout
        if re.search(r"RED[-_ ]?PROV", body, re.I):
            claiming.append(short)
    listed = {sha for sha, _, _ in rows}
    unlisted = [c for c in claiming
                if not any(c.startswith(l) or l.startswith(c) for l in listed)]
    check("every commit in range that claims RED-proof appears in the inventory",
          not unlisted, f"absent: {unlisted}")
    check("...and the range's endpoint commit is covered too",
          any(l.startswith(m.group(2)[:7]) or m.group(2).startswith(l) for l in listed),
          m.group(2))

    # ── D0A-R41-07: THE COMPARATOR'S SENSITIVITY ────────────────────────────────────────
    # A blanket "no two records collide" assertion passes near-vacuously on a small ledger
    # and says nothing about WHICH differences the tool can see — the D0A-R41 ruling asks for
    # sensitivity instead. Each relevant input is changed on its own; the tool must notice.
    spec_ld = importlib.util.spec_from_file_location(
        "ld", REPO / "scripts" / "ledger-distinguishable.py")
    ld = importlib.util.module_from_spec(spec_ld)
    spec_ld.loader.exec_module(ld)
    base = json.loads((REPO / "scratch" / "weaken-records" /
                       "445b1fb1e289af02.json").read_text())
    check("the comparator sees a record as identical to itself",
          ld.inputs(base) == ld.inputs(json.loads(json.dumps(base))))

    for label, mangle in (
        ("the instrument digest", lambda r: r["instrument"].update(digest_executing="x")),
        ("the subject's before-digest", lambda r: r["subject"].update(digest_before="x")),
        ("the mutation", lambda r: r["subject"].update(replacement="something else")),
        ("the suite argv", lambda r: r["suite"]["argv"].append("--extra")),
        ("a suite source's bytes", lambda r: r["suite"]["sources"][0].update(sha256="x")),
        ("the expected guard", lambda r: r["expectation"].update(guard="another guard")),
        ("the timeout", lambda r: r["execution"].update(timeout_s=1)),
        ("the subject's original bytes",
         lambda r: r["inputs"]["subject_original"].update(sha256="x")),
        # D0A-R42-05: these used to move BOTH validation commands at once, so the
        # original-phase difference concealed blindness to the mutant phase — excluding
        # `validate-mutant` from the comparator still left every guard passing. One phase
        # at a time, for the same reason the contract's obligations get one mutation each.
        ("the VALIDATION COMMAND of validate-original",
         lambda r: [p.setdefault("validation", {}).update(argv=["other-validator"])
                    for p in r["phases"] if p["name"] == "validate-original"]),
        ("the VALIDATION COMMAND of validate-mutant",
         lambda r: [p.setdefault("validation", {}).update(argv=["other-validator"])
                    for p in r["phases"] if p["name"] == "validate-mutant"]),
    ):
        other = json.loads(json.dumps(base))
        mangle(other)
        check(f"...and distinguishes two records differing in {label}",
              ld.inputs(base) != ld.inputs(other),
              "a relevant input change was invisible to the comparator")

    # ...while still EXCLUDING results and timings, or every pair looks distinct and the tool
    # reports nothing. That exclusion is what makes a collision meaningful.
    for label, mangle in (
        ("phase durations", lambda r: [p.update(duration_s=99.9) for p in r["phases"]]),
        ("the restored digest", lambda r: r["subject"].update(digest_restored="x")),
        ("a validation RESULT", lambda r: [p["validation"].update(exit=7) for p in r["phases"]
                                           if "validation" in p]),
    ):
        other = json.loads(json.dumps(base))
        mangle(other)
        check(f"...and ignores {label}, which is an outcome rather than an input",
              ld.inputs(base) == ld.inputs(other),
              "an outcome leaked into the input projection, making every pair look distinct")

    print(f"\n{PASSED} guards held")
    return 0


if __name__ == "__main__":
    sys.exit(main())
