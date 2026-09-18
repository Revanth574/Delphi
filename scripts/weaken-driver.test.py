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
import os
import pathlib
import shutil
import sys
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

    print(f"\n{PASSED} guards held")
    return 0


if __name__ == "__main__":
    sys.exit(main())
