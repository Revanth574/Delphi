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
    assert condition, f"GUARD FAILED: {label}{(' — ' + detail) if detail else ''}"
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

    print(f"\n{PASSED} guards held")
    return 0


if __name__ == "__main__":
    sys.exit(main())
