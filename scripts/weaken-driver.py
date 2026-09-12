#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Drive a weaken end to end and decide, structurally, whether it is RED-proven.

# Why this exists (D0A-R37, after three wrong readings in one session)

"RED-proven" was established by running a weaken and reading a grep. That produced three
wrong claims in a single session:

  * the `b51bd8f` bisect — "only b51bd8f fails", from a binary that never reached the gate;
  * the R36-04 weaken — "RED-proven", committed and then withdrawn, when the suite had PASSED;
  * the R36-06 weaken — "NO BITE", when the mutation died on a `NameError`.

Each was a reading rule failing. A fourth reading rule is not the answer: the filter returns
the same empty string for success, for absence, and for malformed input (`DEFECT_CLASSES` 50).

**This driver never greps.** The failing guard identifies itself through a SIDE CHANNEL — the
suite's `check()` writes its label to a file whose path this process chooses per invocation —
and the driver compares labels. Everything else it decides from exit statuses and file
digests.

# What it proves, and what it does not

It proves a weaken made the INTENDED guard fail, that the mutation was applied and buildable,
and that restoration returned the tree byte-for-byte. **It does not prove the guard is
well-chosen.** `NOT_CAUGHT` remains ambiguous between "this check is redundant" and
`DEFECT_CLASSES` 58's "the condition was never arranged", and the driver reports that
ambiguity rather than resolving it — naming it is the most it can honestly do.

# The refusal that makes it different from a convention

`RED_PROVEN` requires the side-channel report to exist and to name the expected guard. If the
report is missing, the verdict is `UNVERIFIABLE` — never `RED_PROVEN` — because the only
remaining way to identify the failure would be to read text, which is the thing this replaces.
"""

from __future__ import annotations

import argparse
import hashlib
import os
import pathlib
import subprocess
import sys
import tempfile

# Every way the chain can break, each a distinct verdict. Collapsing any two of these is how a
# non-measurement becomes a proof.
BASELINE_NOT_GREEN = "BASELINE_NOT_GREEN"      # the suite failed BEFORE the weaken
MUTATION_NOT_APPLIED = "MUTATION_NOT_APPLIED"  # the anchor did not match; nothing changed
MUTATION_INVALID = "MUTATION_INVALID"          # the weakened source does not parse or build
NOT_CAUGHT = "NOT_CAUGHT"                      # the suite still PASSED: nothing bit
WRONG_GUARD = "WRONG_GUARD"                    # something failed, but not the intended one
UNVERIFIABLE = "UNVERIFIABLE"                  # no structured report; refuse to claim
TIMEOUT = "TIMEOUT"
RESTORE_FAILED = "RESTORE_FAILED"              # the tree did not come back byte-identical
RED_PROVEN = "RED_PROVEN"                      # and only here


def _digest(p: pathlib.Path) -> str:
    return hashlib.sha256(p.read_bytes()).hexdigest()


def _run(cmd: list[str], report: pathlib.Path | None, timeout: int) -> tuple[int, list[str]]:
    """Run a suite; return its exit status and the labels its failing checks reported."""
    env = dict(os.environ)
    if report is not None:
        report.unlink(missing_ok=True)
        env["DELPHI_GUARD_FAILURE_REPORT"] = str(report)
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, env=env)
    except subprocess.TimeoutExpired:
        return -1, []
    labels = []
    if report is not None and report.exists():
        labels = [l.strip() for l in report.read_text().splitlines() if l.strip()]
    return p.returncode, labels


def drive(target: pathlib.Path, anchor: str, replacement: str, suite: list[str],
          expect: str, timeout: int = 900) -> tuple[str, dict]:
    """The six-stage chain. Returns (verdict, evidence)."""
    ev: dict = {"target": str(target), "expect": expect}
    original = target.read_text()
    before = _digest(target)
    ev["digest_before"] = before
    report = pathlib.Path(tempfile.mkdtemp(prefix="weaken-report-")) / "labels.txt"

    # 1. BASELINE. A suite that is already red cannot attribute anything to a weaken.
    rc, labels = _run(suite, report, timeout)
    ev["baseline_exit"] = rc
    if rc == -1:
        return TIMEOUT, ev
    if rc != 0:
        ev["baseline_failing_guards"] = labels
        return BASELINE_NOT_GREEN, ev

    try:
        # 2. APPLY, and VERIFY IT APPLIED. `str.replace` with a missing anchor returns the
        # string unchanged and raises nothing — the silent no-op that has shipped twice here.
        # NOT WEAKEN-PROVEN, AND SAID SO RATHER THAN CLAIMED. Removing this check changes no
        # outcome, because the digest comparison below catches a missing anchor too — a no-op
        # replacement leaves the file byte-identical. It is kept for its MESSAGE (it names the
        # anchor as the cause, where the digest can only say "nothing changed"), and it is
        # DEFENCE IN DEPTH by §6's own definition. "Every check weaken-proven" has been a false
        # claim twice in this arc; this comment is what prevents a third.
        if anchor not in original:
            ev["reason"] = "the anchor does not occur in the target"
            return MUTATION_NOT_APPLIED, ev
        target.write_text(original.replace(anchor, replacement, 1))
        if _digest(target) == before:
            ev["reason"] = "the file is byte-identical after the replacement"
            return MUTATION_NOT_APPLIED, ev
        ev["digest_weakened"] = _digest(target)

        # 3. BUILDABLE. A mutation that does not parse fails for its own reason, which is the
        # INVALID vs NOT CAUGHT distinction the mutation harness itself draws.
        if target.suffix == ".py":
            try:
                compile(target.read_text(), str(target), "exec")
            except SyntaxError as e:
                ev["reason"] = f"the weakened source does not parse: {e}"
                return MUTATION_INVALID, ev

        # 4. RUN UNDER THE WEAKEN.
        rc, labels = _run(suite, report, timeout)
        ev["weakened_exit"] = rc
        ev["failing_guards"] = labels
        if rc == -1:
            return TIMEOUT, ev
        if rc == 0:
            ev["reason"] = ("the suite still passed. Either the check is redundant, or the "
                            "condition it needs was never arranged (DEFECT_CLASSES 58) — "
                            "this driver cannot tell those apart")
            return NOT_CAUGHT, ev

        # 5. ATTRIBUTE — structurally. No text is read.
        if not labels:
            ev["reason"] = ("the suite failed but reported no guard label. Without the side "
                            "channel the only way to attribute this is to read text, which is "
                            "what this driver exists to replace")
            return UNVERIFIABLE, ev
        if expect not in labels:
            ev["reason"] = f"failed on {labels}, not on the expected guard"
            return WRONG_GUARD, ev
    finally:
        # 6. RESTORE, and VERIFY the restore — against the digest, not the write's return.
        target.write_text(original)
        ev["digest_restored"] = _digest(target)

    # ALSO NOT WEAKEN-PROVEN, and for a stronger reason: it is UNREACHABLE as written. The
    # restore writes `original`, so the digest necessarily matches; this fires only if the
    # filesystem returned success on a write that did not land. No discriminating case can be
    # constructed without faking the filesystem, so it is carried as an assertion about a
    # condition that should be impossible rather than as a checked predicate.
    if ev["digest_restored"] != before:
        return RESTORE_FAILED, ev
    rc, _ = _run(suite, report, timeout)
    ev["restored_exit"] = rc
    if rc != 0:
        ev["reason"] = "the suite is not green again after restoration"
        return RESTORE_FAILED, ev
    return RED_PROVEN, ev


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--target", required=True)
    ap.add_argument("--anchor", required=True)
    ap.add_argument("--replacement", default="")
    ap.add_argument("--expect", required=True, help="the guard label the weaken must fail on")
    ap.add_argument("--timeout", type=int, default=900)
    ap.add_argument("suite", nargs="+")
    a = ap.parse_args()

    verdict, ev = drive(pathlib.Path(a.target), a.anchor, a.replacement, a.suite, a.expect,
                        a.timeout)
    print(f"VERDICT: {verdict}")
    for k, v in ev.items():
        print(f"  {k}: {v}")
    if verdict != RED_PROVEN:
        print(f"\nNOT RED-PROVEN. `{verdict}` is not a weakness in the weaken's TARGET; it is a "
              f"statement about the experiment.", file=sys.stderr)
    return 0 if verdict == RED_PROVEN else 1


if __name__ == "__main__":
    sys.exit(main())
