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
suite's `check()` writes its label to a file this process names PER INVOCATION — and the driver
compares labels. Everything else it decides from recorded observations.

# The record is primary; the verdicts are a derived view (D0A-R38)

The first version made the nine verdicts the design. That was wrong, and three defects had one
cause: FIVE independent facts were being inferred from ONE exit code and ONE report file.

  * **phase** — which stage produced the terminal state
  * **execution outcome** — `exited` / `signalled` / `timed-out` / `launch-failed`, kept apart,
    because a process killed by SIGHUP has returncode -1 and that was read as the timeout
    sentinel
  * **validity** — whether the mutant LOADS, measured against the same command run on the
    unmutated target, because `compile()` proves syntax and a `NameError` at import is an
    invalid experiment rather than a detection
  * **guard observation** — labels from a report path allocated per invocation, because a
    process left behind by the baseline could otherwise write into the mutant's window
  * **restoration** — bytes back, verified on every terminal path, and the suite green again

Each is observed on its own terms and recorded; the verdict is read off the record afterwards.

# What it proves, and what it does not

It proves a weaken made the INTENDED guard fail, that the mutation was applied and loadable,
and that restoration returned the tree byte-for-byte. **It does not prove the guard is
well-chosen.** `NOT_CAUGHT` remains ambiguous between "this check is redundant" and
`DEFECT_CLASSES` 58's "the condition was never arranged", and the driver reports that ambiguity
rather than resolving it.

**And the side channel is a report channel for TRUSTED HELPERS, not unforgeable evidence.** The
path is inherited by the whole subject process tree; anything in it can write any label. What
per-invocation allocation buys is that a label cannot arrive from a stale file, a previous run,
a hardcoded path, or an EARLIER STAGE OF THIS RUN. It buys nothing against a hostile subject.

# The refusal that makes it different from a convention

`RED_PROVEN` requires this invocation's report to exist and to name the expected guard. If the
report is missing, the verdict is `UNVERIFIABLE` — never `RED_PROVEN` — because the only
remaining way to identify the failure would be to read text, which is the thing this replaces.
"""

from __future__ import annotations

import argparse
import hashlib
import os
import pathlib
import signal
import subprocess
import sys
import tempfile
import typing

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

# D0A-R38-01/03/09: THE VERDICTS ARE A DERIVED VIEW, NOT THE RECORD. Five independent facts
# were being inferred from one exit code and one report file, which is why three separate
# defects had one cause. Each is now OBSERVED and recorded on its own terms, and the verdict is
# read off the record afterwards.
EXITED, SIGNALLED, TIMED_OUT, LAUNCH_FAILED = "exited", "signalled", "timed-out", "launch-failed"


class Invocation(typing.NamedTuple):
    """One run of the suite: how it ended, and what it reported, kept apart."""
    outcome: str
    code: int | None = None        # set when EXITED
    signal: int | None = None      # set when SIGNALLED — never folded into `code`
    labels: list[str] = []
    report: str = ""
    survivors: bool = False        # anything still alive in the group when the stage ended

    @property
    def green(self) -> bool:
        return self.outcome == EXITED and self.code == 0


def _digest_bytes(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def _digest(p: pathlib.Path) -> str:
    return _digest_bytes(p.read_bytes())


def _run(cmd: list[str], report_dir: pathlib.Path, tag: str, timeout: int) -> Invocation:
    """Run a suite once, into a report path of its OWN.

    D0A-R38-01: the three stages shared one path. `unlink` cannot revoke a descriptor or a
    pathname from a child that outlived an earlier stage, so a process left behind by the
    BASELINE could write the expected label during the MUTANT's window and the driver credited
    it — RED_PROVEN from a suite that reported nothing. A path allocated per invocation cannot
    be written by an invocation that was never told it.
    """
    report = report_dir / f"labels-{tag}.txt"
    env = dict(os.environ)
    env["DELPHI_GUARD_FAILURE_REPORT"] = str(report)
    try:
        # D0A-R38-02: OWN PROCESS GROUP. `subprocess.run` kills the direct child on timeout and
        # nothing else, so a detached grandchild outlived the run and rewrote the target AFTER
        # restoration had been verified. `start_new_session` makes the child a group leader, so
        # `pgid == pid` and the whole tree can be collected.
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                text=True, env=env, start_new_session=True)
    except OSError as e:
        return Invocation(LAUNCH_FAILED, code=e.errno, report=str(report))
    timed_out = False
    try:
        proc.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        timed_out = True
        _collect_group(proc.pid)
        proc.communicate()
    survivors = _collect_group(proc.pid)
    if timed_out:
        return Invocation(TIMED_OUT, report=str(report))
    labels = []
    if report.exists():
        labels = [l.strip() for l in report.read_text().splitlines() if l.strip()]
    # D0A-R38-09: a process killed by signal N has returncode -N, and SIGHUP is 1 — the same
    # value the timeout sentinel used, so a self-SIGHUP was classified TIMEOUT. Death by signal
    # is its own observation and is never an exit code.
    if proc.returncode < 0:
        return Invocation(SIGNALLED, signal=-proc.returncode, labels=labels,
                          report=str(report), survivors=survivors)
    return Invocation(EXITED, code=proc.returncode, labels=labels, report=str(report),
                      survivors=survivors)


def _collect_group(pgid: int) -> bool:
    """SIGKILL everything left in the group. True if anything was there to kill."""
    try:
        os.killpg(pgid, signal.SIGKILL)
        return True
    except (ProcessLookupError, PermissionError):
        return False


class Refusal(Exception):
    """The experiment cannot be run at all — not an outcome of running it."""


def _backup_path(target: pathlib.Path) -> pathlib.Path:
    return target.with_name(target.name + ".weaken-backup")


def _open_backup(target: pathlib.Path, original: bytes) -> pathlib.Path:
    """Put the original bytes somewhere a CRASH cannot take with it.

    D0A-R38-02: signal handlers cannot cover SIGKILL or power loss, and this repository lost a
    commit to the latter mid-session. A handler makes the catchable cases clean; this file makes
    the uncatchable ones VISIBLE and reversible — it sits beside the target, so `git status`
    reports it, which is the external check that has caught what self-checks did not.
    """
    backup = _backup_path(target)
    if backup.exists():
        raise Refusal(
            f"{backup} already exists: a previous run died with {target} possibly mutated. "
            f"Compare the two and restore before running another weaken — this driver will not "
            f"overwrite a record of an unfinished experiment")
    backup.write_bytes(original)
    return backup


def _validation_cmd(target: pathlib.Path) -> list[str] | None:
    """How to establish that the target can actually LOAD, not merely parse.

    D0A-R38-03: `compile()` proves syntax and nothing else. `FLAG = MISSING_NAME` compiles,
    raises `NameError` at import, and a suite whose guard checks command success then reported
    that guard — so an INVALID experiment was credited as RED_PROVEN, which is precisely the
    R36-06 misreading this driver exists to foreclose.
    """
    if target.suffix != ".py":
        return None
    return [sys.executable, "-c",
            "import importlib.util,sys\n"
            "spec = importlib.util.spec_from_file_location('_subject', sys.argv[1])\n"
            "m = importlib.util.module_from_spec(spec)\n"
            "spec.loader.exec_module(m)\n", str(target)]


def _loads(cmd: list[str] | None, timeout: int) -> tuple[bool, str]:
    """Run a validation command. Returns (loaded, detail)."""
    if cmd is None:
        return True, "no validation command for this target type"
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except (subprocess.TimeoutExpired, OSError) as e:
        return False, f"validation could not be run: {e}"
    return p.returncode == 0, (p.stderr or p.stdout).strip()[-400:]


def _apply_and_observe(target: pathlib.Path, original: bytes, before: str, anchor: bytes,
                       replacement: bytes, suite: list[str], report_dir: pathlib.Path,
                       expect: str, timeout: int, validate: list[str] | None, ev: dict) -> str:
    """Stages 2-5, with the target MUTATED throughout. The caller restores unconditionally."""
    # 2. APPLY, and VERIFY IT APPLIED. `bytes.replace` with a missing anchor returns the input
    # unchanged and raises nothing — the silent no-op that has shipped twice here. Which of the
    # two predicates fired is RECORDED, because that is what makes the first one testable.
    ev["phase"] = "mutate"
    if anchor not in original:
        ev["reason"] = "the anchor does not occur in the target"
        ev["not_applied_because"] = "anchor-absent"
        return MUTATION_NOT_APPLIED
    target.write_bytes(original.replace(anchor, replacement, 1))
    if _digest(target) == before:
        ev["reason"] = "the file is byte-identical after the replacement"
        ev["not_applied_because"] = "bytes-unchanged"
        return MUTATION_NOT_APPLIED
    ev["digest_weakened"] = _digest(target)

    # 3. VALID. Syntax is not validity: the mutant must LOAD. Measured against the same command
    # that loaded the ORIGINAL, so a target that never loads is the experiment's fault and not
    # the mutation's (that control runs in `drive`, before anything is written).
    ev["phase"] = "validate"
    loaded, detail = _loads(validate, timeout)
    ev["mutant_loads"] = loaded
    if not loaded:
        ev["reason"] = f"the weakened target does not load: {detail}"
        return MUTATION_INVALID

    # 4. RUN UNDER THE WEAKEN.
    ev["phase"] = "observe"
    run = _run(suite, report_dir, "weakened", timeout)
    ev["weakened"] = run._asdict()
    ev["weakened_exit"] = run.code
    ev["failing_guards"] = run.labels
    if run.outcome == TIMED_OUT:
        return TIMEOUT
    if run.outcome == LAUNCH_FAILED:
        ev["reason"] = "the suite could not be launched under the weaken"
        return UNVERIFIABLE
    if run.outcome == SIGNALLED:
        # Not a guard failing, and not a hang. Whatever the report holds, the run did not
        # finish judging, so it attributes nothing (D0A-R38-09).
        ev["reason"] = (f"the suite was killed by signal {run.signal}; it did not finish "
                        f"judging, so nothing here attributes a failure to the weaken")
        return UNVERIFIABLE
    if run.code == 0:
        ev["reason"] = ("the suite still passed. Either the check is redundant, or the "
                        "condition it needs was never arranged (DEFECT_CLASSES 58) — "
                        "this driver cannot tell those apart")
        return NOT_CAUGHT

    # 5. ATTRIBUTE — structurally, from THIS invocation's own report. No text is read.
    if not run.labels:
        ev["reason"] = ("the suite failed but reported no guard label. Without the side "
                        "channel the only way to attribute this is to read text, which is "
                        "what this driver exists to replace")
        return UNVERIFIABLE
    if expect not in run.labels:
        ev["reason"] = f"failed on {run.labels}, not on the expected guard"
        return WRONG_GUARD
    return RED_PROVEN


def drive(target: pathlib.Path, anchor: str, replacement: str, suite: list[str],
          expect: str, timeout: int = 900, *, validate: list[str] | None = None,
          _restore=None) -> tuple[str, dict]:
    """The chain. Returns (verdict, evidence); the verdict is DERIVED from the record."""
    ev: dict = {"target": str(target), "expect": expect, "phase": "baseline"}
    # D0A-R38-06: BYTES, NOT TEXT. `read_text`/`write_text` translate newlines, so on a CRLF
    # target the restore wrote LF back and the driver CORRUPTED the tree it was measuring —
    # reporting MUTATION_NOT_APPLIED while doing it. Nothing here may round-trip through str.
    original = target.read_bytes()
    before = _digest_bytes(original)
    ev["digest_before"] = before
    anchor_b, repl_b = anchor.encode(), replacement.encode()
    # Test seam, keyword-only: the ONE fault this models is a restore write that reports
    # success without landing, which is the condition the digest check exists for.
    restore = _restore if _restore is not None else target.write_bytes
    report_dir = pathlib.Path(tempfile.mkdtemp(prefix="weaken-report-"))
    if validate is None:
        validate = _validation_cmd(target)

    # 1. BASELINE, both halves: the target must LOAD and the suite must be green. Nothing has
    # been written yet, so every exit here owes no restoration.
    loaded, detail = _loads(validate, timeout)
    ev["original_loads"] = loaded
    if not loaded:
        ev["reason"] = f"the UNMUTATED target does not load: {detail}"
        return BASELINE_NOT_GREEN, ev
    base = _run(suite, report_dir, "baseline", timeout)
    ev["baseline"] = base._asdict()
    ev["baseline_exit"] = base.code
    if base.outcome == TIMED_OUT:
        return TIMEOUT, ev
    if not base.green:
        ev["baseline_failing_guards"] = base.labels
        return BASELINE_NOT_GREEN, ev

    # D0A-R38-02: from here the target may be mutated, so the original is parked where a crash
    # cannot take it, and the catchable signals restore before dying.
    backup = _open_backup(target, original)
    previous = {}

    def _on_signal(signum, _frame):
        restore(original)
        backup.unlink(missing_ok=True)
        signal.signal(signum, previous.get(signum, signal.SIG_DFL))
        os.kill(os.getpid(), signum)

    for sig in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
        previous[sig] = signal.signal(sig, _on_signal)
    try:
        verdict = _apply_and_observe(target, original, before, anchor_b, repl_b, suite,
                                     report_dir, expect, timeout, validate, ev)
    finally:
        # RESTORE, and VERIFY the restore — against the digest, not the write's return.
        ev["phase"] = "restore"
        restore(original)
        ev["digest_restored"] = _digest(target)
        for sig, handler in previous.items():
            signal.signal(sig, handler)
        if ev["digest_restored"] == before:
            backup.unlink(missing_ok=True)
        else:
            ev["backup_retained"] = str(backup)

    # D0A-R38-06: ON EVERY TERMINAL PATH. This check used to sit below the success path only,
    # so each early return jumped past it and a corrupted tree was reported as a clean refusal.
    if ev["digest_restored"] != before:
        ev["verdict_before_restore_check"] = verdict
        ev["reason"] = "the target did not come back byte-identical"
        return RESTORE_FAILED, ev
    if verdict != RED_PROVEN:
        return verdict, ev
    back = _run(suite, report_dir, "restored", timeout)
    ev["restored"] = back._asdict()
    ev["restored_exit"] = back.code
    if not back.green:
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

    try:
        verdict, ev = drive(pathlib.Path(a.target), a.anchor, a.replacement, a.suite, a.expect,
                            a.timeout)
    except Refusal as e:
        print(f"REFUSED: {e}", file=sys.stderr)
        return 2
    print(f"VERDICT: {verdict}")
    for k, v in ev.items():
        print(f"  {k}: {v}")
    if verdict != RED_PROVEN:
        print(f"\nNOT RED-PROVEN. `{verdict}` is not a weakness in the weaken's TARGET; it is a "
              f"statement about the experiment.", file=sys.stderr)
    return 0 if verdict == RED_PROVEN else 1


if __name__ == "__main__":
    sys.exit(main())
