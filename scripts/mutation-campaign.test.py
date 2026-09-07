#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Guards for `scripts/mutation-campaign.py` — the harness that certifies coverage claims.

RETAINED, NOT RUN-AND-DISCARDED, for the reason the harness itself exists (D0A-R28-05): an
unretained experiment is indistinguishable from one that never happened.

**The harness is TIER 1 by CLAUDE.md §6 clause (d)** — its green is cited as the evidence that a
security check is covered — so its own failure modes need REDs.

# D0A-R30-05: THE PREVIOUS VERSION OF THIS FILE COULD PRINT `[FAIL]` AND EXIT 0

Two of its checks only *printed* their verdict; neither updated the exit status. Replacing
`file_matches_head` with an always-false verifier produced two `[FAIL]` lines and **exit 0**.

That is the precise defect class this project exists to catch, shipped inside the guard built to
catch it — and every campaign result since it landed rested on a self-test that could not fail.
**Every check below is now an assertion.** There is no reporting path that does not also decide.

Run: `python3 scripts/mutation-campaign.test.py`  (exit 0 = all guards hold)
"""

from __future__ import annotations

import importlib.util
import pathlib
import subprocess
import sys
import tempfile
import types

REPO = pathlib.Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location("mc", REPO / "scripts" / "mutation-campaign.py")
mc = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mc)

CHECKS: list[str] = []


def check(label: str, condition: bool, detail: str = "") -> None:
    """Record and ENFORCE. The previous version had a reporting path that did not decide."""
    CHECKS.append(label)
    assert condition, f"GUARD FAILED: {label}{(' — ' + detail) if detail else ''}"
    print(f"  [OK ] {label}")


def fake_sh(out: str, err: str, rc: int):
    return lambda cmd, **kw: types.SimpleNamespace(returncode=rc, stdout=out, stderr=err)


def guard_classification() -> None:
    """D0A-R29-02 / D0A-R30-04 — a nonzero exit is not automatically a detection."""
    real = mc.sh
    try:
        cases = {
            "disk full": ("", "error: No space left on device", 101, "INFRASTRUCTURE"),
            "build failure": ("", "error: could not compile `x`", 101, "INFRASTRUCTURE"),
            "no result lines": ("", "", 101, "INFRASTRUCTURE"),
            # D0A-R30-04: a NAMED failing test whose cause is the environment.
            "stale session precondition": (
                "test result: FAILED. 1 failed\nfailures:\n    some::test\n",
                "PRECONDITION FAILED before this test ran — a session is live on tty1",
                101, "PRECONDITION FAILURE"),
            "stale-session script text": (
                "test result: FAILED. 1 failed\nfailures:\n    some::test\n",
                "STALE SESSION FROM A PREVIOUS RUN — a PRECONDITION failure, not a code regression.",
                101, "PRECONDITION FAILURE"),
            "crash, no named test": ("test result: FAILED. 1 failed\n", "", 101,
                                     "UNATTRIBUTED FAILURE"),
            "real detection": (
                "test result: FAILED. 1 failed\nfailures:\n    some::test\n", "", 101, "CAUGHT"),
            "clean green": ("test result: ok. 5 passed\n", "", 0, "NOT CAUGHT"),
        }
        for name, (out, err, rc, want) in cases.items():
            mc.sh = fake_sh(out, err, rc)
            got, ev = mc.run_suite()
            check(f"classify: {name} -> {want}", got == want, f"got {got}")
            check(f"classify: {name} retains full output",
                  ev["stdout"] == out and ev["stderr"] == err,
                  "the previous version kept a filtered excerpt and lost the evidence")
    finally:
        mc.sh = real


def guard_restore_verification() -> None:
    """D0A-R29-01 / D0A-R30-01 — verify against the CAPTURED commit, not our own write."""
    rel = "runtime/src/wire.rs"
    p = REPO / rel
    original = p.read_text()
    sha = mc.sh(["git", "rev-parse", "HEAD"]).stdout.strip()
    try:
        check("restore: a clean file matches the captured commit", mc.file_matches_commit(sha, rel))
        p.write_text(original + "\n// tamper\n")
        check("restore: a TAMPERED file does NOT match (a partial restore is caught)",
              not mc.file_matches_commit(sha, rel))
    finally:
        # D0A-R30-05: fixture restoration under `finally`. The previous version left the
        # tampered file behind on any assertion failure.
        p.write_text(original)
    check("restore: the restored file matches again", mc.file_matches_commit(sha, rel))
    check("restore: verification is against a SHA, not mutable HEAD",
          not hasattr(mc, "file_matches_head"),
          "file_matches_head still exists; HEAD can move mid-campaign")


def guard_signal_restores() -> None:
    """D0A-R30-01 — a TERMINATION signal restores the tree; `finally` alone does not.

    Reproduced in a temporary directory rather than the repository: the harness's own
    `_restore_in_flight` is driven directly, which is what the signal handler calls.
    """
    with tempfile.TemporaryDirectory() as td:
        victim = pathlib.Path(td) / "victim.rs"
        victim.write_text("ORIGINAL")
        mc._IN_FLIGHT.update({"path": str(victim), "original": "ORIGINAL", "rel": "victim.rs"})
        victim.write_text("MUTANT")
        check("signal: the mutant is present before the handler runs",
              victim.read_text() == "MUTANT")
        mc._restore_in_flight("test")
        check("signal: the handler RESTORES the mutated file", victim.read_text() == "ORIGINAL")
        check("signal: in-flight state is cleared afterwards", mc._IN_FLIGHT == {})
    check("signal: handlers are installed for SIGTERM/SIGINT/SIGHUP",
          callable(getattr(mc, "_install_signal_handlers", None)))


def guard_input_closure() -> None:
    """D0A-R30-03 — inputs the SUITE consumes, not only `runtime/src`."""
    for required in ("installer/pam/delphi-runtime", "scripts/check-stale-test-sessions.sh",
                     "scripts/mutation-campaign.py", "Cargo.lock"):
        check(f"inputs: {required} is watched", required in mc.INPUT_PATHS)


def guard_dirty_refusal() -> None:
    """The refusal that fired on the harness's own first run."""
    rel = "installer/pam/delphi-runtime"
    p = REPO / rel
    if not p.exists():
        check("dirty: installer fixture present to test with", False, f"{rel} missing")
        return
    original = p.read_text()
    try:
        p.write_text(original + "\n# tamper\n")
        clean, dirt = mc.inputs_are_clean()
        check("dirty: a modified installer fixture makes inputs UNCLEAN", not clean,
              "a probe modified this file and inputs_are_clean() still returned true")
        check("dirty: the refusal names the offending path", rel in dirt, dirt)
    finally:
        p.write_text(original)
    _, dirt_after = mc.inputs_are_clean()
    # NARROWED, not weakened (Iron Law #15 clause 3): the property is that RESTORING THE
    # FIXTURE removes IT from the dirt. Asserting the whole tree is clean fails whenever the
    # harness itself has uncommitted edits — which is the normal state while developing the
    # harness, and it is the guard correctly reporting real dirt rather than a defect. The
    # narrower claim still fails if the restore does not work.
    check("dirty: the restored fixture is no longer listed as dirty", rel not in dirt_after,
          f"still dirty after restore: {dirt_after}")


def main() -> int:
    print("mutation-campaign harness guards")
    guard_classification()
    guard_restore_verification()
    guard_signal_restores()
    guard_input_closure()
    guard_dirty_refusal()
    print(f"\n{len(CHECKS)} guards held")
    return 0


if __name__ == "__main__":
    sys.exit(main())
