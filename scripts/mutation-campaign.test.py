#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Guards for `scripts/mutation-campaign.py` — the harness that certifies coverage claims.

RETAINED, NOT RUN-AND-DISCARDED, for the reason the harness itself exists (D0A-R28-05): an
unretained experiment is indistinguishable from one that never happened.

**The harness is TIER 1 by CLAUDE.md §6 clause (d)** — its green is cited as the evidence that a
security check is covered — so its own failure modes need REDs.

# D0A-R30-05: THE PREVIOUS VERSION OF THIS FILE COULD PRINT `[FAIL]` AND EXIT 0

**TWO** of its checks only *printed* their verdict without updating the exit status; the others
did decide. Replacing `file_matches_head` with an always-false verifier produced two `[FAIL]`
lines and **exit 0**.

**The claim first written here — "a self-test that could not fail" — was itself an overstatement
(D0A-R31).** It could fail, and did, for most of what it checked; two specific checks were
inert. Saying the whole thing was inert is the same shape as the defect: a statement about
coverage that is broader than what was measured. **Every check below is now an assertion**, and
there is no reporting path that does not also decide.

Run: `python3 scripts/mutation-campaign.test.py`  (exit 0 = all guards hold)
"""

from __future__ import annotations

import importlib.util
import pathlib
import os
import shutil
import signal
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
            # D0A-R31-06: the reviewer's case — the checker could not be LAUNCHED, so the
            # environment is UNKNOWN. It has a named failing test and no infra substring, and
            # was therefore scored CAUGHT: an infrastructure failure credited to the mutation.
            "checker-launch failure": (
                "test result: FAILED. 1 failed\nfailures:\n    some::test\n",
                "DELPHI_PRECONDITION_FAILED: could not run scripts/check-stale-test-sessions.sh: "
                "Permission denied (os error 13) — the environment is UNKNOWN, not clean",
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
    # D0A-R31-04: the callable() check that used to live here proved nothing — a no-op
    # `_install_signal_handlers` passed it. The real property is exercised by
    # `guard_real_signal_during_a_real_campaign`, which sends an actual signal.


def guard_input_closure() -> None:
    """D0A-R30-03 — inputs the SUITE consumes, not only `runtime/src`."""
    for required in ("installer/pam/delphi-runtime", "scripts/check-stale-test-sessions.sh",
                     "scripts/mutation-campaign.py", "Cargo.lock"):
        check(f"inputs: {required} is watched", required in mc.INPUT_PATHS)


def guard_real_signal_during_a_real_campaign() -> None:
    """D0A-R31-04 — the four properties cancellation owes, driven by a REAL signal.

    # What this replaces, and why that mattered

    The previous guard asserted that `_install_signal_handlers` is **callable**, and the checks
    around it invoked `_restore_in_flight` directly. Neither established that handlers were
    installed or that a signal reaches them: **replacing `_install_signal_handlers` with a no-op
    still passed all 31 guards.** A guard that tests a function's existence rather than its
    effect is the same shape as asserting an outcome the harness itself supplies (D0A-R31-02).

    This runs the actual campaign as a subprocess, waits until the journal shows a mutation IN
    PROGRESS — synchronising on real state rather than sleeping — sends it a real SIGTERM, and
    asserts all four properties. **Any one failing fails the guard.**

    `DELPHI_MUTATION_TEST_CMD` substitutes a fast command for cargo. The property under test is
    signal handling, not compilation, and a guard that takes minutes is a guard nobody runs.
    """
    import time

    out = pathlib.Path(tempfile.mkdtemp(prefix="delphi-r3104-"))
    victim = REPO / "runtime" / "src" / "shutdown.rs"
    before = victim.read_text()
    sha = mc.sh(["git", "rev-parse", "HEAD"]).stdout.strip()

    env = dict(os.environ)
    # Green baseline, then slow enough to be caught mid-mutation.
    env["DELPHI_MUTATION_TEST_CMD"] = 'sh -c "echo \'test result: ok. 1 passed\'; sleep 6"'
    proc = subprocess.Popen(
        [sys.executable, str(REPO / "scripts" / "mutation-campaign.py"), "--out", str(out)],
        cwd=REPO, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        start_new_session=True,
    )
    try:
        journal = out / "results.jsonl"
        deadline = time.time() + 90
        while time.time() < deadline:
            if journal.exists() and "IN PROGRESS" in journal.read_text():
                break
            if proc.poll() is not None:
                raise AssertionError(
                    f"the campaign exited before any mutation was in flight:\n"
                    f"{proc.stdout.read()}\n{proc.stderr.read()}"
                )
            time.sleep(0.2)
        else:
            raise AssertionError("no mutation reached IN PROGRESS within 90s")

        # (3) JOURNAL STATE — recorded BEFORE the mutation was written, so an uncatchable kill
        # still names the file at risk.
        check("signal: the journal records a mutation IN PROGRESS before the signal",
              "IN PROGRESS" in journal.read_text())

        descendants_before = subprocess.run(
            ["pgrep", "-g", str(proc.pid)], capture_output=True, text=True).stdout.split()
        check("signal: the campaign has a live process group to collect",
              len(descendants_before) >= 1, f"group members: {descendants_before}")

        os.kill(proc.pid, signal.SIGTERM)      # A REAL SIGNAL to the real campaign.
        try:
            proc.wait(timeout=30)
        except subprocess.TimeoutExpired:
            proc.kill()
            raise AssertionError(
                "the campaign did not exit within 30s of SIGTERM — cancellation blocked, which "
                "is what happened when it waited on a child it had not been told to stop"
            ) from None

        # (4) EXIT STATUS — a cancelled campaign is a FAILURE, not a quiet success.
        check("signal: the campaign exits non-zero after SIGTERM", proc.returncode != 0,
              f"exit was {proc.returncode}")
        # (1) SOURCE PROTECTION — the working tree, which nothing should have written to.
        check("signal: the WORKING TREE source is untouched", victim.read_text() == before)
        check("signal: the working tree still matches the commit",
              mc.file_matches_commit_in_repo(sha, "runtime/src/shutdown.rs"))
        # (2) PROCESS CLEANUP — no descendants, and no abandoned worktree.
        time.sleep(0.5)
        left = subprocess.run(["pgrep", "-g", str(proc.pid)],
                              capture_output=True, text=True).stdout.split()
        check("signal: no descendants survive the cancelled campaign", not left,
              f"survivors: {left}")
        worktrees = mc.sh(["git", "worktree", "list"]).stdout
        check("signal: no isolated checkout is left behind",
              "delphi-mutation-wt-" not in worktrees, worktrees)
    finally:
        if proc.poll() is None:
            proc.kill()
        victim.write_text(before)
        mc.sh(["git", "worktree", "prune"])
        shutil.rmtree(out, ignore_errors=True)

def guard_precondition_token_is_emitted_not_just_matched() -> None:
    """D0A-R31-06 — the classifier and the emitters agree on ONE token.

    Matching prose meant each new phrasing was a new instance to discover (class 48 by
    construction). A token only helps if the places that fail actually carry it, so this checks
    both ends rather than the classifier alone.
    """
    token = mc.PRECONDITION_TOKEN
    guard_src = (REPO / "runtime" / "src" / "test_child_guard.rs").read_text()
    check("precondition: the runtime defines the token",
          f'PRECONDITION_TOKEN: &str = "{token}"' in guard_src)
    check("precondition: the checker-LAUNCH failure carries it",
          "{PRECONDITION_TOKEN}: could not run" in guard_src,
          "this is the site the reviewer showed being scored as a detection")
    check("precondition: the live-session failure carries it",
          "{PRECONDITION_TOKEN}: before this test ran" in guard_src)
    sh_src = (REPO / "scripts" / "check-stale-test-sessions.sh").read_text()
    check("precondition: the shell checker carries it", token in sh_src)

def guard_isolation() -> None:
    """D0A-R31-01 — mutations happen in an ISOLATED CHECKOUT, never the working tree.

    The journal added at R30-01 records damage; it cannot prevent it, and the reviewer's SIGKILL
    reproduction left the source MUTATED with the journal correctly saying so. The fix is that
    nothing writes to the working tree at all.

    **THE ISOLATION MUST BE OF THE CAPTURED SHA, NOT A COPY OF THE TREE.** A copy inherits
    uncommitted state, which reintroduces the attribution problem the clean-tree check existed
    to prevent — and hides it, because the check inspects the working tree while the campaign
    runs elsewhere.
    """
    sha = mc.sh(["git", "rev-parse", "HEAD"]).stdout.strip()
    victim_rel = "runtime/src/shutdown.rs"
    working = REPO / victim_rel
    before = working.read_text()

    # Prove it is a checkout of the COMMIT: dirty the working tree first, then verify the
    # isolated copy does NOT contain that change.
    marker = "\n// R31-01 isolation probe — must NOT appear in the isolated checkout\n"
    working.write_text(before + marker)
    try:
        work = mc.make_isolated_checkout(sha)
        try:
            isolated = (work / victim_rel).read_text()
            check("isolation: the checkout exists and has the source", "fn shutdown_child" in isolated)
            check("isolation: it is of the SHA, not a copy of the dirty working tree",
                  marker not in isolated,
                  "the isolated tree contains an uncommitted working-tree change")
            # And a mutation inside it does not touch the working tree.
            target = work / victim_rel
            target.write_text(isolated.replace("fn shutdown_child", "fn MUTATED_shutdown_child", 1))
            check("isolation: mutating the checkout leaves the working tree unchanged",
                  working.read_text() == before + marker,
                  "the working tree changed while only the isolated checkout was written")
        finally:
            mc.remove_isolated_checkout()
        check("isolation: the checkout is collected afterwards", not work.exists())
    finally:
        working.write_text(before)
    check("isolation: the working tree is restored by this guard",
          mc.file_matches_commit(sha, victim_rel))


def guard_sigkill_leaves_working_tree_intact() -> None:
    """D0A-R31-01 — the reviewer's reproduction, run against the new harness.

    Their probe SIGKILLed a campaign mid-mutation and found the source mutated. SIGKILL cannot
    be handled, so the only defence is that the mutation was never in the working tree. This
    drives the real lifecycle: create the isolated checkout, register an in-flight mutation,
    write it, then simulate an uncatchable death by abandoning the handlers entirely.
    """
    sha = mc.sh(["git", "rev-parse", "HEAD"]).stdout.strip()
    victim_rel = "runtime/src/shutdown.rs"
    working = REPO / victim_rel
    before = working.read_text()
    work = mc.make_isolated_checkout(sha)
    try:
        target = work / victim_rel
        original = target.read_text()
        mc._IN_FLIGHT.update({"path": str(target), "original": original, "rel": victim_rel})
        target.write_text("// MUTANT — a removed security check\n" + original)
        check("sigkill: the mutant is in the ISOLATED checkout", "MUTANT" in target.read_text())
        # No handler runs — this is the uncatchable case.
        check("sigkill: the WORKING TREE is untouched", working.read_text() == before,
              "an uncatchable kill would have left a removed check in the working tree")
        check("sigkill: the working tree still matches the commit",
              mc.file_matches_commit_in_repo(sha, victim_rel))
    finally:
        mc._IN_FLIGHT.clear()
        mc.remove_isolated_checkout()
        working.write_text(before)

def guard_cancellation_kills_descendants() -> None:
    """D0A-R31-03 — cancellation collects the build's DESCENDANTS, not just its leader.

    `cargo` spawns `rustc`; signalling the leader alone leaves them compiling. Worse, before
    this the handler could not even finish exiting: it ran, and Python's teardown then BLOCKED
    waiting for the cargo child it had never been told to stop — a SIGTERM'd campaign hung with
    its isolated checkout uncollected until `timeout` gave up.
    """
    import threading
    import time

    result: dict = {}

    def run() -> None:
        # The cargo->rustc shape: a child that spawns a grandchild and waits on it.
        result["r"] = mc.sh(["sh", "-c", "sleep 300 & wait"])

    t = threading.Thread(target=run, daemon=True)
    t.start()
    time.sleep(1.5)
    pid = mc._ACTIVE_CHILD.get("pid")
    check("cancel: the live child is registered", bool(pid),
          "_ACTIVE_CHILD was empty; cancellation would have nothing to kill")
    in_group = subprocess.run(["pgrep", "-g", str(pid)], capture_output=True, text=True).stdout.split()
    check("cancel: the child leads its own session with a descendant in it",
          len(in_group) >= 2, f"group had {len(in_group)} member(s); expected leader + grandchild")
    mc._kill_active_child_group()
    time.sleep(0.7)
    after = subprocess.run(["pgrep", "-g", str(pid)], capture_output=True, text=True).stdout.split()
    check("cancel: the WHOLE group is gone, grandchild included", not after,
          f"{len(after)} process(es) survived: {after}")

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
    guard_real_signal_during_a_real_campaign()
    guard_precondition_token_is_emitted_not_just_matched()
    guard_isolation()
    guard_sigkill_leaves_working_tree_intact()
    guard_cancellation_kills_descendants()
    guard_dirty_refusal()
    print(f"\n{len(CHECKS)} guards held")
    return 0


if __name__ == "__main__":
    sys.exit(main())
