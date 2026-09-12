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
import json
import pathlib
import os
import shlex
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
    # D0A-R37: THE SIDE CHANNEL a weaken driver reads instead of grepping stdout. The label is
    # written by the FAILING check itself, to a path the driver names per invocation — so
    # "which guard failed" is a structured fact rather than a text match. Three text-derived
    # readings were wrong this session; this is the mechanism that replaces the fourth.
    if not condition:
        report = os.environ.get("DELPHI_GUARD_FAILURE_REPORT")
        if report:
            try:
                with open(report, "a", encoding="utf-8") as f:
                    f.write(label + "\n")
            except OSError:
                pass
    assert condition, f"GUARD FAILED: {label}{(' — ' + detail) if detail else ''}"
    print(f"  [OK ] {label}")


def fake_sh(out: str, err: str, rc: int):
    """Answer the SUITE invocation only; delegate everything else to the real `sh`.

    D0A-R36-06: this used to answer EVERY call, so the campaign's own free-space measurement —
    taken to replace a forgeable text marker — was answered by the test's stub and returned the
    stub's nonzero exit. A fake that intercepts more than it was written for makes the code
    under test appear to behave in ways it does not, which is the harness misreporting the
    subject (Iron Law 15 clause 5's own hazard).
    """
    real = mc.sh

    def _sh(cmd, **kw):
        if any("check-free-space" in str(c) or "check-stale" in str(c) for c in cmd):
            return real(cmd, **kw)
        return types.SimpleNamespace(returncode=rc, stdout=out, stderr=err)

    return _sh


def guard_classification() -> None:
    """D0A-R29-02 / D0A-R30-04 — a nonzero exit is not automatically a detection."""
    real = mc.sh
    try:
        cases = {
            "disk full": ("", "error: No space left on device", 101, "INFRASTRUCTURE"),
            "build failure": ("", "error: could not compile `x`", 101, "INFRASTRUCTURE"),
            "no result lines": ("", "", 101, "INFRASTRUCTURE"),
            # D0A-R30-04 established this as PRECONDITION FAILURE when the token in output was
            # the evidence. D0A-R35-03 removed that path: any test can print the token, and one
            # that did was classified as an environment failure while a real detection was
            # discarded. The token in output is now DATA, and the case is retained inverted —
            # the genuine precondition path is asserted through the SIDE CHANNEL in
            # `guard_markers_in_assertion_data_do_not_decide_cause`.
            "precondition token as text is NOT a precondition report": (
                "test result: FAILED. 1 failed\nfailures:\n    some::test\n",
                "PRECONDITION FAILED before this test ran — a session is live on tty1",
                101, "CAUGHT"),
            # Same inversion, same reason: the legacy phrasing is text too.
            "legacy stale-session phrasing as text is NOT a report": (
                "test result: FAILED. 1 failed\nfailures:\n    some::test\n",
                "STALE SESSION FROM A PREVIOUS RUN — a PRECONDITION failure, not a code regression.",
                101, "CAUGHT"),
            # D0A-R31-06: the reviewer's case — the checker could not be LAUNCHED, so the
            # environment is UNKNOWN. It has a named failing test and no infra substring, and
            # was therefore scored CAUGHT: an infrastructure failure credited to the mutation.
            "checker-launch text is NOT a report either": (
                "test result: FAILED. 1 failed\nfailures:\n    some::test\n",
                "DELPHI_PRECONDITION_FAILED: could not run scripts/check-stale-test-sessions.sh: "
                "Permission denied (os error 13) — the environment is UNKNOWN, not clean",
                101, "CAUGHT"),
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
        [sys.executable, str(REPO / "scripts" / "mutation-campaign.py"), "--out", str(out),
         "--instrument-dirty-ok"],
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

        # D0A-R32-02: assert about the WORKER's group, which is where the build actually is.
        # The previous version watched the CAMPAIGN's group — but `sh()` gives every child its
        # own session, so the build was never in it and the check passed with the group killer
        # replaced by a no-op. A guard aimed at the wrong identity is indistinguishable from one
        # that works.
        worker_file = out / "worker.json"
        check("signal: the campaign publishes the live worker's identity", worker_file.exists(),
              "nothing to aim the cancellation assertion at")
        # Synchronise on a LIVE worker, not merely on the journal. The journal says a mutation
        # is in flight; it does not say the suite process for that mutation has started, and
        # the file still names the BASELINE run — which has exited — until it does. Waiting for
        # the published identity to be alive lands on the mutation's own suite run.
        deadline = time.monotonic() + 30
        worker, alive_before = None, []
        while time.monotonic() < deadline:
            try:
                worker = json.loads(worker_file.read_text())
            except (OSError, ValueError):
                time.sleep(0.05)
                continue
            alive_before = subprocess.run(
                ["pgrep", "-g", str(worker["pgid"])], capture_output=True, text=True
            ).stdout.split()
            if alive_before:
                break
            time.sleep(0.05)
        check("signal: the WORKER's group is alive before cancellation",
              len(alive_before) >= 1, f"worker {worker} group members: {alive_before}")
        wpgid = worker["pgid"]

        os.kill(proc.pid, signal.SIGTERM)      # A REAL SIGNAL to the real campaign.

        # (2a) PROMPT WORKER CLEANUP — sampled HERE, before `proc.wait()`, because waiting is
        # what erases the difference. D0A-R32-02, second layer: aiming the guard at the worker's
        # identity was necessary and not sufficient. Measured with the killer disabled, the
        # worker group is alive at +0.2/+0.5/+1.0s and gone by +3.0s on its own, while
        # `proc.wait()` returns only after ~3s — so a check placed after the wait passes in both
        # worlds. Same shape as R31-02's survivor sample: observe before the intervention.
        deadline = time.monotonic() + 1.5
        left_prompt = subprocess.run(["pgrep", "-g", str(wpgid)],
                                     capture_output=True, text=True).stdout.split()
        while left_prompt and time.monotonic() < deadline:
            time.sleep(0.05)
            left_prompt = subprocess.run(["pgrep", "-g", str(wpgid)],
                                         capture_output=True, text=True).stdout.split()
        check("signal: the WORKER's group dies PROMPTLY, before the campaign is waited on",
              not left_prompt,
              f"worker group {wpgid} still had {left_prompt} 1.5s after SIGTERM; with the "
              f"killer disabled it survives this window and only exits on its own at ~3s")

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
        left = subprocess.run(["pgrep", "-g", str(wpgid)],
                              capture_output=True, text=True).stdout.split()
        # Retained, but it is the WEAK half: by this point both worlds look the same. Kept
        # because a survivor here would still be a defect; not counted as the discriminator.
        check("signal: the WORKER's group is still gone once the campaign has exited", not left,
              f"survivors in worker group {wpgid}: {left}")
        left_campaign = subprocess.run(["pgrep", "-g", str(proc.pid)],
                                       capture_output=True, text=True).stdout.split()
        check("signal: nothing survives in the campaign's own group either", not left_campaign,
              f"survivors: {left_campaign}")
        worktrees = mc.sh(["git", "worktree", "list"]).stdout
        check("signal: no isolated checkout is left behind",
              "delphi-mutation-wt-" not in worktrees, worktrees)
        # D0A-R32-05: `git worktree list` is NOT the resource. `remove` cleans the registration
        # and leaves the `mkdtemp` that held it, so this guard passed while 38 directories
        # accumulated in /tmp. Check what the harness actually created.
        leaked = sorted(pathlib.Path(tempfile.gettempdir()).glob("delphi-mutation-wt-*"))
        check("signal: no mkdtemp parent is left behind either",
              not leaked, f"leaked directories: {[str(x) for x in leaked]}")
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

def guard_dirty_instrument_is_refused() -> None:
    """D0A-R32-04 — the EXECUTING harness must be committed, and it is identified separately.

    The isolated checkout moves the source under test to the captured commit. It does not move
    the Python that is running: the interpreter keeps executing the working tree's harness,
    mutation inventory and classifier included. The reviewer demonstrated the consequence — an
    uncommitted `MUTATIONS = []` produced exit 0 and an empty campaign attributed to the
    original commit, under a message stating the changes were NOT included.

    Refusal was chosen over re-exec'ing the captured harness: re-exec means the harness you are
    editing is not the harness that runs, trading a loud stop for a silent divergence.
    """
    inst = REPO / "scripts" / "mutation-campaign.py"
    before = inst.read_bytes()
    out = pathlib.Path(tempfile.mkdtemp(prefix="delphi-r3204-"))
    try:
        inst.write_bytes(before + b"\n# dirty instrument (D0A-R32-04 guard)\n")
        env = dict(os.environ)
        env["DELPHI_MUTATION_TEST_CMD"] = "true"
        r = subprocess.run([sys.executable, str(inst), "--out", str(out)],
                           cwd=REPO, env=env, capture_output=True, text=True, timeout=300)
        check("instrument: a dirty harness is REFUSED, not warned about", r.returncode == 2,
              f"exit was {r.returncode}")
        # EXIT 2 ALONE DOES NOT DISCRIMINATE, and this was found by weakening: with the
        # refusal turned into a warning the campaign proceeds, the stub baseline is not green,
        # and the BASELINE refusal returns 2 as well. The same exit code from a different
        # mechanism — the shape D0A-R32-02 named, reproduced inside the guard written for
        # D0A-R32-04. The campaign body's first artifact is what separates them.
        check("instrument: the campaign BODY never ran (no lane.json was written)",
              not (out / "lane.json").exists(),
              "lane.json exists, so the refusal did not stop the campaign — it continued and "
              "some later check produced the exit code")
        check("instrument: no isolated checkout was even created",
              "isolated checkout:" not in r.stdout, r.stdout[-300:])
        check("instrument: the refusal names the harness",
              "scripts/mutation-campaign.py" in r.stderr, r.stderr[-300:])
        check("instrument: the refusal explains that the checkout does not cover it",
              "keeps running from your working tree" in r.stderr, r.stderr[-300:])
        check("instrument: a refused run leaves no checkout behind",
              not sorted(pathlib.Path(tempfile.gettempdir()).glob("delphi-mutation-wt-*")),
              "a refusal should have nothing to collect")
    finally:
        inst.write_bytes(before)
        shutil.rmtree(out, ignore_errors=True)
    # And with the instrument clean again, its identity is RECORDED rather than inferred.
    ident = mc.instrument_identity()
    import hashlib as _h
    check("instrument: the recorded digest is of the executing bytes",
          ident["sha256"] == _h.sha256(inst.read_bytes()).hexdigest(), ident["sha256"][:16])


def guard_markers_in_assertion_data_do_not_decide_cause() -> None:
    """D0A-R34-05 — the reviewer's counterexamples, through the REAL classifier.

    Their probe changed only the EXPECTED VALUE of a real libtest assertion: `ordinary payload`
    gave CAUGHT, `Killed` gave INFRASTRUCTURE, `DELPHI_PRECONDITION_FAILED` gave PRECONDITION
    FAILURE — same exit 101, same named failing test. A genuine property failure was discarded
    because its data contained a marker.
    """
    def transcript(expected: str) -> str:
        return (
            "running 1 test\n"
            "test the_property ... FAILED\n\n"
            "failures:\n\n"
            "---- the_property stdout ----\n"
            "thread 'the_property' panicked at runtime/src/x.rs:1:1:\n"
            "assertion `left == right` failed\n"
            '  left: "altered payload"\n'
            f'  right: "{expected}"\n\n'
            "failures:\n"
            "    the_property\n\n"
            "test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out\n"
        )

    def classify(stdout: str, code: int = 101, stderr: str = "",
                 precondition: str | None = None) -> tuple[str, dict]:
        prev = os.environ.get("DELPHI_MUTATION_TEST_CMD")
        # A stub that writes the given streams — and, when asked, writes the SIDE-CHANNEL file
        # the campaign named, which is what a real helper does and what test text cannot.
        body = (f"import os,sys; sys.stdout.write({stdout!r}); sys.stderr.write({stderr!r}); ")
        if precondition is not None:
            body += ("open(os.environ['DELPHI_PRECONDITION_REPORT'],'a')"
                     f".write({precondition!r} + chr(10)); ")
        # A NEGATIVE code means death BY SIGNAL, which must be real: `sys.exit(-9)` merely
        # exits 247. The whole point of the signal branch is that output cannot fake it.
        if code < 0:
            body += f"sys.stdout.flush(); sys.stderr.flush(); os.kill(os.getpid(), {-code})"
        else:
            body += f"sys.exit({code})"
        os.environ["DELPHI_MUTATION_TEST_CMD"] = "python3 -c " + shlex.quote(body)
        try:
            return mc.run_suite()
        finally:
            if prev is None:
                del os.environ["DELPHI_MUTATION_TEST_CMD"]
            else:
                os.environ["DELPHI_MUTATION_TEST_CMD"] = prev

    # D0A-R34-05's three, PLUS D0A-R35-03's two framing escapes: a test that prints its own
    # "running " line to fake a section boundary, and a test that prints the precondition token
    # at the start of a line. Both defeated the round-34 parser, which is why the parser is gone
    # and cause is now read from invocation-bound facts instead.
    for expected in ("ordinary payload", "Killed", "DELPHI_PRECONDITION_FAILED",
                     "running user command\nKilled",
                     "\nDELPHI_PRECONDITION_FAILED: not really"):
        outcome, ev = classify(transcript(expected))
        check(f"markers: printed {expected.splitlines()[0][:28]!r} is still CAUGHT",
              outcome == "CAUGHT",
              f"classified {outcome} — a detection was discarded because of text a TEST "
              f"printed")

    # D0A-R36-06 — THE TEXT CHANNEL IS CLOSED, not narrowed a fourth time. A REAL failing test
    # that writes an infrastructure marker straight to stderr flipped CAUGHT to UNATTRIBUTED
    # FAILURE. stdout and stderr are INPUTS FROM THE SUBJECT; matching on them is the same shape
    # as trusting a self-report.
    outcome, ev = classify(transcript("x"), 101, stderr="Killed\n")
    check("markers: a failing test writing `Killed` to STDERR is still CAUGHT",
          outcome == "CAUGHT",
          f"classified {outcome} — stderr is an input from the subject under test")
    check("markers: the forged marker is RETAINED for a human even though it decides nothing",
          "Killed" in ev.get("markers_seen_as_data", []), f"{ev.get('markers_seen_as_data')}")
    outcome, _ = classify(transcript("x"), 101,
                          stderr="error: No space left on device\nerror: could not compile\n")
    check("markers: TWO forged markers on stderr are still CAUGHT", outcome == "CAUGHT", outcome)

    # D0A-R36-06 — THE AMBIGUOUS BRANCH: nonzero exit, tests reported, NO named failure. This
    # is the only place the campaign consults its own free-space measurement, and closing the
    # text channel would otherwise have deleted disk-exhaustion detection outright. Exercised by
    # faking BOTH answers, because the real check passes on this box and the branch would
    # otherwise have no discriminating case at all (the D0A-R36-11 lesson).
    real_sh = mc.sh
    try:
        def short_disk(cmd, **kw):
            if any("check-free-space" in str(c) for c in cmd):
                return types.SimpleNamespace(
                    returncode=1, stdout="/tmp  10M  512M  *** SHORT ***\n", stderr="")
            return types.SimpleNamespace(
                returncode=101, stdout="test result: FAILED. 1 failed\n", stderr="")
        mc.sh = short_disk
        outcome, ev = mc.run_suite()
        check("space: an unattributable failure WITH a short disk is INFRASTRUCTURE",
              outcome == "INFRASTRUCTURE", outcome)
        check("space: ...and the campaign's own measurement is retained as the reason",
              "SHORT" in ev.get("free_space", ""), f"{ev.get('free_space')!r}")

        def ample_disk(cmd, **kw):
            if any("check-free-space" in str(c) for c in cmd):
                return types.SimpleNamespace(returncode=0, stdout="all above floors\n", stderr="")
            return types.SimpleNamespace(
                returncode=101, stdout="test result: FAILED. 1 failed\n", stderr="")
        mc.sh = ample_disk
        outcome, _ = mc.run_suite()
        check("space: the SAME failure with an ample disk stays UNATTRIBUTED",
              outcome == "UNATTRIBUTED FAILURE",
              f"{outcome} — if the disk does not change the verdict, the measurement is inert")
    finally:
        mc.sh = real_sh

    # D0A-R37-03 — ATTRIBUTION was the last thing the subject's own text controlled. A real
    # aborting test moved UNATTRIBUTED -> CAUGHT by printing a `failures:` block naming a test
    # that does not exist.
    real_sh = mc.sh
    try:
        def with_listing(known: str, stdout: str):
            def _sh(cmd, **kw):
                if "--list" in cmd:
                    return types.SimpleNamespace(returncode=0, stdout=known, stderr="")
                return types.SimpleNamespace(returncode=101, stdout=stdout, stderr="")
            return _sh

        mc.sh = with_listing("genuine::test: test\n",
                             "test result: FAILED. 0 passed; 1 failed\n"
                             "failures:\n    fabricated_name\n")
        outcome, ev = mc.run_suite()
        check("attribution: a FABRICATED failure name is UNATTRIBUTED, not CAUGHT",
              outcome == "UNATTRIBUTED FAILURE", outcome)
        check("attribution: ...and the unknown name is retained as the reason",
              ev.get("unknown_failure_names") == ["fabricated_name"],
              f"{ev.get('unknown_failure_names')}")

        mc.sh = with_listing("genuine::test: test\n",
                             "test result: FAILED. 0 passed; 1 failed\n"
                             "failures:\n    genuine::test\n")
        outcome, _ = mc.run_suite()
        check("attribution: a REAL failure naming a KNOWN test is still CAUGHT",
              outcome == "CAUGHT",
              f"{outcome} — narrowing that deletes real detection is not a fix")

        mc.sh = with_listing("a::t: test\nb::t: test\n",
                             "test result: FAILED. 0 passed; 2 failed\n"
                             "failures:\n    a::t\n")
        outcome, ev = mc.run_suite()
        check("attribution: a count that disagrees with the summary is UNATTRIBUTED",
              outcome == "UNATTRIBUTED FAILURE",
              f"{outcome} — libtest said 2 failed and one name was produced")
    finally:
        mc.sh = real_sh

    # The genuine events must still be detected, or this is a deletion rather than a narrowing.
    # A run that produced NO test results is INFRASTRUCTURE BY STRUCTURE, not by matching
    # cargo's words: a test can ADD output but cannot remove the libtest summary that proves
    # tests ran. Asserted with marker text and without it, so the structural path is the one
    # being tested.
    outcome, _ = classify("", 101, stderr="error: could not compile `delphi-runtime`\n")
    check("markers: a run with NO test results is INFRASTRUCTURE (marker present)",
          outcome == "INFRASTRUCTURE", outcome)
    outcome, _ = classify("", 101, stderr="")
    check("markers: ...and with NO marker text at all — purely structural",
          outcome == "INFRASTRUCTURE", outcome)
    outcome, _ = classify(transcript("x"), -9)
    check("markers: death by SIGNAL is INFRASTRUCTURE, unfakeable from output",
          outcome == "INFRASTRUCTURE", outcome)
    outcome, ev = classify(transcript("x"), 101, precondition="stale session on tty1")
    check("markers: a SIDE-CHANNEL report is PRECONDITION FAILURE",
          outcome == "PRECONDITION FAILURE", outcome)
    check("markers: and it carries the reported reason",
          any("stale session" in m for m in ev.get("precondition_markers", [])),
          f"{ev.get('precondition_markers')}")


def guard_cleanup_failure_is_visible_and_retryable() -> None:
    """D0A-R33-01 — a cleanup that CANNOT FAIL cannot be trusted to have happened.

    `shutil.rmtree(..., ignore_errors=True)` plus an unconditional `_WORKTREE.clear()` meant a
    mode-000 directory produced a NORMAL RETURN with the checkout still on disk and its git
    registration already pruned: invisible to `git worktree list`, unowned by this process, and
    impossible to retry. The reviewer reproduced exactly that.
    """
    sha = mc.sh(["git", "rev-parse", "HEAD"]).stdout.strip()
    mc.make_isolated_checkout(sha)
    parent = mc._WORKTREE["parent"]
    os.chmod(parent, 0o000)
    try:
        ok = mc.remove_isolated_checkout()
        check("cleanup: an undeletable checkout is reported as FAILED", ok is False,
              f"remove_isolated_checkout returned {ok!r}")
        check("cleanup: the directory really is still there", os.path.exists(parent), parent)
        check("cleanup: OWNERSHIP IS RETAINED so a retry is possible",
              mc._WORKTREE.get("parent") == parent,
              f"state was cleared despite failure: {mc._WORKTREE!r}")
    finally:
        os.chmod(parent, 0o755)
    ok = mc.remove_isolated_checkout()
    check("cleanup: the retry succeeds once the obstruction is gone", ok is True, f"{ok!r}")
    check("cleanup: and the directory is actually gone", not os.path.exists(parent), parent)
    check("cleanup: ownership is released only after success", not mc._WORKTREE, f"{mc._WORKTREE!r}")


def guard_cleanup_verifies_the_git_registration_too() -> None:
    """D0A-R34-03 — the filesystem is not the only resource this harness owns.

    A LOCKED worktree keeps its entry in `git worktree list` after the directory is gone, since
    `prune` refuses locked entries by documented design. Verifying only file absence therefore
    reported success while forgetting a registration — and exit 4 could not catch it, because
    the cleanup predicate itself was falsely true.
    """
    sha = mc.sh(["git", "rev-parse", "HEAD"]).stdout.strip()
    path = str(mc.make_isolated_checkout(sha))
    mc.sh(["git", "worktree", "lock", path])
    try:
        ok = mc.remove_isolated_checkout()
        listed = mc.sh(["git", "worktree", "list", "--porcelain"]).stdout
        check("registration: a LOCKED entry makes cleanup report FAILURE", ok is False,
              f"returned {ok!r} while {path} was still registered")
        check("registration: and the entry really is still there",
              any(l.strip() == f"worktree {path}" for l in listed.splitlines()), listed)
        check("registration: ownership is retained for the retry",
              mc._WORKTREE.get("path") == path, f"{mc._WORKTREE!r}")
    finally:
        mc.sh(["git", "worktree", "unlock", path])
        mc.sh(["git", "worktree", "remove", "--force", path])
        mc.sh(["git", "worktree", "prune"])
        shutil.rmtree(mc._WORKTREE.get("parent", "/nonexistent"), ignore_errors=True)
        mc._WORKTREE.clear()
    listed = mc.sh(["git", "worktree", "list", "--porcelain"]).stdout
    check("registration: the guard leaves nothing of its own behind",
          not any(l.strip() == f"worktree {path}" for l in listed.splitlines()), listed)


def guard_checkout_collected_on_every_exit_path() -> None:
    """D0A-R32-05 — the checkout is collected on the ORDINARY exits, not only on signals.

    `remove_isolated_checkout()` sat at the bottom of `main`, so the baseline refusal's early
    return and any exception unwound straight past it. Thirty-eight abandoned `mkdtemp` parents
    had accumulated in `/tmp` before anyone looked — and the guard did not see them, because it
    read `git worktree list`, which `git worktree remove` had faithfully cleaned.
    """
    def residue() -> tuple[list[str], str]:
        dirs = [str(x) for x in
                sorted(pathlib.Path(tempfile.gettempdir()).glob("delphi-mutation-wt-*"))]
        return dirs, mc.sh(["git", "worktree", "list"]).stdout

    # (a) BASELINE REFUSAL — a red baseline returns 2 before the campaign body.
    out = pathlib.Path(tempfile.mkdtemp(prefix="delphi-r3205-"))
    env = dict(os.environ)
    env["DELPHI_MUTATION_TEST_CMD"] = "false"
    r = subprocess.run([sys.executable, str(REPO / "scripts" / "mutation-campaign.py"),
                        "--out", str(out), "--instrument-dirty-ok"], cwd=REPO, env=env, capture_output=True,
                       text=True, timeout=300)
    check("lifetime: a red baseline refuses", r.returncode == 2, f"exit was {r.returncode}")
    dirs, wt = residue()
    check("lifetime: the baseline refusal leaves no mkdtemp parent", not dirs, str(dirs))
    check("lifetime: the baseline refusal leaves no registered worktree",
          "delphi-mutation-wt-" not in wt, wt)
    shutil.rmtree(out, ignore_errors=True)

    # (b) AN ORDINARY EXCEPTION — the path the reviewer named alongside the refusal. Raised
    # from inside the campaign body, AFTER the checkout exists, so the `finally` is what
    # collects it.
    sha = mc.sh(["git", "rev-parse", "HEAD"]).stdout.strip()
    original = mc._main

    def _boom() -> int:
        mc.make_isolated_checkout(sha)
        raise RuntimeError("ordinary exception inside the campaign body")

    mc._main = _boom
    raised = False
    try:
        mc.main()
    except RuntimeError:
        raised = True
    finally:
        mc._main = original
    check("lifetime: the exception propagates (it is not swallowed)", raised)
    dirs, wt = residue()
    check("lifetime: an ORDINARY EXCEPTION still collects the mkdtemp parent", not dirs,
          str(dirs))
    check("lifetime: an ORDINARY EXCEPTION still collects the worktree",
          "delphi-mutation-wt-" not in wt, wt)


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
    guard_dirty_instrument_is_refused()
    guard_markers_in_assertion_data_do_not_decide_cause()
    guard_cleanup_failure_is_visible_and_retryable()
    guard_cleanup_verifies_the_git_registration_too()
    guard_checkout_collected_on_every_exit_path()
    print(f"\n{len(CHECKS)} guards held")
    return 0


if __name__ == "__main__":
    sys.exit(main())
