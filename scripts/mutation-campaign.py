#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Mutation campaign over the canonical action's fields — with a checkable artifact set.

WHY THIS EXISTS (D0A-R28-05). Round 28 handed a reviewer a twelve-row table of mutation
results. The reviewer could not substantiate it: the retained harness reported PATCH-MISS for
the row it claimed a result for, the successful run had happened in an unretained shell
heredoc, and "no test at any privilege level" had been asserted from unprivileged runs only.
The experiments may well have been real. The record could not show it — and for a project whose
whole discipline is that a claim must be checkable by someone who was not there, an
unreproducible experiment is indistinguishable from one that never happened.

**So the output of a mutation campaign is the ARTIFACT SET, not the table.**

WHAT ROUND 29 FOUND IN THE FIRST VERSION OF THIS FILE, because the harness built to fix an
evidence problem had three defects of its own:

* **D0A-R29-01 (P1) — an interrupted campaign could leave a security check REMOVED.** Mutation
  and restoration were not enclosed in `try/finally`, and results were written only at the end.
  An exception between the two left the mutant in the tree with no record. **And restoration
  failure printed REFUSE and still exited 0**, because it never became an invalid outcome.
  Now: `try/finally`, results appended incrementally as JSONL, and **the restore is VERIFIED
  with `git diff --quiet` against the recorded commit rather than trusted from the write** — a
  partial restore leaves a security check removed and reports success just as loudly as a
  complete one.
* **D0A-R29-02 (P2) — infrastructure failures were scored as detections.** Any nonzero `cargo
  test` exit became CAUGHT: a build failure, a launch failure, `No space left on device`. A
  crash may be mutation-induced, but it needs ATTRIBUTION rather than automatic credit. Now
  classified, with full stdout/stderr retained per experiment.
* **D0A-R29-03 (P2) — the clean-tree check excluded inputs that determine the result.** Only
  `runtime/src` was checked, so modified integration tests, manifests, or `Cargo.lock` could
  change the outcome while the metadata attributed everything to the recorded commit. And there
  was **no baseline run** establishing that the reported failures were introduced by the
  mutation at all. Both closed below.

**D0A-R31-01: THE JOURNAL RECORDS DAMAGE; IT DOES NOT PREVENT IT.** R30-01 added signal
handlers and a journal-before-mutate, and I accepted that as covering the uncatchable case. It
does not: a reviewer's SIGKILL reproduction left the source MUTATED, with the journal correctly
saying so. Evidence of a removed security check is not the same as not removing it.

**Mutations now happen in an ISOLATED CHECKOUT of the captured commit** (`git worktree add
--detach`), never in the working tree. Three consequences:

* **A SIGKILL cannot damage the working checkout**, because nothing writes to it. The worst case
  is an abandoned worktree, which the journal names and `git worktree remove --force` collects.
* **It is a checkout of the SHA, not a COPY OF THE TREE.** A copy would inherit uncommitted
  state and reintroduce the attribution problem the clean-tree guard exists to prevent — while
  hiding it, since the guard inspects the working tree and the campaign would be elsewhere.
* **The input-closure question dissolves rather than being answered** (D0A-R30-03). The inputs
  ARE the commit. The dirty-tree check therefore becomes a WARNING: uncommitted work no longer
  affects the result, but a campaign of committed code while you have uncommitted changes is
  probably not what you meant.

RUNNING THIS AT ROOT DOES NOT WORK YET, and the reason is written down rather than left to be
discovered. `sudo -E cargo` does not work on this box (sudoers drops `-E`; root has no rustup
toolchain), so the single `cargo test` call below is unrunnable as root. A root campaign must
SPLIT what this conflates: apply the mutation, build UNPRIVILEGED, enumerate the binaries, run
THOSE under sudo, parse, restore — `scratch/lane-run-7-procedure.md` §1-§4 with a mutation
wrapped around it. Artifact writes must stay unprivileged, and the recorded euid must be the
TESTS', not the harness's. Until that exists, **every result here is an unprivileged result**
and the root-gated tests are not exercised at all.

Usage:  scripts/mutation-campaign.py [--out DIR]
"""

from __future__ import annotations

import argparse
import json
import os
import pathlib
import re
import shlex
import signal
import subprocess
import sys
import tempfile
import time

REPO = pathlib.Path(__file__).resolve().parent.parent
SRC = REPO / "runtime" / "src"

# D0A-R29-03: everything whose modification could change a campaign's outcome. `runtime/src`
# alone was not enough — an edited integration test, manifest or lockfile changes the result
# while the metadata still attributes it to the recorded commit.
INPUT_PATHS = [
    "runtime/", "Cargo.toml", "Cargo.lock", ".cargo/", "delphi-hardening/",
    # The harness itself. A campaign run from an uncommitted harness is no more reproducible
    # than one run from an uncommitted tree — the same argument, applied to the instrument.
    "scripts/mutation-campaign.py",
    # D0A-R30-03: inputs the SUITE consumes that are not under `runtime/`. A probe modified the
    # installer PAM fixture and `inputs_are_clean()` still returned true, so a result could be
    # attributed to a commit whose inputs were not the ones used.
    "installer/pam/delphi-runtime",       # embedded by b1_integration.rs
    "scripts/check-stale-test-sessions.sh",  # executed by the test helper
]

# **THIS LIST IS NOT PROVEN COMPLETE, and saying so is the point.** Adding entries after each
# discovery is exactly the class-48 shape (the fix scoped to the named instance). The sound
# construction is an ISOLATED CHECKOUT of the captured commit, which makes the closure question
# disappear rather than answering it — recorded as owed. Until then this is a best-effort
# allowlist and a campaign's attribution is only as good as it.

# Markers that mean the suite did not get to judge the mutation. A nonzero exit carrying any of
# these is INFRASTRUCTURE, never a detection (D0A-R29-02).
# D0A-R30-04: a NAMED failing test is not automatically a detection. The project's own
# precondition diagnostics fail loudly, name a test, and mean "the environment was wrong" —
# not "the mutation was caught". Classifying those as CAUGHT credits the mutation for an
# infrastructure failure, and a green baseline does not exclude one arising later.
# D0A-R31-06: ONE machine-readable token, emitted by every precondition site
# (`test_child_guard::PRECONDITION_TOKEN`, `check-stale-test-sessions.sh`). The prose entries
# below it are LEGACY — they matched some phrasings and missed others, notably a failure to
# LAUNCH the stale-session checker ("could not run …"), which was therefore scored as a
# detection. Matching prose means every new phrasing is a new instance to discover, which is
# class 48 by construction.
PRECONDITION_TOKEN = "DELPHI_PRECONDITION_FAILED"
PRECONDITION_MARKERS = (
    PRECONDITION_TOKEN,
    # Legacy phrasings, retained so an older binary in the tree is still classified correctly.
    "PRECONDITION FAILED",
    "PRECONDITION failure",
    "STALE SESSION FROM A PREVIOUS RUN",
)

INFRA_MARKERS = (
    "No space left on device",
    "could not compile",
    "error: linking with",
    "Killed",
    "Cannot allocate memory",
    "Resource temporarily unavailable",
    "error: could not execute process",
    "Text file busy",
)

MUTATIONS: list[tuple[str, str, str, str]] = [
    ("argv: drop everything after argv[0]", "execute.rs",
     "    for arg in action.argv.iter().skip(1) {",
     "    for arg in std::iter::empty::<&String>() {"),
    ("cwd: drop --chdir", "sandbox.rs",
     '        args.push("--chdir".to_string());',
     '        if false { args.push("--chdir".to_string()); }'),
    ("env_delta: pass an empty delta to the transport", "execute.rs",
     "let transport = plan_env_transport(&action.env_delta, creds);",
     "let transport = plan_env_transport(&[], creds);"),
    ("env names: hash a constant instead of the name", "action.rs",
     "                s.field(k.as_bytes()).field(v.as_bytes());",
     '                s.field(b"CONSTANT").field(v.as_bytes());'),
    ("fs_binds: emit zero bind arguments", "sandbox.rs",
     "        for (path, mode) in ordered {",
     "        for (path, mode) in ordered.into_iter().take(0) {"),
    ("net_policy: --unshare-net becomes --share-net", "sandbox.rs",
     '            NetPolicy::None => args.push("--unshare-net".to_string()),',
     '            NetPolicy::None => args.push("--share-net".to_string()),'),
    ("required_tier: disable the ENFORCED_TIER refusal", "service.rs",
     "    if action.required_tier > ENFORCED_TIER {",
     "    if false && action.required_tier > ENFORCED_TIER {"),
    ("script: ignore the pinned interpreter", "execute.rs",
     "    if let Some(script) = script_arg_fd {",
     "    if let Some(script) = None::<i32> {"),
    ("executable_digest: remove require_digest_matches", "execute.rs",
     '    require_digest_matches(action.executable_fd.as_raw_fd(), &action.executable_digest, "executable")?;',
     "    // MUTANT: digest check removed"),
    ("executable_fd: remove require_exec_sealed (program fd)", "execute.rs",
     "    require_exec_sealed(action.executable_fd.as_raw_fd())?;",
     "    // MUTANT: program-fd seal check removed"),
    ("script memfd: remove require_fully_sealed [CONTROL]", "execute.rs",
     "        require_fully_sealed(sp.script_memfd.as_raw_fd())?;",
     "        // MUTANT: script seal check removed"),
    ("preview_version: render a constant", "action.rs",
     'out.push_str(&format!("preview_version={}\\n", action.preview_version));',
     'out.push_str("preview_version=3\\n");'),
    ("pending_id: hash a constant", "action.rs",
     "    h.field(pending_id.as_bytes())",
     '    h.field(b"CONSTANT")'),
    ("timeout: hash 0 instead of the value", "action.rs",
     "        .fixed(&timeout.as_nanos().to_le_bytes())",
     "        .fixed(&0u128.to_le_bytes())"),
]


# D0A-R30-01: `try/finally` unwinds PYTHON. It does not run when the process is TERMINATED.
# A SIGTERM during a mutant compilation left the modified source in place and `results.jsonl`
# empty — exit -15, a security check removed from the tree, and no record that anything had
# been attempted. `finally` was necessary and not sufficient.
#
# Two things close it. (1) Catchable termination signals are handled: restore, journal, exit
# non-zero. (2) The in-progress experiment is journalled BEFORE the mutation is written, so an
# UNCATCHABLE kill still leaves evidence naming the file that may be dirty. There is no handler
# for SIGKILL by construction — hence the journal.
_IN_FLIGHT: dict = {}
# The isolated checkout, so the signal handler can name it. Never the working tree.
_WORKTREE: dict = {}


def make_isolated_checkout(sha: str) -> pathlib.Path:
    """A checkout of `sha` that is NOT a copy of the working tree (D0A-R31-01)."""
    d = pathlib.Path(tempfile.mkdtemp(prefix="delphi-mutation-wt-"))
    target = d / "tree"
    r = sh(["git", "worktree", "add", "--detach", str(target), sha])
    if r.returncode != 0:
        raise RuntimeError(f"git worktree add failed: {r.stderr.strip()}")
    _WORKTREE["path"] = str(target)
    return target


def remove_isolated_checkout() -> None:
    path = _WORKTREE.get("path")
    if not path:
        return
    sh(["git", "worktree", "remove", "--force", path])
    _WORKTREE.clear()


def _restore_in_flight(reason: str) -> None:
    """Put back whatever is mutated, then drop the isolated checkout. Safe to call twice.

    D0A-R31-01: everything here operates on the ISOLATED checkout. The working tree is never
    written to, so even total failure of this function cannot leave a removed security check in
    the repository the developer is using.
    """
    path = _IN_FLIGHT.get("path")
    original = _IN_FLIGHT.get("original")
    if path is not None and original is not None:
        try:
            pathlib.Path(path).write_text(original)
            print(f"\nRESTORED {path} (isolated checkout) after {reason}", file=sys.stderr)
        except Exception as e:  # noqa: BLE001 - last-resort path; report and continue
            print(f"\nFAILED TO RESTORE {path} after {reason}: {e}\n"
                  f"This is the ISOLATED checkout, not your working tree. Collect it with: "
                  f"git worktree remove --force {_WORKTREE.get('path', '<worktree>')}",
                  file=sys.stderr)
    _IN_FLIGHT.clear()
    remove_isolated_checkout()


def _on_signal(signum, _frame):
    # ORDER MATTERS (D0A-R31-03): stop the build FIRST. Restoring while `cargo` still runs
    # races it, and exiting while it runs blocks Python's teardown on a child it is waiting for.
    _kill_active_child_group()
    _restore_in_flight(f"signal {signal.Signals(signum).name}")
    # 128+n is the shell's convention for death by signal, and this exit is a FAILURE.
    sys.exit(128 + signum)


def _install_signal_handlers() -> None:
    for sig in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
        try:
            signal.signal(sig, _on_signal)
        except (ValueError, OSError):
            pass  # not on the main thread, or unsupported — the journal still covers us


# D0A-R31-03: the harness must OWN the subprocess tree it starts.
#
# Cancellation used to restore source and exit while leaving the build running. Worse, it could
# not even finish exiting: the signal handler ran, and Python's own teardown then BLOCKED
# waiting for the cargo child it had never been told to stop — measured, a SIGTERM'd campaign
# hung with its isolated checkout uncollected until `timeout` gave up (exit 124).
#
# So every child gets its OWN SESSION (`start_new_session=True`), the live one is registered
# here, and cancellation kills that whole group before anything else. `cargo` spawns `rustc`
# descendants; signalling the leader alone leaves them compiling.
_ACTIVE_CHILD: dict = {}


def _kill_active_child_group() -> None:
    pid = _ACTIVE_CHILD.get("pid")
    if not pid:
        return
    try:
        os.killpg(pid, signal.SIGKILL)   # the whole session, not just the leader
    except (ProcessLookupError, PermissionError):
        pass
    _ACTIVE_CHILD.clear()


def suite_cmd(no_run: bool) -> list[str]:
    """The build/test command, overridable ONLY so the signal guard can run (D0A-R31-04).

    `DELPHI_MUTATION_TEST_CMD` replaces the cargo invocation. It exists because the property the
    guard tests is SIGNAL HANDLING — does cancellation protect the tree and collect the group —
    and a real cargo build makes that test take minutes, so it would not be run.
    Substituting the command narrows the measurement without weakening it: every asserted
    property still fails if violated (Iron Law #15 clause 3).

    It is read from the environment of the HARNESS, never from a mutated tree, and a campaign
    that uses it records the fact in `lane.json` so no result can silently claim to be a real
    build.
    """
    override = os.environ.get("DELPHI_MUTATION_TEST_CMD")
    if override:
        return shlex.split(override)
    base = ["cargo", "test", "-p", "delphi-runtime", "--lib", "--tests"]
    return base + ["--no-run"] if no_run else base


def sh(cmd: list[str], cwd: pathlib.Path | None = None, **kw) -> subprocess.CompletedProcess:
    """Run in the main repo by default; pass `cwd` to run inside the isolated checkout.

    The child leads its own session so cancellation can collect its descendants (D0A-R31-03).
    """
    with subprocess.Popen(
        cmd, cwd=cwd or REPO, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        text=True, start_new_session=True, **kw
    ) as proc:
        _ACTIVE_CHILD["pid"] = proc.pid
        try:
            out, err = proc.communicate()
        finally:
            _ACTIVE_CHILD.clear()
        return subprocess.CompletedProcess(cmd, proc.returncode, out, err)


def inputs_are_clean() -> tuple[bool, str]:
    """D0A-R29-03: every input that could change the outcome, not just `runtime/src`."""
    p = sh(["git", "status", "--porcelain", "--"] + INPUT_PATHS)
    if p.returncode != 0:                     # a failed git command is not "clean"
        return False, f"git status failed: {p.stderr.strip()}"
    return p.stdout.strip() == "", p.stdout.strip()


def file_matches_commit_in_repo(sha: str, rel: str) -> bool:
    """Like [`file_matches_commit`] but always against the MAIN working tree.

    Needed because the isolation guard asks about the working tree precisely while an isolated
    checkout exists, which is when `file_matches_commit` is looking somewhere else.
    """
    return sh(["git", "diff", "--quiet", sha, "--", rel]).returncode == 0


def file_matches_commit(sha: str, rel: str) -> bool:
    """D0A-R29-01: VERIFY the restore rather than trusting the write. D0A-R30-01: against the
    CAPTURED commit, not `HEAD`.

    A partial restore leaves a security check removed and reports success just as loudly as a
    complete one, so the check is against the committed blob rather than our own bookkeeping.
    And it must be the blob the campaign RECORDED: `HEAD` is mutable, so a commit landing
    mid-campaign would silently redefine what "restored" means.
    """
    return sh(["git", "diff", "--quiet", sha, "--", rel],
              cwd=pathlib.Path(_WORKTREE["path"]) if _WORKTREE.get("path") else None
              ).returncode == 0


def run_suite(cwd: pathlib.Path | None = None) -> tuple[str, dict]:
    """Run the suite and CLASSIFY the outcome (D0A-R29-02).

    Returns (outcome, evidence). A nonzero exit is not automatically a detection: a build
    failure, a launch failure or a full disk all exit nonzero and none of them is a test
    judging the mutation.
    """
    p = sh(suite_cmd(no_run=False), cwd=cwd)
    ev = {
        "exit": p.returncode,
        "stdout": p.stdout,           # RETAINED WHOLE — the previous version kept a filtered
        "stderr": p.stderr,           # excerpt and experiment 9's came out empty.
    }
    result_lines = re.findall(r"^test result: (\w+)\.", p.stdout, re.M)
    ev["result_lines"] = len(result_lines)
    ev["failing_tests"] = sorted(set(
        re.findall(r"^\s{4}(\S+)$", p.stdout[p.stdout.find("failures:"):], re.M)
    )) if "failures:" in p.stdout else []

    blob = p.stdout + p.stderr
    infra = [m for m in INFRA_MARKERS if m in blob]
    if infra:
        ev["infra_markers"] = infra
        return "INFRASTRUCTURE", ev
    precond = [m for m in PRECONDITION_MARKERS if m in blob]
    if precond:
        # A named failing test whose failure is a PRECONDITION, not a detection (D0A-R30-04).
        ev["precondition_markers"] = precond
        return "PRECONDITION FAILURE", ev
    if ev["result_lines"] == 0:
        # Nothing reported a result: the suite did not get to judge anything.
        return "INFRASTRUCTURE", ev
    if p.returncode == 0:
        return "NOT CAUGHT", ev
    if not ev["failing_tests"]:
        # Nonzero, tests ran, but no named failure — a crash or signal. It MAY be
        # mutation-induced; it is not a test detecting the mutation, and it needs attribution.
        return "UNATTRIBUTED FAILURE", ev
    return "CAUGHT", ev


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=None)
    args = ap.parse_args()
    out = pathlib.Path(args.out or tempfile.mkdtemp(prefix="delphi-mutation-"))
    (out / "logs").mkdir(parents=True, exist_ok=True)

    _install_signal_handlers()

    head = sh(["git", "rev-parse", "HEAD"]).stdout.strip()

    # D0A-R31-01: this is now a WARNING, not a refusal. The campaign runs in an isolated
    # checkout of `head`, so uncommitted work in the developer's tree cannot affect the result
    # — the attribution question the refusal existed to answer is dissolved by construction.
    # It still warns, because campaigning committed code while holding uncommitted changes is
    # usually not what was meant.
    clean, dirt = inputs_are_clean()
    if not clean:
        print("NOTE: your working tree has uncommitted changes. The campaign runs against an\n"
              "      ISOLATED CHECKOUT of " + head[:12] + ", so those changes are NOT included\n"
              "      and NOT at risk. Uncommitted paths:\n" + dirt + "\n", file=sys.stderr)

    work = make_isolated_checkout(head)
    print(f"isolated checkout: {work}  (working tree is never written to)")
    lane = {
        "isolated_checkout": str(work),
        "working_tree_written_to": False,
        "euid": os.geteuid(),
        "privileged": os.geteuid() == 0,
        "commit": head,
        "started_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "cargo": sh(["cargo", "--version"]).stdout.strip(),
        "suite_cmd_override": os.environ.get("DELPHI_MUTATION_TEST_CMD"),
        "rustc": sh(["rustc", "--version"]).stdout.strip(),
        "cargo_target_dir": os.environ.get("CARGO_TARGET_DIR", "(unset — cargo default)"),
        "inputs_checked": INPUT_PATHS,
    }
    (out / "lane.json").write_text(json.dumps(lane, indent=2) + "\n")

    # D0A-R29-03: THE BASELINE. Without it, "the mutation caused these failures" is an
    # inference from one observation. A red baseline invalidates the whole campaign.
    print("baseline (unmutated) ...", end=" ", flush=True)
    base_outcome, base_ev = run_suite(cwd=work)
    (out / "logs" / "baseline.stdout").write_text(base_ev["stdout"])
    (out / "logs" / "baseline.stderr").write_text(base_ev["stderr"])
    (out / "baseline.json").write_text(json.dumps(
        {k: v for k, v in base_ev.items() if k not in ("stdout", "stderr")}, indent=2) + "\n")
    print(base_outcome, f"({base_ev['result_lines']} result lines)")
    if base_outcome != "NOT CAUGHT":
        print("REFUSE: the UNMUTATED suite is not green. Every result would be "
              "unattributable.", file=sys.stderr)
        return 2
    baseline_targets = base_ev["result_lines"]

    jsonl = (out / "results.jsonl").open("w")
    results = []
    fatal = None

    for i, (label, fname, anchor, repl) in enumerate(MUTATIONS, 1):
        rel = f"runtime/src/{fname}"
        path = work / "runtime" / "src" / fname
        original = path.read_text()
        rec: dict = {"n": i, "label": label, "file": fname, "commit": head}

        if anchor not in original:
            rec["outcome"] = "INVALID: anchor not found in current source"
            rec["anchor"] = anchor
        else:
            # D0A-R29-01: the mutate/restore pair is transactional. Anything raised between
            # them — including KeyboardInterrupt — still restores.
            try:
                # JOURNAL BEFORE MUTATING (D0A-R30-01). If the process is killed uncatchably
                # from here on, this line is the only evidence that `rel` may be dirty.
                jsonl.write(json.dumps(
                    {"n": i, "label": label, "file": fname, "commit": head,
                     "outcome": "IN PROGRESS: mutation about to be written", "rel": rel}) + "\n")
                jsonl.flush()
                os.fsync(jsonl.fileno())
                _IN_FLIGHT.update({"path": str(path), "original": original, "rel": rel})
                path.write_text(original.replace(anchor, repl, 1))
                rec["applied_diff"] = sh(["git", "diff", "--", rel], cwd=work).stdout
                build = sh(suite_cmd(no_run=True), cwd=work)
                if build.returncode != 0:
                    rec["outcome"] = "INVALID: mutant does not compile"
                    (out / "logs" / f"{i:02d}.build.stderr").write_text(build.stderr)
                    (out / "logs" / f"{i:02d}.build.stdout").write_text(build.stdout)
                    rec["compile_stderr_head"] = build.stderr[:1200]
                else:
                    rec["compiles"] = True
                    outcome, ev = run_suite(cwd=work)
                    (out / "logs" / f"{i:02d}.stdout").write_text(ev["stdout"])
                    (out / "logs" / f"{i:02d}.stderr").write_text(ev["stderr"])
                    rec["outcome"] = outcome
                    rec["result_lines"] = ev["result_lines"]
                    rec["failing_tests"] = ev["failing_tests"]
                    rec["suite_exit"] = ev["exit"]
                    if "infra_markers" in ev:
                        rec["infra_markers"] = ev["infra_markers"]
                    # Evidence the relevant tests actually RAN: a mutant that silently reduces
                    # the reporting target count is not a clean detection.
                    if ev["result_lines"] != baseline_targets:
                        rec["target_count_drift"] = {
                            "baseline": baseline_targets, "mutant": ev["result_lines"]}
            finally:
                path.write_text(original)
                _IN_FLIGHT.clear()
                rec["restored_verified"] = file_matches_commit(head, rel)

            if not rec["restored_verified"]:
                # FATAL, and it must not be possible to exit 0 from here (D0A-R29-01).
                rec["outcome"] = "FATAL: restore not verified against the captured commit"
                fatal = rec

        results.append(rec)
        jsonl.write(json.dumps(rec) + "\n")
        jsonl.flush()                     # incremental: an interrupt keeps what completed
        os.fsync(jsonl.fileno())
        print(f"[{i:2}/{len(MUTATIONS)}] {label:<52} {rec['outcome']:<22} "
              f"{','.join(rec.get('failing_tests', []))[:36]}")
        if fatal:
            print(f"ABORT: {rel} does not match HEAD after restore. The tree may be carrying a "
                  f"REMOVED SECURITY CHECK. Run: git checkout -- {rel}", file=sys.stderr)
            break

    jsonl.close()
    remove_isolated_checkout()
    (out / "results.json").write_text(json.dumps(
        {"lane": lane, "baseline_targets": baseline_targets, "results": results}, indent=2) + "\n")

    by = {}
    for r in results:
        by[r["outcome"].split(":")[0]] = by.get(r["outcome"].split(":")[0], 0) + 1
    print(f"\nartifacts: {out}")
    print("outcomes:", ", ".join(f"{k}={v}" for k, v in sorted(by.items())))
    print(f"lane: euid={lane['euid']} "
          f"({'ROOT' if lane['privileged'] else 'unprivileged'}) — claims about other privilege "
          f"levels are NOT supported by this run")
    if not lane["privileged"]:
        print("      root-gated tests were NOT exercised; see the module docstring for what a "
              "root campaign would require")
    if fatal:
        return 3
    return 1 if any(r["outcome"].startswith(("INVALID", "INFRASTRUCTURE", "UNATTRIBUTED", "PRECONDITION", "IN PROGRESS"))
                    for r in results) else 0


if __name__ == "__main__":
    sys.exit(main())
