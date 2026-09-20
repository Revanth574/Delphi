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
import json
import os
import pathlib
import signal
import subprocess
import sys
import tempfile
import time
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

_ALL_VERDICTS = frozenset({BASELINE_NOT_GREEN, MUTATION_NOT_APPLIED, MUTATION_INVALID,
                           NOT_CAUGHT, WRONG_GUARD, UNVERIFIABLE, TIMEOUT, RESTORE_FAILED,
                           RED_PROVEN})

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
    stdout: str = ""
    stderr: str = ""
    survivors: bool = False        # anything still alive in the group when the stage ended

    @property
    def green(self) -> bool:
        return self.outcome == EXITED and self.code == 0


# ── THE RECORD (D0A-R39, the placement question settled BEFORE this was built) ────────────
#
# WHAT THE RECORD IS FOR. Not "what happened" — **re-openability**. The test for every field
# is whether a reader who was not here could reconstruct the experiment well enough to
# DISAGREE with its verdict. A field that does not serve that is decoration; a missing field
# that does is a gap.
#
# WHY `duration_s` IS IN HERE, and the reasoning the next person adding a field needs:
# every other field is a CONTENT fact (which bytes, which label, which exit). The sharpest
# refusal this tool has produced was a TIMING fact — deleting a `killpg` made the driver hang
# for the suite's full timeout, so its restore landed AFTER a grandchild's write and masked
# the defect the weaken targeted. A record of what happened that cannot show WHEN it happened
# cannot surface a self-invalidating experiment, which is the category this tool exists to
# catch and the one that produced three refusals in a single session.
#
# WHY THE INSTRUMENT AND THE SUBJECT ARE TWO FIELDS. This driver's own rounds were the driver
# making claims about the driver: it runs from memory while mutating its own source on disk.
# "instrument digest: X" is ambiguous exactly when X is also the mutated target, which is the
# case needing the MOST scrutiny. `digest_executing` is captured at import, before anything
# can be written.
#
# WHY EVERY RECORD CARRIES ITS OWN LIMITS. A claim that travels without them is what "unwired"
# concealed: the register held the limits and the citation did not. Attached to the artifact,
# they travel with every citation by construction.
SCHEMA = "delphi.weaken-record/3"

RECORD_LIMITS = [
    "does not establish that the weakened guard is well-chosen",
    "NOT_CAUGHT does not separate a redundant check from a condition never arranged "
    "(DEFECT_CLASSES 58)",
    "the guard-label side channel is a report channel for TRUSTED HELPERS; it is not evidence "
    "against a hostile subject",
    "a descendant that calls setsid escapes process-group collection (D0A-R38-02, pinned)",
    "content-addressing prevents POST-HOC EDITING of this record, not fabrication of one",
]

# Captured at import, before this process can write anything — so for a self-weaken it is the
# EXECUTING bytes, not whatever is on disk when the record is written.
_INSTRUMENT_PATH = pathlib.Path(__file__).resolve()
_INSTRUMENT_DIGEST = hashlib.sha256(_INSTRUMENT_PATH.read_bytes()).hexdigest()


# D0A-R40-01: THE EVIDENCE CONTRACT, SHARED. The consumer checked a hash and a declared
# verdict and nothing else — `{"id": ..., "verdict": "RED_PROVEN"}` was accepted and a commit
# claiming RED-proof succeeded. There was no experiment to re-open. Gutting the producer's
# observation whitelist to `if False` also left all guards passing and produced records the
# hook accepted. Both sides now answer to ONE list, here, so neither can drift from it.
REQUIRED_PATHS = [
    "schema", "id", "verdict",
    "expectation.guard", "expectation.registered_at",
    "instrument.path", "instrument.digest_executing",
    "subject.path", "subject.digest_before", "subject.is_the_instrument_file",
    "suite.argv", "suite.cwd", "suite.sources",
    "inputs.subject_original", "inputs.instrument",
    "execution.timeout_s", "execution.interpreter",
    "phases", "observations", "limits",
]

# What a RED_PROVEN record must ALSO carry. A verdict is a claim about an experiment; these
# are the observations that experiment must have produced for the claim to be re-openable.
#
# D0A-R41-01: the first version required these CONTAINERS and stopped. Dropping `baseline`,
# `weakened` and `restored` from the producer's whitelist left every guard passing and produced
# records — with no invocation results in them at all — that the validator ACCEPTED as
# RED_PROVEN. Requiring `observations` to be non-empty is not requiring evidence.
RED_PROVEN_PHASES = ("validate-original", "baseline", "validate-mutant", "observe", "restore",
                     "restored")
INVOCATION_PHASES = ("baseline", "observe", "restored")
VALIDATION_PHASES = ("validate-original", "validate-mutant")


def _check_source_ref(ref, where: str, problems: list[str]) -> None:
    """A reference is recoverable or it is a placeholder. `{"path": "x"}` is a placeholder."""
    if not isinstance(ref, dict):
        problems.append(f"{where} is not a source reference")
        return
    if not ref.get("sha256"):
        problems.append(f"{where} carries no sha256, so it names bytes rather than binding them")
    if not ref.get("git_blob") and ref.get("content") is None:
        problems.append(f"{where} is neither resolvable from git nor carries its content")


def _check_red_proven_evidence(body: dict, problems: list[str]) -> None:
    """The observations a RED_PROVEN claim rests on, checked as observations."""
    phases = {p.get("name"): p for p in body["phases"] if isinstance(p, dict)}
    absent = [p for p in RED_PROVEN_PHASES if p not in phases]
    if absent:
        problems.append(f"RED_PROVEN without the phases that would show it: {absent}")
        return
    for name in INVOCATION_PHASES:
        if "outcome" not in phases[name] or "streams" not in phases[name]:
            problems.append(f"phase {name!r} records no process evidence, only its timing")
    for name in VALIDATION_PHASES:
        val = phases[name].get("validation")
        if not isinstance(val, dict) or not val.get("argv") or "exit" not in val:
            problems.append(f"phase {name!r} records no validation evidence, only its timing")

    obs = body.get("observations") or {}
    expected = ((body.get("expectation") or {}).get("guard"))
    for name, want_zero in (("baseline", True), ("weakened", False), ("restored", True)):
        inv = obs.get(name)
        if not isinstance(inv, dict) or "outcome" not in inv:
            problems.append(f"RED_PROVEN without the {name} invocation's result")
            continue
        if inv["outcome"] != EXITED:
            problems.append(f"the {name} invocation did not exit ({inv['outcome']}), so it "
                            f"cannot support a verdict about a guard")
        elif want_zero and inv.get("code") != 0:
            problems.append(f"the {name} invocation exited {inv.get('code')}; RED_PROVEN needs "
                            f"it green")
        elif not want_zero and inv.get("code") in (0, None):
            problems.append("the weakened invocation did not fail, so nothing bit")
    weakened = obs.get("weakened")
    if isinstance(weakened, dict) and expected not in (weakened.get("labels") or []):
        problems.append(f"the weakened invocation's OWN report does not name {expected!r}; "
                        f"`observations.failing_guards` is a summary, not the observation")

    _check_source_ref(_at(body, "inputs.subject_original"), "inputs.subject_original", problems)
    _check_source_ref(_at(body, "inputs.instrument"), "inputs.instrument", problems)
    for i, ref in enumerate(_at(body, "suite.sources") or []):
        _check_source_ref(ref, f"suite.sources[{i}]", problems)


def _at(body: dict, path: str):
    node = body
    for part in path.split("."):
        if not isinstance(node, dict) or part not in node:
            return None
        node = node[part]
    return node


def validate_record(body: dict) -> list[str]:
    """Every reason this record fails the evidence contract. Empty means it holds."""
    problems = []
    for path in REQUIRED_PATHS:
        value = _at(body, path)
        if value is None or value == "" or value == [] or value == {}:
            problems.append(f"missing or empty: {path}")
    if body.get("schema") not in (None, SCHEMA):
        problems.append(f"schema {body['schema']!r} is not {SCHEMA!r}; this record predates "
                        f"the evidence contract and carries no credit under it")
    if body.get("id") and record_id(body) != body["id"]:
        problems.append("the body does not hash to its own id")
    if body.get("verdict") not in _ALL_VERDICTS:
        problems.append(f"unknown verdict: {body.get('verdict')!r}")
    if problems:
        return problems

    phases = {p.get("name") for p in body["phases"] if isinstance(p, dict)}
    if any("duration_s" not in p for p in body["phases"] if isinstance(p, dict)):
        problems.append("a phase carries no duration")

    if body["verdict"] == RED_PROVEN:
        named = _at(body, "observations.failing_guards") or []
        if _at(body, "expectation.guard") not in named:
            problems.append(f"RED_PROVEN, but the expected guard is not among the observed "
                            f"failures {named!r} — the verdict is not supported by the record")
        if _at(body, "observations.mutant_validation") != LOADED:
            problems.append("RED_PROVEN without a mutant that loaded; an invalid experiment "
                            "cannot prove a guard bites")
        if not _at(body, "subject.digest_mutant"):
            problems.append("RED_PROVEN without a recorded mutant digest")
        if _at(body, "subject.digest_restored") != _at(body, "subject.digest_before"):
            problems.append("RED_PROVEN without a verified restoration")
        _check_red_proven_evidence(body, problems)
    return problems


def canonical_body(body: dict) -> bytes:
    """The bytes an ID is computed over. `id` is NEVER part of its own input."""
    return json.dumps({k: v for k, v in body.items() if k != "id"},
                      sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def record_id(body: dict) -> str:
    return hashlib.sha256(canonical_body(body)).hexdigest()[:16]


STREAM_CAP = 64 * 1024


def _streams(inv) -> dict:
    """The subject's own output, RETAINED — and a truncation that says it truncated.

    D0A-R39: the first version of this record carried a comment reading "retained whole and
    deciding nothing" above a field that retained NOTHING. The comment was a claim about the
    code that the code did not honour, which is the R38-06 shape one level up. Streams are the
    channel a human reads to spot "it never reached the gate", so the design test wants them
    present; a SILENT cap would be the same defect again, so the cap announces itself.
    """
    out = {}
    for name, text in (("stdout", inv.stdout or ""), ("stderr", inv.stderr or "")):
        if len(text) > STREAM_CAP:
            out[name] = text[:STREAM_CAP]
            out[f"{name}_truncated_from"] = len(text)
        else:
            out[name] = text
    return out


SOURCE_CAP = 256 * 1024


def _git_has_blob(digest_path: pathlib.Path) -> str | None:
    """The git blob id for these exact bytes, if git already stores them."""
    # Through the primitive like everything else. These are short reads that cannot touch the
    # target, but "there is one way to start a process" is the property, and the structural
    # guard caught these the moment they were added — which is what it is for.
    out = _managed_run(["git", "hash-object", "--", str(digest_path)], None, 30)
    if out.launch_error or out.timed_out or out.returncode != 0:
        return None
    blob = out.stdout.strip()
    held = _managed_run(["git", "cat-file", "-e", blob], None, 30)
    if held.launch_error or held.timed_out or held.returncode != 0:
        return None
    return blob


def _source_ref_from_bytes(path: str, raw: bytes) -> dict:
    """The subject's ORIGINAL bytes, which no later read can recover once it is restored."""
    if not raw:
        return {"path": path, "unavailable": "original bytes were not captured"}
    ref: dict = {"path": path, "sha256": _digest_bytes(raw), "bytes": len(raw)}
    text = raw.decode("utf-8", "replace")
    if len(text) > SOURCE_CAP:
        ref["content"] = text[:SOURCE_CAP]
        ref["content_truncated_from"] = len(text)
    else:
        ref["content"] = text
    return ref


def _source_ref(path: pathlib.Path) -> dict:
    """A RESOLVABLE reference to an input file, or the bytes themselves.

    D0A-R40-02: the record bound the instrument by digest and the suite by ARGV ONLY. Two
    records already in the ledger — a7c6e196 and 7dc26d27 — are identical in instrument,
    subject, suite and expectation and carry UNVERIFIABLE and RED_PROVEN, because the input
    that actually differed was the SUITE FILE'S BYTES, which nothing recorded. A reader could
    not tell them apart, which is the design test failing on its own entries.

    A digest alone does not recover an untracked or dirty file, so when git does not already
    hold these bytes the content is embedded — with an announced cap, never a silent one.
    """
    try:
        raw = path.read_bytes()
    except OSError as e:
        return {"path": str(path), "unreadable": str(e)}
    ref: dict = {"path": str(path), "sha256": _digest_bytes(raw), "bytes": len(raw)}
    blob = _git_has_blob(path)
    if blob:
        ref["git_blob"] = blob
        return ref
    # Not in git: the bytes travel with the record, because nothing else can supply them.
    text = raw.decode("utf-8", "replace")
    if len(text) > SOURCE_CAP:
        ref["content"] = text[:SOURCE_CAP]
        ref["content_truncated_from"] = len(text)
    else:
        ref["content"] = text
    return ref


class _Phase:
    """Time one phase into the evidence, in order."""

    def __init__(self, ev: dict, name: str):
        self.ev, self.name = ev, name

    def __enter__(self) -> dict:
        self.t0 = time.monotonic()
        self.entry = {"name": self.name, "started_at": round(self.t0 - self.ev["_t0"], 3)}
        self.ev.setdefault("phases", []).append(self.entry)
        return self.entry

    def __exit__(self, *_exc) -> bool:
        self.entry["duration_s"] = round(time.monotonic() - self.t0, 3)
        return False


def _digest_bytes(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def _digest(p: pathlib.Path) -> str:
    return _digest_bytes(p.read_bytes())


# D0A-R39-02/03: EVERY subprocess the driver starts goes through `_managed_run`, and every
# group it creates is registered here until collected. The two findings were one defect — a
# process outside managed lifetime, able to write the target after the driver's last
# observation. Validation was a whole PHASE outside it: added by R38-03's fix, never joined to
# R38-02's.
_LIVE: set[int] = set()


def _collect_group(pgid: int) -> bool:
    """SIGKILL everything left in the group. True if anything was there to kill."""
    _LIVE.discard(pgid)
    try:
        os.killpg(pgid, signal.SIGKILL)
        return True
    except (ProcessLookupError, PermissionError):
        return False


def _collect_all() -> int:
    """Collect every group this driver still owns. Used on cancellation and before restoring."""
    return sum(1 for pgid in list(_LIVE) if _collect_group(pgid))


class Completed(typing.NamedTuple):
    returncode: int | None
    stdout: str = ""
    stderr: str = ""
    timed_out: bool = False
    launch_error: str = ""
    survivors: bool = False


def _managed_run(cmd: list[str], env: dict | None, timeout: int) -> Completed:
    """Run a command in its own process group, and collect that group afterwards.

    `start_new_session` makes the child a group leader, so `pgid == pid`. Nothing in this
    driver may call `subprocess.run` directly: that is precisely what left the validation
    phase able to leave children running past restoration.
    """
    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                text=True, env=env, start_new_session=True)
    except OSError as e:
        return Completed(None, launch_error=str(e))
    _LIVE.add(proc.pid)
    timed_out = False
    try:
        out, err = proc.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        timed_out = True
        _collect_group(proc.pid)
        out, err = proc.communicate()
    survivors = _collect_group(proc.pid)
    return Completed(proc.returncode, out or "", err or "", timed_out, "", survivors)


class Refusal(Exception):
    """The experiment cannot be run at all — not an outcome of running it."""


def _backup_path(target: pathlib.Path) -> pathlib.Path:
    return target.with_name(target.name + ".weaken-backup")


def _open_backup(target: pathlib.Path, original: bytes) -> pathlib.Path:
    """Put the original bytes somewhere a CRASH cannot take with it.

    D0A-R38-02: signal handlers cannot cover SIGKILL or power loss, and this repository lost a
    commit to the latter mid-session. A handler makes the catchable cases clean; this file
    makes the uncatchable ones VISIBLE and reversible — it sits beside the target, so
    `git status` reports it, which is the external check that has caught what self-checks did
    not.
    """
    backup = _backup_path(target)
    if backup.exists():
        raise Refusal(
            f"{backup} already exists: a previous run died with {target} possibly mutated. "
            f"Compare the two and restore before running another weaken — this driver will not "
            f"overwrite a record of an unfinished experiment")
    backup.write_bytes(original)
    return backup


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
    done = _managed_run(cmd, env, timeout)
    # D0A-R40-03: these two returns used to drop the streams `_managed_run` had already
    # collected, so a reader could not tell silence from discarded diagnostics.
    if done.launch_error:
        return Invocation(LAUNCH_FAILED, report=str(report), stdout=done.stdout,
                          stderr=done.stderr or done.launch_error)
    if done.timed_out:
        return Invocation(TIMED_OUT, report=str(report), stdout=done.stdout,
                          stderr=done.stderr)
    labels = []
    if report.exists():
        labels = [l.strip() for l in report.read_text().splitlines() if l.strip()]
    # D0A-R38-09: a process killed by signal N has returncode -N, and SIGHUP is 1 — the same
    # value the timeout sentinel used, so a self-SIGHUP was classified TIMEOUT. Death by signal
    # is its own observation and is never an exit code.
    if done.returncode < 0:
        return Invocation(SIGNALLED, signal=-done.returncode, labels=labels,
                          report=str(report), stdout=done.stdout, stderr=done.stderr,
                          survivors=done.survivors)
    return Invocation(EXITED, code=done.returncode, labels=labels, report=str(report),
                      stdout=done.stdout, stderr=done.stderr, survivors=done.survivors)


_MISMATCH_SENTINEL = "DELPHI-VALIDATION-DIGEST-MISMATCH"
_MISMATCH_EXIT = 97

# Validity is bound to the BYTES ON DISK. Nothing here imports, so `__pycache__` is never
# consulted — see `_validation_cmd`.
_VALIDATE_SRC = """\
import hashlib, pathlib, sys
path, want = sys.argv[1], sys.argv[2]
raw = pathlib.Path(path).read_bytes()
got = hashlib.sha256(raw).hexdigest()
if got != want:
    sys.stderr.write("%s: validated %s, measured %s\\n" % (sys.argv[3], got, want))
    raise SystemExit(__MISMATCH_EXIT__)
sys.path.insert(0, str(pathlib.Path(path).parent))
exec(compile(raw, path, "exec"), {"__name__": "__delphi_validation__", "__file__": path})
""".replace("__MISMATCH_EXIT__", str(_MISMATCH_EXIT))

LOADED, LOAD_FAILED, DIGEST_MISMATCH = "loaded", "load-failed", "digest-mismatch"


def _validation_cmd(target: pathlib.Path, digest: str) -> list[str] | None:
    """How to establish that the target's CURRENT BYTES can run.

    D0A-R38-03: `compile()` proves syntax and nothing else, so a `NameError` at import read as
    a detection. D0A-R39-01: the import that replaced it consults `__pycache__`, whose header
    records source mtime truncated to SECONDS plus size — a same-size edit inside one second
    leaves the cache valid, so validation executed the ORIGINAL's bytecode and certified an
    invalid mutant. Reproduced as RED_PROVEN from a target raising `NameError`.

    Three rounds, three proxies for "the mutant is valid": text, then compilation, now an
    import that can resolve elsewhere. This one reads the bytes, checks their digest against
    what the driver measured, and `exec`s them. There is no cache in that path to be stale.
    """
    if target.suffix != ".py":
        return None
    return [sys.executable, "-B", "-c", _VALIDATE_SRC, str(target), digest, _MISMATCH_SENTINEL]


def _validate_for(target: pathlib.Path, digest: str,
                  custom: list[str] | None) -> list[str] | None:
    """A caller-supplied command cannot be digest-bound; the default one always is."""
    return custom if custom is not None else _validation_cmd(target, digest)


def _loads(cmd: list[str] | None, timeout: int) -> tuple[str, str, dict]:
    """Run a validation command. Returns (status, detail, observation).

    D0A-R40-03: this used to return a status and a truncated string, so the validation
    phases carried nothing but their timing and a reader could not examine the process
    evidence behind the word "loaded".
    """
    if cmd is None:
        return LOADED, "no validation command for this target type", {"ran": False}
    # D0A-R39-03: through the SAME primitive as the suite. This executes target code, so it
    # can leave children running; `subprocess.run` left them outside every group the driver
    # manages, and one wrote the target after restoration had been verified.
    done = _managed_run(cmd, None, timeout)
    obs = {"ran": True, "argv": list(cmd), "exit": done.returncode,
           "signal": -done.returncode if (done.returncode or 0) < 0 else None,
           "timed_out": done.timed_out, "launch_error": done.launch_error,
           "streams": _streams(done)}
    if done.launch_error:
        return LOAD_FAILED, f"validation could not be run: {done.launch_error}", obs
    if done.timed_out:
        return LOAD_FAILED, "validation timed out", obs
    detail = (done.stderr or done.stdout).strip()[-400:]
    # Both halves required: a target is free to exit 97 on its own.
    if done.returncode == _MISMATCH_EXIT and _MISMATCH_SENTINEL in done.stderr:
        return DIGEST_MISMATCH, detail, obs
    return (LOADED if done.returncode == 0 else LOAD_FAILED), detail, obs


def _purge_bytecode(target: pathlib.Path) -> None:
    """Drop compiled forms of the target after every write.

    The driver's own validation no longer imports, but the SUITE may — and a suite that
    imported a stale cache would judge the ORIGINAL while the mutant sat on disk, reporting
    NOT_CAUGHT for a weaken that would have bitten.
    """
    if target.suffix != ".py":
        return
    cache = target.parent / "__pycache__"
    if cache.is_dir():
        for stale in cache.glob(f"{target.stem}.*.pyc"):
            stale.unlink(missing_ok=True)
    (target.parent / f"{target.stem}.pyc").unlink(missing_ok=True)


def _apply_and_observe(target: pathlib.Path, original: bytes, before: str, anchor: bytes,
                       replacement: bytes, suite: list[str], report_dir: pathlib.Path,
                       expect: str, timeout: int, validate: list[str] | None, ev: dict) -> str:
    """Stages 2-5, with the target MUTATED throughout. The caller restores unconditionally."""
    # 2. APPLY, and VERIFY IT APPLIED. `bytes.replace` with a missing anchor returns the input
    # unchanged and raises nothing — the silent no-op that has shipped twice here. Which of the
    # two predicates fired is RECORDED, because that is what makes the first one testable.
    ev["phase"] = "mutate"
    _Phase(ev, "mutate").__enter__()["duration_s"] = 0.0
    if anchor not in original:
        ev["reason"] = "the anchor does not occur in the target"
        ev["not_applied_because"] = "anchor-absent"
        return MUTATION_NOT_APPLIED
    target.write_bytes(original.replace(anchor, replacement, 1))
    _purge_bytecode(target)
    if _digest(target) == before:
        ev["reason"] = "the file is byte-identical after the replacement"
        ev["not_applied_because"] = "bytes-unchanged"
        return MUTATION_NOT_APPLIED
    ev["digest_weakened"] = _digest(target)

    # 3. VALID. Syntax is not validity: the mutant must LOAD. Measured against the same command
    # that loaded the ORIGINAL, so a target that never loads is the experiment's fault and not
    # the mutation's (that control runs in `drive`, before anything is written).
    ev["phase"] = "validate"
    with _Phase(ev, "validate-mutant") as ph:
        status, detail, obs = _loads(
            _validate_for(target, ev["digest_weakened"], validate), timeout)
    ph["validation"] = obs
    ev["mutant_validation"] = status
    ev["mutant_loads"] = status == LOADED
    if status == DIGEST_MISMATCH:
        # Something else wrote the target. That is a broken experiment, not a verdict about
        # the mutation, and it must never read as either INVALID or CAUGHT.
        ev["reason"] = f"the bytes validated are not the bytes measured: {detail}"
        return UNVERIFIABLE
    if status != LOADED:
        ev["reason"] = f"the weakened target does not load: {detail}"
        return MUTATION_INVALID

    # 4. RUN UNDER THE WEAKEN.
    ev["phase"] = "observe"
    with _Phase(ev, "observe") as ph:
        run = _run(suite, report_dir, "weakened", timeout)
    ph["outcome"], ph["report"] = run.outcome, run.report
    ph["streams"] = _streams(run)
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
    ev: dict = {"target": str(target), "expect": expect, "phase": "baseline",
                "_t0": time.monotonic()}
    # The expectation is registered at offset 0.0 — BEFORE any invocation. That ordering is
    # what makes a mis-aimed weaken visible as WRONG_GUARD rather than as a red suite.
    ev["expectation_registered_at"] = 0.0
    # D0A-R38-06: BYTES, NOT TEXT. `read_text`/`write_text` translate newlines, so on a CRLF
    # target the restore wrote LF back and the driver CORRUPTED the tree it was measuring —
    # reporting MUTATION_NOT_APPLIED while doing it. Nothing here may round-trip through str.
    original = target.read_bytes()
    before = _digest_bytes(original)
    ev["digest_before"] = before
    ev["_original_bytes"] = original
    ev["timeout"] = timeout
    anchor_b, repl_b = anchor.encode(), replacement.encode()
    # Test seam, keyword-only: the ONE fault this models is a restore write that reports
    # success without landing, which is the condition the digest check exists for.
    restore = _restore if _restore is not None else target.write_bytes
    report_dir = pathlib.Path(tempfile.mkdtemp(prefix="weaken-report-"))

    # 1. BASELINE, both halves: the target must LOAD and the suite must be green. Nothing has
    # been written yet, so every exit here owes no restoration.
    with _Phase(ev, "validate-original") as ph:
        status, detail, obs = _loads(_validate_for(target, before, validate), timeout)
    ph["validation"] = obs
    ev["original_validation"] = status
    ev["original_loads"] = status == LOADED
    if status == DIGEST_MISMATCH:
        ev["reason"] = f"the bytes validated are not the bytes measured: {detail}"
        return UNVERIFIABLE, ev
    if status != LOADED:
        ev["reason"] = f"the UNMUTATED target does not load: {detail}"
        return BASELINE_NOT_GREEN, ev
    with _Phase(ev, "baseline") as ph:
        base = _run(suite, report_dir, "baseline", timeout)
    ph["outcome"], ph["report"] = base.outcome, base.report
    ph["streams"] = _streams(base)
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
        # D0A-R39-02: COLLECT FIRST. Restoring while the suite was still running let it
        # overwrite the restored bytes a second later — and the backup had already been
        # deleted, so this handler removed the recovery copy and then left the damage.
        _collect_all()
        restore(original)
        if _digest(target) == before:
            backup.unlink(missing_ok=True)
        else:
            sys.stderr.write(f"RESTORE FAILED under signal {signum}; the original bytes are "
                             f"kept at {backup}\n")
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
        _rp = _Phase(ev, "restore"); _rp.__enter__()
        ev["groups_collected_at_restore"] = _collect_all()
        restore(original)
        _purge_bytecode(target)
        ev["digest_restored"] = _digest(target)
        for sig, handler in previous.items():
            signal.signal(sig, handler)
        if ev["digest_restored"] == before:
            backup.unlink(missing_ok=True)
        else:
            ev["backup_retained"] = str(backup)
        _rp.__exit__()

    # D0A-R38-06: ON EVERY TERMINAL PATH. This check used to sit below the success path only,
    # so each early return jumped past it and a corrupted tree was reported as a clean refusal.
    if ev["digest_restored"] != before:
        ev["verdict_before_restore_check"] = verdict
        ev["reason"] = "the target did not come back byte-identical"
        return RESTORE_FAILED, ev
    if verdict != RED_PROVEN:
        return verdict, ev
    with _Phase(ev, "restored") as ph:
        back = _run(suite, report_dir, "restored", timeout)
    ph["outcome"], ph["report"] = back.outcome, back.report
    ph["streams"] = _streams(back)
    ev["restored"] = back._asdict()
    ev["restored_exit"] = back.code
    if not back.green:
        ev["reason"] = "the suite is not green again after restoration"
        return RESTORE_FAILED, ev
    return RED_PROVEN, ev


def build_record(target: pathlib.Path, anchor: str, replacement: str, suite: list[str],
                 expect: str, verdict: str, ev: dict) -> dict:
    """Assemble the record. Everything here is CAPTURED by this process — nothing is typed."""
    body = {
        "schema": SCHEMA,
        "verdict": verdict,
        "expectation": {"guard": expect, "registered_at": ev.get("expectation_registered_at")},
        "instrument": {"path": str(_INSTRUMENT_PATH), "digest_executing": _INSTRUMENT_DIGEST},
        "subject": {
            "path": str(target),
            # The one that matters when the driver weakens itself: the file on disk that was
            # mutated may be the very file this process is running from.
            "is_the_instrument_file": target.resolve() == _INSTRUMENT_PATH,
            "digest_before": ev.get("digest_before"),
            "digest_mutant": ev.get("digest_weakened"),
            "digest_restored": ev.get("digest_restored"),
            "anchor": anchor,
            "replacement": replacement,
        },
        "suite": {"argv": list(suite), "cwd": os.getcwd(),
                  # Every argv element that names a real file, bound by content. The suite is
                  # the input that decides the verdict; binding only its argv binds nothing.
                  "sources": [_source_ref(pathlib.Path(a)) for a in suite
                              if pathlib.Path(a).is_file()]},
        "inputs": {"subject_original": _source_ref_from_bytes(
            str(target), ev.get("_original_bytes", b"")),
            "instrument": _source_ref(_INSTRUMENT_PATH)},
        "execution": {"timeout_s": ev.get("timeout"),
                      "interpreter": sys.executable,
                      "python": sys.version.split()[0],
                      "platform": sys.platform},
        "phases": ev.get("phases", []),
        "observations": {k: ev[k] for k in (
            "original_validation", "mutant_validation", "baseline", "weakened", "restored",
            "failing_guards", "baseline_failing_guards", "not_applied_because",
            "groups_collected_at_restore", "verdict_before_restore_check", "reason")
            if k in ev},
        # The R36-06 disposition one level up: retained, and deciding nothing. The streams
        # live on their phases, where a reader meets them next to the outcome they explain.
        "diagnostics": {"note": "the subject's own output, retained on each phase; data for a "
                                "human reader, and no verdict is derived from it",
                        "stream_cap_bytes": STREAM_CAP},
        "limits": RECORD_LIMITS,
    }
    return {"id": record_id(body), **body}


def write_record(record_dir: pathlib.Path, body: dict) -> pathlib.Path:
    # The producer answers to the same contract as the consumer. A record that cannot be
    # accepted should never have been written — finding that out at commit time is finding it
    # out too late to re-run cheaply.
    failures = validate_record(body)
    if failures:
        raise Refusal("this run produced a record that fails the evidence contract, which is "
                      "a defect in the driver rather than in the weaken: " + "; ".join(failures))
    record_dir.mkdir(parents=True, exist_ok=True)
    path = record_dir / f"{body['id']}.json"
    path.write_text(json.dumps(body, sort_keys=True, indent=2, ensure_ascii=False) + "\n")
    return path


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--target", required=True)
    ap.add_argument("--anchor", required=True)
    ap.add_argument("--replacement", default="")
    ap.add_argument("--expect", required=True, help="the guard label the weaken must fail on")
    ap.add_argument("--timeout", type=int, default=900)
    ap.add_argument("--record-dir", default="scratch/weaken-records",
                    help="where the proof record is written (the ledger this repo cites)")
    ap.add_argument("suite", nargs="+")
    a = ap.parse_args()

    try:
        verdict, ev = drive(pathlib.Path(a.target), a.anchor, a.replacement, a.suite, a.expect,
                            a.timeout)
    except Refusal as e:
        print(f"REFUSED: {e}", file=sys.stderr)
        return 2
    body = build_record(pathlib.Path(a.target), a.anchor, a.replacement, a.suite, a.expect,
                        verdict, ev)
    path = write_record(pathlib.Path(a.record_dir), body)
    print(f"VERDICT: {verdict}")
    print(f"  record: {body['id']}  ({path})")
    # Underscore keys are the driver's own working state (the timeline origin, the captured
    # original bytes). They belong in the RECORD, shaped, not dumped to a terminal.
    for k, v in ev.items():
        if not k.startswith("_"):
            print(f"  {k}: {v}")
    if verdict != RED_PROVEN:
        print(f"\nNOT RED-PROVEN. `{verdict}` is not a weakness in the weaken's TARGET; it is a "
              f"statement about the experiment.", file=sys.stderr)
    return 0 if verdict == RED_PROVEN else 1


if __name__ == "__main__":
    sys.exit(main())
