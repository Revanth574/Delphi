#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Refuse to certify a lane run whose evidence is missing, failed, or out of order.

# Why this exists (D0A-R35, after four instances)

Four required checks were disconnected from acceptance, every one of them AFTER the decision
to defer this tool, and three of them inside remediation for the finding that named the
pattern:

* run 20's §4b membership check was dropped from a hand-assembled sequence;
* run 20's free-space refusal was overridden and the run proceeded;
* run 21's `$LOG`/`$STATUS` were unset, so a step failed at its first token while looking like
  the long-running loop it should have started;
* run 21's freshness, producer-exit and hygiene claims had no retained evidence at all.

None was caught by the actor that caused it. Each was found afterwards, by someone reading.

# What this is NOT

It is **not** the runner reverted at D0A-R23-05. That runner REPLACED the procedure and
silently dropped five of its checks. This one executes nothing: the procedure still runs, by
hand, exactly as written. This reads what the procedure retained and decides whether the run
may be cited as acceptance. Conflating "a tool that runs the lane" with "a tool that refuses
an under-evidenced lane" is what made the deferral look reasonable.

# What it cannot do — stated because a verifier that overstates is worse than none

Nothing here binds the artifacts to a commit. A directory of evidence from run N proves the
steps ran and passed; it does not prove they ran against the tree you are about to merge. The
run record carries the SHA and a reader must still check it.
"""

from __future__ import annotations

import argparse
import os
import os
import pathlib
import re
import time
import sys

EXPECTED_TARGETS = 17

# From this run on, a lane run must also carry the NEGATIVE control's evidence (D0A-R35). It is
# keyed to the run number rather than applied unconditionally: run 23 and earlier predate the
# fixture, and a check that retroactively invalidated history it was never applied to would be a
# different kind of overreach. Runs from here cannot quietly omit it — which is the whole
# distinction this tool exists to hold (`DEFECT_CLASSES` 54).
FIRST_RUN_REQUIRING_NEGATIVE_CONTROL = 24

# D0A-R36-03: freshness rests on a rebuild that SUCCEEDED, and the exit status is the
# evidence. Keyed like the negative control so historical runs are not retroactively refused.
FIRST_RUN_REQUIRING_REBUILD_STATUS = 26

# D0A-R36-04: a distinct run-start event, so freshness is compared against the run's START
# rather than its last append.
FIRST_RUN_REQUIRING_RUN_START = 26


class Refusal(Exception):
    """A named, specific reason this run cannot be certified."""


def _read(d: pathlib.Path, name: str) -> str:
    p = d / name
    if not p.exists():
        raise Refusal(f"{name} is MISSING — the step that produces it left no evidence, which "
                      f"is indistinguishable from it never having run")
    return p.read_text(errors="replace")


def check_hygiene(d: pathlib.Path) -> list[str]:
    """Every hygiene check must be present AND show its passing result."""
    text = _read(d, "hygiene.txt")
    required = {
        "delphi-tool:x:997:972": "the tool account's uid:gid (D0A-R17-02 — gid 972, not 997)",
        "above their floors": "free space (run 20's refusal was OVERRIDDEN; that must not "
                              "certify again)",
        "no stale sessions": "stale-session sweep",
        "bubblewrap": "the bwrap version",
    }
    notes = []
    for needle, what in required.items():
        if needle not in text:
            raise Refusal(f"hygiene.txt does not show {what} passing (looked for {needle!r})")
    if not re.search(r"delphi-runtime: OK", text):
        raise Refusal("hygiene.txt does not show the PAM stack unchanged (`md5sum -c` OK) — "
                      "class 16 is a defect this project has already paid for once")
    # D0A-R35: the commit the run was taken against, RECORDED so the binding stops being an
    # inference from file timestamps. Run 23's SHA was established that way and it is the one
    # link this tool could not check.
    if "=== commit ===" in text:
        m = re.search(r"=== commit ===\n([0-9a-f]{40})\n(.*?)(?=\n=== |\Z)", text, re.S)
        if m is None:
            raise Refusal("hygiene.txt has a commit section but no 40-char SHA under it")
        # The run's OWN artifacts make the tree untracked-dirty by construction — the
        # directory is created by §4b, several steps before this is recorded. Filtering them is
        # not a loophole: they ARE the run's output, and treating a run's own products as
        # evidence that it ran against no commit refused run 24 for a condition the procedure
        # guarantees (D0A-R35). Anything else dirty still refuses.
        dirty = [
            l for l in m.group(2).splitlines()
            if l.strip() and not re.match(r"^\?\?\s+scratch/lane-run-\d+/?$", l.strip())
        ]
        if dirty:
            m = type("M", (), {"group": staticmethod(lambda n: "\n".join(dirty))})()
            raise Refusal(f"the working tree was DIRTY when the run was taken:\n"
                          f"{m.group(2).strip()[:300]}\n— the artifacts do not describe any "
                          f"commit, so the run cannot be attributed to one")
    digests = re.findall(r"^([0-9a-f]{64})\s+\S*delphi-drop$", text, re.M)
    if len(digests) < 2:
        raise Refusal("hygiene.txt does not record BOTH helper digests (installed and staged)")
    if len(set(digests)) != 1:
        raise Refusal(f"the installed and staged helper digests DIFFER: {sorted(set(digests))} "
                      f"— a stale install, not a profile difference")
    notes.append(f"helper digest {digests[0][:16]}… installed == staged")
    return notes


def check_freshness(d: pathlib.Path) -> list[str]:
    before, after = _read(d, "hashes-before.txt"), _read(d, "hashes-after.txt")
    nb, na = len(before.strip().splitlines()), len(after.strip().splitlines())
    if nb != EXPECTED_TARGETS or na != EXPECTED_TARGETS:
        raise Refusal(f"the freshness pair covers {nb}/{na} executables, not "
                      f"{EXPECTED_TARGETS} — a subset cannot prove the set is fresh")
    if before != after:
        raise Refusal("the executables CHANGED under the forced rebuild: the hashed set was "
                      "STALE, so the run measured code that is not this tree's")
    log = _read(d, "rebuild.log")

    # D0A-R36-03: IDENTICAL HASHES ARE EQUALLY CONSISTENT WITH A REBUILD THAT NEVER RAN.
    # `rebuild.log` merely had to EXIST — so replacing it with `error: could not compile`
    # still certified "freshness proven". Reproduced against run 23's real artifacts before
    # this fix. A failed rebuild leaves the stale binaries untouched, which is exactly the
    # condition the check exists to exclude.
    run = _run_number(d)
    status = d / "rebuild.status"
    if status.exists():
        rc = status.read_text().strip()
        if rc != "0":
            raise Refusal(f"the forced rebuild exited {rc}, so the identical hashes prove "
                          f"nothing: a rebuild that FAILED leaves the stale binaries in place")
    elif not _is_historical(d, FIRST_RUN_REQUIRING_REBUILD_STATUS):
        raise Refusal("no rebuild.status — identical hashes are consistent with a rebuild "
                      "that failed, so the exit status is what makes them evidence")
    else:
        # Historical runs predate the artifact. Read the log for the failure shapes instead;
        # weaker than an exit status and labelled as such rather than passed off as equal.
        if re.search(r"^error(\[|:)|could not compile|error: linking with", log, re.M):
            raise Refusal("rebuild.log reports a BUILD FAILURE, so the identical hashes are "
                          "the stale set surviving a rebuild that did not happen")
    return [f"freshness: {nb} executables identical across a rebuild that "
            f"{'exited 0' if status.exists() else 'logged no build failure'}"]


def check_producers(d: pathlib.Path) -> list[str]:
    name = next((p.name for p in d.glob("root-run*.status")), None)
    if name is None:
        raise Refusal("no producer-status file (root-run*.status) — without it a target that "
                      "CRASHED before printing its summary vanishes from the count entirely")
    lines = [l for l in _read(d, name).splitlines() if l.strip()]
    if len(lines) != EXPECTED_TARGETS:
        raise Refusal(f"{name} records {len(lines)} producers, not {EXPECTED_TARGETS}")
    bad = [l for l in lines if not l.split("\t")[0].strip() == "0"]
    if bad:
        raise Refusal(f"{len(bad)} producer(s) exited nonzero: {bad[:3]}")

    # D0A-R36-02: COUNTING LINES IS NOT CHECKING IDENTITIES. Seventeen copies of ONE
    # producer's successful status certified — reproduced against run 23's artifacts. The
    # status file is joined to the hash manifest, which is the independently produced list of
    # what was supposed to run.
    paths = [l.split("\t", 1)[1].strip() for l in lines if "\t" in l]
    if len(set(paths)) != EXPECTED_TARGETS:
        raise Refusal(f"{name} names {len(set(paths))} DISTINCT executables across "
                      f"{len(lines)} lines — duplicated status lines are not {EXPECTED_TARGETS} "
                      f"producers")
    hashed = {l.split(None, 1)[1].strip()
              for l in _read(d, "hashes-before.txt").strip().splitlines() if " " in l}
    if hashed and set(paths) != hashed:
        missing, extra = sorted(hashed - set(paths))[:3], sorted(set(paths) - hashed)[:3]
        raise Refusal(f"the producers that RAN are not the executables that were HASHED. "
                      f"hashed-but-not-run: {missing}; run-but-not-hashed: {extra}")
    return [f"producers: {len(set(paths))}/{EXPECTED_TARGETS} distinct, all exited 0, "
            f"matching the hashed set"]


def check_membership(d: pathlib.Path) -> list[str]:
    text = _read(d, "membership.txt")
    for side in ("IN ROOT NOT UNPRIV", "IN UNPRIV NOT ROOT"):
        m = re.search(rf"^{side}: (\d+)$", text, re.M)
        if m is None:
            raise Refusal(f"membership.txt does not report {side!r}")
        if int(m.group(1)) != 0:
            raise Refusal(f"{side} is {m.group(1)}, not 0 — the identity SETS differ, which "
                          f"equal totals cannot detect")
    root, unpriv = _read(d, "root-identities.txt"), _read(d, "unpriv-identities.txt")
    for name, body in (("root-identities.txt", root), ("unpriv-identities.txt", unpriv)):
        for line in body.strip().splitlines():
            if not re.match(r"^\d+\t\S", line):
                raise Refusal(f"{name} line {line!r} has no explicit count — bare keys drop "
                              f"MULTIPLICITY, so the multiset cannot be reconstructed "
                              f"(D0A-R35-05)")
    # D0A-R36-02: THE PRINTED ZEROES WERE TRUSTED. An EMPTY root identity file certified
    # ("0 identities each side, zero either way"), and so did an EMPTY root transcript,
    # because the transcript was read only for its mtime. Both reproduced against run 23's
    # artifacts. The root side is now RE-DERIVED from the retained transcript and compared.
    root_counter: dict[str, int] = {}
    target = None
    for line in _read(d, "root-run.log").splitlines():
        if line.startswith("### "):
            target = os.path.basename(line[4:].strip()).rsplit("-", 1)[0]
        m = re.match(r"^test (\S+) \.\.\. ", line)
        if m and target:
            root_counter[f"{target}::{m.group(1)}"] = root_counter.get(
                f"{target}::{m.group(1)}", 0) + 1
    if not root_counter:
        raise Refusal("the retained transcript contains NO test lines, so the identity files "
                      "cannot be checked against anything — an empty log is not a run")

    recorded: dict[str, int] = {}
    for line in root.strip().splitlines():
        c, ident = line.split("\t", 1)
        recorded[ident.strip()] = int(c)
    if recorded != root_counter:
        only_file = sorted(set(recorded) - set(root_counter))[:3]
        only_log = sorted(set(root_counter) - set(recorded))[:3]
        raise Refusal(f"root-identities.txt does not match the retained transcript "
                      f"({len(recorded)} vs {len(root_counter)} identities). "
                      f"in-file-only: {only_file}; in-log-only: {only_log}")

    n_unpriv = sum(int(l.split("\t", 1)[0]) for l in unpriv.strip().splitlines() if l.strip())
    m = re.search(r"^root (\d+) / unpriv (\d+)$", text, re.M)
    if m is None:
        raise Refusal("membership.txt has no `root N / unpriv N` line to check the files against")
    if (sum(root_counter.values()), n_unpriv) != (int(m.group(1)), int(m.group(2))):
        raise Refusal(f"membership.txt claims root {m.group(1)} / unpriv {m.group(2)}, but the "
                      f"retained files carry root {sum(root_counter.values())} / unpriv "
                      f"{n_unpriv}")
    return [f"membership: {len(root_counter)} identities RE-DERIVED from the transcript and "
            f"matching the retained file, {n_unpriv} unprivileged, zero either way"]


# The exact test each control transcript must contain, and the verdict it must carry.
CONTROLS = {
    "part-b-control.txt": ("b1_daemon_bounds_an_ai_that_completes_the_protocol_and_stays_alive",
                           "Reached", "positive control"),
    "part-b-negative-control.txt": (
        "the_control_reports_topology_when_the_daemons_child_leaves_its_group",
        "Topology", "negative control"),
}


def _check_control_transcript(d: pathlib.Path, name: str) -> str:
    """A verdict line is a DIAGNOSTIC, not a result (D0A-R36-01).

    The positive control prints its verdict BEFORE the survivor, deadline and shutdown
    assertions, so `Reached` followed by an assertion failure certified — reproduced against
    run 23's real transcript. What certifies is the test completing, by name, passing, unskipped.
    """
    test, want, what = CONTROLS[name]
    text = _read(d, name)

    if f"test {test} " not in text:
        raise Refusal(f"{name} does not name {test} — a transcript that does not identify the "
                      f"test it reports cannot certify it")
    if "SKIP" in text or "DEFER" in text:
        raise Refusal(f"the {what} SKIPPED; a skip is scored as a PASS and is not a run")
    m = re.search(r"^test result: (\w+)\. (\d+) passed; (\d+) failed", text, re.M)
    if m is None:
        raise Refusal(f"{name} carries no `test result:` summary, so the {what} did not "
                      f"complete — a verdict printed mid-test is not an outcome")
    outcome, passed, failed = m.group(1), int(m.group(2)), int(m.group(3))
    if outcome != "ok" or passed != 1 or failed != 0:
        raise Refusal(f"the {what} reported `{outcome}. {passed} passed; {failed} failed` — its "
                      f"verdict line says nothing about a test that did not pass")

    mv = re.search(r"verdict: (\w+)", text)
    if mv is None:
        raise Refusal(f"{name} records no `verdict:` line — a {what} with no verdict "
                      f"establishes nothing about whether the control can DISCRIMINATE")
    return mv.group(1)


def _run_number(d: pathlib.Path) -> int | None:
    """The run number, or None when the directory name does not carry one.

    D0A-R37-05: an unknown identity used to WAIVE the modern-artifact requirements, so renaming
    a refused `lane-run-26` directory to anything else made it accept. An age waiver that can be
    obtained by renaming is not a waiver, it is a bypass — and the direction is wrong: the
    unknown case must be treated as CURRENT, because current is the stricter reading and a
    genuinely historical run can say so explicitly.
    """
    m = re.search(r"lane-run-(\d+)", d.resolve().name)
    return int(m.group(1)) if m else None


def _is_historical(d: pathlib.Path, first_required: int) -> bool:
    """Is this run old enough to predate a requirement — ESTABLISHED, not assumed?

    Two ways to establish it, both explicit: the directory name carries a run number below the
    threshold, or the run retains a `PREDATES.txt` naming the requirements it predates. An
    unnamed directory is NOT historical; it is current evidence that failed to identify itself.
    """
    run = _run_number(d)
    if run is not None:
        return run < first_required
    predates = d / "PREDATES.txt"
    return predates.exists() and str(first_required) in predates.read_text()


def check_control(d: pathlib.Path) -> list[str]:
    pos = _check_control_transcript(d, "part-b-control.txt")
    if pos != "Reached":
        raise Refusal(f"the positive control returned {pos}, not Reached — the supplementary "
                      f"scan it underwrites has no basis in this run")
    notes = [f"positive control: {pos}, from a completed passing run of its named test"]

    negative = d / "part-b-negative-control.txt"
    if not negative.exists() and _is_historical(d, FIRST_RUN_REQUIRING_NEGATIVE_CONTROL):
        notes.append(f"negative control: not required for run {_run_number(d)} "
                     f"(predates the fixture)")
        return notes

    verdict = _check_control_transcript(d, "part-b-negative-control.txt")
    if verdict != "Topology":
        raise Refusal(
            f"the negative control returned {verdict}, not Topology. The fixture puts a "
            f"VERIFIED live child of the daemon OUTSIDE its process group, which is exactly the "
            f"input Topology names. `Reached` means THE CONTROL CANNOT DETECT A TOPOLOGY DEFECT, "
            f"and every prior `Reached` in the record is consistent with a control that never "
            f"discriminated; `Scan`/`Unresolved` mean the fixture did not produce the input it "
            f"claims. None of the three may be recorded as an accepted run")
    notes.append(f"negative control: {verdict}, from a completed passing run — the control "
                 f"DISCRIMINATES, so a `Reached` means something")
    return notes


def check_ordering(d: pathlib.Path) -> list[str]:
    """Freshness must be proven BEFORE the run, and membership computed AFTER it."""
    def when(name: str) -> float:
        p = d / name
        if not p.exists():
            raise Refusal(f"{name} is MISSING, so ordering cannot be established")
        return p.stat().st_mtime
    log = next((p.name for p in d.glob("root-run.log")), None)
    if log is None:
        raise Refusal("root-run.log is MISSING — there is no run transcript to order against")
    # D0A-R36-04: `root-run.log` is APPENDED throughout, so its mtime is the run's LAST write,
    # not its start. Comparing freshness against it lets a rebuild performed halfway through the
    # lane qualify as "proven before the run" — and `cp -p` preserves that wrong boundary
    # faithfully. `run-start.txt` is written once, before the first producer, and is the correct
    # boundary. Keyed to the run number so historical runs are not retroactively refused; where
    # it is absent the check falls back to the transcript and SAYS the boundary is the weak one.
    run = _run_number(d)
    start = "run-start.txt" if (d / "run-start.txt").exists() else None
    if start is None and not _is_historical(d, FIRST_RUN_REQUIRING_RUN_START):
        raise Refusal("no run-start.txt — without a distinct start event, freshness can only be "
                      "compared against the transcript's LAST write, which a mid-run rebuild "
                      "also satisfies")
    boundary = start or log
    pairs = [
        ("hashes-before.txt", "hashes-after.txt", "the freshness pair is inverted"),
        ("hashes-after.txt", boundary,
         "FRESHNESS WAS PROVEN AFTER THE RUN STARTED, which proves nothing about the binaries "
         "the run actually executed"),
        (log, "membership.txt", "membership predates the run transcript it is computed from"),
    ]
    if start:
        pairs.append((start, log, "the run-start event is newer than the transcript it opens"))
    for earlier, later, why in pairs:
        if when(earlier) > when(later) + 1.0:      # 1s slack for same-second writes
            raise Refusal(f"MISORDERED: {earlier} is newer than {later} — {why}")
    where = "before the run STARTED" if start else "before the run's last write (WEAK boundary: no run-start.txt)"
    return [f"ordering: freshness proven {where}; membership computed after it"]


CHECKS = (
    ("hygiene", check_hygiene),
    ("freshness", check_freshness),
    ("producers", check_producers),
    ("membership", check_membership),
    ("control", check_control),
    ("ordering", check_ordering),
)


def accept(d: pathlib.Path) -> tuple[bool, list[str]]:
    report, ok = [], True
    for name, fn in CHECKS:
        try:
            for note in fn(d):
                report.append(f"  [OK ] {name}: {note}")
        except Refusal as e:
            report.append(f"  [REFUSE] {name}: {e}")
            ok = False
    return ok, report


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("run_dir")
    args = ap.parse_args()
    d = pathlib.Path(args.run_dir)
    if not d.is_dir():
        print(f"REFUSE: {d} is not a directory", file=sys.stderr)
        return 2

    ok, report = accept(d)
    verdict = "ACCEPTED" if ok else "REFUSED"
    body = "\n".join([f"lane acceptance for {d}", *report, "", f"VERDICT: {verdict}", "",
                      "This verdict covers the retained evidence only. Nothing here binds "
                      "these artifacts to a commit;", "the run record carries the SHA and a "
                      "reader must still check it."])
    print(body)
    # D0A-R35-04 applied to this tool: its own verdict is CAPTURED, never transcribed. Written
    # by the verifier itself so it cannot become another terminal paste on its first use.
    # THE RUN'S VERDICT IS NOT OVERWRITTEN BY A LATER RE-VERIFICATION (D0A-R35). Re-running
    # this tool over a historical directory rewrote run 23's captured verdict with output from
    # a NEWER version of the tool — text that execution never produced. The verdict was still
    # ACCEPTED, so nothing false was claimed, but a capture that any later run can mutate is not
    # a capture. The original stays; the re-verification is retained beside it under its own
    # name, because discarding it would lose evidence too.
    # D0A-R36-05: EVERY capture is created EXCLUSIVELY and never opened for truncation. The
    # previous version tested `exists()` then wrote — a check-then-act race — and its fallback
    # name had ONE-SECOND resolution, so two re-verifications in the same second overwrote each
    # other. Reproduced with the clock held constant: an ACCEPTED capture was replaced by a
    # REFUSED one with only a single file left behind. A capture that another capture can
    # destroy is not a capture, which is the same thing this tool says about the run's verdict.
    stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    candidates = [d / "acceptance.txt"] + [
        d / (f"acceptance-reverified-{stamp}.txt" if n == 0
             else f"acceptance-reverified-{stamp}-{n}.txt")
        for n in range(0, 1000)
    ]
    target, fd = None, None
    for cand in candidates:
        try:
            fd = os.open(cand, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
            target = cand
            break
        except FileExistsError:
            continue
        except OSError as e:
            print(f"REFUSE: could not capture the verdict ({e}) — an uncapturable verdict is "
                  f"the defect this tool exists to stop", file=sys.stderr)
            return 2
    if target is None:
        print("REFUSE: could not create a unique capture after 1000 attempts", file=sys.stderr)
        return 2
    if target.name != "acceptance.txt":
        print(f"\nNOTE: {d / 'acceptance.txt'} already exists and is the RUN's verdict. This "
              f"re-verification is written beside it, not over it.")
    try:
        with os.fdopen(fd, "w") as f:
            f.write(body + "\n")
        print(f"\nverdict captured in {target}")
    except OSError as e:
        print(f"REFUSE: could not capture the verdict ({e}) — an uncapturable verdict is the "
              f"defect this tool exists to stop", file=sys.stderr)
        return 2
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
