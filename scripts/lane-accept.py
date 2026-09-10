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
    _read(d, "rebuild.log")
    return [f"freshness: {nb} executables identical across a forced rebuild"]


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
    return [f"producers: {len(lines)}/{EXPECTED_TARGETS} exited 0"]


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
    return [f"membership: {len(root.strip().splitlines())} identities each side, zero either way"]


def _verdict_in(d: pathlib.Path, name: str, what: str) -> str:
    m = re.search(r"verdict: (\w+)", _read(d, name))
    if m is None:
        raise Refusal(f"{name} records no `verdict:` line — {what}")
    return m.group(1)


def _run_number(d: pathlib.Path) -> int | None:
    m = re.search(r"lane-run-(\d+)", d.resolve().name)
    return int(m.group(1)) if m else None


def check_control(d: pathlib.Path) -> list[str]:
    notes = [f"positive control: {_verdict_in(d, 'part-b-control.txt', 'the control outcome is the evidence the supplementary scan rests on')}"]

    run = _run_number(d)
    negative = d / "part-b-negative-control.txt"
    if run is not None and run < FIRST_RUN_REQUIRING_NEGATIVE_CONTROL and not negative.exists():
        notes.append(f"negative control: not required for run {run} (predates the fixture)")
        return notes
    if run is None and not negative.exists():
        raise Refusal("the directory name carries no run number, so the negative-control "
                      "requirement cannot be waived by age — provide the evidence or a "
                      "correctly named directory")

    verdict = _verdict_in(
        d, "part-b-negative-control.txt",
        "a negative control with no verdict establishes nothing about whether the control can "
        "DISCRIMINATE")
    if verdict != "Topology":
        raise Refusal(
            f"the negative control returned {verdict}, not Topology. The fixture puts a "
            f"VERIFIED live child of the daemon OUTSIDE its process group, which is exactly the "
            f"input Topology names. `Reached` means THE CONTROL CANNOT DETECT A TOPOLOGY DEFECT, "
            f"and every prior `Reached` in the record is consistent with a control that never "
            f"discriminated; `Scan`/`Unresolved` mean the fixture did not produce the input it "
            f"claims. None of the three may be recorded as an accepted run")
    notes.append(f"negative control: {verdict} — the control DISCRIMINATES, so a `Reached` means something")
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
    pairs = [
        ("hashes-before.txt", "hashes-after.txt", "the freshness pair is inverted"),
        ("hashes-after.txt", log, "FRESHNESS WAS PROVEN AFTER THE RUN, which proves nothing "
                                  "about the binaries the run actually executed"),
        (log, "membership.txt", "membership predates the run transcript it is computed from"),
    ]
    for earlier, later, why in pairs:
        if when(earlier) > when(later) + 1.0:      # 1s slack for same-second writes
            raise Refusal(f"MISORDERED: {earlier} is newer than {later} — {why}")
    return ["ordering: freshness proven before the run; membership computed after it"]


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
    target = d / "acceptance.txt"
    if target.exists():
        stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
        target = d / f"acceptance-reverified-{stamp}.txt"
        print(f"\nNOTE: {d / 'acceptance.txt'} already exists and is the RUN's verdict. This "
              f"re-verification is written beside it, not over it.")
    try:
        target.write_text(body + "\n")
        print(f"\nverdict captured in {target}")
    except OSError as e:
        print(f"REFUSE: could not capture the verdict ({e}) — an uncapturable verdict is the "
              f"defect this tool exists to stop", file=sys.stderr)
        return 2
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
