#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Guards for `scripts/lane-accept.py`.

Every guard is an ASSERTION (D0A-R30-05: a self-test that prints FAIL and exits 0 is a
self-test that cannot fail). The positive control comes first: a verifier that refused
everything would pass every negative guard here and be useless.
"""
from __future__ import annotations

import importlib.util
import os
import pathlib
import re
import shutil
import subprocess
import sys
import tempfile
import time

REPO = pathlib.Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location("la", REPO / "scripts" / "lane-accept.py")
la = importlib.util.module_from_spec(spec)
spec.loader.exec_module(la)

PASSED = 0


def check(label: str, condition: bool, detail: str = "") -> None:
    global PASSED
    assert condition, f"GUARD FAILED: {label}{(' — ' + detail) if detail else ''}"
    print(f"  [OK ] {label}")
    PASSED += 1


HYGIENE = """=== free space ===
All checked filesystems above their floors.
=== stale sessions ===
no stale sessions opened by delphi-runtime
=== PAM ===
/etc/pam.d/delphi-runtime: OK
=== helper digests ===
aba0f0ea14b751aa4a78e22467293f643384ac5f659286088864969cb0e8aace  /usr/libexec/delphi-drop
aba0f0ea14b751aa4a78e22467293f643384ac5f659286088864969cb0e8aace  installer/staging/delphi-drop
=== account ===
delphi-tool:x:997:972::/home/delphi-tool:/usr/sbin/nologin
=== bwrap ===
bubblewrap 0.11.1
"""


def fixture() -> pathlib.Path:
    """A run directory in which every step left PASSING evidence, in the right order."""
    # D0A-R37-11/05: THE POSITIVE FIXTURE IS AN EXPLICITLY CURRENT RUN. It used to be a bare
    # mkdtemp with no run number, so `_run_number` returned None, every modern-artifact
    # requirement was waived, and the positive control exercised the HISTORICAL fallback. That
    # is why disabling the rebuild-status requirement, the run-start requirement, or the
    # inverted-hash check each left all assertions passing: no case required them. A fixture
    # that silently exercises the lenient path cannot discriminate the strict one.
    d = pathlib.Path(tempfile.mkdtemp()) / f"lane-run-{la.FIRST_RUN_REQUIRING_RUN_START + 1}"
    d.mkdir()
    (d / "hygiene.txt").write_text(HYGIENE)
    hashes = "\n".join(f"{i:064x}  /t/exe-{i}" for i in range(la.EXPECTED_TARGETS)) + "\n"
    (d / "rebuild.status").write_text("0\n")
    (d / "hashes-before.txt").write_text(hashes)
    (d / "hashes-after.txt").write_text(hashes)
    (d / "rebuild.log").write_text("Finished test profile\n")
    (d / "run-start.txt").write_text("2026-01-01T00:00:00Z\n")
    (d / "root-run7.status").write_text(
        "\n".join(f"0\t/t/exe-{i}" for i in range(la.EXPECTED_TARGETS)) + "\n")
    # The transcript must actually CONTAIN the identities the files claim (D0A-R36-02).
    (d / "root-run.log").write_text(
        "### /t/exe-0\n" + "".join(f"test test_{i} ... ok\n" for i in range(5)))
    ids = "\n".join(f"1\texe::test_{i}" for i in range(5)) + "\n"
    (d / "root-identities.txt").write_text(ids)
    (d / "unpriv-identities.txt").write_text(ids)
    (d / "membership.txt").write_text(
        "root 5 / unpriv 5\nIN ROOT NOT UNPRIV: 0\nIN UNPRIV NOT ROOT: 0\n")
    (d / "part-b-control.txt").write_text(
        "test b1_daemon_bounds_an_ai_that_completes_the_protocol_and_stays_alive ... \n"
        "CONTROL OBSERVATION: ...\n  verdict: Reached\nok\n\n"
        "test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 22 filtered out\n")
    # A CURRENT run carries both controls (D0A-R35). The base fixture is a current run, so a
    # missing negative control must be introduced deliberately by a guard, never be the default.
    (d / "part-b-control.status").write_text("0\n")
    (d / "part-b-negative-control.status").write_text("0\n")
    (d / "part-b-negative-control.txt").write_text(
        "test the_control_reports_topology_when_the_daemons_child_leaves_its_group ... \n"
        "NEGATIVE CONTROL: verdict: Topology, from 1 distinct record(s)\nok\n\n"
        "test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 22 filtered out\n")
    # Stamp the ordering the checks require.
    base = 1_000_000
    # Order encodes the ordering contract: freshness pair, then the run START, then the
    # transcript, then everything derived from it.
    for i, name in enumerate(["hashes-before.txt", "hashes-after.txt", "rebuild.log",
                              "run-start.txt",
                              "root-run.log", "root-run7.status", "rebuild.status",
                              "membership.txt",
                              "root-identities.txt", "unpriv-identities.txt",
                              "part-b-control.txt", "part-b-control.status",
                              "part-b-negative-control.txt",
                              "part-b-negative-control.status", "hygiene.txt"]):
        os.utime(d / name, (base + i * 10, base + i * 10))
    return d


def refuses(mutate, label: str, needle: str) -> None:
    """The verifier must REFUSE, and its refusal must NAME the thing that is wrong."""
    d = fixture()
    try:
        mutate(d)
        ok, report = la.accept(d)
        body = "\n".join(report)
        check(label, not ok, f"ACCEPTED a run with: {label}")
        check(f"{label} — the refusal says why", needle in body,
              f"refusal did not mention {needle!r}: {body}")
    finally:
        shutil.rmtree(d, ignore_errors=True)


def guard_the_procedure_produces_what_the_verifier_requires() -> None:
    """D0A-R36-08 — the two contracts must MEET, and nothing was checking that they do.

    The gate's required inputs and the procedure's produced artifacts are two halves of one
    interface, each correct on its own: the verifier refused for missing controls the procedure
    never told anyone to produce, and the procedure ended without a later acceptance
    invocation. Following it in order could not produce an accepted run, and the arc's ONE
    accepted run went through a hand-assembled sequence instead.

    That is `DEFECT_CLASSES` 55 — producer and consumer agreeing about the property and
    disagreeing about the interface — at the level of a document and a program. This guard is
    the join.
    """
    verifier = (REPO / "scripts" / "lane-accept.py").read_text()
    procedure = (REPO / "scratch" / "lane-run-7-procedure.md").read_text()

    # What the verifier READS: `_read(d, "name")`, `d / "name"`, and its glob patterns.
    # D0A-R37-04: the extraction missed `.status` paths entirely, so `rebuild.status` — a
    # MANDATORY artifact from run 26 — was never checked against the procedure, and the
    # procedure did not produce it. A contract extracted by pattern is only as wide as the
    # pattern, which is this guard's own standing weakness (class 41).
    required = set(re.findall(r'_read\(d,\s*"([^"]+)"\)', verifier))
    required |= set(re.findall(r'd\s*/\s*"([^"]+\.\w+)"', verifier))
    globbed = set(re.findall(r'd\.glob\("([^"]+)"\)', verifier))
    check("contract: the verifier's required inputs were extracted", len(required) >= 6,
          f"only found {sorted(required)} — the extraction is wrong, not the contract")

    # Two exclusions, each for a stated reason rather than to make the guard pass:
    #   acceptance.txt — the verifier WRITES it; it is an output, not an input.
    #   PREDATES.txt   — an OPTIONAL marker by which a historical run declares which
    #                    requirements it predates. A current run never produces one, so
    #                    requiring the procedure to write it would be backwards.
    required -= {"acceptance.txt", "PREDATES.txt"}

    missing = sorted(a for a in required if a not in procedure)
    check("contract: every artifact the gate REQUIRES is produced by the procedure",
          not missing,
          f"the gate reads {missing} and the procedure never writes them — following the "
          f"procedure cannot produce an accepted run")

    for pattern in globbed:
        stem = pattern.split("*")[0]
        check(f"contract: the procedure produces something matching {pattern!r}",
              stem in procedure, f"nothing in the procedure writes a {pattern} artifact")

    # ORDER: acceptance must be invoked after the last artifact-producing step, or the gate
    # runs before the evidence exists — which is exactly what R36-08 found.
    accept_at = procedure.rfind("scripts/lane-accept.py")
    check("contract: acceptance is invoked at all", accept_at != -1)
    for artifact in ("part-b-control.txt", "part-b-negative-control.txt", "hygiene.txt"):
        produced_at = procedure.rfind(artifact)
        check(f"contract: {artifact} is produced BEFORE acceptance is invoked",
              produced_at < accept_at,
              f"acceptance at {accept_at} precedes {artifact} at {produced_at} — the gate "
              f"would read an artifact the procedure has not written yet")

    # D0A-R37-08: hygiene must be captured AFTER both controls, not merely before acceptance.
    # Taken earlier it predates two root daemon runs, so a PAM stack those controls damaged or a
    # session they left behind is certified by a snapshot from before they ran.
    hygiene_at = procedure.rfind("hygiene.txt")
    for control in ("part-b-control.txt", "part-b-negative-control.txt"):
        check(f"contract: hygiene is captured AFTER {control}",
              procedure.rfind(control) < hygiene_at,
              f"hygiene at {hygiene_at} precedes {control} at {procedure.rfind(control)} — it "
              f"would certify the state from before the controls ran")


def main() -> int:
    # POSITIVE CONTROL FIRST. A verifier that refuses everything passes every guard below.
    d = fixture()
    try:
        ok, report = la.accept(d)
        check("a COMPLETE run directory is ACCEPTED", ok,
              "the verifier refuses even complete evidence, so every refusal below is "
              "meaningless:\n" + "\n".join(report))
    finally:
        shutil.rmtree(d, ignore_errors=True)

    refuses(lambda d: (d / "membership.txt").unlink(),
            "a MISSING artifact is refused", "MISSING")
    refuses(lambda d: (d / "hygiene.txt").unlink(),
            "missing hygiene evidence is refused", "MISSING")
    refuses(lambda d: (d / "root-run7.status").write_text("1\t/t/exe-0\n" + "\n".join(
                f"0\t/t/exe-{i}" for i in range(1, la.EXPECTED_TARGETS)) + "\n"),
            "a NONZERO producer exit is refused", "nonzero")
    refuses(lambda d: (d / "root-run7.status").write_text("0\t/t/exe-0\n"),
            "a SUBSET of producers is refused", "not 17")
    refuses(lambda d: (d / "hashes-after.txt").write_text("deadbeef  /t/exe-0\n" * 17),
            "a CHANGED executable set is refused", "STALE")
    refuses(lambda d: (d / "hashes-before.txt").write_text("x  /t/exe-0\n"),
            "a SUBSET of hashes is refused", "cannot prove")
    refuses(lambda d: (d / "hygiene.txt").write_text(
                HYGIENE.replace("aba0f0ea14b751aa4a78e22467293f643384ac5f659286088864969cb0e8aace  installer",
                                "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb  installer")),
            "MISMATCHED helper digests are refused", "stale install")
    refuses(lambda d: (d / "hygiene.txt").write_text(
                HYGIENE.replace("All checked filesystems above their floors.", "*** SHORT ***")),
            "an OVERRIDDEN free-space refusal is refused", "free space")
    refuses(lambda d: (d / "hygiene.txt").write_text(
                HYGIENE.replace("/etc/pam.d/delphi-runtime: OK", "delphi-runtime: FAILED")),
            "a CHANGED PAM stack is refused", "PAM")
    # D0A-R35: the recorded commit. Present-and-clean is required only when the section
    # exists, so historical runs without it are not retroactively refused — but a DIRTY tree
    # is, because artifacts from a dirty tree describe no commit at all.
    refuses(lambda d: (d / "hygiene.txt").write_text(
                HYGIENE + "=== commit ===\n" + "a" * 40 + "\n M runtime/src/execute.rs\n"),
            "a DIRTY tree at run time is refused", "DIRTY")
    refuses(lambda d: (d / "hygiene.txt").write_text(HYGIENE + "=== commit ===\nnot-a-sha\n"),
            "a commit section without a SHA is refused", "no 40-char SHA")

    # D0A-R35: the run's OWN artifacts must not count as a dirty tree. Run 24 was refused for
    # `?? scratch/lane-run-24/`, which §4b creates several steps before the commit is recorded —
    # a condition the procedure guarantees, so the check refused every run by construction.
    d = fixture()
    try:
        (d / "hygiene.txt").write_text(
            HYGIENE + "=== commit ===\n" + "c" * 40 + "\n?? scratch/lane-run-24/\n")
        ok, report = la.accept(d)
        check("the run's OWN artifact directory is not a dirty tree", ok, "\n".join(report))
        (d / "hygiene.txt").write_text(
            HYGIENE + "=== commit ===\n" + "c" * 40 +
            "\n?? scratch/lane-run-24/\n M runtime/src/execute.rs\n")
        ok, report = la.accept(d)
        check("...but a REAL modification alongside it still refuses", not ok)
        check("...and the refusal names only the real one",
              "execute.rs" in "\n".join(report) and "lane-run-24" not in "\n".join(report),
              "\n".join(report))
    finally:
        shutil.rmtree(d, ignore_errors=True)

    refuses(lambda d: (d / "root-identities.txt").write_text("target::test_0\n"),
            "identities without COUNTS are refused", "MULTIPLICITY")
    refuses(lambda d: (d / "membership.txt").write_text(
                "root 5 / unpriv 4\nIN ROOT NOT UNPRIV: 1\nIN UNPRIV NOT ROOT: 0\n"),
            "a NONZERO identity difference is refused", "identity SETS differ")
    # The mutation must remove ONLY the verdict, or it trips the name/completion checks first
    # and stops testing what it names (D0A-R36-01 added those checks).
    refuses(lambda d: (d / "part-b-control.txt").write_text(
                "test b1_daemon_bounds_an_ai_that_completes_the_protocol_and_stays_alive ... ok\n"
                "\ntest result: ok. 1 passed; 0 failed\n"),
            "a control with NO VERDICT is refused", "no `verdict:` line")

    # D0A-R36-01 — a verdict line is a DIAGNOSTIC, not a result. Each of these was reproduced
    # against run 23's REAL transcript before the fix and returned ACCEPTED.
    refuses(lambda d: (d / "part-b-control.txt").write_text(
                "test b1_daemon_bounds_an_ai_that_completes_the_protocol_and_stays_alive ... \n"
                "  verdict: Reached\n\ntest result: FAILED. 0 passed; 1 failed\n"),
            "a control whose verdict is followed by FAILURE is refused", "did not pass")
    refuses(lambda d: (d / "part-b-control.txt").write_text(
                "test b1_daemon_bounds_an_ai_that_completes_the_protocol_and_stays_alive ... "
                "SKIP requires root\n\ntest result: ok. 0 passed; 0 failed\n"),
            "a control that SKIPPED is refused", "skip is scored as a PASS")
    refuses(lambda d: (d / "part-b-control.txt").write_text(
                "test some_other_test ... \n  verdict: Reached\nok\n\n"
                "test result: ok. 1 passed; 0 failed\n"),
            "a control naming the WRONG test is refused", "does not name")
    refuses(lambda d: (d / "part-b-control.txt").write_text(
                "test b1_daemon_bounds_an_ai_that_completes_the_protocol_and_stays_alive ... \n"
                "  verdict: Topology\nok\n\ntest result: ok. 1 passed; 0 failed\n"),
            "a POSITIVE control returning Topology is refused", "not Reached")

    # D0A-R36-02 — counting is not verifying.
    refuses(lambda d: (d / "root-identities.txt").write_text(""),
            "an EMPTY identity file is refused", "does not match the retained transcript")
    refuses(lambda d: (d / "root-run.log").write_text(""),
            "an EMPTY transcript is refused", "NO test lines")
    refuses(lambda d: (d / "root-run7.status").write_text(
                "\n".join("0\t/t/exe-0" for _ in range(la.EXPECTED_TARGETS)) + "\n"),
            "17 copies of ONE producer are refused", "DISTINCT")
    refuses(lambda d: (d / "root-run7.status").write_text(
                "\n".join(f"0\t/t/other-{i}" for i in range(la.EXPECTED_TARGETS)) + "\n"),
            "producers that are not the HASHED set are refused", "not the executables")
    refuses(lambda d: (d / "membership.txt").write_text(
                "root 99 / unpriv 5\nIN ROOT NOT UNPRIV: 0\nIN UNPRIV NOT ROOT: 0\n"),
            "a membership total contradicting the files is refused", "but the retained files")

    # D0A-R36-03 — identical hashes with a rebuild that failed.
    refuses(lambda d: (d / "rebuild.status").write_text("101\n"),
            "a FAILED rebuild is refused despite identical hashes", "exited 101")

    # D0A-R36-11 — two constraints had NO discriminating guard: removing either left all 46
    # assertions passing. These are those cases.
    refuses(lambda d: (d / "rebuild.log").unlink(),
            "a missing rebuild artifact is refused", "MISSING")
    refuses(lambda d: os.utime(d / "membership.txt", (900_000, 900_000)),
            "membership computed BEFORE the run is refused", "MISORDERED")

    # D0A-R37-11 — THE THREE PREDICATES THAT HAD NO DISCRIMINATING CASE. Each was named in
    # R36-11, each survived removal with every assertion passing, and my "correction" checked a
    # different predicate and reported the finding overstated. These are the cases.
    #
    # (a) the INVERTED freshness pair — before NEWER than after, with both still preceding the
    #     run start, so ONLY the pair check can catch it.
    def invert_pair(d: pathlib.Path) -> None:
        os.utime(d / "hashes-before.txt", (1_000_015, 1_000_015))
        os.utime(d / "hashes-after.txt", (1_000_010, 1_000_010))
    refuses(invert_pair, "an INVERTED freshness pair is refused", "inverted")

    # (b) and (c) the modern artifacts, absent from a CURRENT run.
    refuses(lambda d: (d / "rebuild.status").unlink(),
            "a current run with no rebuild.status is refused", "no rebuild.status")
    refuses(lambda d: (d / "run-start.txt").unlink(),
            "a current run with no run-start.txt is refused", "no run-start.txt")

    # D0A-R37-01 — the unprivileged side is a MULTISET, not a total. Changing one identity while
    # preserving the count certified, because only the sum was checked.
    def swap_identity(d: pathlib.Path) -> None:
        ls = (d / "unpriv-identities.txt").read_text().splitlines()
        ls[0] = ls[0].split("\t")[0] + "\texe::DIFFERENT_TEST"
        (d / "unpriv-identities.txt").write_text("\n".join(ls) + "\n")
    refuses(swap_identity, "a CHANGED unprivileged identity is refused despite an equal total",
            "not the same multiset")

    # D0A-R37-02 — the control's invocation status, and the transcript's own summaries.
    refuses(lambda d: (d / "part-b-control.status").write_text("101\n"),
            "a control whose INVOCATION exited nonzero is refused", "invocation exited 101")
    refuses(lambda d: (d / "part-b-control.status").unlink(),
            "a current run with no control status is refused", "how the invocation actually ended")
    refuses(lambda d: (d / "root-run.log").write_text(
                (d / "root-run.log").read_text() + "test result: FAILED. 0 passed; 1 failed\n"),
            "a transcript reporting a FAILED summary is refused", "FAILED summary line")

    # D0A-R37-05 — an UNKNOWN run identity must be treated as CURRENT, not waived. Renaming a
    # refused directory used to make it accept.
    d_anon = fixture()
    try:
        anon = d_anon.parent / "review-copy"
        d_anon.rename(anon)
        (anon / "rebuild.status").unlink()
        ok, report = la.accept(anon)
        check("an UNNAMED directory is treated as CURRENT, not waived", not ok,
              "an age waiver obtainable by renaming is a bypass, not a waiver")
        # ...and a run that declares what it predates IS waived, explicitly.
        (anon / "PREDATES.txt").write_text(
            f"predates {la.FIRST_RUN_REQUIRING_REBUILD_STATUS} and "
            f"{la.FIRST_RUN_REQUIRING_RUN_START}\n")
        (anon / "run-start.txt").unlink()
        ok, report = la.accept(anon)
        check("...but a run DECLARING what it predates is waived explicitly", ok,
              "\n".join(report))
    finally:
        shutil.rmtree(d_anon.parent, ignore_errors=True)

    # D0A-R36-04 — freshness must precede the run's START, not its last append. Without a
    # distinct start event the only available boundary is the transcript's mtime, which a
    # mid-run rebuild also satisfies.
    def with_start(d: pathlib.Path, start_t: int, after_t: int) -> None:
        (d / "run-start.txt").write_text("2026-01-01T00:00:00Z\n")
        os.utime(d / "run-start.txt", (start_t, start_t))
        os.utime(d / "hashes-after.txt", (after_t, after_t))
    # THE DISCRIMINATING CASE, and the first attempt was not one: it put hashes-after LATER
    # than the transcript too, so the OLD last-write boundary refused it as well — same
    # verdict, same message, PASS/PASS (Iron Law 15 clause 2). The rebuild must land AFTER the
    # start and BEFORE the transcript's last write, which is precisely the window the old
    # boundary could not see.
    #   run-start 1_000_005  <  hashes-after 1_000_020  <  root-run.log 1_000_030
    refuses(lambda d: with_start(d, 1_000_005, 1_000_020),
            "a rebuild after the START but before the run's last write is refused",
            "AFTER THE RUN STARTED")

    # D0A-R35 — THE NEGATIVE CONTROL, required from run 24. The fixture's directory name is
    # what carries the run number, so these use a named copy.
    def neg(verdict: str) -> str:
        """A COMPLETE negative-control transcript carrying the given verdict.

        A bare `verdict: X` line stopped being sufficient at D0A-R36-01: the checks now
        require the named test, no skip, and a completed passing summary. A mutation that
        omits those tests the name check rather than the verdict it means to vary.
        """
        return (
            "test the_control_reports_topology_when_the_daemons_child_leaves_its_group ... \n"
            f"NEGATIVE CONTROL: verdict: {verdict}, from 1 distinct record(s)\nok\n\n"
            "test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 22 filtered out\n")

    def as_run(d: pathlib.Path, n: int) -> pathlib.Path:
        dst = d.parent / f"lane-run-{n}"
        shutil.rmtree(dst, ignore_errors=True)
        shutil.copytree(d, dst)
        for f in dst.iterdir():
            st = (d / f.name).stat()
            os.utime(f, (st.st_atime, st.st_mtime))
        return dst

    d = fixture()
    try:
        r23 = as_run(d, 23)
        (r23 / "part-b-negative-control.txt").unlink()
        ok, _ = la.accept(r23)
        check("run 23 is still ACCEPTED without a negative control", ok,
              "requiring it retroactively would invalidate history it was never applied to")
        r24 = as_run(d, 24)
        (r24 / "part-b-negative-control.txt").unlink()
        ok, report = la.accept(r24)
        check("run 24 WITHOUT a negative control is REFUSED", not ok)
        check("...and the refusal names it",
              "part-b-negative-control.txt" in "\n".join(report), "\n".join(report))
        (r24 / "part-b-negative-control.txt").write_text(neg("Reached"))
        ok, report = la.accept(r24)
        check("a negative control returning `Reached` is REFUSED", not ok,
              "a control that cannot discriminate was recorded as an accepted run")
        check("...and the refusal says what Reached means here",
              "CANNOT DETECT A TOPOLOGY DEFECT" in "\n".join(report), "\n".join(report))
        (r24 / "part-b-negative-control.txt").write_text(neg("Unresolved"))
        ok, _ = la.accept(r24)
        check("a negative control returning `Unresolved` is REFUSED", not ok,
              "the fixture did not produce the input it claims, which is not an accepted run")
        (r24 / "part-b-negative-control.txt").write_text(neg("Topology"))
        st = (d / "part-b-control.txt").stat()
        os.utime(r24 / "part-b-negative-control.txt", (st.st_atime, st.st_mtime))
        ok, report = la.accept(r24)
        check("a negative control returning `Topology` is ACCEPTED", ok, "\n".join(report))
        shutil.rmtree(r23, ignore_errors=True)
        shutil.rmtree(r24, ignore_errors=True)
    finally:
        shutil.rmtree(d, ignore_errors=True)
    refuses(lambda d: os.utime(d / "hashes-after.txt", (9_000_000, 9_000_000)),
            "freshness proven AFTER the run is refused", "MISORDERED")

    # The tool's own verdict must be CAPTURED, or it reproduces D0A-R35-04 on first use.
    d = fixture()
    try:
        r = subprocess.run([sys.executable, str(REPO / "scripts" / "lane-accept.py"), str(d)],
                           capture_output=True, text=True, timeout=60)
        check("the verifier CAPTURES its own verdict", (d / "acceptance.txt").exists(),
              "the verdict exists only in stdout, which is a terminal paste waiting to happen")
        check("the captured verdict matches what it printed",
              "VERDICT: ACCEPTED" in (d / "acceptance.txt").read_text() and r.returncode == 0)
    finally:
        shutil.rmtree(d, ignore_errors=True)

    # D0A-R35: a later re-verification must NOT overwrite the RUN's verdict.
    d = fixture()
    try:
        (d / "acceptance.txt").write_text("VERDICT: ACCEPTED\nthe run's own verdict\n")
        original = (d / "acceptance.txt").read_text()
        subprocess.run([sys.executable, str(REPO / "scripts" / "lane-accept.py"), str(d)],
                       capture_output=True, text=True, timeout=60)
        check("re-verification does NOT overwrite the run's captured verdict",
              (d / "acceptance.txt").read_text() == original,
              "a capture any later run can mutate is not a capture")
        extra = list(d.glob("acceptance-reverified-*.txt"))
        check("...and the re-verification is retained beside it", len(extra) == 1,
              f"found {extra} — discarding it would lose evidence too")

        # D0A-R36-05: two captures in the SAME SECOND must not overwrite one another. The
        # filename has one-second resolution and the old code used exists()-then-write, a
        # check-then-act race whose loser is silently destroyed.
        # D0A-R37-10: THE CLOCK PATCH DID NOT REACH THE SUBPROCESSES. Patching `time.strftime`
        # in THIS process leaves a `subprocess.run` child using the real clock, so the three
        # invocations got three different timestamps and distinct names for free — the guard
        # proved nothing about a same-second collision. It also ignored the children's exits, so
        # an implementation that refused after two captures passed. Driven IN-PROCESS, where the
        # patch applies, with EVERY invocation's status checked.
        real_strftime = time.strftime
        rcs = []
        try:
            time.strftime = lambda *a, **k: "FROZEN"
            for _ in range(3):
                argv = sys.argv
                try:
                    sys.argv = ["lane-accept", str(d)]
                    rcs.append(la.main())
                finally:
                    sys.argv = argv
        finally:
            time.strftime = real_strftime
        check("re-verification: every same-clock invocation SUCCEEDED",
              rcs == [0, 0, 0],
              f"exits {rcs} — an implementation that refuses after two captures would pass a "
              f"guard that never looks at the status")
        caps = sorted(d.glob("acceptance-reverified-FROZEN*"))
        check("re-verification: same-second captures do not overwrite each other",
              len(caps) == 3,
              f"{[c.name for c in caps]} — three invocations under one clock must leave three "
              f"distinct captures; a capture another capture can destroy is not a capture")
        check("re-verification: the RUN's verdict is still the one it wrote",
              (d / "acceptance.txt").read_text() == original)
    finally:
        shutil.rmtree(d, ignore_errors=True)

    d = fixture()
    try:
        os.chmod(d, 0o555)
        r = subprocess.run([sys.executable, str(REPO / "scripts" / "lane-accept.py"), str(d)],
                           capture_output=True, text=True, timeout=60)
        check("a verdict it cannot capture is a REFUSAL, not a pass",
              r.returncode == 2 and "could not capture" in r.stderr,
              f"rc={r.returncode} stderr={r.stderr[-200:]}")
    finally:
        os.chmod(d, 0o755)
        shutil.rmtree(d, ignore_errors=True)

    guard_the_procedure_produces_what_the_verifier_requires()

    print(f"\n{PASSED} guards held")
    return 0


if __name__ == "__main__":
    sys.exit(main())
