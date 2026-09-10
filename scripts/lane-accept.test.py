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
import shutil
import subprocess
import sys
import tempfile

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
    d = pathlib.Path(tempfile.mkdtemp(prefix="lane-accept-fixture-"))
    (d / "hygiene.txt").write_text(HYGIENE)
    hashes = "\n".join(f"{i:064x}  /t/exe-{i}" for i in range(la.EXPECTED_TARGETS)) + "\n"
    (d / "hashes-before.txt").write_text(hashes)
    (d / "hashes-after.txt").write_text(hashes)
    (d / "rebuild.log").write_text("Finished test profile\n")
    (d / "root-run7.status").write_text(
        "\n".join(f"0\t/t/exe-{i}" for i in range(la.EXPECTED_TARGETS)) + "\n")
    (d / "root-run.log").write_text("### /t/exe-0\ntest a ... ok\n")
    ids = "\n".join(f"1\ttarget::test_{i}" for i in range(5)) + "\n"
    (d / "root-identities.txt").write_text(ids)
    (d / "unpriv-identities.txt").write_text(ids)
    (d / "membership.txt").write_text(
        "root 5 / unpriv 5\nIN ROOT NOT UNPRIV: 0\nIN UNPRIV NOT ROOT: 0\n")
    (d / "part-b-control.txt").write_text("CONTROL OBSERVATION: ...\n  verdict: Reached\n")
    # A CURRENT run carries both controls (D0A-R35). The base fixture is a current run, so a
    # missing negative control must be introduced deliberately by a guard, never be the default.
    (d / "part-b-negative-control.txt").write_text("NEGATIVE CONTROL: ...\n  verdict: Topology\n")
    # Stamp the ordering the checks require.
    base = 1_000_000
    for i, name in enumerate(["hashes-before.txt", "hashes-after.txt", "rebuild.log",
                              "root-run.log", "root-run7.status", "membership.txt",
                              "root-identities.txt", "unpriv-identities.txt",
                              "part-b-control.txt", "part-b-negative-control.txt",
                              "hygiene.txt"]):
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
    refuses(lambda d: (d / "part-b-control.txt").write_text("no verdict here\n"),
            "a control with NO VERDICT is refused", "verdict")

    # D0A-R35 — THE NEGATIVE CONTROL, required from run 24. The fixture's directory name is
    # what carries the run number, so these use a named copy.
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
        (r24 / "part-b-negative-control.txt").write_text("  verdict: Reached\n")
        ok, report = la.accept(r24)
        check("a negative control returning `Reached` is REFUSED", not ok,
              "a control that cannot discriminate was recorded as an accepted run")
        check("...and the refusal says what Reached means here",
              "CANNOT DETECT A TOPOLOGY DEFECT" in "\n".join(report), "\n".join(report))
        (r24 / "part-b-negative-control.txt").write_text("  verdict: Unresolved\n")
        ok, _ = la.accept(r24)
        check("a negative control returning `Unresolved` is REFUSED", not ok,
              "the fixture did not produce the input it claims, which is not an accepted run")
        (r24 / "part-b-negative-control.txt").write_text("  verdict: Topology\n")
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

    print(f"\n{PASSED} guards held")
    return 0


if __name__ == "__main__":
    sys.exit(main())
