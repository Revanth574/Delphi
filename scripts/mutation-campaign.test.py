#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Guards for `scripts/mutation-campaign.py` — the harness that certifies coverage claims.

RETAINED, NOT RUN-AND-DISCARDED, for the reason the harness itself exists (D0A-R28-05): an
unretained experiment is indistinguishable from one that never happened. The first version of
these checks ran in a shell heredoc and proved nothing to anyone who was not watching.

**The harness is TIER 1 by CLAUDE.md §6 clause (d)** — its green is cited as the evidence that
a security check is covered — so its own failure modes need REDs, and D0A-R29 found three that
did not have them:

* **R29-02**: every nonzero `cargo test` exit was scored CAUGHT, including a build failure, a
  launch failure, and `No space left on device`. An infrastructure failure was credited as a
  test detecting a mutation.
* **R29-01**: restoration was trusted from the write. A partial restore leaves a removed
  security check in the tree and reports success just as loudly as a complete one.
* **R29-01 (second half)**: a detected restore failure printed REFUSE and still exited 0.

Run: `python3 scripts/mutation-campaign.test.py`  (exit 0 = all guards hold)
"""
import importlib.util, sys, types, pathlib
spec = importlib.util.spec_from_file_location("mc", "scripts/mutation-campaign.py")
mc = importlib.util.module_from_spec(spec); spec.loader.exec_module(mc)
ok = True

# GUARD: classification (D0A-R29-02): an infrastructure failure must NOT be scored as a detection.
def fake(out, err, rc):
    return lambda cmd, **kw: types.SimpleNamespace(returncode=rc, stdout=out, stderr=err)
real = mc.sh
for name, (out, err, rc, want) in {
  "disk full":        ("", "error: No space left on device", 101, "INFRASTRUCTURE"),
  "build failure":    ("", "error: could not compile `x`", 101, "INFRASTRUCTURE"),
  "no result lines":  ("", "", 101, "INFRASTRUCTURE"),
  "crash, no named":  ("test result: FAILED. 1 failed\n", "", 101, "UNATTRIBUTED FAILURE"),
  "real detection":   ("test result: FAILED. 1 failed\nfailures:\n    some::test\n", "", 101, "CAUGHT"),
  "clean green":      ("test result: ok. 5 passed\n", "", 0, "NOT CAUGHT"),
}.items():
    mc.sh = fake(out, err, rc)
    got, _ = mc.run_suite()
    flag = "OK " if got == want else "FAIL"
    if got != want: ok = False
    print(f"  [{flag}] {name:<18} -> {got:<22} (want {want})")
mc.sh = real

# GUARD: restore verification (D0A-R29-01): restore verification is against HEAD, not our own write.
p = pathlib.Path("runtime/src/wire.rs"); orig = p.read_text()
print(f"  [{'OK ' if mc.file_matches_head('runtime/src/wire.rs') else 'FAIL'}] clean file matches HEAD")
p.write_text(orig + "\n// tamper\n")
tampered_detected = not mc.file_matches_head("runtime/src/wire.rs")
p.write_text(orig)
if not tampered_detected: ok = False
print(f"  [{'OK ' if tampered_detected else 'FAIL'}] tampered file DOES NOT match HEAD (a partial restore is caught)")
print(f"  [{'OK ' if mc.file_matches_head('runtime/src/wire.rs') else 'FAIL'}] restored file matches HEAD again")
sys.exit(0 if ok else 1)
