#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Report any two weaken records that share every recorded INPUT.

TIER 2 by §6: it reports facts and decides nothing. No verdict, no gate, no exit status that
anything consumes — a defect here makes a human read a wrong table, not a claim pass.

WHY IT EXISTS. D0A-R40-02 was found by doing this by hand: `a7c6e196` and `7dc26d27` agreed on
instrument, subject, suite and expectation and carried UNVERIFIABLE and RED_PROVEN, because the
input that actually differed — the suite file's bytes — was recorded nowhere. "Can a reader tell
two experiments apart?" is answerable mechanically, so it should not be answered by inspection.

Timings are excluded deliberately: they always differ, so including them would make every pair
look distinct and the check vacuous. What is compared is what a reader would use to reconstruct
the experiment.
"""
from __future__ import annotations

import itertools
import json
import pathlib
import sys

LEDGER = pathlib.Path(__file__).resolve().parent.parent / "scratch" / "weaken-records"


def validation_config(body: dict) -> list:
    """The validation COMMANDS, without their results.

    D0A-R41-07: these were omitted, so two real experiments differing only in their custom
    validator — one RED_PROVEN, one MUTATION_INVALID — were reported as sharing every recorded
    input. The tool said evidence was missing when the evidence was present and unread, which
    is the diagnostic making the error it exists to find.

    `argv` is configuration and belongs in the comparison. `exit`, `streams` and `ran` are
    RESULTS and stay out, for the same reason `digest_restored` does: comparing outcomes would
    make every pair look distinct and the tool vacuous.
    """
    out = []
    for phase in body.get("phases") or []:
        val = (phase or {}).get("validation")
        if isinstance(val, dict):
            out.append([phase.get("name"), val.get("argv")])
    return sorted(out, key=lambda e: str(e[0]))


def inputs(body: dict) -> str:
    return json.dumps({
        "instrument": body.get("instrument"),
        # `digest_restored` is an OUTCOME, not an input.
        "subject": {k: v for k, v in (body.get("subject") or {}).items()
                    if k != "digest_restored"},
        "suite": body.get("suite"),
        "expectation": (body.get("expectation") or {}).get("guard"),
        "execution": body.get("execution"),
        "inputs": body.get("inputs"),
        "validation": validation_config(body),
    }, sort_keys=True)


def main() -> int:
    records = []
    for path in sorted(LEDGER.glob("*.json")):
        body = json.loads(path.read_text())
        records.append((body["id"], body.get("schema", "?").split("/")[-1],
                        body["verdict"], body))
    print(f"{len(records)} records in {LEDGER}")
    for schema in sorted({s for _, s, _, _ in records}):
        print(f"  schema /{schema}: {sum(1 for _, s, _, _ in records if s == schema)}")
    print()
    collisions = 0
    for (ia, sa, va, a), (ib, sb, vb, b) in itertools.combinations(records, 2):
        if inputs(a) == inputs(b):
            collisions += 1
            verdicts = "SAME verdict" if va == vb else f"DIFFERENT verdicts: {va} vs {vb}"
            print(f"  INDISTINGUISHABLE: {ia} (/{sa}) vs {ib} (/{sb}) — {verdicts}")
    print(f"\n{collisions} pair(s) share every recorded input.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
