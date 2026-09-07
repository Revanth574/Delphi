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

**So the output of a mutation campaign is the ARTIFACT SET, not the table.** Per experiment
this records:

  * the applied diff (the actual mutation, from `git diff` — not the intended one);
  * the compile result;
  * the privilege level and lane the suite ran at;
  * the failing assertion text, when something failed;
  * verification that the tree was restored afterwards.

A PATCH-MISS or a compile error is an INVALID EXPERIMENT, reported as such and never as
"NOT CAUGHT" — the two are indistinguishable in a bare table and opposite in meaning.

Usage:  scripts/mutation-campaign.py [--out DIR]
        sudo -E scripts/mutation-campaign.py --out DIR   (to make the privilege claim at root)
"""

from __future__ import annotations

import argparse
import json
import os
import pathlib
import re
import shutil
import subprocess
import sys
import tempfile
import time

REPO = pathlib.Path(__file__).resolve().parent.parent
SRC = REPO / "runtime" / "src"

# (label, file, anchor, replacement). The anchor must appear VERBATIM in the current source;
# if it does not, the experiment is invalid and says so rather than reporting a result.
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


def sh(cmd: list[str], **kw) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, cwd=REPO, capture_output=True, text=True, **kw)


def tree_is_clean() -> bool:
    return sh(["git", "status", "--porcelain", "--", "runtime/src"]).stdout.strip() == ""


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=None)
    args = ap.parse_args()
    out = pathlib.Path(args.out or tempfile.mkdtemp(prefix="delphi-mutation-"))
    out.mkdir(parents=True, exist_ok=True)

    if not tree_is_clean():
        print("REFUSE: runtime/src is dirty. A campaign that starts from uncommitted changes "
              "cannot attribute a result to the mutation.", file=sys.stderr)
        return 2

    euid = os.geteuid()
    lane = {
        "euid": euid,
        "privileged": euid == 0,
        "commit": sh(["git", "rev-parse", "HEAD"]).stdout.strip(),
        "started_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }
    (out / "lane.json").write_text(json.dumps(lane, indent=2) + "\n")

    results = []
    for i, (label, fname, anchor, repl) in enumerate(MUTATIONS, 1):
        path = SRC / fname
        original = path.read_text()
        rec: dict = {"n": i, "label": label, "file": fname}

        if anchor not in original:
            # INVALID, not "NOT CAUGHT". A bare table cannot tell these apart and they mean
            # opposite things.
            rec["outcome"] = "INVALID: anchor not found in current source"
            rec["anchor"] = anchor
            results.append(rec)
            print(f"[{i:2}/{len(MUTATIONS)}] {label:<52} INVALID (anchor not found)")
            continue

        path.write_text(original.replace(anchor, repl, 1))
        rec["applied_diff"] = sh(["git", "diff", "--", f"runtime/src/{fname}"]).stdout

        build = sh(["cargo", "test", "-p", "delphi-runtime", "--lib", "--tests", "--no-run", "-q"])
        if build.returncode != 0:
            rec["outcome"] = "INVALID: mutant does not compile"
            rec["compile_stderr"] = build.stderr[-4000:]
            path.write_text(original)
            rec["restored"] = tree_is_clean()
            results.append(rec)
            print(f"[{i:2}/{len(MUTATIONS)}] {label:<52} INVALID (compile error)")
            continue

        rec["compiles"] = True
        run = sh(["cargo", "test", "-p", "delphi-runtime", "--lib", "--tests", "-q"])
        rec["suite_exit"] = run.returncode
        rec["outcome"] = "CAUGHT" if run.returncode != 0 else "NOT CAUGHT"
        fails = re.findall(r"^\s{4}(\S+)$", run.stdout[run.stdout.find("failures:"):], re.M) \
            if "failures:" in run.stdout else []
        rec["failing_tests"] = sorted(set(fails))
        # The assertion text is what makes a CAUGHT checkable — a test name alone does not say
        # the test failed for the reason it names.
        rec["assertion_excerpt"] = "\n".join(
            l for l in run.stdout.splitlines() if "assertion" in l or "RED:" in l
        )[:2000]

        path.write_text(original)
        rec["restored"] = tree_is_clean()
        if not rec["restored"]:
            print("REFUSE: tree not restored after mutation; stopping.", file=sys.stderr)
            results.append(rec)
            break

        results.append(rec)
        print(f"[{i:2}/{len(MUTATIONS)}] {label:<52} {rec['outcome']:<11} "
              f"{','.join(rec['failing_tests'][:2])[:40]}")

    (out / "results.json").write_text(json.dumps({"lane": lane, "results": results}, indent=2) + "\n")

    valid = [r for r in results if r["outcome"] in ("CAUGHT", "NOT CAUGHT")]
    invalid = [r for r in results if r["outcome"].startswith("INVALID")]
    print(f"\nartifacts: {out}")
    print(f"valid experiments: {len(valid)}/{len(MUTATIONS)}   invalid: {len(invalid)}")
    print(f"lane: euid={euid} ({'ROOT' if euid == 0 else 'unprivileged'}) — "
          f"claims about other privilege levels are NOT supported by this run")
    if invalid:
        print("INVALID experiments (no result may be reported for these):")
        for r in invalid:
            print(f"  - {r['label']}: {r['outcome']}")
    return 1 if invalid else 0


if __name__ == "__main__":
    sys.exit(main())
