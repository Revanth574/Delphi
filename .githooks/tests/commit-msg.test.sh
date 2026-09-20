#!/bin/bash
# SPDX-License-Identifier: MIT
#
# RED proofs for .githooks/commit-msg — the consumer that gates RED-proof claims.
#
# TIER 1 by §6 clause (d): this hook's acceptance is the evidence that a commit's RED-proof
# claim is re-openable. If it accepts what it should refuse, the claim travels uncheckable,
# which is the state D0A-R39 was opened to end.
#
# The subject is the REAL hook, reached through a SYMLINK into a fake repo (DEFECT_CLASSES
# 25 — a copy would be a different artifact), and so is the real producer, because the hook
# IMPORTS its canonicalisation rather than reimplementing it.

set -uo pipefail
cd "$(dirname "$0")/../.."
REPO=$PWD
work=$(mktemp -d); trap 'rm -rf "$work"' EXIT
pass=0; fail=0

# D0A-R40-06: every failure reports its label to the side channel, so this suite can be
# DRIVEN by the driver it guards. Without it the driver sees a red suite with no attribution
# and correctly returns UNVERIFIABLE — a suite that cannot say which guard failed cannot
# participate in the contract it exists to defend.
report() {
  [ -n "${DELPHI_GUARD_FAILURE_REPORT:-}" ] && printf '%s\n' "$1" >> "$DELPHI_GUARD_FAILURE_REPORT"
  return 0
}
fail_guard() { echo "  [FAIL] $1"; report "$1"; fail=$((fail+1)); }

check() {  # check <label> <expected: accept|refuse> <msgfile> [substring]
  local label=$1 want=$2 msg=$3 want_text=${4:-}
  local out rc
  out=$(cd "$work/repo" && "$work/repo/.githooks/commit-msg" "$msg" 2>&1); rc=$?
  local got=accept; [ $rc -ne 0 ] && got=refuse
  if [ "$got" != "$want" ]; then
    echo "$out" | sed 's/^/         /'; fail_guard "$label"; return
  fi
  if [ -n "$want_text" ] && ! grep -qF -- "$want_text" <<<"$out"; then
    echo "         refused, but the reason never named: $want_text"
    echo "$out" | sed 's/^/         /'; fail_guard "$label"; return
  fi
  echo "  [OK ] $label"; pass=$((pass+1))
}

mkdir -p "$work/repo/.githooks" "$work/repo/scripts" "$work/repo/scratch/weaken-records"
ln -s "$REPO/.githooks/commit-msg" "$work/repo/.githooks/commit-msg"
ln -s "$REPO/scripts/weaken-driver.py" "$work/repo/scripts/weaken-driver.py"
( cd "$work/repo" && git init -q && git config user.email t@t && git config user.name t \
    && git add -A && git commit -qm init \
    && git config core.hooksPath .githooks )   # so the REAL-commit cases below run the hook

mint() {  # mint <verdict> <discriminator> -> prints the id, writes+stages the record
  python3 - "$work/repo" "$1" "$2" "$REPO" <<'PY'
import importlib.util, json, pathlib, subprocess, sys
root, verdict, disc = pathlib.Path(sys.argv[1]), sys.argv[2], sys.argv[3]
REPO = pathlib.Path(sys.argv[4])
spec = importlib.util.spec_from_file_location("wd", root / "scripts" / "weaken-driver.py")
wd = importlib.util.module_from_spec(spec); spec.loader.exec_module(wd)
# A REAL producer record is the base, so these fixtures satisfy the evidence contract the
# way a real one does. A hand-written stub would only prove the hook accepts stubs.
import glob
src = sorted(glob.glob(str(REPO / "scratch" / "weaken-records" / "*.json")))
real = None
for cand in src:
    b = json.loads(pathlib.Path(cand).read_text())
    if b.get("schema") == wd.SCHEMA and not wd.validate_record(b):
        real = b
        break
assert real is not None, "no contract-satisfying record in the ledger to base fixtures on"
body = json.loads(json.dumps(real))
body.pop("id")
body["verdict"] = verdict
body["execution"]["timeout_s"] = 900 + len(disc)   # the discriminator, contract-neutral
body = {"id": wd.record_id(body), **body}
p = root / "scratch" / "weaken-records" / f"{body['id']}.json"
p.write_text(json.dumps(body, sort_keys=True, indent=2) + "\n")
subprocess.run(["git", "-C", str(root), "add", str(p)], check=True)
print(body["id"])
PY
}

echo "== .githooks/commit-msg =="
GOOD=$(mint RED_PROVEN one); NOTCAUGHT=$(mint NOT_CAUGHT two)
# A SECOND, GENUINELY DIFFERENT record. A self-referential hash that works on the first and
# breaks on the next is exactly the shape that ships — and the first version of this file
# minted two IDENTICAL bodies, so "two records" silently cited one record twice.
SECOND=$(mint RED_PROVEN three)
if [ "$GOOD" != "$SECOND" ] && [ -n "$GOOD" ] && [ -n "$SECOND" ]; then
  echo "  [OK ] two distinct records mint distinct ids"; pass=$((pass+1))
else
  fail_guard "two distinct records mint distinct ids"
fi

printf 'chore: ordinary commit with no claim\n' > "$work/plain"
check "a message with no claim and no citation is untouched" accept "$work/plain"

printf 'fix: something\n\nThis is RED-proven.\n' > "$work/claim-no-cite"
check "a RED-proof claim with no record is REFUSED" refuse "$work/claim-no-cite" \
  "cites no record"

printf 'fix: x\n\nRED-proven.\n\nweaken-record: 0123456789abcdef\n' > "$work/unresolved"
check "a citation that does not resolve is REFUSED" refuse "$work/unresolved" \
  "neither staged nor committed"

printf 'fix: x\n\nRED-proven.\n\nweaken-record: %s\n' "$NOTCAUGHT" > "$work/wrong-verdict"
check "a record whose verdict is not RED_PROVEN is REFUSED" refuse "$work/wrong-verdict" \
  "its verdict is 'NOT_CAUGHT'"

printf 'fix: x\n\nRED-proven.\n\nweaken-record: %s\n' "$GOOD" > "$work/ok"
check "a claim citing a resolvable RED_PROVEN record is accepted" accept "$work/ok"

printf 'fix: x\n\nRED-proven.\n\nweaken-record: %s\nweaken-record: %s\n' "$GOOD" "$SECOND" \
  > "$work/ok2"
check "...and so is a message citing TWO records" accept "$work/ok2"

# ── D0A-R40-05 ──────────────────────────────────────────────────────────────────────────
# Distinct ids fixed the collision but both records were ACCEPTABLE, so `for rid in cited[:1]`
# still passed every case. Each citation POSITION must independently cause refusal, or the
# loop is untested past its first iteration.
printf 'fix: x\n\nRED-proven.\n\nweaken-record: %s\nweaken-record: 0123456789abcdef\n' \
  "$GOOD" > "$work/second-unresolved"
check "an unresolved SECOND citation is REFUSED" refuse "$work/second-unresolved" \
  "neither staged nor committed"

printf 'fix: x\n\nRED-proven.\n\nweaken-record: %s\nweaken-record: %s\n' \
  "$GOOD" "$NOTCAUGHT" > "$work/second-wrong-verdict"
check "a wrong-verdict SECOND citation is REFUSED" refuse "$work/second-wrong-verdict" \
  "its verdict is 'NOT_CAUGHT'"

printf 'fix: x\n\nRED-proven.\n\nweaken-record: 0123456789abcdef\nweaken-record: %s\n' \
  "$GOOD" > "$work/first-unresolved"
check "an unresolved FIRST citation is REFUSED" refuse "$work/first-unresolved" \
  "neither staged nor committed"

# The hook distinguishes FIVE refusals, and a position is only proven for the kinds tested
# AT it. Missing and wrong-verdict are covered above; these two are the rest.
CORRUPT=$(mint RED_PROVEN four)
python3 - "$work/repo" "$CORRUPT" <<'PY2'
import json, pathlib, subprocess, sys
root, rid = pathlib.Path(sys.argv[1]), sys.argv[2]
p = root / "scratch" / "weaken-records" / f"{rid}.json"
b = json.loads(p.read_text())
b["execution"]["timeout_s"] = 4242            # bytes change; the id it is filed under does not
p.write_text(json.dumps(b, sort_keys=True, indent=2) + "\n")
subprocess.run(["git", "-C", str(root), "add", str(p)], check=True)
PY2
printf 'fix: x\n\nRED-proven.\n\nweaken-record: %s\nweaken-record: %s\n' \
  "$GOOD" "$CORRUPT" > "$work/second-corrupt"
check "a CORRUPTED second citation is REFUSED" refuse "$work/second-corrupt" \
  "does not hash to its own contents"

# ── D0A-R40-01 at the hook ───────────────────────────────────────────────────────────────
# `{"id": ..., "verdict": "RED_PROVEN"}` hashed correctly and was ACCEPTED: a record with no
# experiment in it. The hook now imports the producer's contract.
STUB=$(python3 - "$work/repo" <<'PY2'
import importlib.util, json, pathlib, subprocess, sys
root = pathlib.Path(sys.argv[1])
spec = importlib.util.spec_from_file_location("wd", root / "scripts" / "weaken-driver.py")
wd = importlib.util.module_from_spec(spec); spec.loader.exec_module(wd)
body = {"verdict": "RED_PROVEN"}
body = {"id": wd.record_id(body), **body}
p = root / "scratch" / "weaken-records" / f"{body['id']}.json"
p.write_text(json.dumps(body, sort_keys=True, indent=2) + "\n")
subprocess.run(["git", "-C", str(root), "add", str(p)], check=True)
print(body["id"])
PY2
)
printf 'fix: x\n\nRED-proven.\n\nweaken-record: %s\n' "$STUB" > "$work/stub"
check "a record that hashes correctly but holds no experiment is REFUSED" refuse \
  "$work/stub" "does not satisfy the evidence contract"

printf 'fix: x\n\nRED-proven.\n\nweaken-record: %s\nweaken-record: %s\n' \
  "$GOOD" "$STUB" > "$work/second-stub"
check "a contract-failing SECOND citation is REFUSED" refuse "$work/second-stub" \
  "does not satisfy the evidence contract"

# ── D0A-R40-04 ──────────────────────────────────────────────────────────────────────────
# Git's `default` cleanup strips `#` lines only when the message is EDITED. With -F or -m it
# publishes them verbatim, so a claim in a comment was published by git and invisible to a
# hook that discarded every `#` line. Verified against REAL commits below, not just the hook.
printf 'chore: probe\n# RED-proven with no record\n' > "$work/hash-claim"
check "a claim in a COMMENT line is still a claim" refuse "$work/hash-claim" "cites no record"

# ...and the converse fails closed too: a citation git might strip cannot discharge a claim.
printf 'fix: x\n\nRED-proven.\n# weaken-record: %s\n' "$GOOD" > "$work/hash-cite"
check "a citation in a COMMENT line does NOT discharge a claim" refuse "$work/hash-cite" \
  "cites no record"

# ── D0A-R41-03 ──────────────────────────────────────────────────────────────────────────
# THE GUARD THAT USED TO SIT HERE ASSERTED THE HOLE. It claimed text below any scissors-looking
# line supplies no claim, and git keeps that text verbatim under -F in EVERY cleanup mode,
# `scissors` included — truncation happens only when the message is EDITED. So the R40-04 fix
# for a cleanup mismatch encoded a new cleanup mismatch as an invariant, which is worse than
# leaving it untested: a wrong guard defends the defect against the next person who notices.
printf 'chore: probe\n\n# ------------------------ >8 ------------------------\nRED-proven with no citation\n' \
  > "$work/author-scissors"
check "a claim below an AUTHOR-written scissors line is REFUSED" refuse \
  "$work/author-scissors" "cites no record"

# ...and git's OWN block, which it writes only in the editor path and then removes, is trimmed
# — otherwise a --verbose diff would supply claims nobody made. The hook sees that text.
printf 'chore: probe\n\n# ------------------------ >8 ------------------------\n# Do not modify or remove the line above.\n# Everything below it will be ignored.\ndiff --git a/x b/x\n+this line mentions RED-proven in a diff\n' \
  > "$work/git-scissors"
check "git's own scissors block is trimmed, so a diff supplies no claim" accept \
  "$work/git-scissors"

# An explicit format beats a regex pretending to understand assertions: a BACKTICKED token is
# a narrative reference and asks for no credit.
printf 'chore: probe\n\nThe record carried `RED_PROVEN` and the other carried `UNVERIFIABLE`.\n' \
  > "$work/backticked"
check "a BACKTICKED token is narrative, not an assertion" accept "$work/backticked"
printf 'chore: probe\n\nThis change is RED-proven.\n' > "$work/unbackticked"
check "...and an unbackticked one still asserts and must cite" refuse "$work/unbackticked" \
  "wrap it in backticks"

# REAL commits, because the hook's view and git's stored message must agree.
real_commit() {  # real_commit <file> -> prints "exit=N stored=<yes|no>"
  local rc out
  out=$(cd "$work/repo" && git commit --allow-empty -q -F "$1" 2>&1); rc=$?
  local stored=no
  if [ $rc -eq 0 ] && (cd "$work/repo" && git log -1 --format=%B | grep -q 'RED-proven'); then
    stored=yes
  fi
  echo "exit=$rc stored=$stored"
}
res=$(real_commit "$work/hash-claim")
if [ "$res" = "exit=1 stored=no" ]; then
  echo "  [OK ] a REAL commit with a commented claim is refused, not published"; pass=$((pass+1))
else
  fail_guard "a REAL commit with a commented claim is refused, not published"; echo "         $res"
fi

# Edit the record after the fact. The bytes no longer hash to the id it is filed under.
python3 - "$work/repo" "$GOOD" <<'PY'
import json, pathlib, subprocess, sys
root, rid = pathlib.Path(sys.argv[1]), sys.argv[2]
p = root / "scratch" / "weaken-records" / f"{rid}.json"
b = json.loads(p.read_text()); b["verdict"] = "RED_PROVEN"; b["expectation"]["guard"] = "edited"
p.write_text(json.dumps(b, sort_keys=True, indent=2) + "\n")
subprocess.run(["git", "-C", str(root), "add", str(p)], check=True)
PY
check "a record edited after it was written is REFUSED" refuse "$work/ok" \
  "does not hash to its own contents"

echo
echo "$pass passed, $fail failed"
[ $fail -eq 0 ]
