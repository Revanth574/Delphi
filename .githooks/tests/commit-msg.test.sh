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

check() {  # check <label> <expected: accept|refuse> <msgfile> [substring]
  local label=$1 want=$2 msg=$3 want_text=${4:-}
  local out rc
  out=$(cd "$work/repo" && "$work/repo/.githooks/commit-msg" "$msg" 2>&1); rc=$?
  local got=accept; [ $rc -ne 0 ] && got=refuse
  if [ "$got" != "$want" ]; then
    echo "  [FAIL] $label — wanted $want, got $got"; echo "$out" | sed 's/^/         /'
    fail=$((fail+1)); return
  fi
  if [ -n "$want_text" ] && ! grep -qF -- "$want_text" <<<"$out"; then
    echo "  [FAIL] $label — refused, but the reason never named: $want_text"
    echo "$out" | sed 's/^/         /'; fail=$((fail+1)); return
  fi
  echo "  [OK ] $label"; pass=$((pass+1))
}

mkdir -p "$work/repo/.githooks" "$work/repo/scripts" "$work/repo/scratch/weaken-records"
ln -s "$REPO/.githooks/commit-msg" "$work/repo/.githooks/commit-msg"
ln -s "$REPO/scripts/weaken-driver.py" "$work/repo/scripts/weaken-driver.py"
( cd "$work/repo" && git init -q && git config user.email t@t && git config user.name t \
    && git add -A && git commit -qm init )

mint() {  # mint <verdict> <discriminator> -> prints the id, writes+stages the record
  python3 - "$work/repo" "$1" "$2" <<'PY'
import importlib.util, json, pathlib, subprocess, sys
root, verdict, disc = pathlib.Path(sys.argv[1]), sys.argv[2], sys.argv[3]
spec = importlib.util.spec_from_file_location("wd", root / "scripts" / "weaken-driver.py")
wd = importlib.util.module_from_spec(spec); spec.loader.exec_module(wd)
body = {"schema": wd.SCHEMA, "verdict": verdict, "expectation": {"guard": "guard-" + disc},
        "instrument": {"path": "x", "digest_executing": "d"},
        "subject": {"path": "y", "is_the_instrument_file": False},
        "suite": {"argv": ["s"], "cwd": "/"}, "phases": [], "observations": {},
        "diagnostics": {}, "limits": wd.RECORD_LIMITS}
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
  echo "  [FAIL] two distinct records collided ($GOOD vs $SECOND)"; fail=$((fail+1))
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
