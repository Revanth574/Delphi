#!/bin/bash
# D0-A — WHICH GREENS BITE? A mutation audit of the shape-E guards.
#
# Round 10 asked "which greens would you not trust?" This answers it by measurement rather
# than by reading the tests: introduce a realistic defect into the production code, run the
# suite, and record which tests notice. A mutation NOTHING catches is either an untrusted
# green or an uncovered property — and the two are distinguished by whether a test claims it.
#
# Each mutation is applied by an EXACT string replacement that asserts it matched (a mutation
# that did not apply would report the SHIPPED code as untested — the worst possible result
# from this tool), and the file is restored and diffed afterwards.
#
# The two intentional D0A-R9-02 REDs are the baseline; a mutation "caught" means at least one
# OTHER test failed.

set -uo pipefail
cd "$(dirname "$0")/.." || exit 2
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$PWD/target}"

SANDBOX=runtime/src/sandbox.rs
EXECUTE=runtime/src/execute.rs
WORK=$(mktemp -d); trap 'cp "$WORK"/*.orig.rs /dev/null 2>/dev/null; rm -rf "$WORK"' EXIT
cp "$SANDBOX" "$WORK/sandbox.orig.rs"
cp "$EXECUTE" "$WORK/execute.orig.rs"

BASELINE_REDS="same_inode_overwrite_executes_unapproved_content nested_interpreter_substitution_executes_unapproved_content"

restore() {
    cp "$WORK/sandbox.orig.rs" "$SANDBOX"
    cp "$WORK/execute.orig.rs" "$EXECUTE"
    diff -q "$WORK/sandbox.orig.rs" "$SANDBOX" >/dev/null && diff -q "$WORK/execute.orig.rs" "$EXECUTE" >/dev/null \
        || { echo "RESTORE FAILED — stop and fix by hand"; exit 3; }
}

mutate() {  # mutate <file> <old> <new>
    python3 - "$1" "$2" "$3" <<'PY'
import sys
p, old, new = sys.argv[1], sys.argv[2], sys.argv[3]
s = open(p).read()
n = s.count(old)
if n != 1:
    sys.exit(f"MUTATION DID NOT APPLY ({n} matches) — a result here would be about the SHIPPED code")
open(p, 'w').write(s.replace(old, new))
PY
}

run_case() {  # run_case <label> <file> <old> <new>
    local label=$1
    if ! mutate "$2" "$3" "$4"; then
        printf '  %-46s !! MUTATION DID NOT APPLY\n' "$label"; restore; return
    fi
    local out; out=$(cargo test -p delphi-runtime --lib --no-fail-fast 2>&1)
    local failed; failed=$(printf '%s\n' "$out" | sed -n 's/^    \(.*\)$/\1/p' \
        | grep -E '^(execute|sandbox|fdsec|privdrop|token|action)::' | sed 's/.*:://' | sort -u)
    local caught=()
    while read -r t; do
        [ -n "$t" ] || continue
        case " $BASELINE_REDS " in *" $t "*) ;; *) caught+=("$t");; esac
    done <<< "$failed"
    if [ "${#caught[@]}" -eq 0 ]; then
        printf '  %-46s NOT CAUGHT\n' "$label"
    else
        printf '  %-46s caught by %s\n' "$label" "${caught[*]}"
    fi
    restore
}

echo "=== D0-A mutation audit — does the suite notice? ==="
echo "(baseline: the 2 intentional R9-02 REDs are excluded from 'caught')"
echo

run_case "denylist: symlink-resolved leg removed" "$SANDBOX" \
  '        std::fs::canonicalize(path).ok().map(|p| lexical_normalize(&p)),' \
  '        None,'

run_case "denylist: ancestor-containment leg removed" "$SANDBOX" \
  '            || base_n.starts_with(&candidate)
' '
'

run_case "ancestors: 0755 -> 0700 (class 40 itself)" "$SANDBOX" \
  '            args.push("0755".to_string());' \
  '            args.push("0700".to_string());'

run_case "ancestors: inside-a-bind exclusion removed" "$SANDBOX" \
  '    wanted.retain(|a| !norm.iter().any(|b| a == b || a.starts_with(b)));' \
  '    '

run_case "ancestors: emission removed entirely" "$SANDBOX" \
  '        for dir in ancestor_dirs(&action.fs_binds) {
            args.push("--perms".to_string());
            args.push("0755".to_string());
            args.push("--dir".to_string());
            args.push(dir);
        }' '        '

run_case "binds: parent-first ordering removed" "$SANDBOX" \
  '        ordered.sort_by_key(|b| lexical_normalize(&b.0));' '        '

run_case "host-creating bind: guard neutered" "$SANDBOX" \
  '        if !path.exists() {' '        if false {'

run_case "net: --unshare-net dropped for NetPolicy::None" "$SANDBOX" \
  '            NetPolicy::None => args.push("--unshare-net".to_string()),' \
  '            NetPolicy::None => {}'

run_case "env: --clearenv dropped" "$SANDBOX" \
  '            "--clearenv".to_string(),' '            '

run_case "script: full-seal requirement neutered" "$EXECUTE" \
  '    if seals & ScriptPin::FULL_SEALS != ScriptPin::FULL_SEALS {' \
  '    if false {'

run_case "drop: helper never interposed" "$EXECUTE" \
  '    let creds = tool_credentials()?;' \
  '    let creds: Option<(u32, u32)> = None;'

run_case "drop: approved argv0 not passed to the tool" "$EXECUTE" \
  '    if helper_fd.is_some() {
        args.push(action.argv.first().cloned().unwrap_or_else(|| format!("/proc/self/fd/{program_fd}")));
    }' '    '

echo
echo "restored; verifying against the pre-audit copies:"
diff -q "$WORK/sandbox.orig.rs" "$SANDBOX" && diff -q "$WORK/execute.orig.rs" "$EXECUTE" && echo "  both byte-identical"
