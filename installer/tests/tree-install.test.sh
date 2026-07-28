#!/bin/bash
# SPDX-License-Identifier: MIT
#
# P1 — regression tests for install.sh's shell-bundle TREE install.
#
# WHAT MAKES THIS A REAL TEST AND NOT A COPY: it runs the PRODUCTION
# `installer/install.sh`, unmodified, reached through a SYMLINK to the real file (so it is
# provably the same inode — a copy could drift within the test), inside a `unshare -rm`
# user+mount namespace with tmpfs mounted over every system path the installer writes. No
# test seam, no env override, and no privilege bypass is added to the installer for this:
# the script still requires uid 0 and still writes its production paths — the namespace is
# what makes uid 0 and those paths harmless. Class 17 (defect propagated by copy) is why
# this is not a reimplementation of the logic under test.
#
# The tree install is the first DIRECTORY install in this project. Per the corrected
# defect-class partition (PROGRESS.md, `docs/DEFECT_CLASSES.md`):
#   - Class 2 (path-resolution races) is PRE-FORECLOSED — the existing per-file bound-fd
#     discipline extends per entry unchanged.
#   - Class 12 (reject the invalid CLASS) is the NEW surface: destination names come from
#     the SOURCE, so traversal / charset / depth / entry-type are inputs. Cases 1-7 below.
#   - The installer no-clobber / replace discipline has no existing shape to copy.
#     Cases 8-12 below.
#
# Run:  bash installer/tests/tree-install.test.sh
set -uo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
REAL_INSTALL="$REPO/installer/install.sh"
[ -f "$REAL_INSTALL" ] || { echo "cannot find $REAL_INSTALL"; exit 1; }

pass=0; fail=0
ok()   { printf '  \033[32mPASS\033[0m %s\n' "$1"; pass=$((pass+1)); }
bad()  { printf '  \033[31mFAIL\033[0m %s\n' "$1"; fail=$((fail+1)); }

# Build a scratch "repo" whose installer/install.sh IS the real script (symlink -> same
# inode), populate staging with the five fixed artifacts install.sh requires, and let the
# caller shape the bundle tree.
#
# Emits the sandbox path on stdout.
make_sandbox() {
    local tmp; tmp="$(mktemp -d)"
    mkdir -p "$tmp/installer/staging" "$tmp/fakebin"
    ln -s "$REAL_INSTALL" "$tmp/installer/install.sh"

    local f
    for f in delphi-runtimed delphi-shell delphi-minimal-ai; do
        printf 'ELF-stub-%s\n' "$f" > "$tmp/installer/staging/$f"
    done
    printf 'unit-stub\n' > "$tmp/installer/staging/delphi-runtimed@.service"
    printf 'pam-stub\n'  > "$tmp/installer/staging/delphi-runtime.pam"
    # The AppArmor profile is a required staged artifact; a REAL one (not a stub), because
    # install.sh runs apparmor_parser on it and a malformed profile must not pass here.
    cp "$REPO/installer/apparmor/delphi-shell" "$tmp/installer/staging/delphi-shell.apparmor"
    chmod 0755 "$tmp/installer/staging" "$tmp/installer/staging"/delphi-*
    chmod 0644 "$tmp/installer/staging/delphi-runtimed@.service" \
               "$tmp/installer/staging/delphi-runtime.pam" \
               "$tmp/installer/staging/delphi-shell.apparmor"

    # systemctl does not work in the namespace; the installer calls it for daemon-reload.
    printf '#!/bin/bash\nexit 0\n' > "$tmp/fakebin/systemctl"
    chmod 0755 "$tmp/fakebin/systemctl"
    # apparmor_parser cannot load into the kernel from inside the namespace; stub it so the
    # INSTALL path is exercised. Profile VALIDITY is covered separately and for real by
    # installer/tests/apparmor-profile.test.sh (`apparmor_parser -QK`, unprivileged).
    printf '#!/bin/bash\nexit 0\n' > "$tmp/fakebin/apparmor_parser"
    chmod 0755 "$tmp/fakebin/apparmor_parser"

    echo "$tmp"
}

# Run the real installer inside the namespace. Everything it writes lands on tmpfs.
# Stdout+stderr are captured to $sandbox/out.log; the installer's exit code is returned.
run_installer() {
    local tmp="$1"
    unshare -rm bash -c '
        set -u
        tmp="$1"
        # /usr/sbin is a tmpfs here so `apparmor_parser` ABSENT is genuinely representable: the
        # real one lives there, and without this the "not found" branch could never be
        # exercised (it would always find /usr/sbin/apparmor_parser and take the other path).
        # Everything the installer actually uses (install, stat, find, chmod) is in /usr/bin.
        for d in /usr/share /usr/libexec /usr/lib/systemd/system /etc/pam.d /etc/apparmor.d /usr/sbin; do
            mkdir -p "$d"
            mount -t tmpfs none "$d" || exit 97
        done
        export PATH="$tmp/fakebin:$PATH"
        bash "$tmp/installer/install.sh" > "$tmp/out.log" 2>&1
        rc=$?
        # The tmpfs vanishes with the namespace, so export what the assertions need.
        ls -1 /usr/libexec 2>/dev/null > "$tmp/libexec.txt" || true
        if [ -d /usr/share/delphi ]; then
            ( cd /usr/share/delphi && find . -printf "%y %p\n" | sort ) > "$tmp/tree.txt"
            for f in /usr/share/delphi/shell/assets/*; do
                [ -e "$f" ] && cat "$f" > "$tmp/asset-$(basename "$f").content"
            done
        fi
        exit $rc
    ' _ "$tmp"
}

# ── Class 12: the invalid CLASS must be refused, fail-closed ──────────────────────────
# Each case builds an otherwise-VALID bundle and injects exactly one violation, so a refusal
# is attributable to that violation and nothing else.

# Stage a VALID bundle tree with build.sh's permissions. Getting this wrong is not a detail:
# a tree left at the default umask 002 (mode 775) is refused by the installer's
# group/other-writable check BEFORE any Class-12 gate runs, so every case below would "pass"
# for the wrong reason. That is exactly what the first run of this file did.
stage_valid_tree() {   # staging-dir
    mkdir -p "$1/shell/assets"
    printf '<!doctype html><div id="root"></div>\n' > "$1/shell/index.html"
    printf 'ASSET-A\n' > "$1/shell/assets/index-AAAA1111.js"
    chmod 0755 "$1/shell" "$1/shell/assets"
    chmod 0644 "$1/shell/index.html" "$1/shell/assets/index-AAAA1111.js"
}

# Re-tighten after a shaping function has added entries under the default umask.
tighten_tree() {   # tree-root
    find "$1" -type d -exec chmod 0755 {} + 2>/dev/null
    find "$1" -type f -exec chmod 0644 {} + 2>/dev/null
}

refuse_case() {   # description  shaping-fn  expected-refusal-substring
    local desc="$1" shape="$2" expect="$3" tmp
    tmp="$(make_sandbox)"
    stage_valid_tree "$tmp/installer/staging"
    "$shape" "$tmp/installer/staging/shell"
    # Re-tighten only for shapes that ADD entries under the default umask. The
    # untrusted-subdir shape IS a permission perturbation, so tightening would erase it.
    if [ "$shape" != "shape_untrusted_subdir" ]; then
        tighten_tree "$tmp/installer/staging/shell"
    fi
    run_installer "$tmp" >/dev/null 2>&1
    local rc=$?
    local log; log="$(cat "$tmp/out.log" 2>/dev/null)"
    # Assert the SPECIFIC reason, not merely that something was refused: a generic
    # "REFUSING" match would be satisfied by any unrelated pre-flight failure (mode bits,
    # a missing artifact), which is how a gate gets credit for a refusal it never made.
    if [ "$rc" -ne 0 ] && [[ "$log" == *"$expect"* ]]; then
        ok "$desc — refused for its own reason"
    else
        bad "$desc — expected refusal containing '$expect' (rc=$rc). log: ${log:0:220}"
    fi
    rm -rf "$tmp"
}

# NOTE on the `..` traversal component: it is NOT directly constructible as a filesystem
# entry — the kernel forbids creating a file or directory named `.` or `..`, so no shaping
# function can produce one. The explicit `..` rejection in install.sh is defence-in-depth
# for a future source that is not a live directory walk (an archive, a manifest, a
# tar/zip extraction). The CONSTRUCTIBLE escape vector is the symlink, covered below.
# Targets a file that is ROOT-OWNED inside the namespace (sandbox files map to uid 0), so
# fstat_trust's owner check cannot fire — this isolates the symlink gate as the ONLY thing
# that can refuse it. An earlier version pointed at /etc/hostname, which maps to `nobody` and
# so also tripped the owner check: the case passed partly for a reason it was not testing.
shape_symlink()    { ln -s ../index.html "$1/assets/leak.js"; }
# B2A-COMP-R1-01 (P1): a SUBDIRECTORY that another local user could write means that user
# controls its contents, so they can race the symlink check against the by-name open and get a
# followed symlink installed. Group/other-writable is the constructible form of "not trusted".
shape_untrusted_subdir() { chmod 0777 "$1/assets"; }
shape_badchars()   { printf 'x\n' > "$1/assets/bad name.js"; }
shape_deep()       { mkdir -p "$1/a/b/c/d/e"; printf 'x\n' > "$1/a/b/c/d/e/deep.js"; }
shape_fifo()       { mkfifo "$1/assets/pipe.js"; }
shape_empty()      { rm -rf "$1"; mkdir -p "$1"; chmod 0755 "$1"; }
shape_no_index()   { rm -f "$1/index.html"; }

echo "Class 12 — name/entry-type gating (each must REFUSE for its OWN reason):"
refuse_case "symlink in tree"             shape_symlink  "is a symlink"
refuse_case "name outside allowed class"  shape_badchars "outside the allowed name class"
refuse_case "tree deeper than the bound"  shape_deep     "exceeds the maximum tree depth"
refuse_case "FIFO in tree"                shape_fifo     "neither a regular file nor a directory"
refuse_case "group/other-writable SUBDIRECTORY" shape_untrusted_subdir \
                                          "group/other-writable inode"
refuse_case "empty tree"                  shape_empty    "contains no regular files"
refuse_case "missing index.html"          shape_no_index "index.html is missing"

# ── The happy path + the replace/no-clobber discipline ────────────────────────────────
echo
echo "Install + replace discipline:"

# Case 8 — a valid tree installs, with content intact.
tmp="$(make_sandbox)"
stage_valid_tree "$tmp/installer/staging"
run_installer "$tmp" >/dev/null 2>&1; rc=$?
tree="$(cat "$tmp/tree.txt" 2>/dev/null)"
if [ "$rc" -eq 0 ] && [[ "$tree" == *"./shell/index.html"* ]] \
                   && [[ "$tree" == *"./shell/assets/index-AAAA1111.js"* ]]; then
    ok "valid tree installs (index.html + hashed asset present)"
else
    bad "valid tree did not install (rc=$rc). log: $(head -c 220 "$tmp/out.log" 2>/dev/null)"
fi
if [[ "$tree" != *"shell.new"* ]] && [[ "$tree" != *"shell.old"* ]]; then
    ok "no shell.new / shell.old left behind after a clean run"
else
    bad "staging dirs survived a clean run: $tree"
fi
if [ "$(cat "$tmp/asset-index-AAAA1111.js.content" 2>/dev/null)" = "ASSET-A" ]; then
    ok "installed asset content matches the staged source"
else
    bad "installed asset content differs from source"
fi
rm -rf "$tmp"

# Case 12 — THE no-clobber proof. Install tree A, then tree B with a DIFFERENT hashed asset
# name, and assert A's asset is GONE. A plain `cp -r` over the live dir leaves it: vite emits
# content-hashed names, so stale assets are never overwritten, only accumulated. This is the
# property the two-rename replace exists to provide.
tmp="$(make_sandbox)"
stage_valid_tree "$tmp/installer/staging"
unshare -rm bash -c '
    set -u
    tmp="$1"
    for d in /usr/share /usr/libexec /usr/lib/systemd/system /etc/pam.d /etc/apparmor.d; do
        mkdir -p "$d"; mount -t tmpfs none "$d" || exit 97
    done
    export PATH="$tmp/fakebin:$PATH"
    bash "$tmp/installer/install.sh" > "$tmp/out1.log" 2>&1 || exit 1
    # Second build: a DIFFERENT content hash, as a real rebuild produces.
    rm -f  "$tmp/installer/staging/shell/assets/index-AAAA1111.js"
    printf "ASSET-B\n" > "$tmp/installer/staging/shell/assets/index-BBBB2222.js"
    chmod 0644 "$tmp/installer/staging/shell/assets/index-BBBB2222.js"
    bash "$tmp/installer/install.sh" > "$tmp/out2.log" 2>&1 || exit 2
    ( cd /usr/share/delphi && find . -printf "%y %p\n" | sort ) > "$tmp/tree2.txt"
' _ "$tmp"
rc=$?
tree2="$(cat "$tmp/tree2.txt" 2>/dev/null)"
if [ "$rc" -eq 0 ] && [[ "$tree2" == *"index-BBBB2222.js"* ]] \
                   && [[ "$tree2" != *"index-AAAA1111.js"* ]]; then
    ok "stale-asset: reinstall REPLACES the tree — previous build's hashed asset is gone"
else
    bad "stale-asset: reinstall did NOT replace the tree (rc=$rc). tree: $tree2"
fi
rm -rf "$tmp"

# Cases 9-11 — leftover states are HANDLED and REPORTED, not stepped over.
leftover_case() {   # description  setup-cmds  expected-log-substring
    local desc="$1" setup="$2" expect="$3" tmp
    tmp="$(make_sandbox)"
    stage_valid_tree "$tmp/installer/staging"
    unshare -rm bash -c '
        set -u
        tmp="$1"; setup="$2"
        # /usr/sbin is a tmpfs here so `apparmor_parser` ABSENT is genuinely representable: the
        # real one lives there, and without this the "not found" branch could never be
        # exercised (it would always find /usr/sbin/apparmor_parser and take the other path).
        # Everything the installer actually uses (install, stat, find, chmod) is in /usr/bin.
        for d in /usr/share /usr/libexec /usr/lib/systemd/system /etc/pam.d /etc/apparmor.d /usr/sbin; do
            mkdir -p "$d"; mount -t tmpfs none "$d" || exit 97
        done
        export PATH="$tmp/fakebin:$PATH"
        mkdir -p /usr/share/delphi
        eval "$setup"
        bash "$tmp/installer/install.sh" > "$tmp/out.log" 2>&1
        rc=$?
        ( cd /usr/share/delphi && find . -printf "%y %p\n" | sort ) > "$tmp/tree.txt"
        exit $rc
    ' _ "$tmp" "$setup"
    local rc=$?
    local log; log="$(cat "$tmp/out.log" 2>/dev/null)"
    local tree; tree="$(cat "$tmp/tree.txt" 2>/dev/null)"
    if [ "$rc" -eq 0 ] && [[ "$log" == *"$expect"* ]] \
       && [[ "$tree" == *"./shell/index.html"* ]] \
       && [[ "$tree" != *"shell.new"* ]] && [[ "$tree" != *"shell.old"* ]]; then
        ok "$desc — handled, reported, and cleared"
    else
        bad "$desc — rc=$rc; expected log to contain '$expect'; log: ${log:0:220}; tree: $tree"
    fi
    rm -rf "$tmp"
}

leftover_case "leftover shell.new (died before the swap)" \
    'mkdir -p /usr/share/delphi/shell.new && echo junk > /usr/share/delphi/shell.new/junk' \
    "clearing leftover"
leftover_case "leftover shell.old WITH shell (died before cleanup)" \
    'mkdir -p /usr/share/delphi/shell /usr/share/delphi/shell.old && echo old > /usr/share/delphi/shell.old/j' \
    "clearing leftover"
# The wording changed with the behaviour (B2A-COMP-R6-01): this state is now RECOVERED by
# restoring shell.old -> shell BEFORE anything is cleared, not warned about and then deleted.
leftover_case "leftover shell.old WITHOUT shell (died BETWEEN the renames)" \
    'mkdir -p /usr/share/delphi/shell.old && echo old > /usr/share/delphi/shell.old/j' \
    "RECOVERING"

# B2A-COMP-R1-02 (P2): AN APPARMOR PROFILE THAT DOES NOT LOAD IS A PROFILE THAT DOES NOTHING.
# The install used to WARN and exit 0 when `apparmor_parser -r -W` failed, leaving the binary
# and the profile file in place on a system where the shell will SIGABRT on its first
# themed-icon load — and the pre-flight only catches that if the operator remembers to run it.
# An install that reports success for a system it has left unable to render is the same
# silent-failure family as the blank window.
tmp="$(make_sandbox)"
stage_valid_tree "$tmp/installer/staging"
# The stub PARSES fine (-QK succeeds) but the KERNEL LOAD (-r) refuses. That split matters:
# after B2A-COMP-R3-01 the parse check is a pre-flight precondition, so a stub that failed
# EVERYTHING would trip that instead and this case would silently stop testing the load path.
cat > "$tmp/fakebin/apparmor_parser" <<'AAP'
#!/bin/bash
for a in "$@"; do
  case "$a" in
    -r|--replace) echo "apparmor_parser: kernel refused the profile" >&2; exit 1 ;;
  esac
done
exit 0
AAP
chmod 0755 "$tmp/fakebin/apparmor_parser"
run_installer "$tmp" >/dev/null 2>&1; rc=$?
log="$(cat "$tmp/out.log" 2>/dev/null)"
# B2A-COMP-R3-01 (P2): a kernel-load refusal is genuinely mid-mutation (loading policy IS a
# mutation), so it must NOT claim "no system change made" — it must say the system is partial.
if [ "$rc" -ne 0 ] && [[ "$log" == *"kernel refused to load"* ]] \
   && [[ "$log" == *"PARTIAL STATE"* ]] \
   && ! [[ "$log" == *"no system change made"* ]]; then
    ok "kernel-load refusal fails the install and reports the PARTIAL state truthfully"
else
    bad "apparmor_parser failed but the install reported success (rc=$rc). log: ${log:0:200}"
fi
rm -rf "$tmp"

# The sibling: apparmor_parser missing entirely must also fail, not silently skip.
# B2A-COMP-R3-01 (P2): apparmor_parser ABSENT is a PURE PRECONDITION and must be caught
# BEFORE any mutation, so the failure is a clean "no system change made" rather than a mixed
# old/new install. Asserted on `refuse`'s wording, which is what makes the claim true.
tmp="$(make_sandbox)"
stage_valid_tree "$tmp/installer/staging"
rm -f "$tmp/fakebin/apparmor_parser"
run_installer "$tmp" >/dev/null 2>&1; rc=$?
log="$(cat "$tmp/out.log" 2>/dev/null)"; tree="$(cat "$tmp/tree.txt" 2>/dev/null)"
# THE DISCRIMINATOR is whether the BINARIES were copied. Asserting only that the bundle tree
# is absent does NOT distinguish "refused in pre-flight" from "refused after the binaries were
# installed" — the tree install runs after the apparmor block either way, so that assertion
# passed even with the precondition moved back below the first copy_fd. Verified by weaken.
libexec="$(cat "$tmp/libexec.txt" 2>/dev/null)"
if [ "$rc" -ne 0 ] && [[ "$log" == *"apparmor_parser not found"* ]] \
   && [[ "$log" == *"no system change made"* ]] \
   && [[ "$libexec" != *"delphi-runtimed"* ]] \
   && [[ "$tree" != *"./shell/index.html"* ]]; then
    ok "apparmor_parser ABSENT refused in PRE-FLIGHT (nothing installed at all)"
else
    bad "apparmor_parser absent but the install reported success (rc=$rc). log: ${log:0:200}"
fi
rm -rf "$tmp"

# ── B2A-COMP-R8-01: THE INVARIANT, DECIDED FROM A COMPLETE RECORD ─────────────────────
# The property is NOT "the rename sequence works" — it is "at every instant there is at least
# one of shell or shell.old; it is never the case that both are absent".
#
# THE INSTRUMENT CHANGED, because three successive samplers each carried a timing defect
# (straddled stats → startup race → bounded busy-wait). That is not three unlucky
# implementations: a sampler observes at INTERVALS, so it cannot decide "at every instant"
# even in principle, and every fix could only shrink the gaps it cannot see. The fourth fix
# would have been on the same wrong axis.
#
# A directory entry changes only by syscall, and `strace -f` records every syscall of the
# traced tree — so existence is a step function whose every step is on record. Deciding the
# invariant after each step decides it at every instant, with no interval, no iteration count,
# and no dependence on scheduling. See installer/tests/trace-invariant.py for the full
# argument and the four fail-closed REFUSE conditions.
#
# The pre-fix code opened exactly such a window: from the died-between-renames state
# (shell.old present, shell absent) it did `rm -rf shell.old` FIRST, so nothing good existed
# until the new tree was built and moved — and a failure in between left neither.
CHECKER="$REPO/installer/tests/trace-invariant.py"
if ! command -v strace >/dev/null 2>&1; then
    # A skipped test yields PASS/PASS and is worthless (Iron Law #15 clause 2). Fail loudly.
    bad "strace not installed — the invariant CANNOT be decided. Install with: apt install strace"
else

# ── The checker is now the instrument, so the checker is proven to bite FIRST ──────────
# Synthetic traces, no installer, no timing: the same input always yields the same verdict.
# This is the deterministic weaken/restore that class 22 says a scheduler-dependent test
# cannot honestly provide — the reason for moving off sampling at all.
checker_case() {   # description  expected-word  trace-body
    local desc="$1" expect="$2" body="$3" out ftmp
    ftmp="$(mktemp)"; printf '%s\n' "$body" > "$ftmp"
    out="$(python3 "$CHECKER" "$ftmp" /usr/share/delphi shell shell.old shell.old 2>&1)"
    rm -f "$ftmp"
    if [[ "$out" == "$expect"* ]]; then ok "checker: $desc → $expect"
    else bad "checker: $desc expected $expect, got: $out"; fi
}
P=/usr/share/delphi
checker_case "restore-before-clear (the shipped order)" OK \
"1 renameat2(AT_FDCWD, \"$P/shell.old\", AT_FDCWD, \"$P/shell\", RENAME_NOREPLACE) = 0
1 mkdir(\"$P/shell.new\", 0777) = 0
1 renameat2(AT_FDCWD, \"$P/shell\", AT_FDCWD, \"$P/shell.old\", RENAME_NOREPLACE) = 0
1 renameat2(AT_FDCWD, \"$P/shell.new\", AT_FDCWD, \"$P/shell\", RENAME_NOREPLACE) = 0
1 unlinkat(AT_FDCWD, \"$P/shell.old\", AT_REMOVEDIR) = 0"
checker_case "clear-before-restore (THE defect this test exists for)" VIOLATION \
"1 unlinkat(AT_FDCWD, \"$P/shell.old\", AT_REMOVEDIR) = 0
1 renameat2(AT_FDCWD, \"$P/shell.new\", AT_FDCWD, \"$P/shell\", RENAME_NOREPLACE) = 0"
checker_case "a FAILED remove changes nothing" OK \
"1 unlinkat(AT_FDCWD, \"$P/shell.old\", AT_REMOVEDIR) = -1 ENOENT (No such file or directory)
1 renameat2(AT_FDCWD, \"$P/shell.old\", AT_FDCWD, \"$P/shell\", RENAME_NOREPLACE) = 0"
checker_case "unclassified syscall naming a watched path" REFUSE \
"1 some_new_syscall(AT_FDCWD, \"$P/shell.old\") = 0"
checker_case "dirfd-relative mutation (fts-style rm)" REFUSE \
"1 unlinkat(3, \"shell.old\", AT_REMOVEDIR) = 0"
checker_case "MUTATING syscall split across <unfinished>" REFUSE \
"1 unlinkat(AT_FDCWD, \"$P/shell.old\", AT_REMOVEDIR <unfinished ...>"
# The narrowing that lets a real trace be decided at all, and its boundary. A real run splits
# `execve` and a directory `openat` on the live bundle path; neither can change existence.
# An `openat` that COULD create still refuses — that is what makes the skip a narrowing.
checker_case "INERT syscall split is skipped, not refused" OK \
"1 execve(\"/usr/bin/find\", [\"find\", \"$P/shell\"], 0x0 /* 83 vars */ <unfinished ...>
1 openat(AT_FDCWD, \"$P/shell\", O_RDONLY|O_DIRECTORY <unfinished ...>
1 renameat2(AT_FDCWD, \"$P/shell.old\", AT_FDCWD, \"$P/shell\", RENAME_NOREPLACE) = 0"
checker_case "split openat that COULD create still refuses" REFUSE \
"1 openat(AT_FDCWD, \"$P/shell\", O_WRONLY|O_CREAT, 0644 <unfinished ...>"
checker_case "a trace with no mutation at all is not a vacuous pass" REFUSE \
"1 newfstatat(AT_FDCWD, \"$P/shell\", 0x7ffd, 0) = 0"

tmp="$(make_sandbox)"
stage_valid_tree "$tmp/installer/staging"
unshare -rm bash -c '
    set -u; tmp="$1"
    for d in /usr/share /usr/libexec /usr/lib/systemd/system /etc/pam.d /etc/apparmor.d /usr/sbin; do
        mkdir -p "$d"; mount -t tmpfs none "$d" || exit 97; done
    export PATH="$tmp/fakebin:$PATH"
    # Reproduce the crash state: shell.old is the ONLY good bundle.
    mkdir -p /usr/share/delphi/shell.old/assets
    printf "PREVIOUS\n" > /usr/share/delphi/shell.old/index.html
    # Record EVERY syscall of the installer and its children. `%file` is deliberately broader
    # than the mutating set: the checker must SEE an unclassified call naming a watched path
    # in order to refuse, and it cannot refuse over what was never traced.
    strace -f -o "$tmp/trace.log" -e trace=%file \
        bash "$tmp/installer/install.sh" > "$tmp/out.log" 2>&1
    echo "$?" > "$tmp/rc"
    ( cd /usr/share/delphi && find . -maxdepth 1 -printf "%p\n" | sort ) > "$tmp/final.txt"
' _ "$tmp"
final="$(cat "$tmp/final.txt" 2>/dev/null)"
log="$(cat "$tmp/out.log" 2>/dev/null)"
verdict="$(python3 "$CHECKER" "$tmp/trace.log" /usr/share/delphi shell shell.old shell.old 2>&1)"
if [[ "$verdict" == REFUSE* ]]; then
    bad "crash-between-renames: the trace could not be fully accounted for — $verdict"
elif [ "$verdict" = OK ] && [[ "$log" == *"RECOVERING"* ]] && [[ "$final" == *"./shell"* ]]; then
    ok "crash-between-renames: a good bundle exists at EVERY instant (complete syscall record)"
else
    bad "invariant verdict=$verdict or no restore. log: $(echo "$log" | grep -E 'RECOVER|NOTE' | head -2)"
fi
rm -rf "$tmp"
fi   # strace available

echo
echo "── tree-install: $pass passed, $fail failed ──"
[ "$fail" -eq 0 ]
