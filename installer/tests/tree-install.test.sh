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

# ── B2A-COMP-R6-01: THE INVARIANT, ASSERTED BY SAMPLING ───────────────────────────────
# The property is NOT "the rename sequence works" — it is "at every instant there is at least
# one of shell or shell.old; it is never the case that both are absent". Testing a specific
# crash point tests one point; SAMPLING the directory throughout the install tests the
# invariant itself, and catches any ordering that opens a both-absent window.
#
# The pre-fix code opened exactly such a window: from the died-between-renames state
# (shell.old present, shell absent) it did `rm -rf shell.old` FIRST, so nothing good existed
# until the new tree was built and moved — and a failure in between left neither.
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
    # ── SAMPLING, SYNCHRONISED BY CONSTRUCTION (B2A-COMP-R7-01) ───────────────────────
    # This sampler has been wrong TWICE. Both failures were the measurement, not the subject:
    #   1st: two separate `[ -e ]` stats straddled the atomic rename(2), inventing a
    #        both-absent state that never existed.
    #   2nd: `echo 0` ran INSIDE the background subshell, so the parent could launch the
    #        installer and kill the sampler before that first write ever happened — the file
    #        then did not exist and the test read "unknown", failing on GOOD code.
    #
    # The second is a class-22 recurrence *in the same test*: the fix for a measurement race
    # introduced a startup race. And "10/10 deterministic" did not catch it, because the
    # window is scheduler-dependent — repetition samples the the scheduler usual interleaving,
    # not the one that matters.
    #
    # BOTH races are now removed BY CONSTRUCTION, so the argument is a happens-before you can
    # read rather than a frequency you have to trust:
    #   * the initial `0` is written by the PARENT, before the fork. The file therefore exists
    #     whenever the parent later reads it — no window at all.
    #   * the sampler signals READINESS after its first completed sample, and the parent waits
    #     for that signal before launching the installer. "Hope it started" becomes "it
    #     demonstrably started".
    echo 0 > "$tmp/both-absent"          # BEFORE the fork — happens-before the parent read
    ( while :; do
          snapshot=$(ls -1 /usr/share/delphi 2>/dev/null)
          # ONE readdir per sample: two stats cannot observe an atomic rename.
          if ! echo "$snapshot" | grep -qxE "shell|shell\.old"; then
              echo 1 > "$tmp/both-absent"; break
          fi
          # Signal readiness only AFTER a completed sample, so the handshake means sampling
          # is genuinely underway, not merely that the subshell was scheduled.
          [ -e "$tmp/sampler-ready" ] || : > "$tmp/sampler-ready"
      done ) &
    sampler=$!
    # Bounded wait for the handshake. If it never arrives the sampler is broken, and that must
    # be a loud failure rather than a silent unsynchronised run.
    for _ in $(seq 1 500); do [ -e "$tmp/sampler-ready" ] && break; done
    [ -e "$tmp/sampler-ready" ] || echo "SAMPLER-NEVER-READY" > "$tmp/both-absent"
    bash "$tmp/installer/install.sh" > "$tmp/out.log" 2>&1; rc=$?
    kill $sampler 2>/dev/null; wait $sampler 2>/dev/null
    echo "$rc" > "$tmp/rc"
    ( cd /usr/share/delphi && find . -maxdepth 1 -printf "%p\n" | sort ) > "$tmp/final.txt"
' _ "$tmp"
both="$(cat "$tmp/both-absent" 2>/dev/null || echo unknown)"
final="$(cat "$tmp/final.txt" 2>/dev/null)"
log="$(cat "$tmp/out.log" 2>/dev/null)"
if [ "$both" = SAMPLER-NEVER-READY ]; then
    bad "crash-between-renames: the sampler never signalled readiness — measurement unusable"
elif [ "$both" = 0 ] && [[ "$log" == *"RECOVERING"* ]] && [[ "$final" == *"./shell"* ]]; then
    ok "crash-between-renames: a good bundle exists at EVERY instant (restore before clear)"
else
    bad "both-absent window observed (=$both) or no restore. log: $(echo "$log" | grep -E 'RECOVER|NOTE' | head -2)"
fi
rm -rf "$tmp"

echo
echo "── tree-install: $pass passed, $fail failed ──"
[ "$fail" -eq 0 ]
