#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Decide the both-absent invariant from a COMPLETE syscall record, not a sample.

WHY THIS EXISTS — the instrument was wrong three times, so the instrument changed.

The property under test is "at every instant at least one of `shell` / `shell.old` exists".
Three successive attempts asserted it by SAMPLING the directory from a background loop, and
all three carried a defect of the same class (Class 22): a straddled pair of stats, a startup
race, and a bounded busy-wait that assumes the sampler gets scheduled within N iterations.
That is not three unlucky implementations. **A sampler cannot decide "at every instant" even
in principle** — it observes at intervals, and between any two observations there is a gap it
did not see. Every fix could only make the gaps smaller, never absent, so every fix was on the
wrong axis and the next one would have been too.

WHAT MAKES THIS COMPLETE RATHER THAN SAMPLED
--------------------------------------------
A directory entry's existence changes ONLY by syscall. `strace -f` records every syscall made
by the traced process tree. Therefore the existence of a name is a STEP FUNCTION whose every
step is in the record, and evaluating the invariant after each step evaluates it at every
instant — the state between two consecutive syscalls is by construction the state after the
first. There is no interval to miss, no iteration count anywhere, and the verdict does not
depend on scheduling at all: the same trace yields the same verdict on any machine, forever.

That is also why this checker can be proven to bite DETERMINISTICALLY (see the synthetic-trace
self-tests in tree-install.test.sh) — the thing a sampler could never offer.

FAIL CLOSED — the four ways a trace could be incomplete, each REFUSED, never guessed
------------------------------------------------------------------------------------
The completeness argument above holds only if every mutation is actually visible AND
understood. Where it might not be, this refuses to render a verdict rather than returning a
reassuring one:

  1. an unknown syscall naming a watched path — cannot classify, so cannot claim completeness;
  2. a mutating syscall using a RELATIVE path (dirfd-based, e.g. fts-style `rm`) — the dirfd
     is not resolvable from the trace text, so the target is genuinely unknown. Measured on
     this installer coreutils used an ABSOLUTE `unlinkat(AT_FDCWD, ".../shell.old",
     AT_REMOVEDIR)`, but that is a fact about one version of `rm`, not a guarantee;
  3. a `<unfinished ...>` / `<... resumed>` split across a watched path — 74 such splits occur
     in a real run, so this is not hypothetical;
  4. a mutation whose success/failure cannot be read from the return value.

A REFUSE is a loud failure of the MEASUREMENT and must never be reported as a passing test.
The one assumption that remains, stated rather than hidden: only the traced tree mutates the
directory. The test runs in a private mount namespace where nothing else is running.

Usage:  trace-invariant.py TRACE PARENT NAME_A NAME_B INITIAL
        INITIAL is a comma list of the names that exist before tracing begins ("" for none).
Prints exactly one of:  OK | VIOLATION <detail> | REFUSE <reason>
Exit status is 0 for OK, 1 for VIOLATION, 2 for REFUSE.
"""

import re
import sys

# Syscalls that CREATE or REMOVE a directory entry, with which quoted argument is affected.
# "src_dst" removes the first path literal and creates the last, atomically (rename family).
MUTATORS = {
    "rename": "src_dst", "renameat": "src_dst", "renameat2": "src_dst",
    "unlink": "remove_first", "unlinkat": "remove_first", "rmdir": "remove_first",
    "mkdir": "create_first", "mkdirat": "create_first",
    "link": "create_last", "linkat": "create_last",
    "symlink": "create_last", "symlinkat": "create_last",
    "open": "maybe_create_first", "openat": "maybe_create_first",
}

# Syscalls that name a path but cannot change whether it exists. Anything naming a watched
# path that is in NEITHER table is a REFUSE: an unclassified call breaks the completeness
# argument, and guessing "probably harmless" is exactly the move this file exists to prevent.
INERT = {
    "stat", "lstat", "fstat", "newfstatat", "statx", "statfs", "access", "faccessat",
    "faccessat2", "readlink", "readlinkat", "execve", "execveat", "chdir", "chmod",
    "fchmodat", "chown", "lchown", "fchownat", "utimensat", "utime", "utimes",
    "getxattr", "lgetxattr", "setxattr", "lsetxattr", "listxattr", "llistxattr",
    "removexattr", "lremovexattr", "truncate", "mount", "umount2", "getcwd", "inotify_add_watch",
}

STRLIT = re.compile(r'"((?:[^"\\]|\\.)*)"')
# strace -f prefixes each line with a pid. The syscall name follows.
CALL = re.compile(r'^(?:\d+\s+)?([a-z_0-9]+)\((.*)$')
RESUMED = re.compile(r'<\.\.\.\s+([a-z_0-9]+)\s+resumed>')
RET = re.compile(r'=\s+(-?\d+|\?)(?:\s|$)')


def main() -> int:
    if len(sys.argv) != 6:
        print("REFUSE bad-usage")
        return 2
    trace_path, parent, name_a, name_b, initial = sys.argv[1:6]
    watched = {f"{parent}/{name_a}": name_a, f"{parent}/{name_b}": name_b}
    basenames = {name_a, name_b}
    exists = {n: False for n in basenames}
    for n in (x for x in initial.split(",") if x):
        if n not in exists:
            print(f"REFUSE initial-name-not-watched:{n}")
            return 2
        exists[n] = True

    if not any(exists.values()):
        print("REFUSE initial-state-already-violates")
        return 2

    try:
        with open(trace_path, encoding="utf-8", errors="replace") as fh:
            lines = fh.readlines()
    except OSError as exc:
        print(f"REFUSE cannot-read-trace:{exc}")
        return 2

    step = 0
    for lineno, raw in enumerate(lines, 1):
        line = raw.rstrip("\n")
        literals = [m.group(1) for m in STRLIT.finditer(line)]
        touches = [lit for lit in literals if lit in watched]
        # A split line's arguments and return value straddle two lines, so a MUTATING call
        # cannot be applied from either half alone — refuse. But a split whose syscall is
        # provably inert cannot change existence however it completes, so skipping it is
        # NARROWING (the measurement still fails if the property is violated), not weakening:
        # the mutating-split case below still refuses, and is covered by its own self-test.
        # This is not hypothetical tidying — a real run splits `execve` and a directory
        # `openat` on the live bundle path.
        if "<unfinished" in line or "resumed>" in line:
            if not (touches or any(lit in basenames and not lit.startswith("/")
                                   for lit in literals)):
                continue
            sm = CALL.match(line) or RESUMED.search(line)
            sname = sm.group(1) if sm else None
            if sname in INERT:
                continue
            # open/openat create only with O_CREAT. The access mode is always rendered first
            # in the flags argument, so seeing one proves the flags argument was fully
            # serialized before the split and its O_CREAT verdict can be trusted.
            if sname in ("open", "openat") and "O_CREAT" not in line \
                    and re.search(r"\bO_(RDONLY|WRONLY|RDWR)\b", line):
                continue
            print(f"REFUSE split-line-names-watched-path:{sname}:{lineno}")
            return 2

        m = CALL.match(line)
        if not m:
            continue
        name, rest = m.group(1), m.group(2)
        effect = MUTATORS.get(name)

        # A mutator naming a watched BASENAME relatively: the dirfd is unresolvable here.
        if effect and not touches:
            for lit in literals:
                if lit in basenames and not lit.startswith("/"):
                    print(f"REFUSE relative-mutation-on-watched-basename:{lineno}")
                    return 2
        if not touches:
            continue
        if effect is None:
            if name in INERT:
                continue
            print(f"REFUSE unclassified-syscall:{name}:{lineno}")
            return 2

        rm = RET.search(rest)
        if rm is None:
            print(f"REFUSE unreadable-return:{name}:{lineno}")
            return 2
        if rm.group(1) == "?" :
            print(f"REFUSE unknown-return:{name}:{lineno}")
            return 2
        if int(rm.group(1)) < 0:
            continue                                   # failed call changes nothing

        paths = [lit for lit in literals if lit in watched or lit.startswith(parent + "/")]
        if effect == "src_dst":
            src, dst = paths[0], paths[-1]
            if src in watched:
                exists[watched[src]] = False
            if dst in watched:
                exists[watched[dst]] = True
        elif effect == "remove_first":
            if paths[0] in watched:
                exists[watched[paths[0]]] = False
        elif effect in ("create_first", "create_last"):
            tgt = paths[0] if effect == "create_first" else paths[-1]
            if tgt in watched:
                exists[watched[tgt]] = True
        elif effect == "maybe_create_first":
            if "O_CREAT" in rest and paths[0] in watched:
                exists[watched[paths[0]]] = True

        step += 1
        if not any(exists.values()):
            print(f"VIOLATION both-absent-after:{name}:line{lineno}:step{step}")
            return 1

    if step == 0:
        # No mutation at all means the installer never touched the names it must replace;
        # accepting that would let a no-op install pass the invariant vacuously.
        print("REFUSE no-mutations-observed")
        return 2
    print("OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
