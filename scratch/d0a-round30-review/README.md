# D0-A round 30 review evidence

Reviewed branch: `phase-3b/d0-readiness-contract`.
Reviewed range: `2c7dee0..9fa4017` (nine commits; 14 files, +1310/-337).
The checkout was at `9c8984022730b351dee5f68be9421748094bfe0b`; its only additional
tracked change was the round-30 prompt. Reviewed product/scripts/docs matched the pinned tip.
No product fixes were made. These probes are retained review artifacts, not registered suite tests.

## Shutdown status probe

`shutdown-probe.rs` compiles the repository's actual `runtime/src/shutdown.rs`.
`waitid(WEXITED | WNOWAIT)` waits for the child to become terminal without reaping it.
The two fixtures exit with code 7 and SIGTERM respectively. Both returned `Exited { code: 0 }`.
The probe only spawns/signals its own children.

Command on this workspace:

```bash
rustc --edition=2024 scratch/d0a-round30-review/shutdown-probe.rs --extern nix=/home/revanth-aditya/delphi-target/debug/deps/libnix-0954cd18a62ad1fa.rlib -L dependency=/home/revanth-aditya/delphi-target/debug/deps -o /tmp/d0a-r30-shutdown-probe
/tmp/d0a-r30-shutdown-probe
```

The dependency path is the existing Cargo artifact, not a portable path. On another checkout,
resolve the matching nix rlib from that checkout's Cargo target directory. Output is retained
in `shutdown-probe.log`.

## Harness probes

Run `python3 scratch/d0a-round30-review/harness-probe.py` from any directory.
It imports the actual harness, mocks a captured libtest precondition failure, then uses
isolated temporary Git repositories and a fake cargo to test source protection and its self-test.
It does not mutate tracked workspace files or run a real mutation campaign.

Results in `harness-probe.log`:

- A captured stale-session PRECONDITION failure is classified CAUGHT.
- A modified installer PAM fixture is admitted by inputs_are_clean().
- SIGTERM during mutant compilation exits -15, leaves mutant source, and leaves empty JSONL.
- An always-false restore verifier makes mutation-campaign.test.py print two FAILs but exit 0.

The fake build is deliberately held at a known point; this tests interruption handling,
not Cargo behavior or real mutation detection.

## Existing checks and historical lane audit

- `python3 scripts/mutation-campaign.test.py`: exit 0, six classifier cases passed.
- `cargo test -p delphi-runtime --lib shutdown::tests -- --nocapture`: 8 passed,
  0 failed, 158 filtered out; one unprivileged run, default parallel settings.
- `bash scripts/check-free-space.sh`: exit 0; checked /run, /tmp, and configured target path.
- Parsed `/tmp/root-run19.log` with the actual `scripts/test-count.sh`, setting
  `DELPHI_TESTCOUNT_LOG` and `DELPHI_TESTCOUNT_EXPECT_TARGETS=17`: 216 executed,
  5 skipped, 221 reported.
- `lane-audit.py`: eight shutdown names in historical root log; 17 producer statuses all zero;
  root log identities 221 and current binary --list identities 221, no differences.
  Output retained in `lane-audit.log`.

The lane audit checks retained historical output and current enumeration. It does not rerun
root tests, independently recreate the historical euid, or certify the production gate.

## Primary API references checked

- https://man7.org/linux/man-pages/man2/waitpid.2.html
- https://man7.org/linux/man-pages/man2/kill.2.html
- https://docs.python.org/3/library/signal.html

Linux kill(2) makes a distinction missing from the prompt: signal permission is based on
credentials/capabilities, not parenthood. PID 1 also has special signal protection; ordinary
root kill(1, SIGKILL) is not a reliable way to kill host init. No signal was sent to PID 1.
