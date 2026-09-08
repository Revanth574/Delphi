# D0-A round 31 review evidence

Scope: `git diff 9fa4017..63af7f7`, on `phase-3b/d0-readiness-contract`.
Nine commits, 20 files, 1347 insertions and 148 deletions: matched the prompt.
Checkout HEAD was `303a6d735d3102fc2451f5de799876a7af29854e`; its only additional tracked
change was the round-31 prompt. Product/scripts/docs matched the pinned tip after review.
No product files were changed by this review. Probes and logs are retained here as review
artifacts, not installed suite tests. Except the explicitly revision-pinned EINTR experiment,
these scripts inspect current source; reproduce this review with source at `63af7f7`.

## Execution limits

The existing 31 Python harness guards passed. The ten existing shutdown unit tests passed
in one unprivileged, default-parallel run. `sudo -n true` reported that interactive
authentication is required, so this review did not run or mutation-test the root/PAM assembly.
The prompt's reported root run is not independently re-executed here.

## Retained probes

Run each with `python3 scratch/d0a-round31-review/<name>.py`. Each has a matching `.log`.
Rust probes use rustc and an existing nix rlib resolved from Cargo's target directory.
No new Cargo dependencies are installed. Temporary mutant trees and fake build workers
are isolated from tracked workspace files; spawned/adopted probe children are cleaned up.

- `assembly-probe.py`: extracts the actual DaemonGuard spawn/wait/group-kill methods,
  strip_ansi, and all nine assertions from the new assembly test. A counterfeit daemon
  emits the expected observations but exits with its sleeper alive. All assertions pass;
  killed=false; the guard supplies SIGKILL. System-account sweeping is a no-op because
  this unprivileged probe creates no system accounts. This demonstrates an oracle gap,
  NOT a root/PAM production mutation run.
- `shutdown-mutation-probe.py`: changes only `Waited::Timeout => {}` to
  `Waited::Timeout => return ChildOutcome::Terminated` in a temporary copy of shutdown.rs.
  All ten actual module tests pass. Two sleepers survive the runner, are observed as
  adopted children, then are killed and reaped by the probe. This mutant skips signalling
  and post-kill reaping while retaining the expected return value.
- `campaign-signal-probe.py`: runs the actual campaign with fake Cargo in temporary Git
  repositories. SIGTERM sent only to the harness exits 143 and restores source, but a
  fake build grandchild survives. SIGKILL exits -9, leaves source mutated, and also leaves
  the worker alive. Both journals contain an IN PROGRESS row. The probe kills/reaps all
  remaining fake workers after recording their state.
- `selftest-probe.py`: runs all 31 actual guards in a temporary repository while replacing
  `_install_signal_handlers` with a no-op. All 31 pass; return 0.
- `wait-barrier-probe.py`: compiles the actual shutdown tests with a linker wrapper making
  waitid return -1/EINTR without establishing a terminal barrier. Both new supposedly
  deterministic tests still pass, confirming the syscall result is ignored.
- `classifier-probe.py`: gives run_suite captured-output-shaped text for the actual
  stale-session helper's launch-error diagnostic (Permission denied / environment UNKNOWN).
  Classification is CAUGHT. This is a classifier-input probe, not a real failed campaign.
- `eintr-probe.py`: real targeted SIGUSR1 delivery without SA_RESTART to a thread blocked
  in ChildGuard::reap_status. A linker wrapper OBSERVES actual waitpid EINTR returns;
  it does not inject errno. Helper code is extracted from Git at 2c7dee0 and 63af7f7.
  Pre-fix: one observed EINTR, panic, child StillAlive. Reviewed revision: 81 observed
  EINTR returns, no panic, result 0, subsequent wait returns ECHILD. All children are
  reaped. This is now retained experimental evidence; no required suite invokes it.
  The old round-30 evidence directory did not contain an EINTR reproduction.
- `normalizer-probe.py`: the actual helper handles its complete-SGR example. Outside
  that input class it drops a non-CSI escape's following character, leaves OSC payload,
  and can swallow a newline in malformed CSI. These inputs are NOT demonstrated to be
  emitted by the current controlled assembly fixture's formatter. They characterize its
  scope rather than establishing a production exploit.

## Correction to the previous review

The previous review's claim that the minimal shell cannot satisfy SurfaceLive under the
feature was wrong. Both 9fa4017 and the reviewed tree contain cfg(feature =
"insecure-test-seams") calling signal_ready, and the non-feature branch calls
signal_scaffold_ready. A skip at the root precondition alone would not prove readiness;
source inspection of the feature branch does establish the correction.

## API references checked

- https://docs.python.org/3/library/subprocess.html
- https://man7.org/linux/man-pages/man2/waitpid.2.html
- https://docs.rs/tracing-subscriber/latest/tracing_subscriber/fmt/struct.SubscriberBuilder.html
