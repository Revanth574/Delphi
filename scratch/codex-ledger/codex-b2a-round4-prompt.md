# Codex adversarial review — B2a round 4 (the round-3 fixes)

You are a COLD adversarial reviewer. Round 3 (REVISE, 2×P2, you noted the sweep otherwise
CONVERGED) is fixed in ONE commit. Attack the fixes; confirm convergence or name what remains.

## Target
- **Fix commit:** `9582322` (only commit since round 3's review of `65b4bf3~1..HEAD`).
- **Expected diff stat:** 2 files changed, 29 insertions(+), 4 deletions(-). Flag scope drift.
- Inspect LIVE code. Verify `test -f`/`-d` on `/proc/self/fd/N` follows the magic symlink to
  the bound inode and is locale-independent; verify `tracing::warn!` field syntax.

## The fixes to attack

### B2A-C-R3-01 [was P2] — locale-independent file check (`install.sh` fstat_trust)
Replaced `stat -c %F == "regular file"` with `[ -f /proc/self/fd/$fd ]` (files) / `[ -d ]`
(dirs). Attack: does `-f` on the magic symlink check the BOUND inode (not re-resolve a path)?
Any case where a non-regular but trusted source (e.g. the unit is fine, but could a legitimate
source be a symlink the build produced) is now wrongly refused, or a bad one wrongly accepted?

### B2A-C-R3-02 [was P2] — WARN not ABORT on a false startup verdict (`delphi-runtimed.rs`)
**You asked to ABORT. The author deliberately did NOT, and warns instead.** Engage with the
REASONING before re-flagging — do not just restate "abort":
- Claim: for a valid `ttyN` (1..63) the session is ALWAYS seated (`pam_systemd` seats any
  valid VT), so the only axis that can be false at startup is ACTIVE, which is DYNAMIC (which
  VT holds the seat's foreground). Is that claim TRUE? If you can exhibit a valid `ttyN` that
  yields a NON-seated session (so a static, abortable config error exists), the abort is
  justified and this is a REVISE. If you cannot, the abort false-positives on the dev SECONDARY
  shape (§4 R3-02a) and on any boot where the shell's VT is not yet foreground (a race), and
  the warn+per-request-gate is correct.
- Also: the daemon snapshots `logind_verdict` once (line ~128) and reuses it in
  `serve_one_action`. For B1 (one immediate action) that is fine; is it a latent bug for the
  B2 loop (a session that becomes active AFTER the snapshot stays denied)? If so, that is a
  SEPARATE finding about staleness, distinct from the abort question.

## Apply Class 17 to your own findings (mandatory) — grep each shape across the fix.

## Convergence verdict (required)
State whether the sweep has CONVERGED. APPROVE if the fixes are correct (accepting the warn
reasoning if you cannot exhibit a non-seated valid VT). If you REVISE, say whether it is a NEW
defect or a restatement of the abort preference — the latter, at convergence, is an operator
merge-with-documented-reasoning decision, not an auto-continue (§6).

## Required verdict
APPROVE / REVISE / FAIL, each finding with ID, severity, root cause, impact, fix sketch,
cross-scope grep.
