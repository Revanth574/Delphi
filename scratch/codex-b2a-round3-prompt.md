# Codex adversarial review — B2a round 3 (the round-2 fixes)

You are a COLD adversarial reviewer. Round 2 (REVISE, 2 findings) is fixed in ONE commit.
Attack the fixes; find any NEW defect they introduced. Note the convergence question at the
end.

## Target

- **Fix range:** `65b4bf3~1..HEAD` — the two round-2 fix commits `65b4bf3` (R2-01/R2-02) + `ed6c6fc` (atomic `copy_fd`, folded into R2-01). The intervening `ab9b18f` is docs only.
- **Expected diff stat:** `3 files changed, 68 insertions(+), 66 deletions(-)`. Flag scope drift if your checkout differs.
- Inspect the LIVE code via the Codex CLI. Verify bash semantics (`exec {fd}<`, `<&"$fd"`,
  `stat -L /proc/self/fd/N`, `$(( 0$mode & 022 ))`) and the claim that a path/dir swap cannot
  change what an open fd points at — do NOT reason from memory.

## The fixes to attack

### B2A-C-R2-01 [was P1] — install.sh TOCTOU-free copy (`installer/install.sh`)
Now opens every source read-only (binding an fd to its inode), `fstat`s the OPEN fd (owner ∈
{root, SUDO_UID}, no group/other-write, regular file), and copies FROM the fd (`cat <&fd`), not
the path. The staging DIR is fd-checked too. Attack SPECIFICALLY:
- **Is the fd copy actually TOCTOU-free?** `cat <&"$fd"` reads the bound inode — confirm. Is
  there any remaining path-based operation between check and use (the `install -d`, the
  `chown`/`chmod` on the DEST — could the DEST be a symlink an attacker planted so `chown root`
  follows it to a file the attacker wants root-owned)? Check `/usr/libexec` / `/etc/pam.d`
  destination safety, not just the source.
- **The documented residual** (a rename substituting symlinks-to-root-files → wrong root binary,
  a DoS): is it correctly bounded as DoS-not-RCE, or is there a path to RCE the author missed
  (e.g. a symlink to a file the attacker CAN later write, or `cat`→`>` truncating a
  root-symlink target)?
- **`copy_fd`**: `cat <&fd > "$dest"` then `chown`/`chmod`. Between the `>` create and the
  `chmod`, the dest is briefly the default umask mode — is that a window on a multi-user box?
  Should it `install -m` atomically instead?
- **Error handling**: `set -euo pipefail` + `refuse` inside a function called in a pipeline —
  does a `refuse` mid-install actually abort, or can it leave a partial system?

### B2A-C-R2-02 [was P2] — VT-existence preflight REMOVED (`delphi-runtimed.rs`)
The round-1 `ensure!(tty.exists_on_system())` is gone; the comment argues the consent-time
active-local-seated gate is the real defense. Attack: with NO startup VT check, is there any
input `DELPHI_SHELL_VT=ttyN` (valid form, N in 1..63) that now reaches PAM and causes a WORSE
outcome than a clean deny — a hang, a wrong-seat session that the gate ADMITS, or a resource
issue? Confirm the gate genuinely denies a non-seating VT (don't assume). `exists_on_system`
remains defined and used only by tests — confirm no production caller was left dangling.

## Apply Class 17 to your own findings (mandatory)
For any defect, grep the shape across the fix and report all instances (e.g. every `copy_fd`
dest, every `stat -L /proc/self/fd` site).

## Convergence check (state explicitly)
Round 1: 1×P1 + 2×P2 + 1×P3. Round 2: 1×P1 (an escalation of the round-1 install fix) + 1×P2
(a self-reversal). State whether round 3 is converging: are the remaining findings NEW attack
surface (P1) or inherited policy-drift (P2-low/P3)? If you find only P3/informational or
APPROVE, say the sweep has converged.

## Required verdict
APPROVE / REVISE / FAIL. Each finding: ID, severity, one-line root cause, impact, fix sketch,
cross-scope grep. If a surface is clean, say so.
