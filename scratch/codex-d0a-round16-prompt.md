# Codex adversarial review — D0-A round 16 (D0A-R10-12: the pre-drop capability window)

This prompt is `scratch/codex-d0a-round16-prompt.md`, the round-16 prompt for the
`phase-3b/d0-readiness-contract` branch. It is the review ledger entry for its own round —
if you are reading it detached from that branch, say so and stop, because the target below
will not resolve.

## Your target, and how to detect that you are looking at the wrong thing

**Commit `3e4a275`**, on `phase-3b/d0-readiness-contract`, parent `0e6a567`.

Inspect it yourself through the CLI — `git show 3e4a275` — rather than trusting any diff
pasted to you. Expect exactly:

```
 .githooks/runtime-test-count-baseline |  10 +-
 docs/CONFORMANCE_REGISTER.md          |  70 +++++-
 runtime/src/execute.rs                |  98 +++++++-
 runtime/src/sandbox.rs                |  53 +++++
 scratch/d0a-r10-12-red-proof.sh       | 180 ++++++++++++++
 scratch/d0a-r10-12-window-probe.sh    | 437 ++++++++++++++++++++++++++++++++++
 6 files changed, 844 insertions(+), 4 deletions(-)
```

**If what you find disagrees with that stat, report the mismatch as a finding and review
what is actually there.** Scope drift is a defect, not a detail to absorb silently.

## Grounding

Verify every claim about bubblewrap, Linux capabilities, and `execve` semantics against the
source or official documentation — `bwrap --help` / the bubblewrap repository,
`capabilities(7)`, `credentials(7)`, or the kernel's `security/commoncap.c`. Do not reason
from memory about `cap_bprm_creds_from_file`, `no_new_privs`, or bounding-set inheritance.
Where this repo makes an empirical claim, the measurements are reproducible: the probe is
`scratch/d0a-r10-12-window-probe.sh` (root, seven legs) and the weaken/stability harness is
`scratch/d0a-r10-12-red-proof.sh` (run unprivileged; it sudo's for the test binary only).

## What the change claims

`SandboxProfile::with_credential_drop()` appends `--cap-drop ALL --cap-add CAP_SETUID
--cap-add CAP_SETGID`; `run_fd_pinned` applies it when `tool_credentials()` returns `Some`.
The claim is that the pre-drop payload — bwrap's payload, which is `delphi-drop` up to
`setresuid` — then holds only those two capabilities and **cannot recover more across a
further `execve`**.

Measured support, all on the privileged path:

- lowering permitted/effective alone does nothing: a root `execve` recomputes
  `P'(permitted) = F(permitted) & P(bounding)`, restoring the full set;
- the restriction cannot be applied daemon-side (bwrap needs `CAP_SYS_ADMIN`);
- under the flags, `c0` persists across a further exec, and the unflagged control returns
  `000001ffffffffff`;
- it persists **only because bwrap sets `no_new_privs=1`**, which no bwrap flag governs.

## Attack surfaces to concentrate on

**1. Is the "not weaken-provable in-tree" limit true, or is it an alibi?** The change grades
its own guard below its name: stable (30/30 default parallel), emission weaken-proven twice,
but the NNP discrimination **probe-measured rather than weaken-proven**, on the argument that
the variable making it bite belongs to bwrap. **Try to falsify that.** If a test could
construct the NNP-absent shape in-tree — the way probe leg 4b does out-of-tree — then the
limit is overstated and the guard owes a real RED. This is the claim I most want attacked.

**2. The gate on `creds.is_some()` hardens the safer path and leaves the more dangerous one
untouched — is that defensible?** Answer this directly rather than in passing. When
`tool_credentials()` returns `None` no helper is interposed, bwrap execs the approved tool
itself, no restriction is emitted, and **the tool runs as root holding
`000001ffffffffff`**. The change therefore narrows capabilities in the configuration where a
uid drop already constrains the payload, and does nothing in the configuration where nothing
else does. Is that boundary right — is the un-dropped path a supported deployment, a
dev-only path, or an unremarked hole — and should the restriction be unconditional?

**3. Does the minimality design establish minimality, given its results?** MEASURED at root
on 2026-08-25, after the reviewed commit (probe leg 7 — the file is in `3e4a275`; these
numbers are not):

```
only CAP_SETUID (no SETGID)   failed   setgroups failed: Operation not permitted
only CAP_SETGID (no SETUID)   failed   setresuid failed: Operation not permitted
neither (control)             failed   setgroups failed: Operation not permitted
both caps                     SUCCESS  (control holds)
```

Each removal fails at a **different syscall**, and a positive control shows the harness can
succeed — so this is not three identical refusals sharing one explanation. The narrow ask:
**does that design actually establish necessity of both capabilities**, or is there a way
for a variant to fail for a reason unrelated to the capability removed?

**4. Arg construction and scope enforcement.** The flags land after `--chdir` and before
`--args <fd>` and the `--` separator. Check the interaction with `--args` fd-carried tokens
(D0A-R9-06), with `args_enforce_scope`, and with `emitted_dirs`/bind parsing. Does any
existing arg parser mis-read the new tokens?

**5. Digest coverage.** The flags ride the `SandboxProfile` object specifically so
`sandbox_profile_digest` covers them — but `RuntimeAuditEntry::record` currently has **no
production caller**, so that coverage is forward-looking. Is the claim in the commit message
overstated for the code as it stands?

**6. The guard's fixture vs production.** The test builds bwrap args from `derive()` +
`with_credential_drop()` and appends its own `--`/payload rather than going through
`run_fd_pinned`. That is a fixture that constructs the invocation differently from the thing
it stands in for.

## Defect-class partition (`docs/DEFECT_CLASSES.md`), per CLAUDE.md §13.9

**(a) Pre-foreclosed — do not spend budget re-hunting these:**

- **10** (a skipped test reports as `ok`) — foreclosed by `scripts/test-count.sh` and the
  exact-equality `.githooks/runtime-test-count-baseline`, which refused this very commit
  until the pair was updated with a reason.
- **44** (a restore whose precondition is absent looks like a successful one) — the
  red-proof harness restores via `trap` on every exit path and verifies with `cmp`.
- **1** (`canonical_hash` both-halves / a new field silently unhashed) — unchanged by this
  commit; no `PendingAction` or `ScriptPin` field was added.

**(b) Applicable and NOT foreclosed — these deserve explicit coverage:**

- **42** (a negative assertion whose sufficiency rested on a default the change removed) —
  the change is a *self-declared instance*: the restriction rests on bwrap's `no_new_privs`
  default. Judge whether asserting after a further exec is an adequate response, or theatre.
- **34** (a deferral is an untested claim) — minimality WAS this, and is now measured
  (surface 3). It stays listed because the measurement post-dates the commit: judge whether
  anything else in the change is still carrying a deferral in place of a result.
- **41** (the assertion is at the wrong altitude) — the guard asserts on `CapPrm` text
  scraped from `/proc/self/status` inside the jail.
- **25** (the fixture is constructed differently from the thing it stands in for) — surface 6.
- **38 / R7-09** (a sound check whose report carries none of what it verified) — both legs
  are now printed; check the print actually carries the discrimination.
- **22 / 37** (the fix inherits the class it was closing; remediation is where a class
  reappears) — **live here.** The probe harness *committed the defect it exists to detect*:
  its first version ran `cargo` under `sudo`, found nothing, and read the absent failure line
  as a verdict, reporting contradictory numbers. It was rebuilt around a `require_suite_ran`
  precondition. Check the rebuild did not re-inherit.

## Verdict format

Structured verdict — **APPROVE** / **REVISE** / **FAIL**. Every finding carries:

- an **ID** (`D0A-R16-nn`),
- a **severity** (P1-high → P2-medium → P2-low → P3-informational),
- a **root-cause** statement,
- an **impact** statement,
- a **fix sketch**.

Findings against the *grading* — that the change claims more or less than its evidence
supports — are in scope and welcome. So is a finding that the honest-limit framing is being
used to avoid work that is in fact doable.
