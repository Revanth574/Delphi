# Delphi Defect-Class Corpus

Mined from the project's adversarial-review history: Task 3A.5 (F4–F26, nine
rounds), Task 3A.6 (R1–R5), the Phase 3B.0 sweeps — `services/` (SVC-*),
`die/orchestrator/` (ORCH-R1/R2), `fortress/` (FORT-R1/R2/R3) — and INF-1.

**Purpose.** Each entry names a *class* of defect that recurred, the findings that
instantiate it, the **foreclosing primitive** (a `delphi-hardening` module where
extracted, a discipline otherwise), and the **RED-proof test shape** that proves a
fix actually closes the class. This is the institutional memory that makes
"fix-known, don't-rediscover" operational: a new task should not re-derive these
the hard way.

**How to use (mandatory — see CLAUDE.md §13).** Every new task's design step and
every Codex round-1 prompt MUST reference this file and state **which classes are
pre-foreclosed by `delphi-hardening`** (so review attention goes to genuinely new
surface, not to classes a primitive already closes), and **which apply but are
not yet foreclosed** (so they get explicit coverage).

**Grounding.** Every finding ID and instance below is grounded in the recorded
history (`PROGRESS.md`, the sweep ledgers, `git log`). Where the record does not
pin a detail, it is marked `[GAP]` rather than invented.

---

## 1. Under-coverage hashing / non-injective encoding  *(CENTERPIECE)*

**Description.** A value's hash either omits a field that affects behavior
(under-coverage — the digest is stable while the meaning changes), or concatenates
variable-length fields so distinct inputs alias (non-injective encoding — a
field-boundary shift produces a colliding digest). Either lets a record be
tampered, or a capability token bound to a hash authorize a behaviorally-different
input, without breaking the hash. This class bit the project repeatedly.

**Foreclosing primitive.** [`delphi_hardening::canonical_hash`] — length-prefixed
injective encoding (`u64`-LE len ++ bytes; collections count-prefixed) **plus** a
declared-field-count guard.

> **The foreclosure is two-part, and BOTH halves are required — the guard alone
> does not foreclose the class.** The declared-field-count guard closes the
> append≠declare gap (the hasher drifting from its own declaration); the per-site
> no-`..` exhaustive destructure closes the struct≠hash gap (a field added to the
> struct that neither the declaration nor the hasher covers). Instances:
> fingerprint confidence omission, delimiter ambiguity, audit tier+result
> omission, + the length-prefixing each needed.

**Applying it — the subtle case the tripwire is FOR.** The no-`..` destructure
forces a conscious decision for *every* field; the non-obvious case is a field that
must **not** be hashed. In `Workflow::fingerprint`, `consent` is the binding TARGET
— the token binds to the fingerprint, so it cannot bind to itself:

```rust
let Workflow { name, steps, consent } = &wf;  // consent: bound target, NOT hashed
```

Three options for `consent`, only one correct:
- **hash it → WRONG** — breaks the binding (the token could never match its own workflow);
- **add `..` to skip it → WRONG** — defeats the tripwire, lets the next field slip in unhashed;
- **name it, exclude it from the hash, and document why → correct.**

The tripwire exists precisely to force that third option to be an explicit reviewed
decision rather than a silent omission — that is what makes this entry *appliable*
to the next field-add, not merely descriptive of past ones.

**Instances (grounded):**
- **ORCH-R1-05 round-2** (`b601ef3`) — `Workflow::fingerprint` omitted `step.confidence`; a mutated-confidence workflow could ride a stale consent token (under-coverage).
- **ORCH-R2-02** (`b5f8ef4`) — delimiter-joined fingerprint collided: `("a\0b","c") ≡ ("a","b\0c")` (non-injective).
- **fortress audit pre-fix** (`3035681`) — `hash_entry` omitted `result` + `permission_tier` (a `Denied`/`Biometric` record editable to `Allowed`/`Autonomous`) AND was delimiter-ambiguous; fixed with full coverage + length-prefixing (the same two halves).
- **F5** (3A.5) — *sibling*: the source uniqueness key `(uri, content_hash)` was non-injective across formats; extended to `(uri, content_hash, format)`. (Fixed by widening the key, not by `canonical_hash`; cited as the same class.)

**RED-proof shape.** (a) a golden pinned from the pre-fix encoding, reproduced
byte-identically after migration; (b) a boundary-collision inequality
(`("ab","c") ≠ ("a","bc")`); (c) the per-site **no-`..` exhaustive destructure**
test — adding a struct field fails compilation until someone decides whether it
must be hashed. Reference: `audit_entry_hash_is_exhaustive_and_byte_identical_canonical_hash`,
`fingerprint_is_exhaustive_and_byte_identical_canonical_hash`.

---

## 2. Path-resolution races (symlink / TOCTOU / intermediate-component)

**Description.** Validating a path string and then opening it is racy: a symlink
can be swapped between check and open (TOCTOU), an intermediate component can be a
symlink that escapes the root, or the root directory itself can be replaced.

**Foreclosing primitive.** [`delphi_hardening::safe_open`] — `open_beneath` uses
`openat2(RESOLVE_NO_SYMLINKS | RESOLVE_BENEATH)` anchored to a **held directory
fd** (the trust anchor), with `/proc/self/fd` re-validation; non-Linux returns
`Unsupported` with a caller-supplied message.

**Instances (grounded):**
- **F8** — final-component TOCTOU between canonicalization and open; first patched with `O_NOFOLLOW`.
- **F11** — intermediate-component TOCTOU still open after F8; replaced with full-path `openat2(RESOLVE_NO_SYMLINKS|RESOLVE_BENEATH)`.
- **F15** — `trusted_root: PathBuf` vulnerable to root-replacement TOCTOU; replaced with a held directory **handle** anchored to the inode (a proto-capability — see class 5).

**RED-proof shape.** Construct the attack on a tempdir (leaf symlink, intermediate
symlink, `..` escape, target-outside-root, path-swap-after-open) and assert the
open is refused; on non-Linux, pin the verbatim `Unsupported` message on **every**
platform (not cfg-gated — see class 11). Reference: `safe_open::tests::*`,
knowledge's `safe_open_under_root_handle_rejects_*` suite.

---

## 3. Per-connection state assumptions (PRAGMA) / transient-lock classification

**Description.** SQLite PRAGMAs are per-*connection*, not per-*database*; relying
on a default (`busy_timeout`) or setting a pragma only on fresh-DB setup
(`foreign_keys`) leaves connections mis-configured. Separately, a `SQLITE_BUSY`/
`SQLITE_LOCKED` is *retryable* contention, not a logic error — conflating them
forces daemons to string-match error messages.

**Foreclosing primitive.** [`delphi_hardening::pragma_setup`] — `init_connection`
(the `busy_timeout` pin + the single seam for per-connection policy) +
`is_transient_lock` (the base-`ErrorCode` classifier that also catches extended
codes) + `SQLITE_BUSY_TIMEOUT`. Per STOP POINT A it is a **predicate**; each crate
keeps its thin error-construction wrapper (so the foundation crate never depends on
a crate's error enum).

**Instances (grounded):**
- **F10** — `PRAGMA foreign_keys = ON` set only on fresh-DB DDL; moved to run on every connection open with verification.
- **F19** — concurrent openers raced; `busy_timeout` + `BEGIN IMMEDIATE` serialization.
- **F21** — all SQLite errors classified as `Planning`; added typed `TransientLock` via `map_sqlite_err` for `DatabaseBusy`/`DatabaseLocked` (base + extended).
- **F22** — routing existed only in `knowledge.rs`; extracted to the shared `die_orchestrator::sqlite` helpers and migrated all four stores (also class 10).

**RED-proof shape.** Assert `busy_timeout` reads 5000 on every store (incl.
`:memory:` constructor-parity — F23); assert an **extended** code classifies the
same as its base (`SQLITE_BUSY_SNAPSHOT` ≡ `SQLITE_BUSY`) — the proof that matching
the base catches the masked extended forms. Reference:
`pragma_setup::tests::extended_busy_snapshot_classifies_same_as_base_busy`,
each store's `busy_timeout_pinned_to_5_seconds`.

---

## 4. Hand-enumeration vs authoritative-category  *(new — from the fortress sweep)*

**Description.** A hand-listed set of characters/codes/cases is *structurally
incomplete* — the list is finite, the domain isn't, and the next input outside the
list slips through. The fix is never "add the missing entries" (whack-a-mole); it
is to replace the enumeration with the **authoritative definition** (a Unicode
property/category, an RFC grammar). The proof is a *never-enumerated* member: if it
is handled, the category — not a longer list — is doing the work.

**Foreclosing primitive.** Discipline (no extracted module): use the authoritative
source. For digits, Unicode `General_Category = Decimal_Number` (Nd).

**Instances (grounded):**
- **FORT-R1-01 class** (`70ae808`) — ZKQP digit scanners matched ASCII only; full-width digits (U+FF10–19) slipped through. Hand-adding full-width was the first patch.
- **FORT-R2-01** (`84bb641`) — after full-width, Arabic-Indic slipped through; the lesson landed — replaced enumeration with `GeneralCategory::DecimalNumber` (Nd). Thai (U+0E50…), a script **never enumerated anywhere in the file**, is the proof row.

**RED-proof shape.** A completeness table covering the authoritative category with
a **never-enumerated** member (the Thai row) that must be handled with zero
script-specific code. Reference: `zkqp_detection_completeness_table_fort_r1_01`.

---

## 5. Capability-type pattern: invariants enforced by convention → unforgeable type  *(new — consolidated)*

**Description.** When an invariant ("this value was sanitized", "this path cleared
the allowlist", "this key is a secret", "this consent matches this workflow") is
enforced by *convention* — a comment, a code-review habit, a "callers must…" doc —
it erodes: a future caller forgets. Enforce it with an **unforgeable type** whose
only constructor establishes the invariant, so possession of the type *is* the
proof. (Includes the secret-in-a-rendering-trait corollary: a secret reachable via
`Debug`/`Display`/`Serialize`/`Deref` is leakable; redact on the type.)

**Foreclosing primitive.** The capability-type idiom (per-instance, not a shared
module).

**Instances (grounded):**
- **INF-1** (`382b4a3`) — `CloudClient` derived `Debug` over a raw `api_key: String`; wrapped in a module-private `ApiKey` newtype with redacting `Debug`/`Display` + a single `expose()` accessor.
- **ORCH-R1-05** (`9a844de`) — `ConsentToken`: private field, sole `issue(&Workflow)` ctor, `#[serde(skip)]`, bound to the workflow fingerprint, re-verified at the execution door.
- **SVC-1** — `SanitizedPrompt`: mintable only from a ZKQP sanitize; the sole constructor of the cloud-egress capability.
- **SVC-1-R1-1 / -02** — `ConfirmationToken` (HMAC-bound) + `ConfirmationTokenWire` (redacted `Debug`, no `Display`/`Deref`).
- **F15** — the held directory **handle** as the safe-open trust anchor (a proto-capability for the root-flags invariant).
- **B2a C1** — `VtName` (`runtime/src/launcher.rs`): a `ttyN` validated by its sole constructor. The invariant is **well-formedness, not secrecy** — the variant of this class where the raw value is not a secret but a string whose malformed form fails SILENTLY downstream (`pam_open_session` SUCCEEDS and registers a `Class=background`, seatless session that the seated gate then denies forever). Proven by three `compile_fail` doctests (external bypasses) + a scoped source audit (module-internal sites) — see class 15 for why both.

**PENDING (teeth):** **`TrustedRoot` for `ValidatedIngestionPath`.** The
root-handle flags-invariant (`O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC`) is currently
enforced by **convention** in the ingestion controller, not by the type. A
`TrustedRoot` newtype whose only constructor sets those flags would make it
unforgeable (same idiom). Deferred from the leverage pass because it is a
type-shape change to the Codex-hardened SVC-8 `ValidatedIngestionPath` + its ~10
path-safety tests — **its own change + own Codex round**, not a bundled refactor of
reviewed code. Reference impl to adapt: `delphi_hardening::safe_open` +
`knowledge::IngestionAccessController`.

**RED-proof shape.** Prove the invariant cannot be bypassed: no public constructor
/ accessor reaches the raw value except the named one (grep the accessor — exactly
the sanctioned sites); `{:?}`/`{}` of the type (and of any type that holds it) does
not contain the secret, RED-proven against a leaking impl. Reference:
`cloud_client_debug_does_not_leak_api_key_inf_1`, `api_key_type_redacts_in_debug_and_display_inf_1`.

---

## 6. Correct-fixes-incorrect-composition  *(new — from the fortress sweep)*

**Description.** Two fixes are each correct in isolation, but the bug lives in how
they **compose**: one fix changes an invariant the other relied on. Reviewing each
fix alone passes; the seam between them is where the regression hides.

**Foreclosing primitive.** Discipline: **review how fixes compose, not each
alone** — when two changes touch a shared data path, test the interaction.

**Instances (grounded):**
- **FORT-R3-01** (`d5a437e`) — R2-03's span-merge absorbed an embedded match (email inside a URL), minting only the outer placeholder; but R1-02's `restore()` still iterated the *full* detection mapping, which retained the absorbed match's entry → a cloud response echoing a never-minted placeholder was rewritten to raw PII. Each round-2 fix was correct; the bug was the R2-02/R2-03 composition seam (R2-03 broke the `mapping == minted-set` equality R1-02's restore relied on). Fixed by `replace_spans` returning the minted submap; restore-set == minted-set by construction.

**RED-proof shape.** Construct the composed scenario (the overlap that triggers the
seam) and assert the bad outcome cannot occur. Reference:
`restore_only_acts_on_minted_placeholders_under_overlap_fort_r3_01`.

---

## 7. Cross-crate regression caught by the workspace gate  *(new — the `#[from]` lesson)*

**Description.** A change to a *shared type's* contract (e.g. an error type's
`Display`) can leave a **downstream consumer's tests asserting the old behavior**.
The crate-scoped test run is green (the changed crate's own tests pass); the
regression hides until a consumer that `#[from]`-converts or re-renders the type is
compiled and tested. The **whole-workspace audit is the gate**; crate-scoped green
is not sufficient.

**Foreclosing primitive.** Process: run `cargo test --workspace` (not per-crate)
before declaring a shared-type change done; in CI, fail on an unexpected
executed-test-count drop (see class 10).

**Instances (grounded):**
- **FORT-R1-04 downstream** (`e7fdbb0`) — redacting `FortressError`'s `Display` was correct, but `die-inference`'s `InferenceError` doctest + unit test and `die-orchestrator`'s `all_downstream_errors_convert` asserted the credential name *survives* the `#[from]` conversion (the very leak R1-04 closed). The fortress-only per-crate audits never compiled those consumers; the full-workspace pre-merge run caught it.
- **POSITIVE instance — leverage pass P2 (this branch):** the full-workspace gate ran clean (`cargo test --workspace` = 1882 passed, 0 failed) after the canonical_hash / safe_open / pragma_setup migrations, confirming no downstream consumer's contract drifted. The gate working *is* the evidence the class is contained.

**RED-proof shape.** The downstream consumer's test is corrected to assert the new
contract (and would fail against the old behavior); the workspace run is the gate.

---

## 8. Same post-condition reached by multiple paths

**Description.** A correctness/security post-condition (a size cap, a uniform
rejection, a typed error routing, an FK-check-inside-the-txn) is enforced on *one*
path but the same post-condition is producible by *other* paths that drift. The fix
is to find **every** path that reaches the post-condition, not just the reported
one — ideally route them through a single shared choke-point.

**Foreclosing primitive.** Discipline: enumerate all paths to the post-condition;
prefer one shared guard over per-site copies.

**Instances (grounded):**
- **F14 → F17** — the atomic FK-check-inside-the-txn was fixed for the migration path (F14), then the *backfill* path was found to have the same race window (F17).
- **F22** — typed transient-lock routing existed in `knowledge.rs` only; the three sibling stores produced untyped errors → extracted to one shared helper.
- **F25** — F22's regex sweep converted `map_err(|e| Planning(format!(…: {e})))` forms but missed the `map_err(|_| Planning("…not found"))` block form that *discards* the error; two `query_row` sites silently swallowed `SQLITE_BUSY` as "not found". (`F25 pattern`: the regression test codifies the missed path.)
- **ORCH cap-centralization** (`5e9b192`) — ingestion byte-caps were enforced at 3 per-entry call sites; centralized to one `enforce_ingest_byte_cap` choke-point.

**RED-proof shape.** A test per *previously-uncovered* path asserting the
post-condition now holds there (RED against the pre-fix path). The discipline:
audit every site, not just the flagged one.

---

## 9. Normalize-then-detect offset drift (broaden-in-place)

**Description.** When scanning text for matches, normalizing the input first
(lower-casing, width-folding) and detecting on the normalized copy emits match
values/offsets in *normalized* coordinates that no longer substring-match the
*original* — so a later `replace`/redact on the original misses. The invariant: a
detector's emitted value must equal `original[start..end]`. Fix by **broadening in
place** — accept confusables/variants in the predicate over the ORIGINAL text,
never normalize-then-detect.

**Foreclosing primitive.** Discipline (the broaden-in-place doctrine), with the ZKQP
detector design as the reference.

**Instances (grounded):**
- **fortress `c86e075`** — `detect_credit_cards` scanned a copy, not the original text → offset drift; fixed to scan the original.
- **fortress `518e0e6`** — `detect_emails` advanced by a byte past a multibyte separator (a UTF-8 panic / offset bug); fixed to advance past the whole char.
- The `is_pii_separator` / `is_pii_digit` predicates accept Unicode confusables IN PLACE on the original rather than normalizing.

**RED-proof shape.** Assert the emitted `value` is a substring of the original at
the emitted offsets, and that `sanitize().replace` round-trips. Reference:
`full_width_card_value_is_a_substring_of_the_original_zkqp`.

---

## 10. Platform test-gating that masks bugs

**Description.** A test gated to one platform (`#[cfg(target_os = "linux")]`) does
not execute on another platform's CI — so a bug it would catch is masked, and a
silent drop in executed-test count goes unnoticed.

**Foreclosing primitive.** Discipline: gated tests must execute on the platform
they target (CI runs Linux → Linux-gated tests MUST run); pin platform-specific
*behavior* (e.g. a message) with a **non-gated** test where possible; guard against
executed-test-count drops (CI baseline-count artifact — P4).

**Instances (grounded):**
- **F18** — Linux-only ingest tests broke `cargo test` on Windows; added platform gates **plus meta-tests asserting the gates themselves stay correct**.
- **F16** — the non-Linux `Unsupported` compile-gate (the behavior the message-pin protects).
- **safe_open extraction (P2)** — the non-Linux `Unsupported` message is pinned by a **non-cfg-gated** test (`safe_open_unsupported_message_is_verbatim`) so it runs on Linux CI too.

**RED-proof shape.** A non-gated test that pins the platform-specific behavior, +
(P4) a CI executed-test-count guard.

---

**AND THE AUTOMATED GATE MEANT TO CATCH THIS WAS ITSELF BLIND TO IT (D0-R6).**
`.github/workflows/ci.yml` guarded against tests silently disappearing by summing
`test result: ok` **passes** against a floor. A skipped test scores as a pass, so **a test
that starts skipping keeps the floor satisfied forever** — precisely the disappearance the
guard exists to catch. The one mechanism that would have caught the 19-skipped problem
automatically was structurally incapable of seeing it.

**This is the fifth "absent, not passing" of the arc, and the first that was supposed to be
watching.** The other four were silent for want of a checker; this one had a checker, running
on every push, reporting green. It surfaced only from a grep for a *different* pattern, in a
file neither participant had thought to open.

The lesson is not "fix the CI line". It is that **a guard must be checked against the failure
it names**, exactly as a test must be RED-proven: this one had never been shown to fail when a
test disappeared, so it had never been shown to work. CI now calls `scripts/test-count.sh`,
which subtracts skips and refuses on an unparseable format.

**AND THE FIX LEFT THE BLINDNESS IN PLACE, ONE COMPONENT OVER (D0-R7-01) — the third form of
one bug in one file.** R6 fixed the **measurement** (executed, not reported) and left the
**threshold** untouched: a FLOOR whose own protocol read "count goes UP freely", recorded as
`1891`, a number predating the entire `runtime` crate. The actual sat scores of tests above it,
so the newly-correct measurement was compared against a number it could not fall below — and a
test that started skipping still passed. **Fixing the instrument does not fix the comparison
the instrument feeds.** When a guard is found blind, ask which of its *stages* was blind and
audit the others, because they were written under the same assumption.

Now equality on **both** counts, extracted to `scripts/ci-test-count-gate.sh` — inline shell
cannot be RED-proven except through a copy (Class 25), so the guard was moved into a file the
RED suite can execute. **SKIPPED is compared too**: a single total is satisfiable two ways, and
one test deleted while another stops skipping leaves EXECUTED unchanged. That is weaken (b) in
`scripts/ci-test-count-gate.test.sh`; weaken (a) restores the floor and shows it passing a
disappearance. **The recorded value is deliberately absent rather than guessed** — the old one
is known wrong and a workspace count is not obtainable off-CI, so the gate fails on the next
run and prints the pair to record. A number known to be wrong is worse than no number: it
answers the question the guard was built to ask.

**SURVIVORSHIP APPEARS INSIDE ITS OWN REMEDY (D0-R6-06).** The physical floor was added as a
*second, independent* signal precisely because the SKIP parse had already been wrong. Its first
implementation matched `finished in` **anywhere** in the output — so nested or quoted output
**inflates** the elapsed total, which **raises** ms-per-test and therefore **weakens** the
floor. The independent signal degraded under exactly the noise it existed to survive, and it
degraded in the reassuring direction: a weaker floor passes. Fixed by taking elapsed only from
`test result:` summary lines. **A guard that fails open under noise is not a guard**, and the
bias toward calm failures documented above does not spare the instruments built to answer it.

**THE SHELL MANGLING ITS OWN EVIDENCE — third instance, same class (D0).** Output plumbing
has now corrupted this project's evidence three times, each time making a result mean
something other than what it said:

1. `cargo clippy … | tee log` reported `tee`'s exit `0` and masked a real `-D warnings`
   failure (the SVC-2 sweep; already in §13.4's exit-code note).
2. `cargo test … | grep "test result:" | awk` summed *passes* and was structurally blind to a
   target that failed to build — how the shell-host `E0004` survived.
3. `cargo test … 2>&1 > log` — the redirect order is backwards. `2>&1` points stderr at the
   *current* stdout (the terminal) and only then does `> log` move stdout, so stderr escapes
   the file. `compile_fail` doc-tests then printed `E0614`/`E0599`/`E0423` to the terminal and
   looked like three real compile errors in a suite that had in fact passed. Caught before it
   was reported, by re-running with `&>`; use `&>` or `> log 2>&1`, never `2>&1 > log`.

The common shape: **the instrument reported on itself rather than on the subject**, and in
every case the wrong answer was the *reassuring* one — a masked failure, an invisible failure,
and a fabricated failure.

**That bias is what makes this a class rather than three anecdotes, and it is not
coincidence.** A plumbing fault that produces *alarming* output gets investigated within
minutes, because something visibly broke; a plumbing fault that produces *calm* output is
never investigated at all, because nothing asks to be. The failures therefore survive
selectively — the reassuring ones accumulate and the alarming ones are gone by lunchtime. Any
sample of surviving plumbing faults will look biased toward false confidence, and the
inference to draw is not "we were unlucky" but **"this is what the survivors look like; assume
the calm ones are still there."** Prefer `&> file` plus an explicit `$?`, and never let a pipeline's
last stage speak for the command.

**A SKIPPED TEST REPORTS AS `ok`, SO THE COUNT OVERSTATES EXECUTED COVERAGE (D0).** The
project's gated tests return early after an `eprintln!("SKIP …")`, and libtest scores an early
return as a pass. `cargo test` therefore prints `test result: ok. 121 passed` when **19 of
those skipped**, and the reason is invisible without `--nocapture` (stderr is captured for
passing tests). Measured on the dev box: `delphi-runtime` 121 reported / **19 skipped** / ~102
executed; `runtime/shell-host` 19 reported / **7 skipped** (the whole `real_webkit_load`
suite).

This is how "compiles clean, 19 tests" was reported for a suite that had never run. **Any test
count quoted as evidence must state executed-vs-skipped**, obtained with `--nocapture`, or it
is not a coverage claim — it is a count of functions that returned.

---

## 11. Error-message oracles at validation boundaries

**Description.** Varying a rejection message by *why* validation failed leaks
information (existence, internal structure, a path, a credential name) across the
boundary. Collapse every rejection to a single uniform message; send detail only to
local `tracing` (never to the caller).

**Foreclosing primitive.** Discipline + the `services::error::opaque` helper.
**(Deferred extraction — see below.)**

**Instances (grounded):**
- **F7** — path-validation messages distinguished "does not exist" vs "exists but outside allowlist"; collapsed to one uniform message + `tracing::warn!`.
- **SVC-4** — single sanctioned domain-error→bus sanitizer `opaque(context, err)` crate-wide.
- **ORCH-R1-07** — public-boundary errors leaked caller ids / filesystem paths into `Display`; typed variants with ids/paths to `tracing` only.
- **FORT-R1-04** (`e6e447b`) — `FortressError` `Display`/`Debug` leaked credential name / path; redacted + a `diagnostic()` channel for local use.

**PENDING (teeth):** **`uniform_reject` is NOT extracted.** The pattern is realized
by `services::error::opaque` (`opaque<E: Display>(context, err) -> zbus::fdo::Error`),
24 callers, **one crate**. NOT extracted for **two** independently-sufficient
reasons: (1) single-consumer (rule-of-three not met); (2) **dependency direction** —
it returns `zbus::fdo::Error`, and a foundation crate below `fortress` must not pull
a transport (`zbus`) downward. Stays in `services`. Extract only if a
**transport-agnostic** second instance appears.

**RED-proof shape.** Assert the rejection contains only the fixed context and not
the discriminating detail (path/existence/credential name), across the failing
variants. Reference: `opaque_drops_path_bearing_domain_detail`,
`display_and_debug_redact_caller_identifiers_fort_r1_04`.

---

## 12. Reject the invalid CLASS, not the value

**Description.** Validating against specific bad values (NaN, a known-bad string)
leaves siblings of the same class unhandled (`+inf`, `> 1.0`). A fail-open gate that
admits an un-enumerated invalid value is a security hole. Gate the **whole invalid
class** (e.g. `is_finite() && (min..=max).contains(&x)`), fail-closed.

**Foreclosing primitive.** Discipline.

**Instances (grounded):**
- **ORCH-R1-05 round-2** (`3b2de18`) — the confidence gate admitted `NaN`/`+inf` (both `< min` comparisons false → auto-execute without confirmation); made fail-closed.
- **ORCH-R2-01** (`79097d9`) — the fail-closed gate still admitted `+inf` / `> 1.0`; gated the whole invalid class: `confidence.is_finite() && (min_confidence..=1.0).contains(&confidence)`.

**RED-proof shape.** Test every member of the invalid class (`NaN`, `+inf`,
`-inf`, `> max`, `< min`) is rejected — RED against the value-enumerating gate.
Reference: `gate_rejects_non_finite_and_out_of_range_confidence_orch_r2_01`.

---

## 13. Atomic versioned migration  *(DEFERRED extraction — pattern recorded)*

**Description.** A schema migration that writes the new version row in a *separate*
transaction from its integrity check, or that races with concurrent openers,
leaves a window where the DB reports version=N without N's invariants. The pattern:
a `schema_version` table + `BEGIN IMMEDIATE` (take the write lock before any read) +
**re-read the version under that lock** (double-checked locking) + `PRAGMA
foreign_key_check` *inside* the txn + version-write — all-or-nothing.

**Foreclosing primitive.** **NONE YET — deferred.** Canonical instance:
`knowledge.rs::{backfill_version_with_integrity_check, migrate_epoch_1_to_2}`,
hardened by F14/F17/F19. **PENDING:** extract `run_migration(conn, version_table,
target, apply)` into `delphi-hardening` **when a 2nd versioned-migration store
appears** (rule of three) — and as **its own reviewed change + Codex round**, since
it touches F14/F17/F19-hardened correctness code, not a bundled refactor. Today
there is exactly one versioned store (knowledge); `timeline`/`goals`/`conversation`
do plain table setup.

**Instances (grounded):** **F9** (implicit→explicit `schema_version`), **F14**
(atomic FK-check + version-write in one txn), **F17** (backfill path same race),
**F19** (concurrent-opener serialization via `BEGIN IMMEDIATE` + under-lock
re-read).

**RED-proof shape.** A deliberately-corrupt fixture (`make_corrupt_epoch_1_db`)
proving an interrupted/invalid migration never yields a version row without its
invariants; concurrent-opener tests proving serialization.

---

## 14. Guard must cover all forms of what it guards  *(new — leverage pass P4/P5)*

**Description.** A guard, ignore-pattern, or detector that covers *some* forms of
what it targets but not all passes silently on the uncovered form — and a guard that
cannot fire against its target is decorative (worse than none: false confidence). The
reliable check is to read what a thing DOES, not to pattern-match the markers it
carries. Sibling instances of "covered one form, missed another" already in this
corpus: the count-guard's silent-extraction mode (Class 7/10 — a `tee`/`grep` chain
masking a real `cargo` exit), and `is_transient_lock` matching the base `ErrorCode`
so it also covers the extended busy/locked codes (Class 3).

**Foreclosing primitive.** **NONE — discipline.** When writing a guard, enumerate the
forms its target takes and confirm coverage of each; when classifying code, read the
behavior, not the markers.

**Instances (grounded):**
- **gitignore dir-form vs file-form (P4):** `**/proptest-regressions/` matched the
  *directory* a unit test's proptest writes, but NOT the integration-test
  `<name>.proptest-regressions` *file* — residue slipped into a commit, was caught on
  the post-commit status, amended out, and the pattern broadened to
  `*.proptest-regressions`.
- **stub-grep vs error-returning shell (P5):** a `grep STUB|todo!()|unimplemented!`
  hollow-implementation check classified `die/orchestrator/src/planner.rs` "built"
  because `plan()` returns a plain `Err("inference backends not yet available")` with
  no marker. Reading what `plan()` DOES (logs, then unconditionally errors) overturned
  it — a doc-lie (interface shell), not a stub. Same category-not-marker lesson as the
  date-scope precision: assert what the detector DOES under a transform, not what the
  Unicode category suggests.

- **B2a C1 — the PAM-03 stack guard, both forms** (`runtime/src/launcher.rs`
  `open_own_session`). The first guard checked only that `/etc/pam.d/delphi-runtime`
  EXISTS. It covered "file absent" and missed "file present, `session` group EMPTY" — and
  the missed form is **worse**, because `pam_open_session` then returns SUCCESS while
  registering **no logind session at all**: a cleanly-succeeding call that yields nothing,
  surfacing far away as a shell the seated gate denies forever. (Structurally identical to
  the `VtName` seatless-string failure in class 5, one level up.) The fix deliberately did
  NOT grep the config for a `session` line — that would repeat the mistake, covering one
  form and missing `@include` / `session include` / `substack` / a module that loads and
  no-ops. Instead it asserts the **OUTCOME**: after a successful `open_session` the pid MUST
  resolve to a logind session (`logind::session_id_for_pid`). Read what the call DID, not
  the markers the config carries.
- **B2a C1 — `build.rs` artifact-kind enumeration.** `cargo:rustc-link-arg-{bins,tests}`
  covered two artifact kinds; **doctests are neither**, so the first doctest referencing an
  sd-login symbol failed to link (`undefined symbol: sd_pid_get_session`). Replaced with
  `cargo:rustc-link-lib`, which attaches to the CRATE — the authoritative-category form that
  every linking artifact inherits.

**RED-proof shape.** Demonstrate the guard FAILING against the uncovered form before
broadening it — both instances here actually fired in reality (the residue file
reached a commit; the stub-grep actually mis-classified). A guard not shown to miss
the form it missed is unproven.

---

## 15. Self-inspecting guard counts its own assertions  *(new — B2a C1)*

**Description.** A guard that inspects SOURCE TEXT — a grep, a `matches().count()`, a
`contains()` over the file it lives in or a tree that includes itself — has its own
assertion literals inside the scope it audits. Two directions, and the second is the class:

*Loud (benign).* The guard's first run reports an inflated count and fails. Self-announcing,
fixed immediately.

*Silent (the actual defect).* The guard passes initially. Later a contributor adds an
assertion, comment, or doc example containing the matched literal. The count rises, the test
fails, and the natural reading is "the guard is stale." The natural fix is to **bump the
expected value**. The constant now encodes *production sites + the guard's own text*, and a
genuinely-new production site is absorbed into that slack **silently, while the test stays
green**. The guard is disarmed by its own maintenance.

**Relationship to Class 14 (sibling, not duplicate).** Both end at "a guard that cannot fire
against its target is decorative — worse than none, because it is false confidence." They
differ in the disarming vector: Class 14's guard misses an **uncovered form of the target**;
this one is disarmed by **edits to the guard itself**. A Class-14 audit ("enumerate the
forms") would not catch it, because every form IS covered — the *scope* is what is wrong.

**Foreclosing primitive.** **NONE — discipline**, in two parts:

1. **Prefer a mechanism with no self-inspection where one covers the shape.** A
   `compile_fail` doctest (rustdoc built-in — **no `trybuild` dependency needed**) proves a
   bypass *cannot be written* from outside the module: compiler-enforced, no count constant,
   nothing to disarm.
2. **Where source inspection is unavoidable, scope it to the region under audit**, excluding
   the assertion's own text, and derive the boundary so it **fails loudly if it stops
   working** (`split_once(MARKER).expect(..)`, not an offset or an optimistic filter). State
   in a comment what each unit of the count corresponds to, and name the re-derivation
   command, so "bump it" requires re-deriving.

**The two mechanisms are COMPLEMENTARY, not ordered** — this is the part worth internalising.
`compile_fail` is **enumerative**: it catches the shapes you can NAME, from OUTSIDE the
module. Source inspection is **exhaustive over the module**: it catches ANY new construction
site or raw-field reader added INSIDE it, whose name is unknowable in advance and where the
private field is legitimately accessible. Neither subsumes the other; use each for what it
alone reaches.

**Instances (grounded):**
- **B2a C1 — the `VtName` class-5 audit** (`runtime/src/launcher.rs`, test
  `vtname_internal_construction_and_reads_stay_at_the_sanctioned_sites`; cited by stable
  identifier rather than commit hash, deliberately — the hash is not knowable when the entry
  lands and a stale one rots). The audit greps its own module via `include_str!` for
  construction sites (`Self(`) and raw-field readers (`self.0`). First run reported **4
  constructors instead of 1** — the three extra were the test's own assertion literals.
  Production counts were independently re-derived as 1 and 2 (`awk` split at `#[cfg(test)]`,
  then `grep -c`), so the shipped invariant was never violated; the guard was measuring
  itself. Fixed by scoping to the pre-`#[cfg(test)]` half. Caught on the FIRST run — the loud
  direction. Filed here because the silent direction was one "just bump it to 4" away.
- **The same change's remedy split, as the worked example:** three `compile_fail` doctests
  took over the pub-field / `Deref` / `into_inner` erosions (each RED-proven — introducing
  the erosion makes the snippet compile and the doctest FAIL), leaving the grep only the two
  module-internal properties it alone can reach.
- **B2a C1, SECOND INSTANCE — a reporting regex matching its author's own prose**
  (`scratch/iterate-flakiness.sh`). The flakiness runner summarised skips with
  `grep -oh "SKIP [a-z0-9_]*"`. The test files' skip MESSAGES contain the sentence *"A SKIP
  INVALIDATES A WEAKEN/RESTORE RUN"* — written by the same author, in the same change. The
  uppercase `I` fell outside `[a-z0-9_]`, so the pattern matched zero characters and emitted
  a bare `SKIP ` with no test name: a **skip with no reason**, which is precisely the
  unreadable output the marker discipline exists to prevent. Fixed by requiring a real test
  name (`SKIP \K[a-z0-9_]+(?=:)`).
  **Why this instance matters more than its size:** it shows the class is NOT limited to
  `include_str!` source audits. It generalises to **any grep over text the author also
  wrote** — reporting layers, CI log scrapers, doc-lint scripts. The audited corpus need not
  be source code; it need only overlap with the matcher's own vocabulary. And it appeared in
  the REPORTING LAYER OF THE TOOL BUILT TO MEASURE THIS CLASS, which is the sharpest
  available demonstration that noticing the class does not immunise you against it.

- **THREE self-corrupting-measurement defects in ONE tool** (`scratch/iterate-flakiness.sh`,
  the flakiness runner). Grouped because the pattern is the point: (1) the marker **counting
  bug** — `grep -c` over a string appearing in both the `println` and the panic, so failures
  counted double (34 markers over 30 iterations); (2) this entry's **blank-SKIP regex**
  matching the author's own prose; (3) **`--nocapture` interleaving** under parallel execution
  splitting `test NAME ... FAILED` lines so the per-line grep misses them, potentially
  *manufacturing* apparent non-executions from real failures. Each is a check whose own
  plumbing decided its verdict; each was caught only by an EXTERNAL cross-check (an impossible
  total, a bare token, an arithmetic that did not close). **The tool exists to measure exactly
  this class and exhibited three instances of it** — the strongest statement available that a
  class is not neutralised by awareness, only by an independent check outside the measured
  artifact. Generalisation for any measurement harness: its output is a *claim*, owed the same
  adversarial scrutiny as the product it measures (Iron Law #15 clause 5 — a harness *number*
  is evidence only when shown to mean what it says).
- **Sibling shape (different mechanism, same lesson — a check whose own plumbing decides its
  verdict):** the `tee`/`grep` exit-code mask, **CLAUDE.md §13.4** — `cmd | tee log` reports
  `tee`'s status, masking a failed `cmd`. (Classes 7 and 10 are related but distinct: they
  prescribe the CI **executed-test-count** guard, not the pipe-masking defect.)

**RED-proof shape.** Two parts, both required:
1. **The guard bites.** It must FAIL against each bypass shape it claims to catch, RED-proven
   against a deliberately-broken implementation.
2. **The scoping is necessary and the constant is grounded.** Show the unscoped guard reports
   a violation that does not exist in production, AND derive the production count by an
   INDEPENDENT means (a shell `grep -c` over the scoped region) that agrees with the
   constant. A count-based guard whose constant was never independently derived is unproven.

Disjoint-defect evidence from the C1 instance — the class-5 argument as measurement rather
than assertion. The two rows that pass behaviourally are the reason structural audits exist:

| Injected defect | Behavioural tests | Structural audit |
|---|---|---|
| `new` weakened to "any non-empty string" | **3 FAIL** | passes |
| field made `pub String` | pass | **FAIL** |
| `impl Deref for VtName` added | pass | **FAIL** |

---

## 16. Test fixture mutates shared system state it does not own  *(new — B2a C1)*

**Description.** A fixture that writes a **shared, real system path** and removes it on
teardown is safe only while that path is *exclusively* test scaffolding. The moment
production installs the same path, the fixture becomes **destructive**: it clobbers the real
artifact and DELETES it on drop. The damage is not local — it lands on every later test in
the run, and on the developer's machine after the run ends. Worse, the symptom appears
somewhere else entirely: later tests report "not installed" / "misconfigured" and are read
as *their own* failures, so the diagnosis starts in the wrong place.

The rule, stated so it needs no judgement call: **a test must never delete a system file it
did not create.** Ownership must be tracked explicitly, not inferred from "the test wrote
this path, so presumably it owns it".

**Foreclosing primitive.** **NONE — discipline.** Adopt-or-provision: if the path already
exists, ADOPT it (use it, record that you did not create it); only if absent, PROVISION it
and record that you did. Teardown removes **only** what teardown's own fixture created. Where
a test genuinely needs a hostile variant of a shared file, it should use a THROWAWAY name it
certainly owns (as `scratch/pam-empty-group-probe.sh` does with `delphi-probe-emptygroup`),
never the production path.

**Instances (grounded):**
- **B2a C1** — `runtime/tests/b1_integration.rs` and `runtime/tests/end_to_end.rs` wrote and
  `remove_file`d `/etc/pam.d/delphi-runtime`. Harmless while that file was pure scaffolding.
  Once C2's real stack was installed there, the first suite to run DELETED the operator's
  production file mid-run; `leader_is_shell` then SKIPPED on "not installed", and that skip
  was very nearly read as a B-1 result. It was not — a skip passes under both topologies.
  Fixed with a `provisioned: bool` on the fixture gating removal.
- **Adjacent, same family:** the probe script for the empty-`session`-group measurement
  deliberately used a throwaway service name so it could not damage the very stack it was
  characterising — the correct shape, arrived at before this defect was found.
- **B2a lane close-out — the FOURTH deleter, on a DIFFERENT path (`systemd_smoke.rs`).** After
  the three PAM copies were fixed, `systemd_smoke.rs` was found unconditionally `remove_file`-ing
  `/usr/libexec/delphi-runtimed` — the operator's installed *daemon binary* — in its `Drop`
  teardown, having `std::fs::copy`'d over it with no existence check. It deleted the installed
  daemon binary mid-session; the surviving-unit asymmetry pinpointed it (the test installs its
  unit to `/etc/systemd/system/` while `install.sh` ships to `/usr/lib/systemd/system/`, so the
  operator's unit survived while the shared binary path died). Fixed with **backup-and-restore**
  (rename the operator's binary aside, install the fresh build, restore on teardown) rather than
  adopt-or-provision, because a smoke test must run against the *fresh* build, not adopt a
  possibly-stale installed one. **This is why Class 17 exists** (see below): the original
  `fixture_hygiene.rs` guard watched only the PAM path, so it was blind to the identical shape on
  the binary path.

**RED-proof shape.** Two parts: (1) with the production artifact present, run the suite and
show the artifact SURVIVES (pre-fix it is deleted); (2) with it absent, show the fixture
still provisions and cleans up its own copy, so the fix does not silently disable teardown.
A test asserting only (2) would pass against the destructive version.

**Cross-cutting note.** This is the second defect this session where a HARNESS damaged or
misreported the thing it measured — the other being a runner that reported an unavailable
`sudo` as N *test failures*. Harness defects present as product defects and cost the most
diagnostic time; treat the test infrastructure as production code for review purposes.

---

## 17. Defect propagated by copy — fix the PATTERN, not the instance  *(new — B2a)*

**Description.** A defect that exists as a **repeated shape** across sibling files/functions
is not fixed by patching the instances you happened to look at — the copies you did not open
still carry the original shape. The fix feels done (the instances you saw are green) while the
defect is still shipping in a sibling. This is distinct from Class 14 (a *guard* that misses a
*form* of its target): here it is a *fix* that misses a *copy* of the defect.

**The reliable check:** before declaring a copy-shaped defect fixed, **`grep` for the shape**
and confirm every match is handled — do not fix by memory of where you have seen it. Where the
shape is enumerable, the *right* remedy is a **guard that finds ALL instances** (so a future
copy is caught mechanically), not a hand-patch of the ones in view. `runtime/tests/fixture_
hygiene.rs` is the exemplar: it greps the whole `tests/` dir for the write-and-delete shape and
fails naming any file that carries it — which is exactly how the third copy was caught.

**Foreclosing primitive.** **NONE — discipline + (where enumerable) a finder-guard.** When you
fix instance N of a repeated shape: (1) `grep` the pattern across the tree; (2) fix every hit,
not just the reported one; (3) where feasible, add a guard that *enumerates* the shape so the
next copy fails loudly rather than shipping green (Class 15's `fixture_hygiene` is the model).

**Instances (grounded, both B2a this session):**
- **The THIRD PAM deleter** — after `b1_integration.rs` and `end_to_end.rs` were fixed to
  adopt-or-provision `/etc/pam.d/delphi-runtime`, `pam_interposition.rs` still carried the
  write-and-delete shape and kept deleting the operator's installed stack. Caught only when
  `fixture_hygiene.rs` (a finder-guard) was written and **RED-fired naming
  `pam_interposition.rs`** — i.e. the guard, not the hand-fix, found the third copy. (Class 16.)
- **The `FAILCOUNT`-unbound bug copied into a sibling script** — `scratch/iterate-flakiness.sh`
  had the `${#FAILCOUNT[@]}`-under-`set -u` bug fixed (plain `TOTAL_FAIL` counter);
  `scratch/iterate-b1.sh` was then written by copying the pattern **without** the fix, and
  crashed on its first empty-`FAILCOUNT` (clean) run. Fixed — but it should have been caught by
  grepping `FAILCOUNT` across `scratch/` when the first fix landed.
- **The finder-guard ITSELF was scoped to one instance-path (B2a lane close-out).** The sharpest
  instance of this class: `fixture_hygiene.rs`, the Class-16 finder-guard, hard-coded a *single*
  `SHARED_SYSTEM_PATH = /etc/pam.d/delphi-runtime`. So when the write-and-delete shape reappeared
  on `/usr/libexec/delphi-runtimed` (`systemd_smoke.rs`, see Class 16), the guard could not see it
  — a finder that finds only the *path* it was born on is the Class-14 "covers-one-form" mistake
  reproduced in the very mechanism meant to foreclose it. Fixed by generalizing the guard to a
  **list** of operator-owned paths (`SHARED_SYSTEM_PATHS`), matching `remove_file` of a shared
  const *or* literal, with the discipline note "extend this list the moment a fixture writes a NEW
  installer-owned path." RED-proven: the generalized guard fires naming `systemd_smoke.rs` against
  the pre-fix code, and passes after — with zero false positives on `leader_is_shell.rs`, which
  references the PAM path but never `remove_file`s it (it removes only test-owned `/run` dirs).

- **AppArmor userns gate — the SAME gate, a DIFFERENT door (B2a composition, 2026-07-25).** Two
  expensive instances on one box, months apart, both rooted in
  `kernel.apparmor_restrict_unprivileged_userns=1`:
  1. **Earlier in the arc:** a test failed with `bwrap: execvp permission denied`. Two diagnoses
     were wrong; `dmesg | grep apparmor` gave ground truth (`profile="bwrap" ... DENIED`). Fixed by
     disabling the `bwrap-userns-restrict` profile — i.e. **bwrap confined by its OWN profile**.
  2. **This session:** the WRY shell host aborts because *glycin*'s bwrap-sandboxed image loader
     cannot create a userns — the **CALLER has no profile at all**, and an unprofiled process is
     denied userns creation under the same sysctl.
  The first remedy could not cover the second: it addressed the door (`bwrap`'s own profile), not
  the gate (the sysctl's treatment of *every* userns creator). **The class lesson: when a fix
  targets one actor's confinement, enumerate the OTHER actors subject to the same control before
  declaring the class closed** — here, "what else on this box creates a userns, and what is ITS
  profile?" would have surfaced the caller-side case immediately. `dmesg | grep -i apparmor` (and
  `/proc/self/attr/current` + `unshare -r`) is the ground-truth probe for this class; reasoning
  about it has now failed twice.

**RED-proof shape.** The finder-guard must FIRE against an un-fixed copy before it is fixed —
`fixture_hygiene.rs` naming `pam_interposition.rs` (and later `systemd_smoke.rs`) is the
reference. A "fix" with no finder and no cross-tree grep is unproven: it is the count of
instances you *remembered*, not the count that *exist*. And a finder-guard must be scoped to the
**shape across all paths**, not the one path it was written for — else it becomes the next Class-17
instance itself.

---

**A GREP THAT FOUND INSTANCES IS NOT EVIDENCE IT FOUND ALL OF THEM (D0).** Four incomplete
enumerations in one arc, each corrected only by enumerating properly — never by re-running the
original grep:

| claimed | actual | how the gap closed |
|---|---|---|
| 2 PAM-deleting fixtures | 3 | reading every fixture, not grepping the one pattern |
| `real_webkit_load` temp dirs: 0 | 3 | reading the file while there for another reason |
| R4-04 at 1 site | 3 | checking the *other* callers of the same conversion |
| 15 hand-rolled temp paths | **28** | enumerating every file x every pattern variant |

The failure is not a bad regex; it is treating *"the grep returned results"* as *"the grep
returned the set"*. A pattern is written from the instances already in mind, so it finds those
and is silent about the variants nobody thought of — and that silence is indistinguishable
from absence.

**Enumerate by construction before claiming a set:** every file in scope x every spelling of
the pattern (`/tmp/x`, `env::temp_dir()`, `PathBuf::from(format!(…))`), then state the count
and the method. When a count is later corrected, **re-derive it — do not patch the old
number**: the 15 -> 28 correction came from a fresh enumeration, and a further pass then cut
the *actionable* set to 5, which no amount of re-running the first grep would have found.

## 18. The verification loop mutates the thing under test  *(new — B2a composition)*

**Description.** A verification procedure — a weaken/restore cycle, a bisect, a
before/after comparison — runs a command that **mutates the artifact it is
measuring**. The damage then surfaces as a **failing test**, so it is read as a
product defect and diagnosed as one. The actor cannot see it: from inside the loop
the red looks exactly like the red you were hunting.

This is the generalisation of two incidents that were first recorded separately as
VCS accidents. They are not about `git` — `git` is merely the sharpest available
instrument. The invariant they share:

> **A verification loop must not run commands that can mutate the thing under
> test.** Measurement is read-only; the only writes a verification loop may make
> are the deliberate, named perturbation (the weaken) and its exact inverse.

The two properties that make this class expensive are worth naming, because they
are why it costs more diagnostic time than the defects it hides:

1. **The damage is silent at the moment it happens** — a destructive command
   succeeds quietly; nothing reports "you just deleted the change you are testing".
2. **The damage is loud in the wrong place** — it re-emerges as a red, attributed
   to the product, one or more steps downstream of its cause.

**Foreclosing primitive.** **NONE — discipline, plus an external check.**
Before any operation that moves `HEAD`, discards changes, or rewrites files —
**inside a verification loop or not**; the 2026-07-30 instance was ordinary work, not a
weaken/restore — **`git status --porcelain` must be empty for the target, or the work
must be committed or stashed first.** See "The operational form" below for the
pre-condition version of this rule and why the post-hoc checks do not substitute for
it. Prefer perturbations that are *exactly invertible in
the editor* (edit → run → edit back) over any that route through `git` at all. When
a restore *does* go through `git`, **verify the restore by reading the diff, not by
observing the test go green** — a green after a botched restore and a green after a
correct one are indistinguishable.

**Instances (grounded):**
- **`git reset --hard HEAD~1` with a dirty tree (B2a C1, 2026-07-22)** — run to
  amend a non-`HEAD` commit; destroyed three fixture fixes, a new test file's
  contents, and a `PROGRESS.md` rewrite. Recovered **only** because those edits
  happened to have been made by scripted `python` patches that could be re-run.
  That is luck, not a property of the workflow. (See §6 "Git history surgery".)
- **`git checkout -- src/app.tsx` mid-weaken-loop (P2, 2026-07-25)** — run to undo a
  weaken, on a file whose P2 mount edit was still **uncommitted**. It reverted the
  file to `HEAD`, i.e. to the *pre-P2* state, discarding the change under test. The
  following "restore" run was red **because the mount was gone**, not because a test
  had broken — the loop reported a product failure it had itself caused. Caught by
  reading `git diff`, not by the test result.

- **A patch script that AssertionError'd partway, reported as done (B2a composition, 2026-07-25).**
  A Python patch was to make three edits to a test file. The first succeeded in memory; a
  later `assert old in s` failed, so the interpreter exited **before its trailing
  `open(p,"w").write(s)`** — writing **nothing**. The visible output still showed the earlier
  step's `print("patched")`, the suite still went green (the change was inert), and the commit
  message went on to assert "The stub is removed, not repaired." **It was not removed.** Caught
  only by grepping the **committed** file (`git show HEAD:… | grep -c`) rather than trusting the
  run. Same shape as the `git checkout` instance above: a **partially-failed tool operation
  reported as its intended state**, with the damage surfacing far from its cause — here as a
  false claim in the audit trail rather than as a red.
  **The rule both instances share: verify the ARTIFACT, not the operation's apparent success.**
  A tool printing progress, exiting 0, or leaving a green suite is not evidence that the
  intended change is in the file. Grep the file; diff the commit.

- **`Write` over an untracked `scratch/display-arc-scoping.md` (display-arc scoping, 2026-07-30)**
  — the file was already present and **untracked** (visible as `?? scratch/display-arc-scoping.md`
  in the session's opening `git status`, which had been *read*). A full-file write replaced it
  without the target ever being inspected. Nothing was recoverable: untracked means no git object,
  no reflog entry, no dangling blob. A search of other session transcripts returned nothing. The
  prior content is simply gone, and **what it contained is unknown** — which is the worst
  available outcome, because the loss cannot even be scoped.

### The operational form — the precondition all four instances share

The four instances above look like four different accidents (a `reset --hard`, a `checkout --`, a
half-applied patch script, a `Write`). They are one. **In every case the target was untracked or
dirty at the moment of the destructive operation, so there was no committed object to recover
from.** That single precondition is what turned each mistake from an inconvenience into a
permanent loss.

**This is why the detection rules above are not sufficient, and saying so is the point of this
subsection.** "Verify the artifact, not the operation" and "read the diff, don't watch the test go
green" are **detection** rules. They work when a committed baseline exists: you notice the damage
and you restore. Against an untracked target they do nothing useful — they convert a *silent*
unrecoverable loss into a *known* unrecoverable loss. **Detection is not recovery.** A rule that
fires after the write is the wrong instrument for a target that cannot be restored.

> **THE OPERATIVE RULE (pre-condition, not post-condition).** Before any operation that
> overwrites, discards, or moves `HEAD` across a target, establish the target's **tracked-ness**,
> and **refuse on untracked**. `git status --porcelain -- <target>`: empty ⇒ tracked and clean ⇒
> git can restore it ⇒ proceed. `??` (untracked) or a dirty marker (` M`, `AM`) ⇒ **stop**, and
> commit, stash, or copy the target aside first.

Three properties make this the right shape:

1. **It is a refusal, not a warning.** A warning is advice the actor is free to be wrong about,
   and every one of the four incidents was committed by an actor who believed the operation was
   safe. Belief is not the failing input here — the check is.
2. **The destructive verb does not have to be a `git` verb.** This is the generalisation the
   fourth instance forces. `Write`, `cp`, `>`, `mv`, `truncate`, an editor save, and a patch
   script's `open(p,"w")` are all the same operation as `git checkout --` when the target is
   untracked. Scoping the discipline to VCS commands (as the original wording of this class did)
   leaves the most common case — an ordinary file write — outside the rule.
3. **The cost asymmetry is absolute.** The check is one command with an empty-string comparison.
   The loss it prevents is unbounded, silent, and — as the 2026-07-30 instance shows — sometimes
   not even scopeable afterwards.

**Mechanizable form (preferred over discipline).** A pre-flight helper that takes the target path,
runs `git status --porcelain -- "$path"`, and exits non-zero on any non-empty output is a
five-line script and forecloses the class for every tool that can be made to call it. It fails
**closed**: an unparseable status, a path outside the repo, or a `git` that errors all yield a
refusal, never an approval. Until such a helper exists this remains **discipline plus an external
check** — and note that all four instances were caught by an external check (the operator, a diff,
a `git show | grep`, the operator again), **never** by the actor that caused them.

**RED-proof shape.** This class is a *process* defect, so its proof is procedural
rather than a test: after any restore step, the restored artifact must be shown
**byte-identical to its pre-weaken state** (`git diff --stat` empty for a committed
baseline, or an explicit content check for uncommitted work) *before* the restored
run's result is believed. A restore verified only by "the test is green again" is
unproven — that is precisely the observation a destroyed change can also produce.
Note the asymmetry with Class 16: there a *fixture* mutated shared state it did not
own; here the *verification procedure itself* mutates the code under test.

---

## 19. Comparing runs taken with DIFFERENT INSTRUMENTS  *(new — B2a composition)*

**Description.** Two runs are compared to locate a difference in the system, but the
**measurement apparatus** changed between them — a different trace filter, log level,
build flag, timeout, or environment. The delta observed is then **the observer's own
change**, attributed to the system. This is the sibling of class 18: there the
verification loop *mutated* its subject; here it *re-instruments* between
observations. Both corrupt the result while looking like a clean experiment, and both
produce a confident, wrong, **publishable-looking** conclusion.

> **The rule: when comparing runs, the instrument is part of the experiment.**
> Change exactly one thing — and it must not be the instrument.

**Foreclosing primitive.** **NONE — discipline.** Pin the instrument first and record
it beside the result (the exact filter/flags), so a later comparison can see whether it
matches. When a comparison produces a surprising result, **re-run the baseline under the
new instrument before believing the delta** — the cheapest possible check, and the one
that reverses this class every time.

**Instances (grounded — both in a single afternoon's diagnosis, both one commit from
being recorded as findings):**
- **"The consent dialog triggers the icon load."** Runs traced with `-e trace=openat`
  showed **0** icon-theme lookups for the none / approval-only / approval+prompt modes,
  while the earlier baseline (traced `openat,newfstatat`) showed 6. GTK **stats** icon
  directories rather than opening them, so the filter — not the dialog — produced the
  difference. Under the matched instrument all three modes show the **same 6**: the
  dialog is irrelevant.
- **"It is WebKit-specific."** With the same truncated filter a bare `GtkWindow` showed
  no sized-category lookups, implying the WebView was responsible. Under
  `openat,newfstatat` the bare window shows the **same 6** — it is GTK3 window creation,
  and WebKit is irrelevant. Had this stood, the fix would have been aimed at the wrong
  component entirely.

**RED-proof shape.** Procedural, like class 18: before accepting a difference between
two runs, **re-run the earlier configuration under the later instrument** and confirm
the delta survives. If it vanishes, the instrument was the variable. Record the
instrument string (e.g. the full `strace -e trace=…` expression) next to each result so
the comparison is auditable after the fact rather than reconstructed from memory.

---

### Instance, 2026-08-23 — class 19 applied to THE PROMPT (the instrument that directs the review)

Every review prompt in this project pins its **diff range** to an explicit SHA, because
D0A-R10-02 established that a moving endpoint cannot be checked against a fixed manifest.
**No prompt pinned ITSELF.**

Round 15 was reissued after its stop-instruction was withdrawn, and the next review still
quoted the withdrawn instruction verbatim — a run against a stale copy of the file, made
after the file had changed in the tree. Nothing in the prompt let either party notice: the
reviewer had no way to tell which version they held, and the operator had no reason to
suspect a mismatch, because the range still matched.

**Foreclosing shape:** a prompt carries a **VERSION line and a self-check the reader can
perform without external state** — "if section X does not appear below, you hold an older
copy; stop and say so." Content-addressed rather than date-addressed, because a date in a
stale file is as stale as the rest of it.

**Why it belongs under class 19 rather than as a new class:** it is exactly "runs compared
under different instruments" — the review ran under a different instrument than the one in
the tree, and the difference was invisible in the output. The instrument here happens to be
prose rather than a script, which changes nothing about the failure.

## 20. A correctly-biting test in a NON-REPRESENTATIVE environment  *(new — B2a composition)*

**Description.** A test is written well: it is RED-proven, its weaken/restore
discriminates, its assertion names a real property. And it certifies **the wrong
thing**, because the environment it runs in **does not implement the mechanism the
property depends on**. Nothing about the test is sloppy; the green is simply
evidence about the harness rather than about production.

This is **distinct from the vacuous-test failure** (class 15 clause 2 — a test never
proven to bite). That test's green means nothing because it cannot fail. *This*
test's green means something — just not what the reader takes it to mean. And it is
distinct from class 19, where the instrument **changed between runs**; here a single
consistent instrument is **incapable of observing the property at all**.

> **The discriminating question: does the test environment IMPLEMENT the mechanism
> the property depends on?**
> If it does not, the green is **evidence about the test environment, not about
> production** — no matter how rigorously the test bites.

**Foreclosing primitive.** **NONE — discipline.** For any property that depends on a
platform mechanism (module loading, origin/CORS rules, process sandboxing, kernel
policy, real IPC transports), name the mechanism explicitly and check the harness
implements it before trusting a green. Where it does not, say so **in the test
file**, scope the test's claim down to what the harness *can* see, and prove the
real property against the real component.

**Instances (grounded):**
- **`shell/src/__tests__/file-protocol-load.test.ts` (P1).** It built through the real
  vite config, resolved every emitted asset with browser semantics, executed the
  bundle, asserted React mounted — and was **verified to bite** (`base:"/"` → 2 failed,
  `base:"./"` → 3 passed). It certified that the bundle loads over `file://`. **It does
  not.** jsdom has **no module loader, no origins and no CORS**, so the test injected
  the emitted module as a *classic script* — a narrowing that was documented, and that
  turned out to remove the very mechanism the production failure lives in. Real WebKit
  **never fetches an external `<script type="module">` from a `file://` page** (opaque
  origin), so the bundle never executes and the page is blank. The `base:"./"` fix
  remains correct; the *claim the green supported* did not transfer.
- **Sibling, same session:** the `aa-status` stub that was **more capable than the tool
  it stood in for** — the suite proved a registry check "works" while the real tool
  returns a permission error to any unprivileged caller. Same shape at the tooling
  layer: the harness implemented a mechanism production does not have.

**RED-proof shape.** The property must be proven against the **real component in the
real environment**, with the harness test demoted to what it can honestly observe.
For P1 that means the ladder (`scratch/file-protocol-ladder.py` → a committed
shell-host test): the **real** `delphi-shell` binary, **real** WebKitGTK, the **real**
scheme, using the only machine-checkable signal the host offers
(`{"kind":"cancel"}` → `process::exit(0)`, so *exit 0 = the page executed*). A green
there is evidence about production because production is what ran.

---

**ONE LEVEL OUT — THE REPLACEMENT INSTRUMENT THAT CANNOT RUN (D0 / `real_webkit_load`).**
The jsdom test could not see the real property, so it was replaced with real WebKit against
the real binary. The replacement then could not **run** on any box with
`apparmor_restrict_unprivileged_userns=1`, because the AppArmor profile granting `userns`
attaches by PATH to the installed binary while the tests ran a build-tree path. Seven tests,
never executed, reported as `ok`.

The instrument got better and the blindness moved from the instrument to the environment.

**When you replace an instrument because it could not see the property, verify the replacement
can RUN where the evidence is needed** — otherwise you have traded a test that sees the wrong
thing for one that sees nothing, **and the second is harder to notice because it looks like
infrastructure trouble.** Not a figure of speech: `Died(6)` was read as a build problem across
two rounds of diagnosis before a profiled/unprofiled A/B settled it.

### Instance, 2026-08-21 (D0A-R12-11) — when the environment selects a BRANCH, the green is about the other one

The sharpest instance this project has produced, because nothing about the test was wrong
and the suite was not skipping.

Shape E drops an approved action to `delphi-tool`. The drop only happens when
`tool_credentials()` returns `Some`, which needs euid 0 — so the **unprivileged** run of
every execution test takes the **no-helper branch**, and its green describes a code path
production never takes at root. Seven tests had been failing at root since E landed
(`cannot create …/out/result: Permission denied` — the tool at uid 997 cannot write an
`out/` the root test process created), and nothing noticed for as long as the only runs were
unprivileged.

**This is not "the suite skipped".** It ran, it passed, and it exercised a different
mechanism than the one under review. A skip is at least legible in the output; a branch
divergence is invisible — the test names, the count, and the result line are all identical
between the two environments.

**Two consequences worth carrying:**

* An `euid`-gated code path makes its unprivileged suite non-representative for **every**
  test that touches it, not only for the tests that name it. The seven failures were spread
  across tests about tokens, seals and one-shot consumption — none of them "about" the drop.
* The failures were **the predicted behavioural change arriving on schedule**: the register
  recorded twice, before E shipped, that dropping the tool off root removes its access to
  root-owned paths, that any test failing for that reason is CORRECT, and that widening the
  new uid's access to turn those reds green would be the forbidden weaken. The fix was the
  FIXTURE (chown the out dir to the planned tuple, in the one place that creates it), not
  the uid.

**Foreclosing discipline, beyond class 20's general form:** when a privilege gate selects a
branch, the unprivileged suite cannot report on the privileged branch at all — so the
privileged run is not a *confirmation* step to be scheduled later, it is the only run that
has ever executed that code. Name it as owed work at the moment the gate is introduced.

## 21. A warning banner is not an enforcement mechanism  *(new — B2a composition)*

**Description.** A test harness, probe, or demo renders something that **looks
authentic** — most sharply, a credential prompt — and relies on **text** to stop the
human from treating it as real. It does not stop them. A dialog that presents as the
system's own password field will receive the system's own password, regardless of
what is written above it, because the person is responding to the interface, not
reading the terms of the experiment.

The failure is not carelessness on the reader's part. An authentic-looking prompt is
*designed* to elicit the credential; a paragraph of warning text competes with that
design and loses. Treating the warning as the control confuses **documentation** with
**enforcement** — the same confusion as a comment that says "do not call this
concurrently" standing in for a mutex.

> **If a probe can receive a real credential, assume it will. Design so that it
> cannot be the thing that matters, rather than asking the human not to supply it.**

**Foreclosing primitive.** **NONE — discipline, with three concrete requirements for
any interactive probe that renders a credential-shaped field:**

1. **Prefill a sentinel** (e.g. `DUMMY-DO-NOT-USE`) so the field is never empty and
   inviting, **or reject any input that is not the sentinel** — an enforcement point,
   not a request.
2. **Never persist what is received.** Report a **length or a hash**, never the value;
   never write it to a log, a file, an argv, or an environment variable. This is the
   property that determines whether an incident is *"a secret crossed a socket into a
   process"* or *"a secret is on disk"* — a large difference in blast radius.
3. **State the residual honestly.** Even with (1) and (2), a credential typed into the
   probe has entered a process's memory. That is a rotation-worthy event, and the probe
   should say so **before** the interaction, not after.

**Instances (grounded):**
- **`scratch/p3a-host-check.py` (P3a-1, 2026-07-25).** The probe drove the REAL consent
  dialog — the real preview, the real PAM-prompt label, the real password field — to
  prove the renderer→native round trip under real WebKit. It carried a banner stating
  plainly that nothing authenticates the value and that a throwaway string should be
  used. **The operator entered their real password**, because the dialog was
  indistinguishable from the production one, which is precisely what the test was
  demonstrating. Mitigating factors held, and they held **by design rather than by
  luck**: the probe reports only `len(data)` and never the bytes, so the value reached
  a process's memory and a socket but **never disk** — confirmed by grepping the run
  log, which contained only the prompt label, the banner text, and the byte count.
  Rotation was still the correct response.

- **THE CLASS CAUGHT ITS OWN AUTHOR, one layer down (same session).** The first attempt at
  fixing the instance above wrote a **sentinel-prefill guard** into the probe — JavaScript to
  set the password field to a dummy value and reject anything else. **The probe structurally
  cannot inject it:** only the HOST calls `evaluate_script`; the probe speaks the private
  channel, and the one renderer-visible string it controls (the PAM prompt) is `serde_json`-
  escaped precisely so content cannot become script. The guard would have sat in the file
  **looking like an enforcement point while enforcing nothing** — the exact shape this class
  describes, one level down: not a warning mistaken for a control, but a *control that cannot
  run* mistaken for a control.
  It was **removed rather than left in**, and replaced by something structural: the probe no
  longer sends the PAM prompt at all by default, so the dialog's `disabled={submitted ||
  !prompt}` makes the credential path **unreachable**. The generalisation: **when you write a
  guard, verify it can actually execute in the position you put it** — an unreachable guard is
  worse than none, because it stops anyone looking for a real one.

**RED-proof shape.** Two parts, because the class has a design half and a hygiene half.
(a) **Design:** inspect the probe for an enforcement point — a prefilled sentinel or a
non-sentinel rejection. Prose in the banner does not satisfy it. (b) **Hygiene:** assert
mechanically that no received byte is written anywhere — grep the probe for any use of
the received buffer other than `len()`/hash, and grep a real run's artifacts for the
value. A probe that passes (b) but fails (a) is one confused human away from an
incident; a probe that fails (b) has already had one.

---

## 22. The FIX inherits the class it was closing  *(new — B2a composition, round 2)*

**Description.** A finding is fixed, the fix is RED-proven, and the fix **exhibits the
same defect class one degree weaker**. The remediation is not wrong in direction —
it genuinely removes the reported instance — but it reintroduces the underlying
shape at a level the new test does not reach. Because a review round tends to close
a finding once its named instance is gone, this survives precisely when everyone is
paying attention.

> **A fix is not exempt from the class it fixes. Re-apply the finding's own
> question to the remedy before declaring it closed.**

**Foreclosing primitive.** **NONE — discipline.** When a fix lands, ask the finding's
question of the fix itself: *if this is a false-green class, can the new gate produce
a false green? If this is a non-biting-test class, can the new test fail to bite?*
Where the answer is "only in a weaker form", that weaker form is a finding now, not
later.

**Instances (grounded):**
- **B2A-COMP-R2-01 → B2A-COMP-R3-02 (this arc).** Round 1's R2-01 added a gate because
  a sandbox misconfiguration read as *all-preconditions-met* — a **false green**. The
  gate compared paths **lexically** (`case "$AI_ARG/" in "$bind_rw"/*`), so
  `/tmp/../var/tmp/marker` against `bind_rw=/tmp` has the right prefix, resolves
  **outside** the bind, and passes — **a false green replaced by a weaker false
  green.** Fixed by canonicalising with `realpath -m` before comparing.
- **FD-01's re-aim (earlier in B2a).** The first version of the regression test passed
  under its own weaken; the re-aimed test bit. The *fix for a non-biting test* was
  itself non-discriminating until run — the same shape at the test layer, and the
  reason "verify the fix's fix" is a rule rather than an instinct.
- **B2A-COMP-R1-01's own test (this round).** The R3-01 fix hoisted the apparmor
  preconditions into pre-flight; its regression test asserted only that the **bundle
  tree** was absent — but the tree install runs after the apparmor block either way,
  so the test passed with the fix reverted. It could not distinguish *refused before
  any mutation* from *refused after the binaries were copied*. Caught by running the
  weaken and **verifying the weaken had applied**; fixed by asserting `/usr/libexec`
  is untouched.

- **THE APPARATUS INHERITS IT TOO — B2A-COMP-R4-04 → R5-02 (round 4).** R4-04 removed a
  mirror by delegation: stop grepping the unit file, ask `systemctl show`. **Its test stub
  then grepped the unit file** and answered any `show` call with the result — the removed
  mirror reinstated *inside the proof*, and green even if production queried the wrong unit
  or the wrong property. **Weaken (b) applies to the TEST APPARATUS, not only to the fix.**
  Ask of every stub: *does this stand in for the thing, or does it reimplement the thing the
  fix just stopped reimplementing?*
- **The positive-assertion shape (round 4, R5-03).** Two of this sweep's four non-biting tests
  shared one form: a POSITIVE case asserting a generic success string **that the unperturbed
  fixture already emits**, so it passed whether or not its perturbation applied. The
  structural remedy is not vigilance: a positive assertion must name a value the BASELINE does
  not produce, and that must be **checked mechanically** — run the pristine fixture first and
  fail if it already satisfies the expectation (`assert_positive` in
  `installer/tests/p3-preflight.test.sh`). A control leg, in the same sense the WebKit suite
  uses one.

- **The SAMPLER that measures its own race (round 5).** The regression test for the
  restore-before-clear invariant sampled with **two separate `[ -e ]` stats**. An atomic
  `rename(2)` landing between them shows *both* paths absent when one existed at every
  instant — so the test reported a violation that never happened. It passed 3× then failed on
  unchanged good code: **intermittent, and therefore worthless** (Iron Law #15 cl. 2 — it
  cannot distinguish a violated property from an unlucky run). Fixed with a single `readdir`
  per sample, then proven **10/10 deterministic** and still biting (3/3 under the weaken).
  The lesson generalises past sampling: **a measurement composed of several observations is
  not a measurement of a single instant.** When the property is "at every instant X", the
  sample must be atomic or the harness will invent violations.

- **THE SAMPLER, TWICE — and what actually proves a synchronisation fix (round 6).** The
  restore-before-clear test's measurement was wrong twice in successive rounds: first two
  stats straddling an atomic `rename(2)` (inventing a violation), then — in the *fix* for
  that — the initial write placed INSIDE the background sampler, so the parent could launch
  the subject and kill the sampler before the write happened, reading "unknown" and failing on
  GOOD code. Class 22 in the same test, two iterations running.

  > **⚠ THE WEAKEN PROTOCOL HAS A BLIND SPOT, AND THIS IS IT.**
  > The weaken/restore cycle is this project's primary verification tool: revert the fix, the
  > test must fail. **For a scheduler-dependent property it can pass while the defect is
  > present.** Measured here — the startup race was *reintroduced* under an ordinary weaken
  > and **the test still passed**, because the bad interleaving simply did not occur in that
  > run. The same race had already survived a **10/10 deterministic** run.
  >
  > This is a limit on the tool, not a note about counting greens. Wherever a property depends
  > on ordering between concurrent actors — sampling, signal handling, fork/exec sequencing,
  > file-descriptor lifetime, lock acquisition — **a passing weaken is not evidence.** The
  > protocol silently degrades from "proven to bite" to "did not happen to bite this time",
  > and nothing in the output distinguishes those two.

  **The standard that does apply, both parts required:**
  1. **A happens-before you can point to in the source** — the race removed *by construction*,
     not by timing. Here: the initial value is written by the PARENT before the fork (so the
     file exists whenever the parent reads it), and the sampler signals readiness after a
     completed sample with the parent blocking on that signal (so "hope it started" becomes
     "it demonstrably started").
  2. **A widened-window experiment** — force the bad interleaving instead of waiting for it.
     Inject a delay at the suspect point so the race is near-certain, and show the old shape
     fails and the new one does not. Measured here under a forced 0.5 s scheduling delay:
     old shape → `UNKNOWN`, new shape → `0`. That discriminates where 10/10 could not.

  **If neither is available — no structural argument and no way to widen the window — say the
  fix is unproven rather than running it more times.**

- **THE SAMPLER, A THIRD TIME — and the resolution: STOP SAMPLING (round 7).** The round-6
  fix carried a third timing defect of the same class: the parent's readiness handshake was a
  bounded busy-wait (`for _ in $(seq 1 500)`), so on a loaded or single-core runner 500 `-e`
  checks can complete before the background sampler is scheduled even once, and GOOD code
  reports `SAMPLER-NEVER-READY`. *"Hope it started"* had become *"hope it starts within 500
  iterations"* — the happens-before argument covered the file existing, not the sampler being
  scheduled. Three fixes, three defects, all timing.

  > **THREE DEFECTS OF ONE CLASS IN ONE TEST IS THE INSTRUMENT TELLING YOU IT IS THE WRONG
  > INSTRUMENT.** A sampler observes at INTERVALS. The property was "at **every instant** at
  > least one of X or Y exists". **A sampler cannot decide that even in principle** — between
  > any two observations there is a gap it did not see — so every fix could only shrink the
  > gaps, never remove them, and every fix was on the wrong axis. The fourth would have been
  > too. The tell is the repetition of a CLASS, not the difficulty of any one instance.

  **The foreclosing move: derive the invariant from a COMPLETE RECORD instead of observing
  states.** A directory entry's existence changes *only* by syscall, and `strace -f` records
  every syscall of the traced tree. Existence is therefore a step function whose every step is
  on record, and evaluating the invariant after each step evaluates it at every instant — by
  construction, with **no interval, no iteration count, and no dependence on scheduling.**
  Implemented as `installer/tests/trace-invariant.py`.

  **What that buys, and it is exactly what the blind spot above denies:** the weaken is
  DETERMINISTIC. Measured — clear-before-restore reintroduced, **10/10 runs detected**, and
  the verdict names the cause (`VIOLATION both-absent-after:unlinkat:line1389:step2`) rather
  than reporting an anomaly. The 10/10 is a *description*, not the evidence: the trace
  CONTAINS the `unlinkat` that opens the window, so the violation is **derived, not observed**,
  and no interleaving is involved. Contrast round 6, where a reintroduced race survived its
  weaken. **Escaping the blind spot beats managing it** — when a property is temporal, look
  for a complete record before accepting a sampling harness and the whole class-22 apparatus
  that a sampling harness then requires.

  **A checker is an instrument too, so it carries the same burden — and can now discharge it
  cheaply:** the checker is proven to bite on **synthetic traces** (fixed input → fixed
  verdict), which is a weaken/restore with no timing in it at all. **It must fail CLOSED**,
  because the completeness argument holds only where every mutation is visible *and*
  classified: an unknown syscall, a dirfd-relative mutation, a `<unfinished>` split on a
  mutating call, or an unreadable return value each yield `REFUSE`, never a reassuring `OK`.
  This is not theoretical — the first run against a real trace **refused**, on `execve` and
  directory-`openat` splits (74 split lines occur in one real install). Narrowing to skip
  splits on *provably inert* syscalls is legitimate (Iron Law #15 cl. 3: a split on a
  *mutating* call still refuses, with its own self-test); widening the accepted set to make
  the refusal disappear would have been the forbidden edit available at the same moment.

### The blind spot, MEASURED at last (D0 round 1, 2026-07-31)

The standing question — *can a weaken pass while the defect is present, for a
scheduler-dependent property?* — was put to Codex twice and **never answered**. It is now
answered by measurement instead, from D0's own round-1 remediation.

One injected R1-02 defect, one weaken, two regression tests that both assert the same
property. Detection rate over 20 runs of the module:

| test | detected the injected defect |
|---|---|
| `marker_then_channel_close_while_alive_is_not_ready` | **20/20** |
| `marker_from_an_already_dead_shell_is_not_ready` | **5/20** |

**So yes: a weaken/restore run resting on the second test alone would have reported "the
weaken did not bite" three times in four**, and the natural reading of that — "this test is
worthless, delete or rewrite it" — would have been wrong. The test was fine; its *setup* was
racy.

**Root cause, and it is the more useful half.** The second test forked a child that wrote the
marker then exited, and the parent `SIGKILL`ed and reaped it. Nothing ordered the child's
`write` before the parent's kill, so 15 runs in 20 the child died **before signalling** — and
the run then exercised *"died without signalling"*, a different property that passes for a
different reason. The test was **passing for the wrong reason 75% of the time** while
appearing green. Adding an explicit setup barrier (child signals a pipe after writing; parent
blocks on it) took detection to **20/20**.

**The rule this yields — CORRECTED, because the first version of it overstated the evidence
(D0-R2-07):**

The original rule said "report the detection rate as `n/N`; below `N/N` means the setup does
not establish its precondition." That is useful but it is **not a soundness criterion**, and
saying it was is the error. A rate over sampled schedules bounds **the schedules sampled**,
nothing more: `20/20` says nothing about the 21st run, and a weaken can detect an *injected*
defect deterministically while missing the real class the injection stands for.

> **Soundness comes from WITNESSING, not from a rate. In order of preference:**
>
> 1. **Witness the four states directly** — the precondition holds; the injected violation is
>    present; the assertion fails; the restoration passes. Each observed, not inferred.
> 2. **Force the interleaving** where a race is involved: construct the input that *makes*
>    the ordering deterministic, rather than running until it happens.
> 3. **`n/N` only as a fallback**, where neither is available — and then state plainly that
>    it bounds **schedules sampled, not soundness.**

**The measurement that settles it, from this module (D0-R2-01c).** Against one injected
defect — returning `ChannelClosed` on the first `POLLHUP` — two tests were compared:

| instrument | detection |
|---|---|
| naturally-racing test, sampled | **3/12** |
| forced-interleaving test (child closes the channel, sleeps 50 ms, *then* exits) | **20/20** |

Same defect, same code, same machine. The sampled instrument would have been reported as "the
weaken is weak"; in fact the *instrument* was. Forcing turned a 25% detector into a
deterministic one.

**The self-indictment, recorded because it is the reusable part.** The stronger instrument
already existed: the widened-window experiment (a forced 0.5 s delay yielding `UNKNOWN` vs
`0`) predates this class by three rounds. The weaker `n/N` rule was then extracted from the
5/20 case *anyway*, because the 5/20 case was the one in front of us. **Deriving a rule from
the instance at hand rather than from the best instrument already built is itself Class 17.**

**AMENDMENT (D0-R3-03) — forcing is not automatically deterministic.** "Force the
interleaving" was stated as if controlling the *subject's* timing were enough. It is not: a
test that makes the child close-then-sleep-then-die has forced when the CHILD acts, while the
window is only entered if the OBSERVER is scheduled inside it. Measured against one injected
defect, same code, same machine, only the instrument differing:

| instrument | detection |
|---|---|
| naturally-racing, sampled | 3/12 |
| child's timing forced (50ms gap) | 20/20 — but still *sampling*, with a wider window |
| **observation sequence injected into a factored state machine** | 20/20 **by construction** |

**READ ROWS TWO AND THREE TOGETHER — THEY SHOW THE SAME NUMBER AND CATEGORICALLY DIFFERENT
EVIDENCE.** Both say 20/20. Row two is a *sample* of 20 schedules that happened to land inside
a widened window; run it on a loaded box, or narrow the gap, and it decays — it bounds the
schedules observed, nothing more. Row three is not a sample at all: the sequence IS the input,
so 20/20 is 20 repetitions of a decided fact and the 21st run cannot differ.

**A reader comparing counts alone would call them equivalent. That comparison is precisely the
error this class exists to prevent** — and it is the error that produced the weak `n/N` rule in
the first place. When reporting, state the instrument, never just the ratio.

**THIRD AMENDMENT (D0-R4-04) — factoring buys determinism for the factored half and MOVES THE
BURDEN TO THE SEAM.** The injected state-machine test is sound and proves what it claims: given
a sequence, the decision is right. It says **nothing** about whether the polling layer maps real
`revents` into the right `Observation` — and that is exactly where the next defect landed.
`Duration -> PollTimeout` truncates, so a 249.9ms remainder polled for 249ms and its `Ok(0)` was
handed to the machine as a genuine `Timeout`. The machine then decided *correctly* on a *false*
input, and the injected test could not see it because it assumes every `Timeout` it is given is
real. Factoring is still the right move — but the seam needs its own test, at the mapper
boundary, with the clock as the authority rather than the poll's return value.

**A forced interleaving is deterministic only when the observer's entry into the window is
synchronized.** Where it is not, report it as what it is — stronger sampling.

**The move that actually worked, for the third time this session: separate the state machine
from the I/O.** `TerminalWitness::observe` split the decision from the polling; every timing
defect in that file had lived in the entanglement. The same shape as replacing the trace
*sampler* with a complete-record derivation. When an instrument keeps producing ambiguous
results, the answer has been "the instrument is wrong", never "the instrument needs tuning".

**RED-proof shape.** Two weakens, not one. (a) the ordinary weaken — revert the fix, the test
must fail; and (b) **the class re-application** — construct the input that exhibits the
ORIGINAL class against the NEW code and assert it is caught. Prefer a forced interleaving for
both; fall back to `n/N` (≥20 runs) only where forcing is impossible, and label it as a
sampled bound. A fix with only (a) is proven to address its instance, not its class.

---

**FOR A STALENESS FIX, ASK WHERE THE TEST OBSERVES: ACROSS THE INTERVAL, OR ONLY BEFORE AND
AFTER IT? (D0A-R1-01 — third instance.)** A staleness defect lives in the gap between reading a
value and using it. A test that samples wholly before and wholly after that gap sees two
consistent worlds and reports success, because the inconsistent world exists only *inside* it.
Three instances now, each while fixing the one below:

1. **A2** resolved pidfd → pid → lookup: two operations with a gap.
2. **A2's own test** reaped, then read — before and after, never across. It passed.
3. **A2's BARRIER test**, written specifically to close that gap, reaped before reading the pid
   too. Under the weaken to the old two-step it still PASSED. Both prior tests *looked like
   proofs*; the weaken is the only thing that said otherwise.

The check is mechanical and belongs in the design step, not the review: name the interval, then
point at the line where the test observes and ask whether that line is inside it.

**VERIFY-IT-APPLIED IS NOT ENOUGH — VERIFY WHERE IT FAILED (D0-A A3).** The existing rule catches
a weaken whose substitution matched nothing. It does not catch a weaken that *did* apply and then
failed **for an adjacent reason**. A3's weaken (a) froze the gate verdict behind a
process-global `OnceLock`; the flip test duly failed — at its FIRST assertion, because a sibling
test in the same binary had already seeded the memo. The weaken was real, the failure was real,
and the failure was **not** the one the test names. Re-run with `--exact`, it failed at the
true→false leg quoting the intended message.

**AN EDIT THAT CAN SILENTLY MATCH NOTHING MUST ASSERT IT MATCHED, AND THE ASSERTION BELONGS IN
THE EDIT — NOT IN A LATER VERIFICATION PASS (D0A-R1-06).** A scripted string replacement that
matches nothing is a no-op that raises no error, so the edit reports success and the file is
unchanged. D0-A A3 "corrected" a stale warning string this way; the replacement matched nothing,
the stale text survived, and it reached review as R1-06. A later verification pass cannot save
this reliably — it checks what you thought to check, and the whole failure is that you believed
the edit landed.

**FIVE IN ONE SESSION — THE RULE SHOULD HAVE EXISTED EARLIER, AND ITS ABSENCE WAS SILENTLY
COSTING EDITS THE WHOLE TIME (2026-08-06).** R1-06 was not "a defect we found once". It was the
one that **reached review while four others were caught**, in a single increment, once the rule
was in force:

1. the stale warning string that shipped and became R1-06;
2. an over-wide test-module deletion that would have removed the very helper it was rewriting;
3. an indentation mismatch;
4. a doc-header mismatch;
5. **the fix for R1-06 itself**, which failed to match for the same line-continuation reason
   the original did — the identical no-op, one layer up, while fixing it.

Before the rule, every one of those would have reported success and changed nothing. An entry
reading "we hit this once" **understates the rate by a factor of five** and would leave the next
reader treating it as a curiosity rather than as a standing property of scripted editing. The
correct reading is the reverse: silent-no-op edits were happening continuously and invisibly,
and the only reason the count is known is that something finally counted.

**"The weaken failed" and "the weaken failed for its stated reason" are different observations,
and only the second is evidence.** So the obligation is: read the failing assertion's line and
message, not the exit code. Shared process state — statics, `OnceLock`, env, the filesystem — is
the usual reason the two diverge, and a weaken that introduces shared state is exactly the kind
most likely to be read wrong.

## 23. Forecasting your own code instead of interrogating it  *(new — B2a composition)*

**Description.** Asked where a defect is likely to be, an author predicts — and the
prediction is a model of code they wrote, built from the same understanding that
produced the code. Where that understanding is wrong, the prediction is wrong in
**exactly the place the defect is**. The failure is not carelessness; it is that
introspection and authorship draw on the same model, so the error is common-mode.

Measured over this sweep: the author's forecasts about **where findings would be**
were wrong twice in succession, both times pessimistic — predicting the
custom-protocol handler would not survive a dedicated pass (it did, three times) and
that a stub audit would find a fourth instance of a three-for-three pattern (it found
zero, which was itself the informative result). Over the same period the author's
**experiments** — weaken/restore, the widened window, running the real binary against
the real bundle — repeatedly produced correct findings, including ones the reviewer
had not asked for.

> **On your own code, construct an experiment rather than forecast a result.**
> A weaken, a widened window, a control leg and a real-binary run all work by making
> the SYSTEM answer. A prediction works by asking yourself — which is the one source
> already known to be wrong wherever the defect lives.

**Foreclosing primitive.** **NONE — discipline.** When tempted to say "I expect X is
where the problem is", convert it: what run would distinguish X from not-X, and can it
be done now? Where the forecast cannot be converted into an experiment, state it as a
guess with its track record attached rather than as an expectation.

**RED-proof shape.** Not applicable in the usual sense — this class is about the
provenance of a claim rather than a defect in code. Its check is procedural: any
statement of the form "this is probably fine" or "this is probably where it breaks",
made about one's own work, is a **claim awaiting an experiment**, and should be
labelled as such in the record so a reader can weigh it correctly.

---

## 24. In-band sentinel — a signal drawn from the value space it describes  *(new — B2a composition, round 7)*

**Description.** A helper needs to report *both* a value and a condition about that value, and
encodes the condition as a **reserved value of the same type** — `<declared-empty>` for a
pathname, `-1` for a count, `<none>` / `N/A` for a string. The value space and the signal
space overlap, so two things become impossible to distinguish: **legitimate data that happens
to equal the sentinel**, and **the condition itself**. Every consumer downstream must then
know about the sentinel, and any consumer that does not silently treats the signal as data.

**Instance.** `p3-preflight.sh`'s `resolve_bin` printed the literal string `<declared-empty>`
when a bin path was declared-but-empty in the unit. Two consequences, both real:

1. **Consumers treated it as a filename.** `$SHELL_BIN` flows into `[ -e ]`, `[ -f ]`,
   `sha256sum`, `strings` and an `[ -x ]`-guarded `execve`. A declared-empty bin produced a
   *second* refusal — `<declared-empty> is ABSENT — run: sudo bash installer/install.sh` —
   naming a file nobody wrote and prescribing the installer when the fault is the unit
   declaration. A misdiagnosis printed in the voice of a diagnosis.
2. **Value collision.** A deployment whose path genuinely is that string is reported as having
   declared nothing. Narrow, but it is the defect proper, and **no amount of downstream
   guarding can fix it** — only moving the signal off the value channel can.

**Foreclosing primitive.** **NONE — discipline, with a standard shape.** Signal out of band:
a **distinct exit status** (`return 2`), a separate flag variable, or a second output field.
Return the *honest* value on the data channel — for `resolve_bin` that is the empty string,
which is literally what the daemon would `execve` — and let the status carry "and that is a
fault". Refuse once, at the point of resolution, and have downstream checks **skip** an
unresolved value rather than re-refusing it under a wrong name.

**RED-proof shape.** The symptom is an EXTRA misleading line, not a missing one, so the
assertions are negative and must be paired:
(a) perturb into the condition and assert the correct refusal appears **and the sentinel
string does not appear anywhere in the log**;
(b) set the value to *be* the sentinel string and assert it is **not** reported as the
condition. Weaken by restoring the in-band return and the unguarded consumers: both go RED,
and (a)'s failure output prints the misleading refusal verbatim — which is the finding.
Implemented as B2A-COMP-R8-03 in `installer/tests/p3-preflight.test.sh`.

**Sibling worth checking whenever this class appears.** The same review found
`AI_BIN=$(unit_env DELPHI_AI_BIN)` in section 4 **reassigning** a name that already held the
*resolved* path from section 0 — one identifier meaning two different things at two points in
one script. Same root disease as the sentinel (a name whose meaning is positional rather than
fixed), so audit for it in the same pass.

---

## 25. The fixture is constructed differently from the thing it stands in for  *(new — D0 round 1)*

**Description.** A test builds its own copy of a resource the production code also builds —
a socket, a pipe, a file, a directory, a process — but with **different flags or options**.
The test then measures a system that differs from the one that ships, and the difference is
invisible because both objects have the same *type*.

Distinct from Class 20 (a correctly-biting test in a non-representative **environment**):
there the environment was wrong; here the **fixture itself** is, and the fixture is code the
test author wrote on purpose.

**Instances (grounded):**

- **`SockFlag::empty()` vs `SOCK_CLOEXEC` (D0, 2026-07-31).** `readiness.rs`'s in-module test
  hand-rolled its `SOCK_SEQPACKET` pair while `channel::approval_socketpair` uses
  `SOCK_CLOEXEC`. Concurrent tests running `Command::spawn` inherited the non-`CLOEXEC` fd
  across `exec` and held it, suppressing the `POLLHUP` the test measured — a **1/30 flake**
  whose cause was a fidelity gap, not scheduling.
- **The three stub-permissiveness findings and R3-03's unit-file mirror** (B2a composition)
  are the same class in non-socket form: a stand-in that accepted more than the real thing.

**The sweep that found it, and its more useful result.** Every *integration* test in
`runtime/tests/` calls `approval_socketpair()` — the production constructor — so none of them
can diverge. The only divergent fixture was the one that hand-rolled the resource because it
was "just a socketpair". A second, harmless instance was found in the same pass
(`nix::unistd::pipe()` in a test helper against `pipe2(O_CLOEXEC)` in `launcher.rs`) and
aligned.

**A FIXTURE DESCRIBING AN EXTERNAL TOOL'S OUTPUT MUST BE CAPTURED FROM THAT TOOL, NEVER
WRITTEN FROM MEMORY (D0 — the sharpest instance in this class).** `scripts/test-count.test.sh`
RED-proved the count extractor against libtest logs **invented from memory**. libtest actually
prints `test <name> ... SKIP …`; the invented fixtures put the marker at column 0. The parser
therefore passed six synthetic cases while matching **zero of 19 markers in real output**.

**Where it sat is what makes it the worst instance: inside the RED-proof of a TIER-1
artifact** — the proof that licenses quoting the tool's counts as evidence. An invented
fixture there means the proof measured *a format that does not exist*, so the licence was
issued against nothing.

The demonstration is clean because only the fixture's provenance changed: against the same
injected bug, in the same suite, **captured fixtures catch it in 4 of 7 cases; invented
fixtures caught it in 0.**

Same shape as the three stub-permissiveness findings and the `SockFlag::empty()` divergence —
a stand-in built differently from its subject — but those were in *tests*. This one was in a
*proof*, which is strictly worse: a wrong test fails to catch a defect; a wrong proof
manufactures permission to stop looking.

**THE PROBE FORM — a diagnostic that exercises a WEAKER operation than its subject
(D0 / real_webkit_load).** The stand-in need not be a fixture; a *probe* stands in for the
subject too, and can be constructed weaker in exactly the same way. Two instances from one
diagnosis:

- **`unshare -U` where the subject needs `unshare -r` + `bwrap`.** Creating a user namespace
  is permitted more widely than creating one *and mapping root into it*, which is what
  `bwrap` requires. The probe's success was read as "userns is fine here", and that negative
  was then taken to **refute a true hypothesis** — the profile explanation — sending the
  diagnosis down three more dead ends.
- **`aa-exec -p delphi-shell -- bwrap` failing does NOT refute the mechanism.** Applying the
  profile's label to `bwrap` is not the same as `delphi-shell` holding the grant and spawning
  `bwrap`. The probe tested a different topology than the one under investigation.

**And the sharpest part, because it generalises past both instances:** on the implementer's
box all three of `unshare -U`, `unshare -r` and `bwrap --unshare-user` succeeded, so the weak
probe returned the *correct* answer — for the wrong reason. **A probe that is right by luck is
indistinguishable from one that is right by construction until the environment changes.** It
had already been wrong on the operator's box, where the two operations diverge.

**The discriminating question for any probe: does it exercise the SAME operation the subject
performs, or a weaker one that happens to be nearby?**

**Deliberate divergence is not this class, and must not be "fixed".** `fdsec.rs`'s tests
create **non-`CLOEXEC`** pipes on purpose: the subject under test is the CLOEXEC-marking
sweep, so a non-`CLOEXEC` fixture is the correct input. The discriminating question is
*whether the difference is the thing being measured*.

**Foreclosing primitive.** **Call the production constructor.** Where one exists and is
reachable (`approval_socketpair`, `ensure_runtime_dir`, `pipe2(O_CLOEXEC)`), a test that uses
it cannot diverge; a test that re-implements it can, silently. Where a fixture must diverge,
say so at the construction site and state which property the divergence serves.

**RED-proof shape.** Construct the fixture the production way and the fixture's way, and show
the test's verdict differs. For the D0 instance that is the measured pair:
`marker + close(), extra dup OPEN → POLLIN=1 POLLHUP=0` versus
`no extra dup → POLLIN=1 POLLHUP=1`.

---

## 26. A stale observation asserted in the present tense  *(new — D0 round 2)*

**Description.** A syscall that observes state — `poll`, `stat`, `access`, a directory
listing — returns a description of **what was true at the moment it ran**. Code then performs
another syscall and *reuses the earlier observation* to draw a conclusion. The conclusion is
a claim about the past, stated in the present tense, and it is wrong exactly when the state
changed in between.

The dangerous half is asymmetric, and naming it is the point:

> **A negative observation is not a positive claim.** "The pidfd was not readable" is not
> "the process is alive"; "`POLLHUP` was not set" is not "the peer still holds its end";
> "the path did not exist" is not "the path does not exist". Positive evidence (death
> observed, HUP observed) is conclusive when it arrives. Its **absence** is conclusive only
> after waiting out the arrival that would contradict it.

**Instances — all three in one module, in three consecutive rounds:**

- **D0-R1-06.** `poll(pidfd, 0)` returning nothing was read as **"alive"**. A child closes its
  fds *before* its pidfd becomes readable, so a corpse was reported as a live shell with a
  protocol fault.
- **D0-R2-01.** The `revents` captured *before* a `read` were reused *after* it to decide
  readiness. Measured: an already-dead shell accepted as ready **83/100**.
- **D0-R2-01b.** The `n == 0` branch read an absent (and stale) `POLLHUP` as proof the peer
  still held its end — "alive by construction". Found by us, not by review.
- **D0-R2-01c.** The *fix* then returned `ChannelClosed` on the first `POLLHUP`, which asserts
  the child is alive — while the death that had already happened was still in flight. The
  class re-entering its own fix (Class 22) at the third attempt.

**Foreclosing primitive.** **Re-poll before concluding; never reuse captured `revents` across
a syscall boundary.** Concretely, in this module: `classify_and_confirm_alive` takes no
`revents` parameter at all — the type makes the stale value unavailable — and every liveness
conclusion goes through `witness_terminal`, which polls afresh and lets only *death* return
early. Where a negative must become a positive claim, it costs a **grace** (`DEATH_GRACE`),
calibrated by measurement rather than chosen: 0 ms → 32/100 wrongly accepted, ≥2 ms → 0/100.

**RED-proof shape.** Force the interleaving rather than sampling it (Class 22): construct an
input where the state provably changes between the two syscalls — a child that writes and
exits immediately, or one that closes its channel and dies 50 ms later — and assert the
verdict is the *post*-change one. Detection must be deterministic; if it is not, the
instrument is sampling a race it should be forcing.

---

## 26. A captured observation read as a present-tense claim  *(new — D0 rounds 1-3)*

**Description.** A `poll`/`read`/`waitpid` result witnesses what was true **at the moment of
the call**. Any conclusion drawn *after* an intervening syscall is a claim about the past
stated in the present tense. The dangerous half is asymmetric: **a negative observation is not
a positive claim.** "pidfd not readable" ≠ alive; "`POLLHUP` not set" ≠ the peer still holds
its end; "`WNOHANG` → `StillAlive`" ≠ the process will be alive when it matters.

**Four instances, three review rounds, and the last two were introduced by fixes for the
previous ones:**

| # | site | the false positive claim |
|---|---|---|
| R1-06 | `poll(pidfd, 0)` | not-readable ⇒ "alive" |
| R2-01 | pre-`read` `revents` reused post-`read` | stale absence of HUP ⇒ "open"; **83/100** wrongly accepted |
| R2-01b | the `n == 0` branch | absent (and stale) HUP ⇒ "alive by construction" |
| R2-01c | the R2-01b **fix** | first HUP ⇒ `ChannelClosed`, i.e. "alive", while death was in flight |

**Foreclosing primitive — a MECHANISM, after three rules failed.** R1-06, R2-01 and R2-01b
were each fixed by a rule ("re-poll here"), and the class recurred. R2-01c was fixed by
**removing the parameter**: `classify_and_confirm_alive` no longer *receives* `revents`, so
the stale value is not available to misuse, and every liveness verdict goes through one
re-polling witness in which **only death may return early**. Independently confirmed by
review: no captured events cross the read, the latched HUP is monotonic and records channel
closure rather than process life, and `StillAlive` never authorizes a launch.

**It is older and wider than D0.** `launcher::wait_for_child_setup` predates the increment and
read setup-pipe EOF as "the `execve` succeeded" — identical for a pre-exec child killed before
it could write its failure byte, so a PAM crash was reported as a WebKit problem (D0-R3-04).

**A SWEEP IS OWED, and it needs the discriminating question or it yields noise.** EOF-as-signal
is **not** a defect in itself. The question is *what is being claimed*, never *whether EOF is
read*:

- `wait_for_child_setup` claimed "`execve` succeeded" — something the fd cannot know. **Defect.**
- A relay reading EOF as "the peer closed" is reading exactly what EOF means. **Correct.**

Candidate sites for the sweep, to be judged by that question rather than by grep:
`runtime/src/service.rs`, `runtime/src/consent_relay.rs` (deny-on-EOF), `runtime/src/channel.rs`.
Expect most to be correct; the sweep's value is the one that is not.

**RED-proof shape.** Inject the observation *sequence* rather than racing a real subject — see
class 22's D0-R3-03 amendment. `[Hup, Death]` must yield `Dead`; a fix that decides on the
first `Hup` yields `ChannelClosed`, deterministically, every run.

---

**THE SAME ASYMMETRY AT A HIGHER ALTITUDE (D0-A A3).** R2-01/R2-01b/R2-01c were a captured
`revents` reused after a syscall. A3 is a captured **verdict** reused across the decision it
authorizes: `LogindVerdict` snapshots three bools, the daemon captured one at startup, and the
consent gate re-read those same bools per request while a comment claimed a live re-check. The
axis in question — `active`, "is this session the seat's foreground **now**" — is precisely the
kind of fact a capture destroys. Foreclosed by a `SessionSource` queried at the decision, with
the tearing shape (three axes read at three instants) rejected by a permanent `#[should_panic]`
law rather than by a comment.

## 27. Two independently-correct fixes whose INTERACTION is unsound  *(new — D0 round 4)*

**Description.** Two changes land together. Each is correct against the code as it stood, each
is reviewed and approved, and neither is wrong in isolation — but one **removes an invariant
the other depends on**. Distinct from class 22 (a fix inheriting the class it was closing):
nothing here inherited anything, and no single fix is defective. The defect exists only at the
seam, which is exactly where nobody looked.

**Instance (grounded).** D0-R3-02 and D0-R3-04, approved in one message:

- R3-02's `ShellGuard` signalled a raw pid, resting on *"an unreaped zombie holds the pid"* —
  true when written, and stated explicitly as the reason it was reuse-safe.
- R3-04 added a **consuming** `waitpid(WNOHANG)` that reaped that zombie first.

Jointly: `pidfd::open` normally returned `ESRCH`, so **the P3a diagnosis R3-04 was narrowed to
protect never fired at all**, and under pid churn the guard could root-`SIGKILL` an unrelated
process. Both properties were destroyed by the pairing, not by either change.

**The discriminating question, to be asked of every multi-fix change:**

> **Does this fix rely on an invariant another fix in the same change removes?**

Ask it per pair, and ask it of the *reviewer's* approvals too — the invariant here was stated
by the reviewer in the approving message and removed two paragraphs later.

**THE COUNTEREXAMPLE, and it is load-bearing — R4-03 ↔ R4-01, same round, opposite outcome.**
Round 4 changed five things on the same path in one commit, which is *structurally identical*
to the situation that produced this class. One of those pairs went the other way: R4-03 removed
`wait_for_child_setup`'s own `waitpid`, and that removal **strengthened** R4-01's precondition —
with no consuming wait left anywhere before `pidfd::open`, the raw-pid window provably contains
none. The same removal also eliminated a double-reap race against the guard. Two fixes, one
path, one change, *mutually reinforcing*.

**Without this counterexample the class reads as "many fixes in one change are dangerous",
which is the wrong lesson and would push toward smaller changes rather than better questions.**
Change size is not the variable. The variable is:

> does one fix remove an invariant another fix needs?

A ten-fix change where none touches another's preconditions is safe; a two-fix change where one
does is not. Ask the question per *pair*, not per *count*.

**Foreclosing primitive — the same one that has worked every time it was available:
turn the maintained invariant into a kernel guarantee.** The guard now owns a **pidfd** and
signals through it, so "signal the right process" is enforced by the kernel rather than by a
property this code has to keep true. Compare `DEFECT_CLASSES` 26, where removing the `revents`
parameter made the stale value unavailable rather than merely forbidden. **Three rule-based
fixes failed in a row; both mechanism-based fixes held.** Where a mechanism is available,
prefer it — a rule is only as good as the next change that does not know about it.

**RED-proof shape.** Exercise the *composition*, not each fix: a shell that execs and exits
immediately must produce the readiness diagnosis, not an `ESRCH` syscall error. Then check the
seam mechanically — extract the window between the two fixes and assert the invariant textually
(here: no consuming wait exists between `fork()` and `pidfd::open`).

---

## 28. Re-deriving a mechanism the repo already documents  *(new — D0 / real_webkit_load)*

**Description.** A mechanism is investigated from symptoms — hypotheses, probes, eliminations —
while the answer sits written down in the tree, in a comment placed there *specifically so the
next reader would not have to re-derive it*.

**Instance (grounded).** `real_webkit_load` aborting with `Died(6)`. Diagnosed across **four
dead hypotheses** (icon theme, build age, debug-vs-release, environmental drift) and **two
review rounds**. `installer/apparmor/delphi-shell:10-22` already carried:

- the mechanism (`apparmor_restrict_unprivileged_userns=1` denies userns to *unprofiled*
  processes; a named profile granting `userns,` is exempt);
- the consequence (glycin's `bwrap` loader fails → GTK's `image-missing` fallback fails →
  `gtkiconhelper.c:495` asserts → SIGABRT);
- the **measurement** (0/24 launches abort from a profiled shell; deterministic from an
  unprofiled one); and
- the sentence that killed the leading candidate fix before it was proposed: *"This is not
  avoidable in our code: the icon request comes from GTK3 window creation itself — identical
  with our bundle, with about:blank, and with a bare GtkWindow containing no WebKit at all."*

Both participants missed it. The operator proposed the icon-theme measurement as the
discriminator; the implementer designed a fix option around avoiding icons. **Both reasoned
from the symptom instead of checking whether the project had already answered it.**

**Name the failure precisely, because the obvious lesson is the wrong one.** It is not "write
it down" — it *was* written down, deliberately and well. It is:

> **The answer being written down does not help if nobody greps for it.**

**Foreclosing discipline.** Before diagnosing a mechanism, grep the repo for it. The
highest-value grep is **the component name plus the error string** (`delphi-shell` + `userns`,
`SIGABRT`, `bwrap`) — and it must be **formed before the first hypothesis, not after the third
one dies.** By then the search is shaped by the surviving hypotheses and looks for
confirmation rather than for prior art.

**RED-proof shape.** Procedural. The check is that the grep happened first and is recorded in
the diagnosis, alongside the hypotheses it pre-empted.

---

## 29. Resource exhaustion presents as flakiness  *(new — D0 lane run)*

**Description.** A per-iteration resource leak accumulates until the resource runs out. The
run then fails in a batch, and the batch reads as *intermittency* — because the failures are
consecutive, unrelated to the assertions, and disappear when the resource is replenished.

**Instance (grounded).** `leader_is_shell`, 30 serial iterations: **9 consecutive failures,
then 21 passes.** That shape is not a flaky test — a flaky test scatters. It was **exhaustion
from the previous run's debris**, cleared partway through. From a clean baseline the same
suite ran **10/10**.

The leak: **one system account per PASSING iteration**, from four of the five tests
(`delphi-b1`, `-b3`, `-fd01`, `-p1`) and not the fifth (`-r402`). `/run` dirs stayed at **0**
throughout — the directory cleanup was RAII and worked; the account cleanup depended on a
layer nobody had touched.

**Two diagnostic tells, both cheap:**

- **Consecutive-then-clean** beats scattered. `9 then 21` is a baseline problem;
  `1 in 10, randomly placed` is instability. Read the *positions* of failures, not the rate.
- **The passing runs are the leakers.** A leak on the success path is invisible to every
  assertion, so the suite that reports green is the one filling the resource. Count the
  resource before and after a *passing* run.

**Foreclosing primitive.** **Tear down at the layer that owns the resource.** The leak here
survived a careful fix that signalled *processes* and waited on pids, because `userdel`
refuses while the user is registered as **logged in** — logind/utmp state, not process state.
`loginctl terminate-user` is the missing layer. The general form: when cleanup fails,
establish *which layer* holds the resource before adding force to the layer you already have.

**And capture the failure's reason.** Both `Setup::drop`s discarded `userdel`'s stderr (one
discarded its exit status entirely), so the cause was rediscovered from the outside instead of
being printed at the moment it happened.

**RED-proof shape.** Count the resource before and after **N passing iterations** and assert
the delta is zero. A green suite is not evidence of no leak; only the count is.

---

## 31. A teardown whose failure is unobservable is not cleanup — it is a hope  *(new — D0)*

**Description.** Cleanup runs, fails, and says nothing. The failure is invisible **not because
it is rare but because nothing looks**: the exit status is discarded, or the error text is
inherited into a stream nobody reads. The leak then accumulates for as long as the code exists,
and surfaces only when some *other* thing breaks against the exhausted resource.

**Instance (grounded).** `b1_integration`'s `Setup::drop` ran
`let _ = Command::new("userdel").arg(&self.user).status();`. The `let _` discarded the status.
`userdel` had been failing — silently — **for the entire life of B1**. Measured when it finally
surfaced: **333 stale accounts**, uid 1001–1377, across every tag the suite uses. They were
removed in one bulk pass with **no refusals**, which confirms nothing had ever been holding
them: they had simply never been removed.

It surfaced only because a *different* failure (a stale session on the wrong VT) sent someone
looking at system state at all.

**Same family as the skip-count problem, and worse in degree.** Both are a green reporting on
work not done. The skip count at least printed something a reader could have checked; this
printed nothing, so there was no green to disbelieve — only an absence, and absences are not
noticed.

**Foreclosing rule — two clauses, and the second is what makes it a rule rather than advice:**

> **A teardown that can fail MUST report its failure. If it cannot report, it must ASSERT.**

A `Drop` cannot return a `Result`, which is exactly why `let _ =` is so tempting there — and
exactly why the reporting obligation has to be stated: the language will not enforce it.

**And capture the REASON, not just the fact.** The fix takes `userdel`'s stderr via `.output()`
and prints it. Previously stderr was *inherited*, so the message existed but was buried in
surrounding test output — which is why the cause had to be rediscovered from outside instead of
being read at the moment it happened. **The difference between a reported failure and a
self-diagnosing one is whether the next reader has to reproduce it.**

**RED-proof shape.** Force the teardown to fail (hold the resource, revoke the permission) and
assert the run *says so*. A teardown tested only on the path where it succeeds is untested —
and that path is the common one, which is why this survives so long.

---

## 29a. A resource-holder check must name the resource the SUBJECT uses  *(D0 lane run)*

**Description.** A cleanup or precondition check is written while diagnosing one failure, and
silently inherits that failure's specifics — its resource type, its VT, its path. It then
reports clean for a *different* holder of the *same* resource, and the next failure is
attributed to code.

**Instance (grounded).** The weaken-cleanup section checked for **processes on tty3**, because
it was written for the weaken's tty3 scenario. The real survivor was a **session on tty1**
(`c523`, `delphi-r402-119101`) — tty1 being the VT the tests actually use. Two errors in one
check, and each alone was enough:

- **wrong resource** — a logind session outlives its last process in `closing`, and it is the
  *session*, not the process, that holds the VT;
- **wrong VT** — hard-coded from the scenario being debugged rather than read from the subject.

Cost: **three wrong diagnoses.** A just-landed cleanup fix was blamed first (0/30 immediately
after it merged — a coincidence in time reading as causation), then PAM. Ground truth came from
the journal.

**The discriminating question:** *does this check name the resource the SUBJECT acquires, or the
resource the LAST FAILURE happened to expose?* A check written during a diagnosis is
fitted to that diagnosis unless deliberately generalised.

**Foreclosing primitive.** `scripts/check-stale-test-sessions.sh` — one script, used by both the
go/no-go block and the post-weaken cleanup, matching **any** session owned by a test-account
pattern on **any** VT. One construction site, so the two callers cannot disagree; and it names
sessions first because only a session holds the VT.

**RED-proof shape.** Replay the real survivor's `loginctl` line through the check and require a
non-zero exit naming it. Verified against `c523 1377 delphi-r402-119101 seat0 119101 user tty1`.

---

## 30. The stale binary — a rebuild that does not rebuild  *(new — D0 lane run)*

**Description.** A test binary is re-run after a source change and silently exercises the OLD
code, because the change was in a *linked library* rather than in the test crate, and the
apparent identity checks (a reported hash, "it recompiled") do not distinguish the two.

**Instance (grounded).** After reverting the `ShellGuard` weaken, 30 iterations were run
against a binary **built before the revert** — so the weakened guard was still under test.
`cargo test --no-run` reported **the same hash** for the test binary, because only the linked
library had changed.

**The tell is `mtime`, not the hash.** Compare the test binary's modification time against the
source file you changed:

```bash
stat -c '%y %n' runtime/src/launcher.rs "$CARGO_TARGET_DIR"/debug/deps/leader_is_shell-*
```

If the binary is older than the source, the run is measuring the previous state — whatever any
hash says.

**Why it belongs beside DEFECT_CLASSES 18.** The verification loop's weaken/restore step is
exactly where this bites: restore, re-run, observe green, conclude the restore worked — when
what was measured was the un-restored build. **A restore verified only by "the test is green
again" was already known to be unproven; this is a second way for the same green to lie.**

**Foreclosing primitive.** Discipline: after any weaken/restore that touches a *library*
crate, force the dependent test binary to rebuild (touch the test source, or `cargo clean -p`
the crate) and confirm by `mtime` before believing the run.

---

## 32. A mechanically-correct substitution, semantically wrong through an undocumented property  *(new — D0-R6)*

**Description.** Code is replaced by something that is *the same kind of thing* — a temp dir
for a temp dir, a socket for a socket — and the replacement is correct in every respect anyone
wrote down. It breaks because the **original had a property nobody recorded as load-bearing**,
usually one it got for free from a default.

**Instances (grounded), and the pair is the point:**

| replaced | with | the unrecorded property |
|---|---|---|
| `PathBuf::from("/tmp/…")` | `tempfile::tempdir()` | bare `/tmp` paths inherited permissive modes; `tempdir()` is **0700 root-owned**, and a privilege-dropped child could no longer write the shared file (D0-R6-03) |
| `socketpair(… SockFlag::empty())` | (production used `SOCK_CLOEXEC`) | the *absence* of `CLOEXEC` let sibling `Command::spawn` children inherit the fd and suppress `POLLHUP` |

Both substitutions were mechanical, reviewed, and wrong. Neither property appeared in a
comment, a test name, or an assertion — they were **accidents of a default** that the
surrounding code had quietly come to depend on.

**Why it evades review.** A reviewer checks that the replacement does what the original *said*
it did. The defect lives in what the original *also happened to do*. Nothing in the diff points
at it, and the substitution reads as an improvement — which it is, on every axis anyone named.

**Foreclosing question, to be asked at the moment of substitution:**

> **What unstated property of the thing being replaced is the caller relying on?**

Permissions, ownership, CLOEXEC, buffering, lifetime, ordering, and mode are the usual answers.
Where such a property is found, **make it explicit in the replacement** (`chown`/`chmod` the
temp dir, pass `SOCK_CLOEXEC`) rather than trusting the new default to coincide.

**RED-proof shape.** Exercise the path that consumed the property — here, the privilege-dropped
child actually writing the file. Both instances were invisible until something *downstream of
the property* ran: the priv-drop for one, a concurrent `Command::spawn` for the other. A test
that only constructs the resource will not see it.

---

## 33. The diagnostic path is the least-executed code in the tool  *(new — lane run 2)*

**Both defects lane run 2 found are this class, and neither is in a mechanism — both are in
what a mechanism SAYS when it fires.**

1. `scripts/check-stale-test-sessions.sh`'s **report branch** — the code that runs only when a
   stale session IS found — had never been executed by anything. A backtick inside a
   double-quoted `echo` therefore shipped: `` `closing` `` ran as a command, printing
   `closing: command not found` and leaving a hole in the sentence. The tool exists to make an
   obscure `VirtualTerminalAlreadyTaken` legible, and the code that does the making-legible was
   its only untested part.
2. `real_webkit_load`'s staleness guard printed the **installed** path and two hash prefixes,
   but never the **built** path. It refused four times, correctly, and was read as a false
   positive — because the operator could not see that the two sides came from different target
   dirs. Its suggested FIX (`sudo installer/install.sh`) was also wrong for that cause, so
   following the message could not converge.

**THE DURABLE FORM, because it generalises past both instances: a diagnostic that names one
side of a comparison cannot diagnose a divergence in the other.** The staleness guard compared
two binaries and printed one path; nothing on screen could reveal that the two sides came from
different target dirs, and its suggested fix (reinstall) could not converge for that cause. A
message about a mismatch owes BOTH operands — a comparison reported half is not a comparison
reported, it is an assertion the reader cannot check.

**Why this class is not just "test your code".** Success paths are exercised constantly by
ordinary use; diagnostic paths run only during failures, which are rare, unrepeatable, and
happen when attention is on the failure rather than the message. So the message accumulates
defects that nothing removes — and it is the artifact a human acts on. A wrong diagnostic is
worse than a silent failure: it spends the operator's attention in the wrong place. Lane run 2
spent four attempts and a manual `cp` on one.

**Foreclosing primitive: none — a discipline.** A tool that reports MUST have its reporting
branch executed by a test that asserts the TEXT, and any message naming one side of a
comparison must name both. Instance: `scripts/check-stale-test-sessions.test.sh` stubs
`loginctl` from a fixture so both branches are reachable without a seat, and asserts the
survivor's id, user, VT, the `terminate-session` command, and the literal sentence.

**RED-proof shape.** Reintroduce the defect in the message and confirm the suite fails on the
text — done for the backtick (suite rc=1 with it, rc=0 without). For a comparison message,
assert both operands appear.

---

## 34. A deferral is an untested claim  *(new — D0-A, three instances in one increment)*

**The pattern: "needs the lane" was written from the author's model of why a test skipped, not
from measuring what it actually lacked.** Examined three times on this branch, it was wrong
three times — and always in the same direction, which is what makes it a bias rather than three
unlucky entries.

| entry | recorded as | what it actually was |
|---|---|---|
| D0A-R1-02 orchestration test | "compile-verified, needs the lane" | **unprovable as written** — it passed env names that exist nowhere, so it could not have run on ANY machine, lane included |
| D0A-R1-01 answer-discrimination | "needs a real session ⇒ lane-only" | **root-gated** — any box with a resolvable logind session; settled by `sudo` on the dev box |
| D0A-R1-02, after R2-01 | "needs the lane" (again) | **root-gated** — the PAM stack, not a seat |

**THE MECHANISM, and it is precise: the SKIP CONDITION and the LEDGER'S DEFERRAL CATEGORY are
different claims, and only the first is ever checked.** `if geteuid() != 0 { eprintln!("SKIP:
requires root") }` is accurate and testable. The ledger entry that grows from it — "owed to the
lane" — is a *larger* claim about what environment is required, written by hand, never verified,
and load-bearing for scheduling. Nothing in the toolchain compares the two.

**Why the bias runs one way.** An expensive deferral is never falsified by the work stopping:
the task simply waits, the entry looks prudent, and no one pays to discover it was cheaper. A
*cheap* mis-categorisation would be caught within minutes by someone trying it. So the error is
selected for.

**The check, and it is one command.** Before writing a deferral, run the thing and read what it
actually says it lacks. `geteuid`, a missing binary, a missing PAM stack and a missing seat are
four different constraints; only one of them is a lane. If the answer is "I have not run it",
the honest entry names *that*, not an environment.

**Foreclosing discipline:** a deferral entry must quote the **measured** blocker — the skip line,
the error, the missing file — not a category. "SKIPS: `requires root (anchor + PAM)`" is a fact.
"Needs the lane" is a forecast.

---

## 35. Use a cited boundary to design the falsifier for the citation  *(new — D0A-R3-01; a technique, not a defect)*

Recorded because it converted the arc's largest outstanding delegation from a citation into a
measurement, and the move is reusable.

**The situation.** A fix rests on behaviour inside a dependency (`sd_pidfd_get_session`
re-verifies the pidfd after resolving). The claim came from a reviewer reading systemd's source.
**A citation is not a measurement**, but the step is internal and cannot be observed directly.

**The move.** Ask the citation for its own boundary, then build the configuration that lands
*inside* it. Here: *verification runs only on SUCCESSFUL session-returning paths, and is skipped
on error paths such as `ENODATA`.* That boundary dictates the experiment — put the **impostor**
in the session, not the victim, because only a successful lookup reaches the step under test.
The naive arrangement (victim in the session) returns `ENODATA` and proves nothing, which is why
the first two attempts read as "no discrimination available off-lane".

**The result, on this machine:**

| run | configuration | result |
|---|---|---|
| control | victim in a real session, barrier inert | `rc=0 session=2` |
| barrier | impostor in the session, victim reaped and its pid recycled mid-call | `rc=-3` (ESRCH) |

**The control is not optional.** `rc != 0` is satisfied by any box where nothing resolves — the
exact way the previous harness fooled itself. Proving the environment CAN produce a positive is
what converts a negative from ambiguous to real. Pair every falsifier with a positive control
that would fail if the environment were incapable.

---

## 36. A stale assertion masks an unfaithful fixture  *(new — D0A-R4-12)*

**Repairing the assertion alone PRESERVES the mask.**

R1-02's fixture returned `SessionSnapshot::DENIED` — all three axes false — to model "the
session stopped qualifying during authentication". That is an **impossible session**: a session
that loses the seat's foreground *keeps its seat*. So the test was proving a transition that
cannot occur.

Nothing surfaced it, because the assertion was pinned to a literal sentence that the
all-false shape happened to produce. The two errors agreed with each other. When D0A-R4-04
rewrote the denial wording to derive from the failing axes, the assertion broke — and the
obvious repair (swap in the new literal) would have restored the agreement and left the
fixture still modelling an impossible event.

**The check:** when an assertion breaks because the code under it changed, ask whether the
FIXTURE still models something that can happen — not just whether the new expectation matches.
A literal assertion and a wrong fixture are mutually stabilising: each makes the other look
correct, and only an external change disturbs the pair.

**Foreclosing discipline:** assert the PROPERTIES a result must carry (it names the failing
axis; it says the change happened during authentication; it does *not* claim axes that did not
fail), never the sentence. A property assertion fails against a wrong fixture; a literal one
agrees with it.

---

## 37. Remediation is where a class reappears  *(unifies 22 and 36's recurrence — D0A-R5)*

**The cause behind both: whoever writes the fix is reasoning in the frame that produced the
defect, so the frame's blind spot survives the repair.**

This is not a description after the fact — it **predicts where to look**:

> **The highest-yield place to look for instance N+1 of any class is the diff that fixed
> instance N.**

Five instances, across DIFFERENT classes, all at remediation:

| instance | appeared inside the fix for |
|---|---|
| R2-01c | R2-01b |
| the barrier test sampling around the interval | a fix for sampling around the interval |
| R5-04 (pipe retention) | R5-01's guard, within a minute |
| R5-06 (untested mapping) | R4-05's classifier extraction |
| R5-02 (trusted parent) | R4-01's unpredictable name |

**THE CAVEAT THAT KEEPS THIS USEFUL — the distinct foreclosures are NOT merged.** Unifying the
*cause* must not average the *remedies*, or the entry becomes "be careful at remediation",
which is weaker than either parent:

- **Class 22's foreclosure stands unchanged:** weaken (a) and weaken (b); verify the weaken
  APPLIED *and* that it failed for its **stated reason**.
- **Class 36's foreclosure stands unchanged:** assert PROPERTIES, never literals; and check the
  fixture models something that **can happen**.
- **This entry adds only the search rule**, which neither parent states: when a fix lands, read
  it as the most likely home of the next instance of the same class — and of a different one.

**Class 17 is adjacent but distinct**, and the record supports keeping them apart: Class 17 is
*the reported instance was one of several* (four instances this arc — R2-01's env names,
R4-07's second spawn site, `reap_and_recycle`'s `atoi`, R5-02's parent). Class 17 is about
**breadth at the time of the fix**; this entry is about **recurrence in the fix itself**. A
sweep answers the first and does nothing for the second.

---

## 38. A sound check whose report carries none of what it verified  *(D0A-R7-09 — DEMOTED to a convention, D0A-R8)*

**REVIEWER JUDGEMENT, ACCEPTED: this is a TRANSCRIPT CONVENTION, not a defect class.** It was
promoted on my argument that a silent-but-correct check "never fails at all"; Codex judged that
over-promoted, and the distinction holds — every other entry here describes something that can
make a wrong claim, while this describes something that makes a *correct* claim illegibly. The
discipline below is worth keeping and following; the framing as a defect class was mine and was
too strong.

Kept in place rather than deleted, because the argument for promoting it is the thing a later
reader should be able to weigh.

**Every prior entry in this corpus is a check that was WRONG. This one is a check that was
RIGHT and unreadable.**

Leg 1 of the R4-03 test asserts a structured gate witness: absence panics on its own named
branch, and `Resolved { active: false, remote: false, seated: true }` is checked field by field.
The assertion is correct and the evidence existed. **The transcript printed `ok`** — because the
test pipes the daemon's stdout into its own sink, so the witness surfaces only inside a FAILURE
message.

**Why that is a defect and not a cosmetic complaint: `ok` from a sound check is indistinguishable
from `ok` from a skip, a vacuous assertion, or a check that never ran.** This project has shipped
all three (Class 10's skip-scored-as-pass, D0A-R6-01's cause-blind gate assertion, D0A-R5-05's
pre-gate false pass), and the reader cannot tell them apart from the output. The correctness of
the check is invisible at exactly the moment someone is deciding whether to trust it.

**The asymmetry that makes this worth its own entry:** a wrong check fails loudly the first time
its subject changes. A silent-but-correct check never fails at all — it simply stops being
believed, or worse, keeps being believed for the wrong reason. Nothing disturbs the pair.

**Foreclosing discipline:** a passing check that establishes a non-obvious property must PRINT
the evidence it established. Not the assertion text — the observed value. `[leg 1 witness]
Resolved(SessionSnapshot { active: false, remote: false, seated: true })` is a transcript a
reader can audit; `ok` is a transcript that requires trusting that an assertion exists and says
what it should.

**Related but distinct:** Class 10 is *the harness reporting success for work it did not do*;
this is *the harness reporting success for work it DID do, without saying what*. The first is a
false claim, the second is an unsupported one.

---

## 39. A first-ordered check that never fires in time  *(new — the D1 measurement session; a DISCIPLINE failure, and the corpus's first entry with nothing to build)*

**The root filesystem reached 97% (1.5 G free). Git wrote six zero-byte objects, advanced the
branch ref to one of them, and corrupted `.git/index`.** `fatal: could not parse HEAD`. No commits
were lost — the reflog named the last good commit and every *reachable* object still read cleanly
— but the tree was one careless `--hard` away from real loss.

**It presented as a Python `AssertionError`.** That assert was correct and was firing for an
unrelated reason. Then it presented as git object corruption. **Two layers of misattribution
before the substrate was suspected.**

**Why this is not Class 29.** 29 is a resource the *test* owns, leaking across iterations,
presenting as flakiness. This is a **global** resource whose exhaustion presents as an unrelated
tool's bug — and, crucially, one whose check **already existed and was already ordered first**.

**The distinguishing fact, and the reason the remedy differs from every other entry here:
`scripts/check-free-space.sh` exists, names WHICH path is short, and §13.4 orders it FIRST. It
would have caught this. It was not run.** There is nothing to extract. Every other class in this
corpus ends in a primitive or a rule that did not exist yet; this one ends in a rule that did.

**Where the discipline actually fails, stated precisely rather than as "remember to run it":**
§13.4's audit runs at the **end** of a work block. Exhaustion corrupts **during** one. A check
ordered first *within a terminal audit* still runs after the damage. The defect is in the
**trigger**, not the tool.

**Foreclosing discipline (two triggers, not one):**

1. Run the space check at the **start** of a block and before any **bulk write** — a multi-file
   commit, a cargo build, a full test run — not only in the closing audit.
2. **On any unexplained tool failure, check the shared substrate before diagnosing the tool.**

**This extends Iron Law #15 clause 5 one layer down.** Clause 5 says suspect the *harness* before
the code. This says suspect the *substrate* before the harness — and it inherits clause 5's
asymmetry unchanged: substrate exhaustion must be **demonstrated** (`df`, the checker's own
output), never offered as a guess to explain an inconvenient red.

---

### Instance, 2026-08-23 — a COMMENT that executes (class 39, loud end)

A comment written into an **unquoted** heredoc quoted two flags in backticks. Backticks are
command substitution, so bash ran them: `--tests: command not found`, twice per fixture built.

Same mechanism as the Rust-continuation-through-Python instance above — **the tool writing the
text and the shell reading it disagree about escapes, and the artifact exists and looks
plausible** — but at the opposite volume. That one wrote a silently wrong literal; this one
shouted. The volume is luck, not a property of the class: a comment is exactly where nobody
looks for executable content, and had the substitution succeeded quietly it would have been
the silent form.

## 40. The sandbox's own scaffolding blocks the measurement  *(new — D0A-R9-01; THREE instances before it was named)*

**Measured, unprivileged, in one command:**

```
/run             mode=700 uid=1000     <- auto-created intermediate
/run/deep        mode=700 uid=1000     <- auto-created intermediate
/run/deep/probe  mode=777 uid=1000     <- the bind, showing the SOURCE's mode
```

**bwrap creates every auto-intermediate directory as `0700`, owned by the sandbox uid.** Only the
bind target itself carries the source's mode. So any measurement of a path beneath a bind whose
parent does not already exist in the jail measures **the scaffolding, not the property**.

**Three instances before it was named**, which is what earns it an entry: leg E died on `/tmp`
three times (diagnosed by guessing twice, then by walking the path), and leg P then died on
`/run` — a different path, the same cause, one round later.

**Why it is more than a probe nuisance — it is a PRODUCTION constraint on D0A-R9-01.** The
sandbox uid is whoever ran bwrap:

* If the payload keeps the uid bwrap ran as, it **owns** the `0700` intermediates and traverses
  them. This is why the defect was invisible while the tool ran as root.
* If the payload **drops to a different uid**, every bind under a not-yet-existing parent becomes
  unreachable to it. Closing that requires the profile to emit `--perms 0755 --dir <ancestor>`
  for **every ancestor of every approved bind** — real complexity for arbitrary paths, and a
  requirement that only appears once the tool stops being root.

**Foreclosing discipline, two parts:**

1. **In production:** a profile that drops the payload's uid must create the ancestors of every
   bind explicitly, with traversable modes. Never rely on bwrap's defaults.
2. **In any probe:** pair the measurement with a **positive control** (class 35). A traversal
   failure and the property being measured are frequently indistinguishable — leg P's desired
   result was a *refused* connect, so scaffolding that blocked traversal produced the exact
   output a success would produce. **A probe whose failure mode is indistinguishable from its
   success condition is not a measurement.**

---

## Calibration — the one suspicion this arc raised that did NOT hold *(2026-08-15)*

Recorded deliberately, because **a rule that only ever fires correctly stops being checked**, and
every other entry here is a suspicion that paid off.

R9-01's root test passed in **0.03 s** and printed nothing. The suspicion — "too fast to have
spawned bwrap, built a jail, exec'd a helper, dropped credentials and run a tool" — was reasonable
and was the right instinct given this session's history of greens that could not fail.

**It was wrong, and measurement is what settled it**, not argument: a full jail + `/bin/sh` +
`id -u` takes **11 ms** on that box, and the sibling bwrap-spawning tests finish in 0.01–0.02 s.
0.03 s was the *slow* end. The re-run, provably doing the work, took 0.01 s.

**The silence was a separate and real defect** (class 38): the tool wrote `id -u` to a FILE and the
test asserted on the contents without surfacing them, so a correct pass printed exactly what a
vacuous one would. Two independent signals, one sound and one not — and reading them as a single
"something is wrong here" would have sent the fix at the wrong target.

**The discipline that generalises:** an anomaly flag is a hypothesis, and it owes the same
measurement a harness excuse owes (Iron Law #15 clause 5's asymmetry, applied in the other
direction). *Timing* is the weakest of these signals, because it has no baseline until one is
taken — so take the baseline before spending a round on the anomaly.

---

## 41. The assertion is at the wrong ALTITUDE  *(new — D0A-R10; THREE instances in one round)*

**THE DISCRIMINATING QUESTION: does the assertion observe the layer where the property would
actually be VIOLATED?**

Three instances in a single round, which is what earns the entry:

| the assertion observed | the property lives in | what was missed |
|---|---|---|
| bwrap's emitted `--argv0` flag | the **kernel's exec handling** — for a shebang script the kernel rebuilds the interpreter's argv from the script path | `$0` cannot observe `--argv0` at all; the test was wrong, not the code |
| the emitted `--perms/--dir` args | the **filesystem** — bwrap creates a missing bind ancestor itself, through the enclosing mount | filtering the ancestor stopped *our* emission, never bwrap's write to the host |
| the error **string** `execvp: No such file or directory` | the **process** — that errno is the signature of a missing loader **and** of a missing fd | a red with no discriminating power; it would have failed identically either way |

**Why it happens, and it is not carelessness:** the assertion drifts to where **observation is
cheap**. Args are a `Vec<String>` you can inspect in a unit test; filesystems, kernels and errnos
need a real run, a before/after comparison, or a second discriminating leg. So the test gets
written at the altitude that is convenient rather than the altitude the property occupies, and it
then passes for reasons unrelated to the claim.

**Distinct from two neighbours it is easily confused with:**

* **Class 25** — the *fixture* diverges from its subject. There the altitude is right and the
  setup is wrong.
* **Class 38** — the check is correct and its *output* carries none of what it verified. There
  the altitude is right and the report is silent.
* **This** — the check is pointed at the wrong altitude entirely, so no amount of better fixture
  or louder output would help.

**Foreclosing discipline:** before writing the assertion, name the layer at which a violation
would first become observable, and assert **there**. If that requires a real run, a before/after
snapshot, or a second leg to separate two causes of one symptom, that cost *is* the test — an
argv-level proxy for a filesystem-level property is not a cheaper version of the test, it is a
different test that does not bite.

---

### Instance, 2026-08-26 — the class in an ANALYSIS rather than in an assertion

**First occurrence of class 41 in a sweep instead of a test.** A dead-code pass over
`runtime/src/**` asked "which `pub`/`pub(crate)` functions have no reference **outside their
own file**?" and returned **eight**. All eight were false: they are module-internal helpers,
used within the files that define them. The predicate was measuring **cross-file** usage while
the question was **any** usage — the wrong altitude, and it produced a list of eight
deletion candidates in security-relevant modules (`logind.rs`, `service.rs`,
`consent_relay.rs`).

Caught by re-checking with total reference counts, not by the sweep. **What makes it worth an
entry: a wrong-altitude assertion fails loudly at the wrong moment, but a wrong-altitude
ANALYSIS produces a confident list that someone then acts on.** There is no red to notice.

The corrected predicate is the trivial one — count all references and subtract the
definition. The generalisation: **when a sweep's output is a list of things to remove, the
predicate needs the same weaken/restore treatment as an assertion** — run it against a symbol
known to be live and confirm it is not listed. The eight false positives were exactly that
control, arrived at by accident.

## 42. A negative assertion whose sufficiency rested on a default the change removed  *(new — D0A-R10, found by mutation audit)*

**The test did not change. What its assertion was sufficient to prove did.**

`net_policy_maps_faithfully_and_cannot_express_an_allowlist` asserted, for
`NetPolicy::None`, that `--share-net` is **absent**. That was a complete proof while the
profile began with `--unshare-all`, which implies the unshare: absence of the opt-in meant
isolation. Shape E replaced `--unshare-all` with an explicit namespace list, so isolation
became an **opt-in of its own** (`--unshare-net`) — and bwrap's default is a **shared**
network. Deleting the `NetPolicy::None` arm entirely left the old assertion true and the
approved-no-network action on the host's network. Measured: the deletion passed the whole
suite.

**Why it evades every existing rule.** The test was not weakened, was not vacuous when
written, is at the right altitude, and its fixture is faithful. Nothing about *it* is
wrong. The defect is that a **negative** ("the widening flag is absent") is only equivalent
to a **positive** ("the narrowing is applied") under an assumption held elsewhere, and that
assumption was deleted three files away by a change nobody connected to this test.

**Distinct from its neighbours:** class 22 is a *fix* inheriting the class it closed; class
26 is a *captured value* read as current; class 41 is the *wrong layer*. This is a
still-correct assertion that quietly stopped being *sufficient*.

**Foreclosing discipline — assert the POSITIVE for any property that has one.** "The
dangerous flag is absent" is evidence only alongside "the protective flag is present". When
a change removes an umbrella default (`--unshare-all`, a deny-by-default base, a global
`set -e`), the audit is not "which behaviours changed" but **"which assertions were
relying on that default to mean what they say"** — and those are found by deleting the new
explicit thing and seeing whether anything fails, not by reading.

**ONE instance, not two — corrected 2026-08-21 (D0A-R11-08).** `--clearenv` was written up
here as a second instance and it is not one: no assertion's sufficiency changed, because no
assertion ever covered it. That is ordinary missing coverage, found by mutation, and filing
it here inflated a class with a case that does not exhibit it. The distinction the entry
turns on is precisely that the network assertion **was complete when written** — so an
example where nothing was ever written cannot illustrate it.

**The class therefore rests on a single grounded instance.** Recorded as such rather than
padded: a corpus entry supported by one real case and one miscategorised case is weaker
than one supported by one real case, because the reader learns the wrong boundary.

---

## 43. One error string, two processes — diagnose from the CHILD's own output  *(new — D0A-R9-02; second occurrence of a class that had already cost a false RED)*

**`execvp: No such file or directory` has two causes in two different processes**, and the
string cannot tell them apart:

| reading | whose state | how it happens |
|---|---|---|
| "the program fd did not survive" | the **parent's** fd table | a keep-list miss, a CLOEXEC left set, a wrong fd number |
| "the dynamic loader is not there" | the **child's** mount namespace | the jail binds nothing, or binds the wrong set |

**Both occurrences cost real time, and the second happened with the first already written
down** in `runtime/helper/delphi-drop.rs`:

* the drop helper's first RED was **false** — it failed with this string and was read as
  proving a static-linking requirement, when it was a missing loader (the helper was
  dynamically linked at the time);
* `canonicalize_for_test` passed `fs_binds: vec![]`, so a dynamically linked ELF ran in a
  jail binding nothing. The same string appeared, and the working hypothesis became "the
  sealed memfd is not executable on this kernel" — a conclusion that would have been wrong
  in a specific and expensive way, since the next step was to redesign around fs-verity.

**What broke the tie both times was the same, and it is not cleverness:** print the
**subprocess's own stderr** instead of reasoning about the parent's fd table. `bwrap` says
which path it could not exec; the parent can only be inferred about. A second measurement —
a direct `memfd_create` + `F_ADD_SEALS` + `execv` probe returning `F_GET_SEALS = 0x3f` and
child exit 0 — killed the wrong hypothesis in under a minute.

**Foreclosing discipline:** an assertion about a spawned process must **carry that process's
stderr in its failure message**. Not as a courtesy — as the thing that makes the failure
attributable at all. Grounded: `same_inode_overwrite_…`'s assertion printed only the exit
code, so the first reading was "exit 1 is gnufalse's" — the substituted binary — when exit 1
was **bwrap's own** and the tool had never run. One line of `String::from_utf8_lossy(&out.stderr)`
turned an hour's misattribution into one read.

**Distinct from class 33** (the diagnostic path is the least-executed code): there the
diagnostic is *wrong when it finally runs*. Here the diagnostic is *absent*, and the string
that remains is ambiguous by construction — no amount of care reading it distinguishes the
two processes.

---

## 44. A restore whose PRECONDITION is absent looks exactly like a successful one  *(new — D0A-R14 remediation; the mechanism existed and was not used)*

**What happened.** After weakening a check to prove it bites, the restore was
`cp "$W/exA.keep" runtime/src/execute.rs`. The backup had never been written — the scratchpad
directory did not exist, so the earlier `cp` had failed too. The restore `cp` then failed
identically. **The next two commands measured the WEAKENED tree and reported clean:**
`EXECUTED 137 / SKIPPED 23` and `clippy rc=0`, both of code that no longer existed as
committed.

**What caught it was the ABSENCE of a line.** Not an error, not a failing test, not a diff —
the `&& echo "restored byte-identical"` never printed, and only reading for a line that
wasn't there separated a clean measurement from a fictional one. Nothing else in the pipeline
disagreed.

**Why "verify the restore" is the wrong remedy, and this is the point of the entry:** the
rule already existed (`CLAUDE.md` §6, and class 18's "verify a RESTORE by diff, never by
green"), and it was broken anyway by someone who had written it down twice that week. This is
the same shape as class 42's `--unshare-net`: **a mechanism present and not used.**

**The remedy is that a restore step must FAIL LOUDLY WHEN ITS OWN PRECONDITION IS ABSENT.**
At the exit-code level being watched, `cp` from a nonexistent path and `cp` from a valid one
are indistinguishable — the failure is on stderr, in a pipeline whose next command overwrites
attention with a green. So:

```bash
cp "$FILE" "$BACKUP" || { echo "BACKUP FAILED — do not weaken"; exit 2; }   # before touching anything
… weaken, measure …
cp "$BACKUP" "$FILE" || { echo "RESTORE FAILED — the tree is WEAKENED"; exit 2; }
diff -q "$BACKUP" "$FILE" || { echo "RESTORE INCOMPLETE"; exit 2; }
```

**The ordering matters more than the checks:** the backup's success is a precondition of the
weaken, not a step beside it. A weaken performed without a proven backup is a change with no
way home, and the moment to discover that is before the tree is modified — not after two
measurements have been published from it.

**Distinct from class 18** (the verification loop mutates its subject): there the *subject*
is destroyed and the discipline is a tracked-ness pre-flight. Here the *restore* silently
does nothing, the subject survives in a modified state, and every downstream measurement is
of the wrong tree while reporting success.

---

## 45. The TOTALITY CLAIM — asserting an absence you cannot measure  *(new — D0A-R17-01; FOUR instances, and the rule that was supposed to stop it was scoped to one document)*

**The shape.** A claim that some path is *absent* — "no handler", "no downstream hops", "not
weaken-provable", "cannot be constructed" — is a claim about **every** mechanism and every
configuration. It cannot be measured. A claim about what is **bound** can be.

**Four instances, all falsified by measurement, none by argument:**

| # | claim | falsified by |
|---|---|---|
| 1 | v7's contract version | D0A-R14 |
| 2 | named limit 2 — the loader is an immutable platform TCB member | D0A-R14-01 (a probe replaced the loader after sealing) |
| 3 | a static native ELF has "no handler" / "no downstream hops" | D0A-R15-02 (`binfmt_misc` dispatches on magic **before** the native handler) |
| 4 | the NNP-absent shape is "NOT WEAKEN-PROVABLE IN-TREE" | D0A-R16-01 (bwrap calls `prctl` through the PLT; `LD_PRELOAD` reaches it) |

**Why it earns its own entry rather than staying a §3 note.** After instance 3,
`docs/TRUST_MODEL.md` §3 adopted the rule *"§3 states what is BOUND. It does not state what
is UNREACHABLE."* **That rule was scoped to §3, and the class is not.** Instance 4 lived in a
**test doc comment** and in `docs/CONFORMANCE_REGISTER.md`. Worse, D0A-R17-01 then found
instance 3's own sentence **still standing in the register** after §3 had been corrected —
the correction was applied to one document while the same claim went on being asserted in
another. A rule with a document-shaped boundary does not close a class that is
sentence-shaped.

**The foreclosing discipline (no primitive; this is a writing rule):**

1. **State what is bound, never what is unreachable.** "v7 binds the first object" survived
   every probe. Every totality claim beside it fell.
2. **Where an absence is genuinely load-bearing, write it as a PRECONDITION the deployment
   enforces and verifies** — not as a property this system provides. Then it is checkable and
   its owner is named.
3. **Prefer the narrow true form.** "The only weaken I found removes the flags" would have
   been true, and would have invited the fix instead of foreclosing it. The narrow form costs
   nothing and cannot be falsified by someone spending five minutes with `readelf`.
4. **A measured absence still needs its resolution floor.** "No driver detected" without the
   instrument's noise figure is a totality claim wearing a measurement's clothes — see
   D0A-R17-04, where the between-cell effect was smaller than one cell's run-to-run spread.

**The RED-proof shape.** For any absence-claim that is load-bearing, the falsifier is
*construct the thing said not to exist*. Instance 4's took one `readelf` (is the binary
dynamically linked?) and a 20-line `LD_PRELOAD` shim. **If constructing the counterexample is
cheap, the claim was never defensible** — and the cost asymmetry is the point: minutes to
attempt, a review round to discover.

## 46. The isolated measurement cannot reach the SEAM  *(new — the chain-gap demonstration, 2026-08-26)*

**The shape.** A mechanism measured in isolation is fed inputs *you* choose. Composed, it is
fed inputs *production* chooses. Where those differ, the isolated measurement is not a weaker
version of the composed one — **it is measuring a different thing**, and it will not fail
where the composed path fails.

**The grounding instance, first run.** `env -i PATH=<dir> /usr/bin/env python3 -c …` was
measured and ran an impostor — the finding that made the `env`+`PATH` hop an exposure rather
than a gap. It was correct, reproducible, and it **could not** have surfaced what composition
surfaced immediately: `/usr/bin/env` on the box is **uutils coreutils, a MULTI-CALL binary
dispatching on `argv[0]`**. The composed action carries the *approved* `argv[0]`, so the
interpreter refused with `coreutils: unknown program 'tool'` before resolving anything. The
isolated command carried `argv[0] = /usr/bin/env`, so multi-call dispatch never fired.

**Consequence, and then a SECOND measurement that corrected the first telling.** On such a
system an `env`-shebang action whose approved `argv[0]` is not `env` does not run at all —
which was first written up as "fails CLOSED, a functionality limit and not a hole". That
framing was **local and was nearly recorded as general**: measured against GNU `env`
(`/usr/bin/gnuenv`, same box), the identical shape **runs the impostor at rc=0**, because GNU
`env` is single-purpose and does not dispatch on `argv[0]`. The refusal is a uutils property,
not a protection this design supplies.

**The compounding lesson: crossing ONE seam does not clear the class.** The composed run
found what isolation could not, and the finding's first write-up still generalised from a
single implementation. A seam crossed once is one data point.

**Relation to class 20.** Class 20's four cases were latent defects waiting for an
ENVIRONMENT nobody had used. This is a defect waiting for a COMPOSITION nobody had run. Same
consequence — dormant until the missing context arrives — different missing context, so the
foreclosing move is different: class 20 wants the environment exercised, this wants the seam
crossed.

**The foreclosing discipline.** An isolated measurement earns a finding, never a clearance.
Where a claim depends on values production supplies — `argv[0]`, the environment, fds,
credentials, the working directory — **the claim is not established until something composes
the real path**. The demonstration test is the mechanism, and its own first run is the proof
that the mechanism was needed.

**RED-proof shape.** Compose, and diagnose the first failure from the CHILD's output rather
than the parent's error (class 43). Here that discipline was written into the lane procedure
before the test existed, and it converted `left: ""` — the signature that had cost this arc
three inferences on four separate occasions — into a named cause on first use.

## 47. A DOCUMENTED FLAKE IS A HYPOTHESIS WITH A NAME ATTACHED  *(new — D0A-R21-01 remediation, 2026-08-29)*

**The shape.** A test with a recorded flake rate fails. Every surface signal agrees: the name
matches, the rate is documented, re-running is what the documentation invites. **The name
offers an excuse and it is not evidence.** A known-flaky test can also fail for a real
reason, and the exemption is exactly what makes that failure cheap to ship.

**The grounding instance.** `terminal_contract_release_produces_eof_no_wedge` is documented in
CLAUDE.md §6 at ~7–10% failure under parallel execution. It failed the pre-commit gate; three
subsequent whole-suite runs came back clean; the obvious reading was "flake, re-run". It was a
**real regression** from the change in that same commit — an ordering fix that made a
gate-denied action stop sending a preview, while the test asserted a preview arrived.

**What actually discriminated.** The panic message pointed at the change; reading the test
then established the MECHANISM — the ordering fix made a gate-denied action stop sending a
preview, and the assertion required one. **That mechanism is what settled it.** The 5/5
serial re-run was corroboration and, as D0A-R22-04 records, was run in the wrong
configuration for this test's shape and is too small a sample to compare against a rate.

**THE FIRST DISCIPLINE WRITTEN HERE WAS WRONG, AND IT WAS WRONG BY OVER-GENERALISING ONE
DIAGNOSIS (corrected 2026-09-01, D0A-R22-04).** It said: read the assertion message, confirm
serially, suspect the exemption when the change is recent. Three of those claims do not hold:

- **An assertion message does not identify the cause.** It named the change *in this
  instance*. A timing failure can trip a semantic-sounding assertion, and a semantic
  regression can surface as a timeout.
- **Serial confirmation is not a discriminator.** A genuine flake can fail serially, and a
  CONCURRENCY regression can PASS serially — which is the dangerous direction, because the
  rule would then excuse a real defect.
- **One run distinguishes nothing.** 5/5 is a sample, not a rate, and the class was written
  from it as though it were a proof.

**And the confirmation used the wrong mode for that test's shape.**
`terminal_contract_release_produces_eof_no_wedge` is an **fd/socket** test, not a fork+PAM
one, so CLAUDE.md §6's carve-out does not apply to it and its authoritative configuration is
**≥30 runs under DEFAULT PARALLEL settings**. It was confirmed with 5 serial runs — the
configuration the carve-out reserves for a different shape.

**The corrected discipline:**

1. **Treat the message and a serial run as CLUES, not verdicts.** They are cheap and they
   point somewhere; they do not conclude.
2. **Reproduce under the configuration where the failure was MEASURED.** A parallel failure
   is investigated in parallel. Switching configuration changes the subject.
3. **Establish the MECHANISM.** "Which line, and why does the change reach it" is the thing
   that ends the question — here, the ordering change made a gate-denied action stop sending a
   preview while the test asserted one arrived. That was determinable by reading, and it is
   what actually settled it.
4. **Compare RATES over ≥30 runs in the failing configuration**, per §6. A documented ~7–10%
   and an observed 100% are distinguishable only by a sample large enough to tell them apart.

**Relation to Iron Law #15 clause 5.** The law says the harness is guilty only when SHOWN to
be, and warns that an undemonstrated harness excuse is how a real defect ships green. This is
the sharpest form of that: **the excuse arrives pre-named, pre-documented, and with a
measured rate behind it.** A prior measurement of flakiness is evidence about the test's
history, never about this failure.

## 48. THE FIX IS SCOPED TO THE INSTANCE THE REVIEWER NAMED  *(new — D0A-R22, three instances in one round)*

**The shape.** A finding names an instance. The instance is fixed — correctly, at root, with
a regression. **The class is not.** The reviewer named what they found, not the boundary of
what they found, and the remediation took the example for the extent.

**Distinct from 17 and 37, and the difference decides the remedy:**

| class | what goes wrong |
|---|---|
| **17** | one defect COPIED to several sites; fixing one leaves the others |
| **37** | the FIX carries the defect it was closing |
| **48** | the fix is correct and complete FOR THE NAMED CASE, and the same class stands untouched elsewhere — the scoping error is in the REMEDIATION POLICY, not in the code |

**Three instances in round 22 alone, every one a correction I had just made somewhere else:**

- **D0A-R22-03** — R21-07 fixed the lane-record propagation defect *for run 10*. Run 11 was
  then recorded in the root baseline only, leaving the register and PROGRESS calling run 10
  current. The remedy covered a run, not the habit.
- **D0A-R22-05** — D0A-R15-02 ruled that superseded reasoning leaves the normative text; §3's
  history was relocated accordingly, and **the next commit wrote five amendments' history into
  §4**. The rule was applied to the section that had been criticised.
- **D0A-R22-06** — R21-02 corrected §4's flow where it claimed the AI receives
  `{pending_id, preview}`. The *next step of the same section* described a mint-confirm
  carrying fields the wire does not carry. One step was checked; the section was not.

**Why it recurs.** A finding arrives with an ID, a file and a line. That specificity is what
makes it actionable and is also what makes the fix's boundary feel decided. Closing the named
line feels like closing the finding, and the ledger then records it closed.

**The foreclosing discipline — one question, asked before the fix:**

> **What is the class, and where else does it hold?**

Then fix that, and say in the commit what the swept scope was. Concretely:

1. **Name the class in one sentence** without referring to the instance. If that cannot be
   done, the finding is not yet understood well enough to fix.
2. **Enumerate the other sites mechanically**, not from memory — grep the pattern, list the
   documents, walk the sibling steps. Round 22's three were all findable that way.
3. **Record the scope in the commit**, so a later reviewer can check the boundary rather than
   re-derive it. "Fixed run 11's record" and "fixed every place a lane run is called current"
   are different claims and only the second is auditable.

**RED-proof shape.** After fixing, apply the reviewer's own predicate to the rest of the tree.
If it finds a second instance, the fix was scoped to the example — which is the finding, not a
new one.

## Appendix: foreclosure status at a glance

| Class | Foreclosed by | Status |
|-------|---------------|--------|
| 1. Under-coverage hashing / non-injective | `delphi_hardening::canonical_hash` (guard + no-`..` destructure) | **Extracted** |
| 2. Path-resolution races | `delphi_hardening::safe_open` | **Extracted** |
| 3. Per-connection PRAGMA / transient-lock | `delphi_hardening::pragma_setup` | **Extracted** |
| 4. Hand-enumeration vs authoritative-category | discipline (Unicode category / RFC grammar) | Discipline |
| 5. Capability-type (convention→unforgeable type) | idiom; **PENDING `TrustedRoot`** | Idiom + 1 pending |
| 6. Correct-fixes-incorrect-composition | discipline (review composition) | Discipline |
| 7. Cross-crate regression | process (workspace gate; CI count guard) | Process |
| 8. Same post-condition, multiple paths | discipline (one choke-point) | Discipline |
| 9. Normalize-then-detect offset drift | discipline (broaden-in-place) | Discipline |
| 10. Platform test-gating masks bugs | discipline (non-gated pins; CI count guard) | Discipline |
| 11. Error-message oracles | `services::error::opaque`; **DEFERRED** (1 crate + transport-coupled) | Local helper |
| 12. Reject the invalid class | discipline (gate the class, fail-closed) | Discipline |
| 13. Atomic versioned migration | **DEFERRED** (1 consumer; extract at the 2nd) | Pattern recorded |
| 14. Guard must cover all forms | discipline (enumerate forms; read behavior, not markers) | Discipline |
| 15. Self-inspecting guard counts itself | discipline (`compile_fail` where it reaches; else scope the audit + derive the boundary loudly) | Discipline |
| 16. Fixture mutates unowned system state | discipline (adopt-or-provision; delete only what you created) | Discipline |
| 17. Defect propagated by copy | discipline (grep the shape before declaring fixed) + finder-guard where enumerable | Discipline |
| 18. Verification loop mutates its subject — **and its operational form: destroying an UNTRACKED target** | discipline (**pre-condition**: `git status --porcelain -- <target>` must be empty before ANY overwrite/discard/`HEAD` move, in a verification loop or not — **refuse on untracked**, because post-hoc "verify the artifact" cannot restore what git never held; verify a RESTORE by diff, never by green) | Discipline (mechanizable: a fail-closed tracked-ness pre-flight) |
| 19. Runs compared under different instruments | discipline (pin + record the instrument; re-run the baseline under the new one before believing a delta) | Discipline |
| 20. Correct test, non-representative environment | discipline (name the mechanism the property needs; prove it against the real component) | Discipline |
| 21. Warning banner as enforcement | discipline (sentinel prefill or non-sentinel rejection; never persist the value; state the residual up front) | Discipline |
| 22. The fix inherits the class it closed | discipline (re-apply the finding's own question to the remedy; two weakens, not one) | Discipline |
| 23. Forecasting your own code | discipline (construct an experiment; a forecast about your own work is a claim awaiting one) | Discipline |
| 24. In-band sentinel drawn from the value space | discipline (signal by exit status / separate field; return the honest value; refuse once, skip downstream) | Discipline |
| 22a. Temporal invariant decided by SAMPLING | `installer/tests/trace-invariant.py` (derive from a complete syscall record; fail closed on anything unclassifiable) | **Extracted** |
| 25. Fixture constructed differently from its subject | **call the production constructor** (`approval_socketpair`, `ensure_runtime_dir`, `pipe2(O_CLOEXEC)`); a fixture that must diverge says so and names the property the divergence serves | Discipline (foreclosed wherever a production constructor is reachable) |
| 26. Stale observation asserted in the present tense | **re-poll before concluding**; never reuse captured `revents` across a syscall boundary (the fix removes the parameter, so the stale value is unavailable); a negative becomes a positive claim only after a measured grace | Discipline + a type that withholds the stale value |
| 26. Captured observation read as a present-tense claim | **remove the stale value from scope** (do not pass `revents` across a syscall); one re-polling witness where only death returns early; inject sequences to test it | **Extracted** (mechanism, after three rules failed) |
| 27. Two correct fixes, unsound interaction | ask per pair: **does this fix rely on an invariant another fix in the same change removes?**; prefer a kernel guarantee (pidfd) over a maintained invariant (raw pid + zombie); check the seam mechanically | Discipline + mechanism |
| 28. Re-deriving a documented mechanism | discipline: grep the repo (**component name + error string**) BEFORE the first hypothesis, not after the third dies | Discipline |
| 29. Exhaustion presents as flakiness | tear down at the layer that OWNS the resource (`loginctl terminate-user` before `userdel`); count the resource across N PASSING iterations and assert delta 0 | Discipline |
| 30. Stale binary — a rebuild that does not rebuild | `mtime` not hash: a library-only change leaves the test binary's hash unchanged; force the rebuild after any weaken/restore touching a lib crate | Discipline |
| 29a. Holder-check names the wrong resource | one shared checker matching the SUBJECT's resource on ANY location (`scripts/check-stale-test-sessions.sh`), used by every caller | **Extracted** |
| 31. Teardown failure unobservable | a teardown that CAN fail must REPORT its failure; if it cannot report, it must ASSERT. Capture the reason (`.output()`), never `let _ = …status()` | Discipline |
| 38. Sound check, silent report | a passing check that establishes a non-obvious property PRINTS the observed value, not just `ok` | Discipline |
| 37. Remediation is where a class reappears | read the fix for instance N as the likeliest home of instance N+1; keep 22's and 36's foreclosures intact rather than averaging them | Search rule |
| 34. A deferral is an untested claim | quote the MEASURED blocker (skip line, error, missing file) in the ledger entry — never an environment category | Discipline |
| 35. Cited boundary → falsifier design | ask a citation for its own boundary, build the configuration inside it, and PAIR it with a positive control | Technique |
| 32. Mechanical substitution, undocumented property | ask at substitution: **what unstated property is the caller relying on?**; make it explicit in the replacement rather than trusting the new default | Discipline |
| 39. First-ordered check that never fires in time | discipline — **the mechanism already exists** (`scripts/check-free-space.sh`): run it at block START and before any bulk write; on an unexplained tool failure suspect the SUBSTRATE before the harness | Discipline (nothing to extract) |
| 40. Sandbox scaffolding blocks the measurement | bwrap auto-creates intermediates `0700` owned by the sandbox uid: emit `--perms 0755 --dir` per ancestor when the payload's uid differs, and pair every such probe with a positive control | Discipline + production constraint |
| 41. Assertion at the wrong altitude | discipline: **does the assertion observe the layer where the property would be violated?** Assert there, even when it costs a real run, a before/after snapshot, or a second discriminating leg | Discipline |
| 44. Restore with an absent precondition | discipline + shape: the BACKUP's success is a precondition of the weaken (`cp … || exit`), the restore fails loudly (`cp … || exit`), and the diff confirms it — because at the exit-code level being watched, a `cp` from a nonexistent path is indistinguishable from a successful one | Discipline (mechanizable in every weaken script) |
| 43. One error string, two processes | discipline: an assertion about a spawned process CARRIES that process's stderr in its failure message; suspect the CHILD's namespace before the PARENT's fd table when the string is `No such file or directory` | Discipline |
| 42. Negative assertion resting on a removed default | assert the POSITIVE wherever one exists ("the narrowing is applied", not only "the widening is absent"); when an umbrella default is removed, find the assertions that relied on it by DELETING the new explicit thing and seeing what fails — `scratch/d0a-mutation-audit.sh` is that search, mechanised | Discipline + a mutation harness |

## 49. A REGION THAT STOPS PRODUCING FINDINGS IS EITHER EXHAUSTED OR UNEXAMINED, AND SILENCE CANNOT TELL YOU WHICH  *(new — D0A-R25, the convergence question answered against both parties)*

**The class.** Reviewers converge or they run out of places they know how to look, and **both
present identically: findings stop arriving.** Treating the silence as evidence of quality is
the error, because the discriminator is not *whether anything was found* — it is **whether
anyone looked.**

**The instance, and it cost four rounds.** Rounds 22, 23 and 24 returned no defect in shipping
product behaviour; `298d4db` (round 21's remediation) was the last commit to change it. That
was offered to round 25 as possible convergence, with an honest measurement attached: across
the round-21..24 prompts, **exactly one `runtime/src/**` file was named by filename**
(`sandbox.rs`, once; the other eight zero). The reviewer read the measurement, went to the
unnamed files, and returned **three P1 product defects** — an unenforced consent tier, an
unbounded read that stalls the root daemon before any human gate, and an empty argv that
becomes a synthesised `argv0` at exec.

So the quiet was **scope exhaustion**, and the measurement that looked like a caveat was
actually the finding. Both parties had preferred the convergence reading, which is precisely
why neither could be the one to settle it.

**The discipline.**

1. **Never infer coverage from an absence of findings.** "Nothing was found in X" is a claim
   about the search, not about X, until you can say what searched it.
2. **Measure attention, not just outcomes.** Counting which regions a review actually
   addressed is cheap, mechanical, and answers the question the finding count cannot. Do it
   *before* proposing that a surface has converged.
3. **When you have a stake in the answer, hand the question over WITH the measurement** — and
   state which reading you would prefer to be true. The preference is the reason the judgement
   cannot be yours.
4. **A region named in a prompt is not thereby reviewed, and a region unnamed is not thereby
   unreviewed.** The count bounds what you *steered* toward. Only the reviewer can say what
   they read — so ask, rather than concluding in either direction.

**The RED-proof shape.** There is none at the code level; this is a review-process class. Its
check is a command: enumerate the source files in the trust boundary, grep the last N review
prompts for each, and report the ones at zero. A region at zero across several rounds is
either genuinely closed by construction — say by what — or it is unexamined.

**Related:** [45] (the totality claim) is the same disease in a single sentence; this is 45
spread across a whole review. [41] (wrong altitude) is why the *measurement* must be
mechanical: three grep sweeps in this arc returned confident false negatives.

## 50. THE FILTER ON A MECHANISM'S OUTPUT IS NOT PART OF THE MECHANISM, AND CAN SILENTLY INVERT IT  *(new — D0A-R26-07, found by the reviewer after the predicate had already succeeded)*

**The class.** A checking mechanism produces output; a human pipes that output through a
suppression pattern to cut noise; **the pattern matches the signal and deletes it.** The
mechanism succeeded. The post-processing defeated it. The result is indistinguishable from the
mechanism having found nothing — which is the worst available failure shape, because the
mechanism's success is what you then trust.

**This is NOT class 41 (wrong altitude).** There the sweep itself looks in the wrong place and
never sees the thing. Here the sweep sees it, reports it, and a *second* step throws it away.
The remedies differ: 41 says widen the search; 50 says audit the filter.

**The instance.** Running class 48's predicate over `CONFORMANCE_REGISTER.md` correctly
surfaced every line naming run 13. To separate live claims from deliberate history, the output
was filtered with `grep -viE "supersed|withdrew|prior|run 13's|historical|run 13 \("`. The line
that mattered read:

```
**LANE RUN 13 (current) — `EXECUTED 177 / SKIPPED 5 / reported 182` …
```

`RUN 13 (current)` contains the substring `run 13 (` — case-insensitively — so the pattern
written to hide *historical* mentions deleted the one line asserting run 13 was **current**.
The register shipped saying run 13 was current AND that run 14 closed the finding run 13 had
failed to close. The predicate had done its job three lines earlier.

**The discipline: a suppression pattern needs the same discrimination test as an assertion.**

1. **Does it exclude only what it names?** `run 13 \(` was meant to name a parenthetical
   citation. It also names `RUN 13 (current)`, `RUN 13 (superseded)`, and every other
   parenthesis that could follow. A pattern that cannot state what it excludes is not a filter,
   it is a guess.
2. **Count what you removed, and look at it.** `grep -c` before and after costs one command.
   Any filter dropping more than a couple of lines is doing enough work to be reviewed.
3. **Prefer positive selection to negative suppression.** "Show me the lines that assert
   currency" is auditable; "hide the lines that look historical" is a claim about everything
   you did not read.
4. **When the filter and the mechanism disagree, the mechanism wins.** If the raw output has a
   hit and the filtered output does not, that difference is the finding.

**The RED-proof shape.** Run the mechanism twice — once raw, once filtered — and diff. Every
line the filter removed must be one you can name a reason for. This is cheap enough to be
unconditional whenever a sweep's output feeds a decision.

**Related:** [41] (wrong altitude) is the sibling failure in the search itself. [48] (the fix
scoped to the named instance) is the mechanism this defeated — note that 48's predicate has now
caught three sites the findings did not name, so the tool was working and the wrapper was not.
[45] (the totality claim) is what the filtered output then licenses: "no remaining sites" stated
from a search whose results were partly discarded.

## 51. A FALSE CLAIM IN A DOCUMENT WHOSE FUNCTION IS TO BE TRUSTED PROPAGATES BY DESIGN  *(new — D0A-R30-06, a safety claim nobody re-derived because the record exists so they need not)*

**The class.** A wrong statement in code is checked by the next person who reads the code, because
reading code means re-deriving it. A wrong statement in a **record** is not, because the record's
entire purpose is that readers *stop* deriving. **The error therefore propagates by design rather
than by accident**, and it propagates fastest in exactly the documents written to be most
trustworthy: lane records, conformance registers, safety rationales.

**The instance.** `.githooks/runtime-test-count-baseline.root` recorded that a test fixture had
named pid 1 and that `kill(1, SIGKILL)` **at root ends init** — offered as the justification for
changing the fixture. **It does not.** Linux gives PID 1 special protection: a signal PID 1 has
installed no handler for is never delivered, SIGKILL included. The dramatic hazard was invented
in the writing and set down as fact.

The same note also **confused wait eligibility with signal permission** — parenthood governs
whether you may `wait` for a process, not whether you may signal it, which depends on credentials
and capabilities. Both errors sat in the document a later reader consults *instead of* working it
out, written by the author and left standing by the operator who had asked for the fixture change.

**Why it is not class 45.** A totality claim overstates the reach of something real. This states
something that is simply not true, in a venue that suppresses checking. The severity comes from
the venue, not the size of the error.

**The discipline.**

1. **A safety claim in a record owes a citation or a measurement**, at the same standard as a
   test assertion. "At root this kills init" is a claim about a syscall; it takes one probe.
2. **State the DULL reason when it suffices.** The fixture change was right for an unglamorous
   reason — *a fixture should not name a process it does not own*. Reaching for the dramatic
   version is the tell: a justification that sounds alarming is one nobody wants to be the person
   who checked.
3. **Correct in place, visibly.** The wrong sentence stays, struck, with the correction beside
   it. Silently editing a record that others may have already read propagates the error a second
   time.
4. **The author's confidence is not evidence, and neither is the reader's assent.** Two people
   passed this claim without checking. Agreement between parties who share an incentive to move
   on is not verification (see [49]).

**The RED-proof shape.** For a claim about system behaviour: a probe that would fail if the claim
were false, retained. For a claim about the tree: a command whose output is quoted. A record
sentence with neither is an assertion, and this project's own rule is that an unverifiable
assertion is indistinguishable from a fabrication.

**Related:** [45] (the totality claim). [12] Iron Law — *verify, don't fabricate* — of which this
is the special case where the fabrication lands where verification is least likely.

## 52. AN ASSERTION WRITTEN FROM A RENDERED DISPLAY CANNOT MATCH THE BYTES  *(new — D0A-R30, four instances in one arc, the last invisible in its own failure output)*

**The class.** Test assertions get written by reading a transcript. **A transcript is a
RENDERING** — escape sequences become formatting, streams are interleaved, and text the program
never emitted appears while bytes it did emit vanish. An assertion built from that reads the
world through a lossy channel and can be unsatisfiable no matter how correct its intent.

**Four instances, one arc, escalating in subtlety:**

| # | what was read | what was true |
|---|---|---|
| 1 | the daemon's log looked like the fixtures' | `tracing_subscriber::fmt()` writes to **stdout**; fixtures use `eprintln!` → **stderr**. The assertion searched the wrong stream |
| 2 | the message text, from memory of the pre-extraction code | the extracted module emitted different wording. The test reported the property **absent while the transcript showed it happening** |
| 3 | `child="ai"` in the terminal | the bytes are `\x1b[3mchild\x1b[0m\x1b[2m=\x1b[0m"ai"`. **A terminal renders the escapes as italics**, so display and bytes differ invisibly |
| 4 | the failure message, to diagnose #3 | the panic prints the same escapes **back through the same terminal**, so the evidence re-hides the defect |

Instance 4 is what makes this a class rather than three mistakes. **The diagnostic channel has the
same lossiness as the original**, so looking harder at the output cannot find it. Only leaving the
rendering — `cat -v`, a hex dump, a byte-level assertion — can.

**The discipline.**

1. **Assert against a shared CONSTANT, never a transcribed literal.** If production and test read
   the same `const`, wording cannot drift (instance 2; the D0A-R2-05 pattern).
2. **Normalise before matching, and TEST the normaliser** against bytes you measured, with a
   discriminator proving the raw form does *not* match — otherwise a no-op passes (instance 3).
3. **Print the NORMALISED form in failure messages.** A panic that re-renders is instance 4.
4. **Name which stream carries what**, measured from the writer's configuration rather than from
   where you last saw a line (instance 1).
5. **When a predicate is correct in isolation but fails in situ, stop reasoning and dump bytes.**
   Three of the four cost a privileged run each, and each was resolved in one command once the
   rendering was removed.

**The RED-proof shape.** Feed the normaliser the exact captured bytes and assert the *raw* form
fails to match. A normaliser tested only on already-clean input is a no-op with a green test.

**Related:** [41] (wrong altitude) — the sibling in searching rather than asserting. [50] (the
filter is not the mechanism) — there post-processing discarded a true result; here rendering
manufactures a false one.
