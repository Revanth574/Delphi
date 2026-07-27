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
Before any step of a verification loop that moves `HEAD`, discards changes, or
rewrites files: **`git status --porcelain` must be empty, or the work must be
committed or stashed first.** Prefer perturbations that are *exactly invertible in
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

**RED-proof shape.** Two weakens, not one. (a) the ordinary weaken — revert the fix,
the test must fail; and (b) **the class re-application** — construct the input that
exhibits the ORIGINAL class against the NEW code (here: a path with the right prefix
that resolves elsewhere) and assert it is caught. A fix with only (a) is proven to
address its instance, not its class.

---

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
| 18. Verification loop mutates its subject | discipline (clean tree before destructive steps; verify the RESTORE by diff, never by green) | Discipline |
| 19. Runs compared under different instruments | discipline (pin + record the instrument; re-run the baseline under the new one before believing a delta) | Discipline |
| 20. Correct test, non-representative environment | discipline (name the mechanism the property needs; prove it against the real component) | Discipline |
| 21. Warning banner as enforcement | discipline (sentinel prefill or non-sentinel rejection; never persist the value; state the residual up front) | Discipline |
| 22. The fix inherits the class it closed | discipline (re-apply the finding's own question to the remedy; two weakens, not one) | Discipline |
