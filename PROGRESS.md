# Delphi OS — Progress State

Last updated: 2026-06-15 (**Leverage pass MERGED to main at v0.4.1 (`b1bf565`)** after a 2-round Codex review — primitives confirmed byte-identical (round-1), R1-01 test-fix (round-2 APPROVE); see the close-out section. Earlier milestones below. INF-1 (API-key Debug redaction) **FIXED + Codex APPROVE, 0 findings**, merged via `fix/inf-1-apikey-redaction` — the first `CODEBASE_REVIEW` security candidate triaged; see the INF-1 section below. Prior milestone — Phase 3B.0 — **`fortress/` sweep COMPLETE + Codex APPROVE + MERGED TO MAIN `84d84b3`**. The FINAL Phase 3B.0 sweep — **Phase 3B.0 is now CLOSED** (the D-Bus boundary `services/`, `die/orchestrator/`, and the security layer `fortress/` have all been swept and merged). Three adversarial Codex rounds + one scoped re-verification: **R1 FAIL (5 findings) → R2 FAIL (4 findings) → R3 FAIL (1 composition-seam regression) → R3-reverify APPROVE (0 findings)**, every finding fixed at root with a RED-proven regression test, plus **7 pre-review fixes** and **3 dead detection paths wired before round 1** (the "fix what you find" discipline). Severities are Codex's actual verdicts — **two P1s** (FORT-R1-01 the silent ZKQP PII leak that justified the sweep; FORT-R2-01 the digit-completeness class), both fixed and verified, so main holds no known P1. The full-workspace pre-merge audit additionally caught 3 downstream tests that encoded the pre-R1-04 credential-name leak across `#[from]` boundaries — corrected (`e7fdbb0`). The 18 fix commits + the pre-merge PROGRESS chore (`06c46a1`) landed via `--no-ff` merge **`84d84b3`** (`68b045d..84d84b3`), pushed to origin, branch `phase-3b/sweep-fortress` deleted. Prior milestone: `die/orchestrator/` sweep merged `ab1ffc7`.)
Current phase: **Leverage pass — MERGED to main at v0.4.1 (`b1bf565`); main clean.** Next unit: the **runtime arc** (trust-model-FIRST; does NOT start with a scaffold — its first deliverable is the ratified trust-model document). In parallel: the focused-fix queue (SFS-1, BVB-3/4, regex migration, date-scope triage `task_71334ce4`) — see the close-out "Next actions (c)". Prior milestones: Phase 3B.0 `fortress/` sweep MERGED `84d84b3`; INF-1 merged `f0f626e`.
Current task: **none active — HOLDING.** The leverage pass is closed on main (2-round Codex APPROVE: round-1 REVISE → R1-01 test-fix `ebf5492` → round-2 APPROVE, 0 findings). The runtime arc is the next unit but begins with a design conversation (the trust-model document), not code.
Current step: leverage pass merged (`--no-ff` `b1bf565`), tagged `v0.4.1`, pushed to `origin/main`; this PROGRESS header flip is the post-merge chore. **Next: design the trust-model document (STOP POINT B) before any runtime code.**
Status: **Leverage pass MERGED at v0.4.1 (`b1bf565`), main clean. HOLDING for the runtime arc (trust-model design first).**
Tests passing: **1,891 Rust** (`cargo test --workspace`, 0 failed; **+30 over the 1,861 branch-point** — P2 extractions ≈ +21 → 1,882, P4 proptests +9 → 1,891) + **94 TypeScript** (`pnpm test --run` in `shell/`, 0 failed — verified on Windows where `node_modules` matches the platform; WSL hits the npm optional-dep platform mismatch, not a real failure). `cargo clippy --workspace --all-targets -- -D warnings` clean; real exit codes per §13.4.

## Leverage pass (`infra/leverage-pass`) — CLOSE-OUT: P0–P5 COMPLETE, MERGED at v0.4.1 `b1bf565` (2026-06-15)

> **MERGED 2026-06-15** to main at **v0.4.1 (`b1bf565`)**, `--no-ff`, after a 2-round Codex review: round-1 REVISE (one P2-med, R1-01) → R1-01 test-fix (`ebf5492`) → round-2 APPROVE, 0 findings. The "held for review / NOT merged" framing in this section is the **pre-merge record, preserved as written** and superseded by this note.

The Exponential Leverage Pass converted the project's adversarial-review learnings into permanent machinery with **zero new attack surface**. **20 commits** from branch point `f0f626e` (the 18 P1–P5 commits + the P7 close-out + the round-2 R1-01 test-fix). Before → after: **1,861 → 1,891 Rust** (0 failed), **94 TS** (0 failed), **CI from zero**, a 14-class defect corpus, the `delphi-hardening` crate, honest docs end-to-end.

### Phase ledger

| Phase | Delivered | Commits |
|-------|-----------|---------|
| P1 | WSL target-dir config + clippy pre-commit hook (no fmt gate — workspace not rustfmt-clean) | `1c865c8` |
| P2 | `delphi-hardening` crate — 3 primitives extracted **byte-identically** with pinned goldens: `canonical_hash` (+ audit-hash `dec4026` & workflow-fingerprint `dc03a5f`), `safe_open` (+ knowledge `635649b`), `pragma_setup` (+ sqlite-policy `6ebbd5a`). 3 deferred-with-corpus-entry. | `b95e9c7 dec4026 dc03a5f 132d031 635649b ec4eac0 6ebbd5a` |
| P3 | `docs/DEFECT_CLASSES.md` corpus (grounded in F4–F26 / sweep history) + CLAUDE.md §13.9 review-attention-partition rule | `e2e7cfc` |
| P4 | First CI (clippy / test + count-floor / audit / deny / shell); `canonical_hash` injectivity proptests (P1/P2/P3 RED-proven); ZKQP detector completeness proptests (Nd-script + ASCII-scope RED-proven); 3 RustSec advisories accepted, split by class (detail in the P4 section below) | `3363901 ac240f9 2c43ea7` |
| P5 | Honest-record: 6 doc-lies fixed + 4 STUB markers + capability tracker corrected; honest README (status table, 1891+94, no-executable reality); CONTRIBUTING; SECURITY (TODO channel); 7 grounded ADRs + DEFECT_CLASSES class 14; STARTER_TASKS (12, grounded) | `584ee29 99ede09 c736b91 bbe06cb bd17170 9cb8d0d` |

(P0 = branch open; **P6 runtime split out** as the next unit — it is the runtime arc in Next action (b).)

### Deferrals recorded (rule-of-three / dependency-direction — surfaced and NOT forced)

- **atomic_migration** (DEFECT_CLASSES 13): 1 versioned-migration consumer (`knowledge.rs`, F14/F17/F19-hardened). Extract `run_migration(...)` into `delphi-hardening` **when a 2nd versioned store appears**, as its own reviewed change + Codex round.
- **uniform_reject** (class 11): 1 crate, zbus-transport-coupled. Local `services::error::opaque` helper today; extract at the 2nd cross-crate consumer.
- **TrustedRoot** (class 5): capability-type reshape of the (already-hardened) `safe_open` root handle. Pending; idiom documented.

### Next actions (priority order)

**(a) Codex review round — BEFORE any merge.** `infra/leverage-pass` is NOT merged. `delphi-hardening` touches security-critical sites — the fortress audit-chain hash, the orchestrator workflow-fingerprint, knowledge safe-open, sqlite policy — across two crates, so this is sweep-grade. The review's job is NOT "find bugs in new code"; it is to **verify the byte-identical lifts preserved behavior and opened no surface**. The evidence is already assembled: pinned goldens before/after each migration, RED-proven proptests, and a clean full-workspace gate that caught no cross-crate regression. Run Codex round-1 scoped to `git diff f0f626e..HEAD`, referencing `docs/DEFECT_CLASSES.md` per §13.9 — **partition the relevant classes into pre-foreclosed-by-`delphi-hardening` (the reviewer SKIPS these — do not re-hunt) vs. applicable-but-not (explicit coverage)** — so attention concentrates on the one question that matters: did extraction preserve behavior, or did a subtle non-byte-identical drift slip in? On APPROVE → `--no-ff` merge + tag.

**(b) THE RUNTIME ARC — immediately-next unit, trust-model-FIRST.** The #1 gap is that nothing runs. But the arc's FIRST deliverable is NOT code — it's a ratified trust-model document (STOP POINT B gates on THIS, before any daemon scaffold):
- The auth boundary for tool execution, designed as a Fortress-class threat model: who mints tool-execution approval, what binds an approval to a specific action (not a blanket grant), how the WebSocket caller is authenticated, what process-isolation boundary contains a running tool.
- The two-parallel-security-worlds reconciliation is a DECISION THIS DOC MAKES, not a task to discover later: built-but-unwired fortress vault/permissions vs. `services/`'s own auth → wire-fortress-in / retire-one / merge. "Which auth system guards tool execution" IS the trust model — leaving it open means building on an unresolved security fork (exactly how two parallel worlds arise).

  THEN the runtime code against the ratified model: daemon + wire the Planner (an always-error shell today) + wire the Brain.

  WHY trust-model-FIRST: the overnight prototype built the execution path and tried to retrofit the trust model — it failed two Critical approval-bypass reviews because the trust model is the FIRST artifact, not a property of the code. This arc inverts that. STOP-POINT-B-gated on the trust-model doc, NOT indefinite deferral (the daemon is the #1 gap and the arc is the immediately-next unit).

**(c) Focused-fix queue — in parallel (does not block the review).** SFS-1 (incremental-reindex correctness — schema change + ratification), BVB-3 / BVB-4 (browser `file://` scheme allowlist; builder template path-traversal), the regex migration (ZKQP detectors → compiled-regex / Unicode-class design, security-reweighted), and the date-scope triage (`task_71334ce4`).

**Do NOT merge `infra/leverage-pass` until the Codex round returns APPROVE.** The branch is the review unit.

## Leverage pass (`infra/leverage-pass`) — P4 CI + RustSec advisory acceptances (2026-06-14)

P4 lands the project's first CI (`CODEBASE_REVIEW` WS-2 — there was none): `.github/workflows/ci.yml` with `clippy -D warnings`, `cargo test --workspace` + an executed-test-count floor guard (`.github/rust-test-count-baseline` = **1882**), `cargo audit`, `cargo deny check` (`deny.toml`), and the shell (`pnpm test`/`build`) job. No `cargo fmt --check` gate (workspace not rustfmt-clean; deferred to its own `style(workspace)` commit per CLAUDE.md §6). Verified before commit: deny `advisories/bans/licenses/sources ok`; test count `1882 == floor`; the count-guard hardened against its own silent-failure mode (real `cargo test` exit via `PIPESTATUS`, empty/non-integer extraction guard, distinct from a count drop).

**Three transitive RustSec advisories accepted — documented, not silenced.** Each surfaced by a local scan BEFORE the CI committed (the verification did its job: caught a day-one-red and a non-gating gap). The gate stays live for everything else — any new advisory, especially a vulnerability, still fails. Acceptance is split BY CLASS, each living once with the tool that actually gates that class (verified, not assumed: cargo-deny v2 gates unmaintained + vulnerability + yanked but has **no `unsound` knob** — `unsound = "deny"` fails config deserialization — so the unsound class is gated by `cargo audit --deny unsound`):

| Advisory | Crate@ver | Class | Transitive via | Gated by | Why accepted | Re-check trigger |
|----------|-----------|-------|----------------|----------|--------------|------------------|
| RUSTSEC-2025-0057 | fxhash 0.2.1 | unmaintained | scraper→selectors | cargo-deny (`deny.toml` ignore) | unmaintained, not vulnerable; no in-range upgrade | scraper/selectors bump that retires fxhash |
| RUSTSEC-2024-0436 | paste 1.0.15 | unmaintained | smithay→pixman | cargo-deny (`deny.toml` ignore) | unmaintained, not vulnerable; no in-range upgrade | smithay bump that retires paste |
| RUSTSEC-2026-0002 | lru 0.12.5 | **unsound** (`IterMut` Stacked-Borrows UB) | tantivy 0.25→semantic-fs | cargo-audit (`--ignore` on the `--deny unsound` step) | **NON-REACHABILITY**, verified at source: tantivy 0.25's sole `LruCache` (store/reader.rs block cache) is touched only by `new`/`get`/`put`/`len`/`peek_lru` and never constructs `lru::IterMut` on any path — the exact unsound type is dead from tantivy's whole surface. 0.12.5 is the latest tantivy 0.25 permits. | any tantivy upgrade OR if semantic-fs's tantivy usage changes |

The unsound gate is **genuinely live**, not decorative: `cargo audit --deny unsound` returns RC 1 without the lru `--ignore` (a future unsound advisory fails CI) and RC 0 with it. The lru acceptance rests on the reachability proof — if a tantivy upgrade ever routed through `lru::IterMut`, the re-check turns the acceptance back into a live finding.

### P4 property-based test suites (RED-proven, test-only)

Two proptest suites turn adversarial-review lessons into executable law. Every property was RED-proven against the exact bug it guards (the property must FAIL against an injected pre-fix regression, then the break is reverted) — a property that can't bite is decorative.

- **canonical_hash injectivity** (`delphi-hardening`, +3 → 1885): P1 length-prefix, P2 seq count-prefix, P3 fixed≠field. Injectivity asserted on the SHA-256 digest (the `Sha256` is private; no pre-hash accessor invented) modulo a collision proptest can't find. Witness-reachable generators (one content split two ways) so the boundary collision exists by construction. `proptest 1.11` added as a workspace dev-dep.
- **ZKQP detector completeness** (`fortress/tests/zkqp_completeness.rs`, +6 → 1891): the FORT-R2-01 Nd-digit / Unicode-separator completeness contract as metamorphic properties — phone/credit-card/national-id/email detected across Arabic-Indic, Devanagari, Bengali, Thai, full-width scripts by construction — plus the **deliberate ASCII-only scope** of IP and date (date = ISO `YYYY-MM-DD` per the code). Public-API only; `pii.rs` byte-identical to HEAD (no fortress source touched). **Engine decision:** stable proptest, NOT nightly cargo-fuzz — the invariant is shape-driven (a generation problem), so coverage-guided byte fuzzing and a rot-prone nightly CI job buy nothing; the suite runs in the existing rust test job, gated by the count floor. The pending fuzz-smoke note in `ci.yml` was removed accordingly.

**Two `detect_dates` follow-ups surfaced here, NOT fixed (kept this commit pure test-only):**
- **Doc/code drift → P5 honesty pass.** The `detect_dates` comment claims `MM/DD/YYYY` but the code implements ISO `YYYY-MM-DD` only ([pii.rs:397](fortress/src/zkqp/pii.rs:397)). Same doc-lie class as INF-3 / vault-zeroize; fix it there with its siblings, not ad hoc in a test commit.
- **Non-ISO false-negative → detector-scope / §10-coverage triage** (alongside FORT-Q4 address/name/geo gap). Framed as an OPEN SCOPE QUESTION, not a confirmed bug: is `detect_dates` meant to be format-complete, or deliberately ISO-only like the IP scanner is deliberately ASCII-only? Does §10 require date redaction across formats? If "format-complete," it's a production `fortress/zkqp` detector change = its own branch + Codex review. Spun out as a background task.

## INF-1 (API-key Debug redaction) — CLOSED (2026-06-12)

**First triage of a `CODEBASE_REVIEW.md` security candidate** (from the `quality/elevation-pass` review), fixed and merged ahead of the leverage-pass scoping. `CloudClient` (`die/inference/src/cloud.rs`) derived `Debug` over a raw `api_key: String`, so a `{:?}` of the client — or of any struct holding one — would print the live Anthropic API key.

**Honest severity: latent-structural footgun, NOT a live leak.** No site formatted a `CloudClient`, no `{:?}` / `dbg!` / log reached the key, and the containers (`CloudEgressGateway`, `Router`) derive no `Debug`/`Clone` over it — nothing leaked today. The derived `Debug` was a loaded gun (the SVC-1-R1-1-02 class already structurally fixed for `ConfirmationTokenWire`); closed before it could fire.

**Fix — redaction on the TYPE so it travels with the value:** a module-private `ApiKey(String)` newtype with hand-written `Debug` + `Display` both rendering `[REDACTED]`; the raw secret is reachable only via the single named accessor `ApiKey::expose()`, used at exactly two sanctioned sites — the `x-api-key` auth header and the `is_available` empty-check. `CloudClient::new` still takes `String` and wraps internally (no call site outside `cloud.rs` changed). `Clone` dropped from `CloudClient` (grep-verified: nothing clones one, no container forces it).

**Codex: APPROVE, 0 findings** — and confirmed the *broad class*: no serde / `Deref` / `AsRef` / `Into` raw-render path, and no container `Debug` reaches the secret. So the footgun is closed against the leak class, not just `Debug`/`Display`. RED-proven: a temporarily-leaking `Debug`/`Display` made tests (a) `cloud_client_debug_does_not_leak_api_key_inf_1` and (b) `api_key_type_redacts_in_debug_and_display_inf_1` FAIL (secret printed at the client and bare-`ApiKey` levels); (c) `api_key_remains_functional_via_expose_inf_1` proves auth still works via `expose()`.

Commit `382b4a3` on `fix/inf-1-apikey-redaction` (1 file, `cloud.rs`, +107/−6); **this chore rides the `--no-ff` merge into `main`.** Pre-merge full-workspace self-audit (from the inf1 worktree): **1,861 Rust / 0 failed**, `cargo clippy --workspace --all-targets -- -D warnings` clean, **94 TS / 0 failed**, `pnpm build` ok — real exit codes per §13.4.

**INF-3 stays a SEPARATE noted follow-up** (NOT fixed here): the `cloud.rs:9-13` module doc claims keys are "retrieved from the Fortress credential vault at runtime," but `new()` takes a plain `String` and the vault is never consulted (drift; ties to the unwired `Vault` — review FORT-Q5). Remaining untriaged `CODEBASE_REVIEW` candidates: BVB-3, BVB-4, FORT-Q4.

## Phase 3B.0 — `fortress/` sweep — COMPLETE + Codex APPROVE (2026-06-11)

**Retroactive Codex adversarial sweep of `fortress/` — the FINAL Phase 3B.0 sweep — converged inside the 3-round budget plus one scoped re-verification.** Applied Task 3A.6's threat model on `phase-3b/sweep-fortress` (branched from `main`). Verdict trajectory **R1 FAIL (5) → R2 FAIL (4) → R3 FAIL (1 regression) → R3-reverify APPROVE (0)** — severity degraded across rounds toward convergence. Every finding fixed at root with a regression test **proven RED against the pre-fix code** and green after. Rounds 1–3 were SOURCE-ONLY on Codex's host (llama-cpp-sys-2 bindgen cannot find libclang there); our WSL RED→GREEN runs are the execution proof. Round 3 pasted literal test bodies and a comment/formatting drift tripped the prompt's own byte-identical rule; the re-verification round fixed the process — Codex read the live committed tests at file:line (no paste, no drift). Full-workspace self-audit on branch tip `e7fdbb0`: **1,858 Rust / 0 failed**, `cargo clippy --workspace --all-targets -- -D warnings` clean, **94 TypeScript / 0 failed**, `pnpm build` ok.

**Bucket discipline (the crate is ~20% built):** the sweep hardened the BUILT-AND-LIVE surface — ZKQP (`zkqp/*`), the audit chain (`audit.rs`), the 4-tier permission engine (`permissions.rs`), `error.rs`, and the vault's Argon2 profile — and inventoried the never-built bucket-3 layers (TPM, full-disk / hidden-volume, FHE, federated sync, zk-SNARK proofs, PQC) plus the `EncryptionService` stub as forward-requirements, not findings.

**"Fix what you find" — 7 pre-review fixes + 3 dead detection paths wired before round 1:** canonical audit-entry hash with full field coverage + length-prefix (`3035681`, the orchestrator R2-02 non-injective-encoding class found proactively here); `detect_emails` multibyte-separator UTF-8 panic (`518e0e6`); `detect_credit_cards` scanned a copy not the original → offset drift (`c86e075`); **dead paths WIRED** — `NationalId`/SSN detection (`70229ac`) and `known_entities` scanning (`18df22e`), both registered-but-never-scanned (silent pass-through of the exact PII they claimed to cover); vault Argon2id pinned to the verified OWASP/RFC 9106 profile (`71540ad`); permission config trust model + escalation-only target documented (`2c8c517`).

**The honest-record catch (the full-workspace gate earned its keep):** the pre-merge `cargo test --workspace` caught 3 downstream tests — die-inference's `InferenceError` doctest + unit test and die-orchestrator's `all_downstream_errors_convert` — that asserted a `FortressError` credential name SURVIVES the `#[from]` conversion: the exact cross-boundary leak FORT-R1-04 closed. The fortress-only per-crate audits never compiled those consumers, so it stayed latent until the whole-tree run. Corrected to assert the redacted contract (`e7fdbb0`), turning each site into a downstream guarantee that R1-04 holds across the boundary. (die-learning + semantic-fs use the non-redacted `Encryption` variant — unaffected.)

### Finding ledger (per-finding disposition + fix commit)

| ID | Finding | Severity | Disposition | Commit |
|----|---------|----------|-------------|--------|
| FORT-R1-01 | ZKQP detection false-negatives = silent PII leak to cloud (the finding that justified the sweep) | **P1** | **FIXED** — completeness table across boundary / case / Unicode-sep / trailing-punct / RFC-validity axes; full-width-digit class added pre-round-2 | `807b36c` + `70ae808` |
| FORT-R1-02 | Predictable placeholders + global-replace restore → cloud-response re-injection | P2-med | **FIXED** — query-bound token (then per-instance namespace in R2-02) | `e3a1502` |
| FORT-R1-03 | WebSocket cloud-egress caller binding (Piece-1b) | — | **SPUN OUT** → task_758940a5, its own shell-bridge change with §8 review | — |
| FORT-R1-04 | `FortressError` Display/Debug leaked caller ids / filesystem paths across `#[from]` | P2-low | **FIXED** — redacted Display/Debug + `diagnostic()` channel; downstream consumer tests corrected (`e7fdbb0`) | `e6e447b` |
| FORT-R1-05 | Permission downgrade paths (`load_config_str` + `add_override`) | latent | **DOCUMENTED** — escalation-only forward-requirement on record | `96357aa` |
| FORT-R2-01 | Digit class incomplete (hand-enumeration: ASCII → +full-width → +Arabic-Indic) | **P1** | **FIXED** — non-enumerative Unicode `General_Category = Nd`; Thai (never-enumerated script) is the verification row, Codex-confirmed | `84bb641` |
| FORT-R2-02 | Placeholder embedded `SHA-256(query)` → wire-visible query fingerprint (links identical queries / offline-verifies guessed PII) | P2-med | **FIXED** — per-instance random namespace, query-independent, generated at construction | `23333e1` |
| FORT-R2-03 | Value-based global replace corrupted minted placeholders | P2-low | **FIXED** — span-based single-pass replacement with overlap absorption | `418683c` |
| FORT-R2-04 | Email local-part over-redacted a URL path (atext `/`) | P3 | **FIXED** — `/` excluded from the local-part | `260c92a` |
| FORT-R3-01 | R2-02/R2-03 composition seam: restore acted on the full detection map → re-injected a never-minted placeholder | P2-med | **FIXED** — `replace_spans` returns the minted submap; restore-set == minted-set by construction | `d5a437e` |

### Convergence (both classes that drove the FAILs are closed)

- **Digit completeness — CLOSED non-enumeratively.** `is_pii_digit` uses Unicode `General_Category = Decimal_Number` (Nd), the authoritative "decimal digit, any script"; phone/card/SSN all route through it; offsets via `char_indices`; the ASCII fast-path is a pure optimization. Hand-enumerated ranges missed full-width (R1) then Arabic-Indic (R2); the category cannot. Codex round 3 CONFIRMED, with Thai as the never-enumerated proof row. The class cannot recur.
- **Re-injection — CLOSED by construction.** `replace_spans` returns the minted submap and `restore()` consumes it, so restore-set == minted-set: restore can only rewrite a placeholder that was genuinely sent.

### Accepted residuals (deliberate, recorded — NOT missed)

- SSN/phone score double-count (conservative over-scoring).
- IP/date scanners ASCII-only (machine-format identifiers, not natural-language PII).
- atext `/` exclusion from the email local-part (over-redaction-avoidance trade).

### Fortress-sweep follow-ups (tracked)

- **regex migration — SECURITY-REWEIGHTED.** Hand classification proved incomplete twice; migrate the detectors to the regex / Unicode-class design (CLAUDE.md §2) before broader production. The detection-completeness table is the regression net; Nd + span-replacement + per-instance namespace close the LIVE holes now, so deferral is tidying, not protection.
- **Piece-1b (FORT-R1-03)** — spun out as task_758940a5; its own shell-bridge change with §8 review.
- **ORCH-R1-06 at-rest encryption** — re-homed here, stays OPEN: `EncryptionService` is a stub; two consumers blocked (orchestrator SQLite-at-rest + die-learning privacy guard).
- **vault crypto-hygiene** — LATENT forward-requirements (no zeroize-on-drop, non-atomic persist, no 0600 perms); the vault is unwired.
- **permission downgrade paths** (`load_config_str` + `add_override`) — documented latent, escalation-only target on record.
- **the leverage pass** (the Fable "Exponential Leverage" document) — the next major unit; runs against stable post-merge `main` where the call sites it extracts (incl. fortress's audit-hash + detectors) are settled. Phase 2's `delphi-hardening` crate can then migrate ALL call sites including fortress's, which it could not while the sweep was open.

### Fortress-sweep commit ledger (`3035681..e7fdbb0`, branch `phase-3b/sweep-fortress`, pre-merge)

Pre-review (7): `3035681` audit hash · `518e0e6` email multibyte · `c86e075` CC original-text · `70229ac` SSN wired · `18df22e` known-entities wired · `71540ad` Argon2 pin · `2c8c517` permission trust-model doc. Round 1 (4): `807b36c` R1-01 (P1) · `e3a1502` R1-02 · `e6e447b` R1-04 · `96357aa` R1-05. Pre-round-2: `70ae808` full-width digits (R1-01 class). Round 2 (4): `84bb641` R2-01 (P1, Nd) · `23333e1` R2-02 · `418683c` R2-03 · `260c92a` R2-04. Round 3: `d5a437e` R3-01. Downstream contract correction (caught by the full-workspace gate): `e7fdbb0` R1-04 `#[from]` consumer tests.

## Phase 3B.0 — `die/orchestrator/` sweep — COMPLETE + Codex APPROVE (2026-06-07)

**Retroactive Codex adversarial sweep of `die/orchestrator/`, converged inside the 3-round budget.** Applied Task 3A.6's threat model on `phase-3b/sweep-orchestrator` (branched from `main@621e574`). Verdict trajectory **R1 REVISE (7) → R2 REVISE (3) → R3 APPROVE (0)** — severity degraded across rounds (R1's ceiling was P2-medium; R2's three findings were subtler P2-medium/low issues *inside* the round-1 fixes; R3 clean). **Nothing rose to P1** — these are Codex's actual verdicts, not inflated. Every finding fixed at root with a regression test **proven RED against the pre-fix code** and green after. Full-workspace self-audit on branch tip `3c7183a`: **1,838 Rust / 0 failed**, `cargo clippy --workspace --all-targets -- -D warnings` clean, **94 TypeScript / 0 failed**. Round 2 was SOURCE-ONLY on Codex's host (llama-cpp-sys-2 bindgen could not find libclang); our WSL RED→GREEN runs are the execution proof, and the round-3 prompt pasted the **literal committed test bodies** so the logic-review and the execution-proof are the same artifact.

**"Fix what you find, review for what you didn't" — 3 defects fixed in my own round-1 code *before* round 2**, so Codex's round 2 reviewed already-hardened code and its scrutiny went to the genuine unknowns:

1. **Cap divergence** (`5e9b192`) — R1-04's ingestion caps were enforced at 3 per-entry call sites; centralized to one shared choke-point (`enforce_ingest_byte_cap` / `enforce_concept_caps`), applying the SVC-2 completeness lesson (one shared guard, never per-site copies that drift).
2. **Confidence excluded from the consent fingerprint** (`b601ef3`) — `Workflow::fingerprint()` omitted `step.confidence`, an *under-coverage* gap (behavior changes at execution, hash stays the same → a mutated-confidence workflow could ride a stale consent token). Enumerated every field read during execution and bound them all.
3. **NaN/non-finite gate fail-open** (`3b2de18`) — the confidence gate's `confidence < min` admitted `NaN`/`+inf` (both comparisons false → auto-execute without confirmation). Made it fail-closed and rejected invalid confidence at construction.

### Finding ledger (per-finding disposition + fix commit)

| ID | Finding | Disposition | Commit |
|----|---------|-------------|--------|
| ORCH-R1-01 | Prompt-injection: fetched web content folded into the LLM prompt with no isolation boundary | **DOCUMENTED** — forward-requirement on `Brain::query` + inline marker; `Brain` is **UNWIRED** (no external caller), so latent not live | `9d8d774` |
| ORCH-R1-02 | `truncate_context` sliced at a byte index inside a UTF-8 char → panic | **FIXED** — floor to a char boundary (stable `is_char_boundary` walk) | `9d8d774` |
| ORCH-R1-03 | `search_url` interpolated the query without percent-encoding | **FIXED** — RFC-3986 `percent_encode_query` | `9d8d774` |
| ORCH-R1-04 | Knowledge ingestion size unbounded → live memory-exhaustion DoS | **FIXED** — `MAX_INGEST_BYTES` (10 MiB) + `MAX_CONCEPTS` / `MAX_CONCEPT_TEXT_LEN`; round-2 centralized to one shared guard | `a095222` + `5e9b192` |
| ORCH-R1-05 | Workflow auto-executes with no consent; the only gate was a forgeable `f64` confidence | **FIXED** — compile-time-unforgeable `ConsentToken` capability (private field, sole `issue(&Workflow)` ctor, `#[serde(skip)]`) bound to a workflow fingerprint, re-verified **at the execution door** (closes the validate→mutate→execute TOCTOU); structural confidence gate; round-2 confidence-in-fingerprint + fail-closed gate | `9a844de` + `b601ef3` + `3b2de18` |
| ORCH-R1-06 | SQLite stores are not encrypted at rest | **NOTED-AND-DEFERRED** → the `fortress/` sweep / Fortress Layer 2 (at-rest encryption is a Fortress concern, not a per-store one) — follow-up (c) | — |
| ORCH-R1-07 | Public-boundary errors leaked caller-supplied ids / filesystem paths into `Display` | **FIXED** — typed `NotFound{entity}` / `Conflict{domain,reason}` / `Validation{domain,field,reason}`; ids/paths to `tracing` only | `553f2c9` |
| ORCH-R2-01 | The fail-closed gate rejected `NaN` + below-min but still admitted `+inf` / `>1.0` | **FIXED** — gate the whole invalid class: `confidence.is_finite() && (min_confidence..=1.0).contains(&confidence)` | `79097d9` |
| ORCH-R2-02 | Delimiter-joined fingerprint collided (`("a\0b","c")` ≡ `("a","b\0c")`) → a token for one authorizes a behaviorally-different other | **FIXED** — canonical **length-prefixed** encoding (u64-LE length ++ bytes; count-prefixed collections) → injective | `b5f8ef4` |
| ORCH-R2-03 | `goals::is_cycle_if_parented` + `knowledge::create_edge` cycle errors leaked caller ids (an R1-07 completeness miss) | **FIXED** — typed `NotFound`/`Conflict`; ids to `tracing`; **exhaustive** read of every store's public-boundary `format!` (not a placeholder-shape grep) | `3c7183a` |

### Accepted residuals (deliberate, recorded — NOT missed)

Re-confirmed during the R2-03 exhaustive store enumeration; intentionally **not** gated because none leaks a cross-tenant resource id, path, or secret:

- **R1-07** — raw `{e}` from a downstream error at non-id/path sites (the typed variant carries static context; the dynamic detail goes to `tracing`, never `Display`).
- **R2-03** — value-echoes at `TryFrom`/validation (priority / role / enum-discriminant, edge-confidence **value**); the store's own internal data-dir paths; internal schema diagnostics (schema version / SQL-preview / FK-violation counts). These echo caller-supplied **values** or internal config, not resource identity.

### Orchestrator-sweep follow-ups (tracked)

- **(a) Cross-crate egress verification** (new — promoted from this sweep + SVC2-F5). Confirm the destination-consent gate covers **all three** cloud-egress paths — D-Bus inference (`services`), WebSocket (`shell-bridge`), and the orchestrator `Brain` — as one picture. No single crate-scoped sweep sees the whole egress surface, so this is a dedicated cross-crate check (it subsumes verifying the `Brain` forward-requirement once `Brain` is wired, and dovetails with Piece-1b).
- **(b) Post-v0.4.0 items ride along unchanged** — **SVC2-F3** (destructive-tier confirmation-token hardening) and **Piece-1b** (WebSocket cloud-send caller binding), both in the "Active tracked follow-ups" list below. Unaffected by this sweep.
- **(c) ORCH-R1-06 → `fortress/` sweep** — at-rest encryption of the orchestrator's SQLite stores belongs to Fortress Layer 2, not a per-store change; carry it into the upcoming `fortress/` sweep / Fortress tracker.

### Orchestrator-sweep commit ledger (`a095222..3c7183a`, branch `phase-3b/sweep-orchestrator`, pre-merge)

`a095222` R1-04 (ingestion DoS) · `553f2c9` R1-07 (id/path leaks) · `9a844de` R1-05 (consent capability + gate) · `9d8d774` R1-02/R1-03/R1-01 (brain hardening) · `b601ef3` R1-05 confidence-in-fingerprint (fix-before-review) · `5e9b192` R1-04 shared-cap centralization (fix-before-review) · `3b2de18` R1-05 fail-closed gate (fix-before-review) · `b5f8ef4` R2-02 (fingerprint length-prefix) · `79097d9` R2-01 (gate invalid class) · `3c7183a` R2-03 (goal/node id leaks + exhaustive enumeration). Branch root `621e574` (`.gitattributes` LF-pin, already on `main`).

## Merge gate (Phase 3B.0 → main)

**Main must not contain a known P1.** The `services/` Wave-1 sweep is APPROVED but is held on `phase-3b/sweep-services` and is NOT merged, because Codex Round 1 surfaced two architectural P1s — SVC-1 (ZKQP structural enforcement) and SVC-2 (permission-tier authorization) — in the same inference/D-Bus boundary. These are **not** "deferred and merged with known gaps"; they are Phase 3B.0a, the engineering unit that lands on the same branch so `services/` Wave 1 + SVC-1 + SVC-2 merge to main **together** in one clean transition from Phase-3A-safe to fully-hardened. **SVC-1 is now COMPLETE + APPROVED** (3 Codex rounds, `78bb6a0`); **SVC-2 remains** (design-first), and SVC-2 must additionally close the **SVC-1-R1-1-01** consent gap (the two-call cloud-consent bypass — see the 3B.0a section's closure-check criterion) before the merge. Codex Round 3 independently confirmed this gate: merged without SVC-2, the known consent gap would become a release blocker. Rationale for front-loading 3B.0a over the `die/orchestrator/` + `fortress/` sweeps: the two P1s sit in the boundary the sweep just hardened, the context is hot, and they are the hardest remaining architectural work in Phase 3B.0.

## Phase 3B.0a SVC-2 — COMPLETE + Codex APPROVE (2026-06-04)

**The merge gate above is SATISFIED — and the merge HAS LANDED.** SVC-2 closed the last known P1 (the SVC-1-R1-1-01 two-call cloud-consent bypass); the three-way merge (`services/` Wave 1 + SVC-1 + SVC-2) landed at merge commit **`0efe67c`** (tag **`v0.4.0`** on origin, feature branch deleted), taking main from Phase-3A-safe to fully-hardened with no resident P1. Verified ON merged main: 1,808 Rust / 0 failed, clippy `--workspace` clean, 94 TS.

**Codex verdict: APPROVE — 0 P1/P2.** Scope `git diff 953ee49..HEAD` (the full SVC-2 sweep, Stage 1 → Stage 3). All five flagged items ratified; one P3 fixed.

| ID | Item | Status |
|----|------|--------|
| SVC2-F1 | SVC-1-R1-1-01 closure — live real-bus test exercises the real D-Bus entry end-to-end (two distinct unique names), RED-proven against pre-SVC-2 | **RATIFIED** (real session-bus path confirmed; RED proof credible; fast-auth-error variant explicitly NOT required) |
| SVC2-F2 | Q9 insert-recheck skip (unique-names-only invariant) | **RATIFIED** (D-Bus spec grounding confirms unique-name non-reuse) |
| SVC2-F3 | Destructive-tier proceed-and-audit (Biometric/Hardware: no structural confirmation-token enforcement in v0.4) | **ACCEPTED for v0.4** — tracked future hardening (same-caller confirmation tokens for the destructive tier), post-v0.4 |
| SVC2-F4 | Destination-consent egress gate — structural refusal, typed-apart in all consumers | **RATIFIED** (structural at the gateway door; typed-apart across all four consumers: services, shell-bridge, die-orchestrator brain, client) |
| SVC2-F5 | Orchestrator-brain third cloud-send entry path threat model | **RATIFIED** (brain unwired — no external caller; forward requirement documented on `Brain::query`) |
| SVC2-AUDIT-01 | (P3) `AuthGuard::record` logged Authorized outcomes at hardcoded Autonomous, mis-labeling a Confirm-tier cloud-send in the audit trail | **FIXED** `b9754cf` — audit at the action's policy tier; RED-then-green test `enforce_cloud_send_audits_at_its_policy_tier` |

**SVC-1-R1-1-01: OPEN → CLOSED.** The two-call cloud-consent bypass — the dependency tracked since SVC-1, the merge-gate blocker — is **discharged**. The live closure test `services/tests/cloud_send_closure_live.rs::cloud_confirmation_token_echo_from_non_caller_is_rejected_live` proves it on the real D-Bus entry path (caller A obtains a confirmation token; caller B, a distinct daemon-assigned unique name, echoes it; the actual cloud send is rejected with `AccessDenied` before egress), RED-proven against pre-SVC-2 (reverting `enforce_cloud_send` makes B reach the egress send). Ratified SVC2-F1.

**Method-count reconciliation (62 vs 61):** 61 D-Bus methods carry an `enforce` guard across the 11 services; `inference.grant_cloud_egress_consent` is the +1 over the Stage-2 count of 60 (the real Confirm-tier grant method added in Piece 2b-i). `inference.cloud_send` is a METHOD_POLICY entry for the cloud-send *subaction* (used by `enforce_cloud_send`'s audit), not an introspected D-Bus method — classified but not method-counted. Codex confirmed.

### SVC-2 commit ledger (`953ee49..HEAD`, branch `phase-3b/sweep-services`, unmerged)

`08c746b` Stage 1 (auth seam) · `ef93cd2` Stage 1b (async caller resolver) · `138d322` Stage 2 (AuthGuard + completeness, timeline) · `268f859`/`7e4e0b9`/`3d6fca7`/`406888a` Stage 2 batches (all 11 services) · `19dead9` file_search clippy fix · `2e161df` CLAUDE.md real-exit-code rule · `af13d65` batch 3b (knowledge) · `81557a4` Piece 1 (cloud-send binding) · `f4bd13d` Piece 3 (live closure) · `0cfd6c5` Piece 2a (egress gate) · `3971928` brain threat-model · `30fafee` Piece 2b-i (D-Bus grant) · `90e1307` Piece 2b-ii (WebSocket grant) · `7430b20` Piece 2b-iii (dialog) · `b9754cf` SVC2-AUDIT-01 fix.

### Active tracked follow-ups (3B.0a landed — now open work items)

Deferred during the SVC-2 sweep; the merge is done, so these are now actionable (none block anything):

1. **SVC2-F3 — destructive-tier confirmation-token hardening** (post-v0.4, future). Mirror the cloud-send same-caller token model for **Biometric/Hardware-tier** operations: a structural confirmation-token bound to the requesting caller, so a destructive action cannot be completed by a different caller. Codex-ratified as the acceptable v0.4 posture (the dev session bus is not the security boundary; deployment uses caller-identity gating + the shell's confirmation flow) — this is the deployment-grade hardening, not a blocker.
2. **Piece-1b — WebSocket cloud-send caller binding**. `shell-bridge`'s `Handler::handle_inference_query` calls the shared `Router` directly with no per-connection caller identity, so the same-caller binding (closed on the D-Bus path) does not yet apply on that transport. Thread a **per-connection identity** through the bridge dispatch and apply `enforce_cloud_send` there, mirroring the D-Bus **Piece-1 wiring** in `services/src/inference.rs`. (A spawned-task chip was created during Stage 3.)
3. **Repo-wide CRLF→LF normalization** — ✅ **DONE** (`621e574`, on `main`; the `phase-3b/sweep-orchestrator` branch root). Added `.gitattributes` (`* text=auto eol=lf` + binary guards grounded in the repo's actual asset types — GGUF/ONNX models, shell image assets — with SVG intentionally left as text), ran `git add --renormalize .`, and verified **only** line-ending changes (`git diff --ignore-cr-at-eol` empty) before committing. Because the orchestrator sweep branched from this commit, every sweep diff is LF-clean — no per-file pre-stage normalization was needed this time.

## Completed phases

- Phase 0: bootstrap Cargo workspace (6 crates) — commit `1c65bcb` — no tag
- Phase 0 continuation: protobuf IPC, fortress, action timeline, shell UI, semantic-fs — commit `5fd5e83` — no tag
- Phase 0 continuation: Wayland compositor, local LLM inference — commit `53a2205` — no tag
- Phase 1+2 (combined, granular split infeasible due to interwoven files — see commit body): inference router, voice, browser, bridge, services, compositor rendering, shell command-bar/timeline/onboarding, die-learning, die-builder, SSI auto-gen, fortress/ZKQP, cross-app orchestration DAG — commit `90a25f8` — tag `v0.3.0-phase2`
- Phase 3A infrastructure: CLAUDE.md Session Recovery Protocol + Phase-end Verification Protocol + Iron Law #11, PROGRESS.md, .gitignore (.claude-flow/, .mcp.json) — commit `4e4f32e` — no tag
- Phase 3A Task 0 (pre-3A.1): CLAUDE.md Section 13 anti-hallucination protocol + Iron Law #12 — commit `dae8bf2` — no tag
- Phase 3A Task 3A.1: persistent conversation memory (`die/orchestrator/src/{conversation,reference}.rs` + `services/src/conversation.rs`; SQLite + FTS5 + WAL, 9-method ConversationStore, ReferenceEntity resolution, 24h/7d/older memory tiering, D-Bus `org.delphi.Conversation`, 49 new tests) — commit `2d67a29` — no tag (end-of-phase-3A tag is `v0.4.0-phase3a`)
- Phase 3A Task 3A.2: goal graph with DAG validation, timeline estimation, and stale detection (`die/orchestrator/src/goals.rs` ~1,100 LOC with 42 tests + `services/src/goals.rs` ~700 LOC with 27 tests; SQLite forest with O(depth) ancestor-walk cycle detection, GoalStatus/Priority/DeadlineRisk enums, GoalPatch `Option<Option<T>>` tri-state for deadline/parent, TimelineEstimator with priority heuristic 7/21/45/90 days + learned-pace sessions/hours model, find_stale + find_approaching_deadline, D-Bus `org.delphi.Goals` at `/org/delphi/Goals` with 10 methods, JSON patch parser for tri-state wire encoding, 4 signal declarations (goal_created / goal_completed / goal_deadline_approaching / goal_stale, each with `timestamp: i64` per D-Bus rule 3), RFC 3339 timestamp encoding) — commit `609826d` — no tag
- Phase 3A pre-3A.3 governance: Iron Law #13 (Highest fidelity wins, lowest fidelity is last resort) + 10-level fidelity hierarchy + Section 4 "Fidelity declarations" subsection requiring per-module declared probe order — commit `9313e16` — no tag
- Phase 3A Task 3A.3: ambient environmental awareness with fidelity-first sensor probing (`die/orchestrator/src/environment.rs` ~1,970 LOC with 69 tests + `services/src/environment.rs` ~620 LOC with 18 tests; `Fidelity` enum {Direct, NativeApi, Subprocess, Unavailable} threaded through every reading, layered battery probe (BAT*/uevent → per-field capacity/status fallback) with BAT* glob (verified against WSL2 BAT1, not hardcoded BAT0), thermal zones with cooling-device + 85°C throttling heuristic, /proc/meminfo with optional /proc/pressure/memory PSI augmentation, integer-math pressure-level boundaries at exactly 40/20/10%, `PressureLevel`/`PowerState`/`TimeBand`/`ActivityState` enums with wire-stable `as_str()`, `df -P /` subprocess for disk usage, `nmcli -t -f active,ssid` subprocess for WiFi SSID, direct sysfs read for wired detection, TOML LocationMap with SSID precedence over wired fallback under `dirs::data_local_dir()`, pure `classify_activity` precedence Idle (strict-`>`) → Meeting (mic beats Gaming) → Gaming (fullscreen + GPU ≥ 70%) → DeepWork → CasualBrowsing → Unknown, `EnvironmentSensor` trait with `LinuxSensor::with_roots(sys, proc)` for tempfile-based mock filesystem trees, `EnvironmentMonitor::snapshot()` composes a single `EnvironmentState` carrying per-domain Fidelity, D-Bus `org.delphi.Environment` at `/org/delphi/Environment` with 8 methods (GetState/GetBattery/GetThermal/GetMemory/GetTimeContext/GetLocation/SetLocationLabel/RemoveLocationLabel) and 6 signal declarations (BatteryLow/ThermalWarning/MemoryPressureHigh/TimeBandChanged/LocationChanged/ActivityStateChanged), no `#[cfg(target_os)]` gating — sensors return Fidelity::Unavailable on missing paths/binaries so the workspace `cargo check` passes on Windows) — commit `62201ee` — no tag
- Phase 3A pre-3A.4 governance: feature-branch workflow rule (`phase-{N}/{task-name}` branches with `git merge --no-ff` to main, replacing the old "Branch Naming" subsection in CLAUDE.md Section 6) — commit `10d5932` on the 3A.4 branch — merged via `188516c`
- Phase 3A pre-3A.4 governance: mandatory Codex security review protocol (CLAUDE.md Section 8 new subsection — explicit determination required at end of every task with NOT REQUIRED / REQUIRED — running now states; trigger list covers fortress/, services/-auth, die/orchestrator/ ZKQP/permissions/vault/cloud, ssi/ capability execution, new external network calls, and every phase boundary; explicit "merge only after review" workflow) — commit `ea39c1a` on the 3A.4 branch — merged via `188516c`
- Phase 3A Task 3A.5: knowledge synthesis engine + nine rounds of Codex adversarial security hardening (`die/orchestrator/src/knowledge.rs` ~6,300 LOC with **436 tests** covering KnowledgeNode/KnowledgeEdge graph data model, SQLite + LanceDB hybrid storage, content-hash deduplication with format-aware uniqueness key, openat2 RESOLVE_NO_SYMLINKS|RESOLVE_BENEATH path safety, schema migration with version table + atomic FK check + AUTOINCREMENT preservation, retry-with-backoff opener loop for bounded multi-process contention; `die/orchestrator/src/sqlite.rs` shared SQLite-policy module providing `SQLITE_BUSY_TIMEOUT`, `init_sqlite_connection`, and `map_sqlite_err` so every store routes lock errors through one canonical helper; `services/src/knowledge.rs` D-Bus `org.delphi.Knowledge` wrapper; sibling stores (`timeline.rs`, `goals.rs`, `conversation.rs`) all migrated to the shared helpers; 23 Codex adversarial-review findings F4–F26 resolved across nine review rounds — see "Task 3A.5 nine-round adversarial-security-hardening history" section near end of file for per-round finding ledger) — feature-branch tip `1482f51` followed by cleanup commits (Cargo.lock libc, this PROGRESS.md entry) — merged to main via the `v0.4.0-phase3a-3a5` tag commit
- Phase 3A Task 3A.6: generative workspace creation (capability #18, final 3A task) + **five rounds of Codex adversarial security hardening (14 findings across R1–R5)** (`die/orchestrator/src/workspace/{spec,validator,templates,executor,dbus}.rs` + `services/src/workspace.rs` + shell `src/workspaces/*` + workspace methods in `src/services/delphi-client.ts`; hybrid template architecture — 4 compile-time-audited baseline templates (research/code/document/design) as the trusted fast path, plus cloud-inferred custom specs validated through a strict `WorkspaceSpec` safety validator before any filesystem mutation; `COMMAND_ALLOWLIST` reduced to git/cargo/uv `init` only (R1 removed npm/pnpm/conda, R3 removed python after the `-m` cwd-module-execution finding); `ALLOWED_LEAF_DOTFILES` deny-by-default dot-prefix path policy (R5 — permits only inert leaf `.gitignore`/`.gitkeep`/`.gitattributes`, blocking the `.git/config` → `init.templateDir` exfiltration vector); openat2 `RESOLVE_NO_SYMLINKS|RESOLVE_BENEATH` path-safe execution with `O_NOFOLLOW|O_EXCL` leaf creation; record-before-execute `Pending` timeline state + symmetric `Undoing` undo; unconditional SIGKILL-to-PGID timeout teardown (R2); `env_clear()`+PATH-only command environment; comprehensive Unicode path sanitation via the `General_Category` property table (R2) incl. variation selectors through U+180F (R3); D-Bus `org.delphi.Workspace` with Preview/Create/CreateFromTemplate/ListTemplates/Undo; dry-run preview UI with Pending/Complete/PartiallyCompleted status surfacing; findings R1 (3 P1 + 6 P2), R2 (2 P2), R3 (1 P1 + 1 P3), R4 (1 P2), R5 (APPROVED, 0 findings) — full per-round ledger in the merge commit `29ddf85` message body) — implementation `201aafe`, review-fix commits `2865d3b` (R1) / `4c2d013` (R2) / `9aa1a1b` (R3) / `5fbd425` (R4-fix, R5-APPROVED), merged to main via merge commit `29ddf85` under umbrella tag `v0.4.0-phase3a`
- Phase 3A Task 3A.4: predictive crisis prevention with baseline-based anomaly detection (`die/orchestrator/src/health.rs` ~1,420 LOC with 38 tests + `die/orchestrator/src/risk.rs` ~1,040 LOC with 29 tests + `services/src/health.rs` ~420 LOC with 20 tests; `Severity` enum {Info<Warning<Critical<Emergency} with derived `Ord`, `HealthFinding` carrying `Fidelity` provenance + optional `baseline_context`, rolling `Baseline` window (1024 samples default, BASELINE_SUFFICIENT_THRESHOLD=100, median + population std_dev + is_anomalous), `DiskHealthMonitor` discovering /sys/block, running `smartctl --json -A`, parsing JSON for ATA reallocated_sectors/wear/temperature + NVMe percentage_used (declared upgrade to NVMe-CLI ioctl), `ProcessMemoryMonitor` tracking per-PID RSS over time and flagging monotonically non-decreasing series ≥10% growth across LEAK_MIN_SAMPLES=6 observations, `CrashMonitor` running `journalctl --since --output=json` and aggregating systemd-coredump MESSAGE_ID + oom-killer messages with severity scaling 1/2-4/5+, `DependencyMonitor` + `KnownVulnerableDatabase` running dpkg-query -W with stub refresh hook, pure parsers `parse_smartctl_json`/`parse_proc_status_for_rss`/`parse_journalctl_json_lines`/`parse_dpkg_query_lines`, `GitStatus` + `parse_git_status_porcelain_v2` (verified actual git format: type-1 lines have 8 tokens after "1 " prefix, type-2 has 9 with new<TAB>old in last token), `oldest_mtime_age` filesystem-mtime walker, `GoalRiskMonitor` integrating with 3A.2 GoalStore for deadline-vs-progress findings (DEADLINE_NEAR_DAYS=14, DEADLINE_IMMINENT_DAYS=7, passed-deadline Critical), `TcpState` enum + `parse_proc_net_tcp` with `parse_ipv4_hex` correctly handling kernel byte-order reversal (verified against actual WSL output: `3500007F`→`127.0.0.53`), `NetworkRiskMonitor` with `ExpectedDestination` allow-list + auto-allow loopback/link-local, `UsbRiskMonitor` polling /sys/bus/usb/devices and emitting Info on first observation only, `CrisisMonitor` composing all monitors with `check_quick`(no-subprocess) + `check_all`(everything) + free-fn `check_all_with_goals`, D-Bus `org.delphi.Health` at `/org/delphi/Health` with 8 methods (CheckAll/CheckQuick/GetDiskHealth/GetProjectRisk/GetSecurityRisk/AddWatchedRepo/RemoveWatchedRepo/AddExpectedNetworkDestination) and 2 signal declarations (HealthFindingDetected/BaselineEstablished), additive change to environment.rs adding `Default` impl to `Fidelity` enum with `Unavailable` as the natural default, no `#[cfg(target_os)]` gating — Codex security review NOT REQUIRED determination per the new §8 protocol since all probes are read-only with no fortress/services-auth/ZKQP/permission-tier/vault/cloud-routing/ssi/network-call changes) — commit `b6864f9` on feature branch — merged to main via `188516c`

## Active work

- **Last action (2026-05-30):** Phase 3B.0a **SVC-1 (ZKQP structural enforcement) COMPLETE + APPROVED** across three Codex rounds on `phase-3b/sweep-services` (3 commits, unmerged). Round 1 `db23288` made the `CloudEgressGateway` the single structurally-enforced cloud door (`CloudClient::complete` is `pub(crate)`, takes a `SanitizedPrompt` capability mintable only from a ZKQP sanitize, independent of the `sensitive` flag). Round 2 `ef24983` replaced the forgeable `cloud_confirmed: bool` confirmation gate with an HMAC-bound `ConfirmationToken` (ephemeral per-gateway key, constant-time `verify_slice`, 30 s TTL, bound to sanitized-prompt/model/max_tokens) — finding SVC-1-R1-1. Round 3 `78bb6a0` wrapped the wire token in a redacted-`Debug` `ConfirmationTokenWire` newtype (no `Display`/`Deref`; sole read path `as_str()`) so a `{:?}` on any boundary type can't persist a live bearer token — finding SVC-1-R1-1-02; +2 RED-proven redaction tests. Codex Round 3 verdict: **APPROVE-with-noted-dependency, 0 findings**, ratifying the SVC-1-R1-1-01 deferral to SVC-2 and confirming the merge gate. §13.4 self-audit at close: `cargo clippy --workspace --all-targets -- -D warnings` clean; `cargo test --workspace` = **1,730 Rust / 0 failed** across 26 binaries (WSL2 Ubuntu-24.04, cargo on `/mnt/c`); 93 TS unchanged (SVC-1 wire contract is a plain string; round-2 TS edits added no test). PROGRESS.md is this post-APPROVE `chore(progress)` commit (held out of every Codex range per the workflow lesson).
- **Previous action (2026-05-26):** Phase 3B.0 `services/` sweep — **Wave 1 (SVC-3..SVC-10) COMPLETE and APPROVED across four Codex rounds** on branch `phase-3b/sweep-services` (4 commits, unmerged). The four-round arc:
  - **Round 1 — REVISE, 10 findings (SVC-1..SVC-10).** Split by operator direction into Wave 1 (the eight directly-fixable: SVC-3,4,5,6,7,8,9,10) and the two architectural P1s (SVC-1 ZKQP structural enforcement, SVC-2 permission-tier authorization) which become Phase **3B.0a**. Wave-1 fix commit **`f72e7ce`**. Highlights: SVC-4 single sanctioned `services::error::opaque` domain-error→bus sanitizer; SVC-8 relocated the 9-round-hardened knowledge path-safety gate into `die_orchestrator::knowledge::IngestionAccessController` behind a `ValidatedIngestionPath` capability token (the store's only public file-ingest entry is now `ingest_validated_file`; raw handle path is `pub(crate)`); SVC-9 typed `OrchestratorError::{Validation,NotFound,Conflict}` (leak-proof `&'static str` fields) + goal validation moved into the domain.
  - **Round 2 — FAIL, 4 findings (1 P1).** The P1 (SVC-5-R2-1) was the integration-completeness blind spot: Wave 1's `LearningFacade` Focus gate was correct in isolation but **unarmed** — `mode.set` never called `enter_focus`, so Focus mode did not actually suppress learning. Fix commit **`826f51e`** introduced `services::mode::apply_focus_from_modes`, called inside the mode-lock critical section from BOTH transports (D-Bus `ModeService::set_mode` + WebSocket `Handler::handle_mode_set`), with a cross-transport integration test that is RED against the unarmed code. Also: SVC-5-R2-2 removed the `engine_mut()` escape hatch (engine field now private; narrow facade methods + `#[cfg(test)]` inspector); SVC-6-R2-3 exhaustive cap rollout across every D-Bus `String`/map param with a per-service `every_string_param_rejects_oversize` completeness test; SVC-7-R2-4 SSID validation switched to IEEE-802.11 byte length + Cc/Cf rejection.
  - **Round 3 — REVISE, 1 P3 (SVC-7-R3-1).** SSID sanitizer missed variation selectors (category Mn, not Cf). Fix commit **`9fff872`** promoted `workspace::validator::is_variation_selector` to `pub(crate)` (visibility-only widening — workspace validator behavior unchanged) and called it from the SSID validator so the two stay in sync by construction; corrected the doc comment; +3 RED-proven test cases (`\u{FE0F}`, `\u{180B}`, `\u{E0100}`).
  - **Round 4 — APPROVE.** No findings. Wave 1 closes SVC-3..SVC-10 with no regression; SVC-1/SVC-2 confirmed as the next unit (3B.0a).
  §13.4 self-audit at close: `cargo clippy --workspace --all-targets -- -D warnings` clean; `cargo test --workspace` = **1,716 Rust / 0 failed** across 26 binaries (WSL2 Ubuntu-24.04, cargo on `/mnt/c`); 93 TS unchanged. The branch is **held unmerged** — see the "Merge gate" section: 3B.0a lands before the merge so main never carries SVC-1/SVC-2.
- **Previous action (2026-05-22):** Task 3A.6 (generative workspace creation, capability #18 — the final Phase 3A task) shipped after five rounds of Codex adversarial security review. Implementation `201aafe` on branch `phase-3a/task-3a6-generative-workspaces`, then four review-fix commits: `2865d3b` (R1: 3 P1 + 6 P2 — npm/pnpm/conda allowlist removal, record-before-execute Pending state, symmetric undo, comprehensive path sanitation, process-group cleanup), `4c2d013` (R2: 2 P2 — unconditional SIGKILL-to-PGID after grace, Unicode `General_Category` property-table sanitation), `9aa1a1b` (R3: 1 P1 + 1 P3 — python `-m venv` allowlist removal + remaining-allowlist audit under the env_clear() regime, U+180F variation-selector precision), `5fbd425` (R4 P2 fix — the `ALLOWED_LEAF_DOTFILES` surgical dot-prefix path policy closing the `.git/config` → `init.templateDir` config-discovery exfiltration vector). Round 5 returned **0 findings — APPROVED**. Merged to main via `git merge --no-ff` at merge commit `29ddf85`; umbrella tag `v0.4.0-phase3a` created at the merge commit and pushed to origin. §13.4 self-audit at close: `cargo clippy --workspace --all-targets -- -D warnings` rc=0, `cargo test --workspace` = **1,655 Rust passed / 0 failed** (26 binaries, summed via Python over per-binary `test result:` lines; +14 vs. the pre-R5 1,641 — itself the R4-corrected baseline after R3's reported 1,629 was found to undercount by 9 via `git diff HEAD` test-fn counting), `pnpm test --run` Windows-side = **93 TS passed / 0 failed**, `pnpm build` clean. WSL2 Ubuntu-24.04 alignment verified at every round boundary including the cfg(unix) process-group descendant-kill and openat2 path-safety tests. Key architectural decision in R5: diverged from the original fix prompt's blanket leading-dot rejection (which would have failed all 4 templates that ship `.gitignore` plus the design template's 3 `.gitkeep`) to a surgical inert-leaf allowlist — surfaced to and approved by the user mid-task; templates unchanged.
- **Previous action (2026-05-16):** Task 3A.5 (knowledge synthesis engine) shipped after nine rounds of Codex adversarial security review. The feature branch `phase-3a/task-3a5-knowledge-synthesis` carried twelve production-fix commits (F4–F26, the rounds 1–9 review iterations) plus two cleanup commits (Cargo.lock for the carried-forward FIX-15 libc delta at `2b52f7e`, this PROGRESS.md update for the nine-round history). All 23 findings (P1-high through P2-low across services-side input validation, orchestrator-side path safety, SQLite schema migration correctness, multi-process opener contention, and project-wide policy completeness) closed and verified with the round-9 final Codex PASS verdict. Section 13.4 self-audit: `cargo check --workspace` clean, `cargo clippy --workspace --all-targets -- -D warnings` clean, `cargo test --workspace` = **1,471 passed / 0 failed / 0 ignored** (+188 vs. 3A.4 baseline of 1,283; +5 in this round-9 commit alone). Pre-merge test count verified by Python regex parser over per-binary `test result:` lines summed to literal `Total: 1471`. WSL2 Ubuntu-24.04 alignment verified at every round boundary. The rsync-residue stash (`ef33afd`, "On main: rsync-residue-pre-round-6-sync 2026-05-14, safe to drop after verification") was preserved as the recovery handle through rounds 6–9 and dropped only after the merge + tag landed. The nine-round adversarial-review methodology — cold-reviewer Codex prompts with mandatory tool grounding via Context7 + Codex CLI — establishes documented precedent for Fortress layer work in Phase 3B.
- **Previous action (2026-04-25):** Task 3A.4 (predictive crisis prevention) shipped via the new feature-branch workflow. The branch `phase-3a/task-3a4-crisis-prevention` carried three commits: `10d5932` (CLAUDE.md branch-workflow rule replacing old "Branch Naming" subsection), `ea39c1a` (CLAUDE.md mandatory Codex security review protocol with Step 1-4 procedure), and `b6864f9` (the 3A.4 implementation: 6 files, 2,887 insertions / 2 deletions — `die/orchestrator/src/health.rs` 1,420 LOC with 38 tests, `die/orchestrator/src/risk.rs` 1,040 LOC with 29 tests, `services/src/health.rs` 420 LOC with 20 tests, plus module wiring in two lib.rs files and the additive `Default` impl on `Fidelity`). Merged to main via `git merge --no-ff` at merge commit `188516c` after explicit "Codex security review: NOT REQUIRED" determination (touched only read-only observation code; no fortress/services-auth/ZKQP/permission/vault/ssi/external-network changes). Section 13.4 self-audit: `cargo check --workspace` clean, `cargo clippy --workspace --all-targets -- -D warnings` clean (two initial warnings — `derivable_impls` on `DependencyMonitor` and `needless_question_mark` in `oldest_mtime_age` — both fixed at root cause), `cargo test --workspace` = **1,283 passed / 0 failed / 0 ignored** (+87 vs. 3A.3 baseline of 1,196; 38 + 29 + 20 = 87 new tests exactly), `pnpm test --run` Windows-side = **73 passed / 0 failed**. Total **1,356 tests passing**. Pre-flight verification on WSL2 Ubuntu-24.04 confirmed: smartctl absent (graceful Unavailable path is primary), /sys/block has sda/sdb/sdc/sdd plus loops/rams (filter test confirms non-real devices excluded), /sys/bus/usb/devices empty on Hyper-V (no false-positive findings), journalctl JSON output structure verified with actual kernel-boot entry, dpkg-query default tab-separated format used (avoids quoting interpolation issues with custom -f format strings), git 2.43.0 present, /proc/net/tcp showed actual systemd-resolved listeners at 127.0.0.53:53 and 127.0.0.54:53 — these exact hex strings (`3500007F:0035`, `3600007F:0035`) are the literal test fixtures verifying the kernel byte-order reversal in `parse_ipv4_hex`. Two test failures during the iteration (`git_porcelain_dirty_repo_classifies_modified_and_staged` and `git_porcelain_handles_renamed_files`) were root-cause-fixed by correcting the splitn field count (porcelain v2 type-1 = 8 fields after "1 " prefix not 9; type-2 = 9 fields not 10) and reversing the test fixture's `<old>\t<new>` to match real git output `<new>\t<old>` per format spec.
- **Next action (2026-06-11, post-merge):** **`fortress/` sweep MERGED at `84d84b3` — Phase 3B.0 is CLOSED** (all three crate sweeps — services / orchestrator / fortress — swept and on main, no known P1). Next major unit: the **leverage pass** (`infra/leverage-pass`, the Fable "Exponential Leverage" document), run against stable post-merge `main` — where Phase 2's `delphi-hardening` crate can finally migrate ALL call sites including fortress's audit-hash + detectors, and Phase 3 can mine the complete fortress corpus into `DEFECT_CLASSES.md`. **Reconcile first:** the parallel `quality/elevation-pass` branch (WIP `docs/CODEBASE_REVIEW.md`, a crate-by-crate quality review — Phase-1 DRAFT, 8 of ~15 crates read) overlaps the leverage pass and must be folded into its scoping rather than run as a second infra branch. Tracked follow-ups carried forward: regex migration (security-reweighted; corroborated by the review's FORT-Q3), Piece-1b (task_758940a5), ORCH-R1-06 at-rest encryption (re-homed, open — `EncryptionService` stub; review FORT-Q7), vault crypto-hygiene (latent; review FORT-Q2), permission downgrade docs (latent). Security-relevant candidates surfaced by the review: **INF-1 CLOSED** (fixed via the module-private `ApiKey` redacting newtype, Codex APPROVE 0-findings — see the INF-1 section); still NOT yet triaged: BVB-3 (`file://` browser nav, no scheme allowlist), BVB-4 (builder template path-traversal vs. the hardened workspace executor), FORT-Q4 (address/name/geo detector coverage gap). INF-3 (cloud.rs vault-doc drift, surfaced during the INF-1 fix) is a separate noted follow-up.
- **Uncommitted WIP:** none on `main` beyond this post-merge `chore(progress)` (records the merge SHA `84d84b3`; mirrors the orchestrator sweep's `9edab8c`; local, ahead 1 of origin until the next push). The `phase-3b/sweep-fortress` branch is merged + deleted. Separately, the `quality/elevation-pass` worktree (`C:/dev/Delphi-quality`, branch tip `8d97cb0`) holds the now-committed codebase-review DRAFT, rebased onto `84d84b3`, clean — preserved for leverage-pass reconciliation, not to be deleted.
- **Verification artefacts (2026-05-26 session):** Rust total **1,716 passed / 0 failed** across 26 binaries via `cargo test --workspace 2>&1 | grep 'test result: ok' | grep -oE '[0-9]+ passed' | grep -oE '[0-9]+' | paste -sd+ - | bc`; clippy clean (`cargo clippy --workspace --all-targets -- -D warnings`, exit 0); 93 TS unchanged (sweep touched only Rust). SVC-7-R3-1 RED proof captured: with `is_variation_selector` disabled the test failed with exactly the three VS SSIDs (`\u{fe0f}`,`\u{180b}`,`\u{e0100}`) stored and no others, confirming the test isolates the gap. All counts from commands executed this session, not memory (Iron Law #12 / §13.5).

## Phase 3B.0 services-sweep — Codex ledger (`services/` crate)

Four-round arc on branch `phase-3b/sweep-services` (all four commits unmerged):

| Round | Verdict | Findings | Fix commit |
|-------|---------|----------|-----------|
| 1 | REVISE | 10 (SVC-1..SVC-10) | `f72e7ce` (Wave 1 = the 8 fixable) |
| 2 | FAIL | 4 (SVC-5-R2-1 P1, SVC-5-R2-2, SVC-6-R2-3, SVC-7-R2-4) | `826f51e` |
| 3 | REVISE | 1 (SVC-7-R3-1 P3) | `9fff872` |
| 4 | **APPROVE** | 0 | — |

**Wave 1 (the eight fixable findings — fixed in `f72e7ce`, hardened in `826f51e`/`9fff872`):**

| ID | Sev | Fix | Where |
|----|-----|-----|-------|
| SVC-3 | P2 | git invocation hardening (disable fsmonitor/hooks/alias config-exec; env isolation; cfg null device) | `die/orchestrator/src/risk.rs` |
| SVC-4 | P1 | single sanctioned domain-error→bus sanitizer `opaque(context,err)` (closes the 3A.5-F7 path-disclosure oracle crate-wide) | `services/src/error.rs` (new) + all service methods |
| SVC-5 | P1 | learning Focus-mode gating via domain `LearningFacade`; **R2-1** armed the gate from both transports via `services::mode::apply_focus_from_modes` (Round-1 gate was unarmed); **R2-2** removed the `engine_mut()` escape (engine field private) | `die/orchestrator/src/learning.rs` (new), `services/src/{learning,mode}.rs`, shell-bridge |
| SVC-6 | P2 | DoS payload caps (1 MiB / 8 MiB); **R2-3** exhaustive rollout across every D-Bus `String`/map param (cap before any log/parse/store) + `ensure_map_within` + per-service `every_string_param_rejects_oversize` completeness tests | `services/src/limits.rs` (new) + all services |
| SVC-7 | P2 | location-label grammar in the domain; **R2-4** IEEE-802.11 byte length + Cc/Cf rejection; **R3-1** also reject variation selectors via shared `workspace::validator::is_variation_selector` | `die/orchestrator/src/environment.rs` `LocationMap::set_label` |
| SVC-8 | P1 | knowledge path-safety → domain `IngestionAccessController` + `ValidatedIngestionPath` capability token; `ingest_validated_file` is the only public ingest entry (raw handle path now `pub(crate)`) | `die/orchestrator/src/knowledge.rs` + `services/src/knowledge.rs` |
| SVC-9 | P1 | typed `OrchestratorError::{Validation,NotFound,Conflict}` (`&'static str`, leak-proof) + domain goal validation + transport `map_orchestrator` | `die/orchestrator/src/{error,goals}.rs` + `services/src/{error,goals}.rs` |
| SVC-10 | P2 | workspace test hardening (specific-rejection + no-leak assertions) | `services/src/workspace.rs` |

**Phase 3B.0a — the two architectural P1s (the NEXT engineering unit; land BEFORE the merge to main, NOT deferred-with-known-gaps):**

These were carved out of Wave 1 because they are architectural, not point fixes — but they are **not** deferred past the merge. Main must never contain a known P1, so the `services/` Wave-1 branch is held unmerged until 3B.0a lands on it (or a stacked branch) and the two merge to main together. 3B.0a is **design-first** (Codex design prescription → joint architecture review → implement), the same discipline SVC-5/8/9 used. Front-loaded ahead of the `die/orchestrator/` + `fortress/` sweeps because both P1s live in the inference/D-Bus boundary the sweep just hardened (hot context) and are the hardest remaining 3B.0 architecture.

- **SVC-1 (P1) — ZKQP structural enforcement. ✅ COMPLETE + APPROVED (3 Codex rounds).** It is now structurally impossible for any module to reach a cloud provider without passing through the ZKQP sanitizer: the `CloudEgressGateway` is the single public door, `CloudClient::complete` is `pub(crate)` and takes a `SanitizedPrompt` capability mintable only from a ZKQP `sanitize` call (mirrors SVC-8's `ValidatedIngestionPath`), independent of the caller-controlled `sensitive` flag. The high-privacy-score confirmation pause is gated by an HMAC-bound `ConfirmationToken` (ephemeral per-gateway key, constant-time verify, 30 s TTL, bound to the sanitized prompt/model/max_tokens) so consent cannot be **forged**; the wire form is a redacted-`Debug` `ConfirmationTokenWire` newtype so a live token cannot leak via `{:?}`. Commits: Round 1 `db23288` (structural egress door), Round 2 `ef24983` (forgery-closed token, finding SVC-1-R1-1), Round 3 `78bb6a0` (redaction newtype, finding SVC-1-R1-1-02). Codex Round 3: **APPROVE-with-noted-dependency, 0 findings** — Codex ratified the SVC-1-R1-1-01 deferral on the layer argument and independently confirmed the merge gate ("merged without SVC-2, the known consent gap would become a release blocker"). See the **SVC-1-R1-1-01 open cross-finding dependency** subsection below.
- **SVC-2 (P1) — permission-tier authorization on D-Bus methods. ⏳ NEXT (design-first).** Privileged/Autonomous-tier D-Bus methods must authorize the caller against the permission model before acting, deny-by-default, with explicit unauthorized-caller tests. Requires designing where the authorization layer lives, the tier taxonomy, and how session-bus callers are authenticated at the boundary. **SVC-2 also carries the named SVC-1-R1-1-01 consent-validation deliverable** (below): cloud-send confirmations must be validated against the authenticated shell session so an echoed token from a non-shell caller is rejected at the live cloud-send path.

**SVC-1-R1-1-01 — OPEN cross-finding dependency (SVC-1 → SVC-2), tracked here so it does not depend on memory:**

The SVC-1 HMAC token closes token **forgery** (a caller cannot fabricate a token the gateway did not mint). It does **not** by itself enforce that a trusted **human** confirmed — a caller can request a token and echo it back in two calls without any human seeing the preview. The token proves "the gateway issued this challenge for this exact sanitized content," not "a human approved." Closing the consent gap requires a trusted-caller-identity layer that distinguishes the legitimate shell (which actually shows the user the dialog) from an arbitrary process echoing a token — that layer is SVC-2 by definition; `die-inference` is a library with no concept of a trusted user, so building it there would be SVC-2's caller-authentication in the wrong crate. Codex Round 3 ratified this deferral and independently confirmed the merge gate. SVC-1 is forgery-closed; consent-enforcement is carried into SVC-2; both land together before the merge to main, so the gap never reaches main.

**SVC-1-R1-1-01 closure check (mandatory acceptance criterion — integration, not isolation):** SVC-2 must close the two-call cloud-consent bypass. Acceptance = a RED-proven test that exercises the **LIVE cloud-send path end-to-end** (the actual D-Bus/WebSocket entry point, **NOT** an isolated identity-check function): an unauthenticated caller requests a cloud-confirmation token through the real entry point, echoes it back through the real entry point, and the **ACTUAL cloud send is rejected**. The test must fail against current code (the two-call bypass reaches the send today) and pass after SVC-2 wires authenticated-shell validation **INTO** the send path. A test that only verifies an authenticated-shell-check function in isolation does **NOT** satisfy this — it must prove the check is armed on the live path (the SVC-5 lesson: a gate that exists but isn't wired looks done and isn't). **SVC-2 is not complete, and the merge to main does not happen, until this integration test exists and is green.**

**Follow-ups captured during the sweep (do NOT implement in 3B.0):**

1. **SVC-5 retro-filter gap.** Wave-1 gating is *observation-only* — engaging Focus mode stops NEW recording but does not retroactively purge events recorded while it was off. Retroactive filter/purge → Phase 3B.0a/3B.1.
2. **SVC-9 `update_progress` wire-contract change.** Out-of-range progress now returns typed `InvalidArgs` instead of silently clamping to 100. `org.delphi.Goals` is backend-only at v0.4 (no shell consumer), so no UI impact today; when the Goals UI is mounted, the client must handle `InvalidArgs` rather than assuming a clamp.
3. **Backend-only interfaces ("built-but-unmounted").** The Goals and Knowledge D-Bus interfaces are not yet wired to any shell surface (corroborated by the ACCESSIBILITY_BASELINE.md v0.4 audit), so their SVC-8/SVC-9 wire-contract changes are transparent to the UI now but must be honored at mount time.
4. **SVC-8 Linux-only ingestion.** `ingest_file` requires Linux `openat2`; Windows/macOS return `AccessDenied` and callers must use `ingest_text`. Cross-OS ingestion is a Phase 3C item (per the multi-OS-from-3C commitment).

## Workspace crate layout (13 Cargo members + shell React app)

```
compositor/             # Wayland compositor (Smithay)
proto/                  # Protobuf IPC definitions
shell-bridge/           # React <-> D-Bus WebSocket bridge
services/               # D-Bus service wrappers (9 interfaces: conversation, environment, file_search, goals, health, inference, learning, mode, timeline)
fortress/               # Security layer (incl. zkqp/)
semantic-fs/            # Indexed file search
die/orchestrator/       # Central brain + planner + timeline + apps + brain
die/inference/          # Three-tier inference router + cloud
die/browser/            # Playwright headless Chromium
die/builder/            # Full-stack project builder
die/voice/              # Whisper STT + Piper TTS
die/learning/           # Universal learning engine
ssi/sdk-rust/           # Rust SSI SDK
(shell/ — React 19 + TypeScript + Vite + Tailwind, not a Cargo member)
```

## Capability tracker (mirror of CLAUDE.md Section 11)

| # | Capability | Status | Phase |
|---|-----------|--------|-------|
| 1 | Behavioral learning engine | Phase 2 complete (built + tested) | 0+2 |
| 2 | Deep internet agency | Partial — die-browser IPC layer built + tested; the Playwright `agent.js` it drives does not exist in-repo, no production consumer (Brain unwired) | 1 |
| 3 | Multi-specialty reasoning | Partial — router exists; specialist mesh → Phase 3 | 3 |
| 4 | Infinite task chaining | Phase 1+2 complete (brain + checkpoints + apps) | 1+2 |
| 5 | Conversational presence | **Task 3A.1 complete** — persistent memory + FTS + reference resolution + memory tiering shipped at `2d67a29`; voice I/O scaffolded in Phase 1 (STT/TTS are stubs — placeholder text / silence, no whisper-rs/Piper) | 3A |
| 6 | Goal and planning architecture | **Task 3A.2 complete** — goal graph + timeline estimation + stale/deadline detection + D-Bus `org.delphi.Goals` shipped at `609826d` | 3A |
| 7 | Full-stack builder | Scaffold-only — template file-copy built + tested; `{{project_name}}` substitution, Generating/Building/Testing states, minijinja, post-scaffold exec all unimplemented; no production consumer | 2 |
| 8 | Client/company workspace adaptation | Not started | 3B |
| 9 | Sovereign local intelligence | Partial — Fortress + ZKQP built | 0+2 |
| 10 | Non-interference philosophy | Encoded (no code) | 0 |
| 11 | Endurance and resilience | Partial — checkpointing exists; rolling context → 3B | 3B |
| 12 | Ambient environmental awareness | **Task 3A.3 complete** — fidelity-tagged sensors (battery / thermal / memory / disk / time / location / activity) + D-Bus `org.delphi.Environment` shipped at `62201ee` | 3A |
| 13 | Predictive crisis prevention | **Task 3A.4 complete** — baseline-based anomaly detection across disk SMART / memory leaks / journal crashes / dependency CVEs / git uncommitted-age / goal deadlines / TCP destinations / USB events + D-Bus `org.delphi.Health` shipped at `b6864f9` (merged via `188516c`) | 3A |
| 14 | Relationship intelligence | Not started | 3B |
| 15 | Cross-device federated sync | Not started | 3B |
| 16 | Temporal intelligence | Not started | 3B |
| 17 | Knowledge synthesis engine | **Task 3A.5 complete** — KnowledgeStore + KnowledgeNode/KnowledgeEdge graph + SQLite hybrid storage + openat2 path safety + atomic schema migration + retry-with-backoff opener + shared `die_orchestrator::sqlite` policy helpers + D-Bus `org.delphi.Knowledge`; hardened across nine rounds of Codex adversarial review (23 findings F4–F26 resolved); merged via tag `v0.4.0-phase3a-3a5` | 3A |
| 18 | Generative workspace creation | **Task 3A.6 complete** — hybrid template architecture (4 compile-time-audited baseline templates + validated cloud-inferred specs), `COMMAND_ALLOWLIST` (git/cargo/uv `init`), `ALLOWED_LEAF_DOTFILES` deny-by-default dot-prefix path policy, openat2 path-safe execution, record-before-execute timeline + symmetric undo, D-Bus `org.delphi.Workspace`; hardened across **five rounds of Codex adversarial review (14 findings R1–R5)**; merged via merge commit `29ddf85` under umbrella tag `v0.4.0-phase3a` | 3A |

**Phase 3A close tally: 10 done / 1 encoded / 3 partial / 4 not-started.** Done: #1, 2, 4, 5, 6, 7, 12, 13, 17, 18. Encoded: #10 (non-interference). Partial: #3 (multi-specialty reasoning), #9 (sovereign local intelligence), #11 (endurance/resilience). Not started — Phase 3B targets per the "Delphi Vision and Architecture" section: #8 (client/company workspace adaptation), #14 (relationship intelligence), #15 (cross-device federated sync), #16 (temporal intelligence).

## Fortress tracker (mirror of CLAUDE.md Section 11)

| Layer | Name | Status | Phase |
|-------|------|--------|-------|
| 1 | Hardware root of trust (TPM) | Not started | 3B |
| 2 | LUKS2 + hidden volumes | Partial (LUKS2 basic); hidden volumes deferred | 3B |
| 3 | ZKQP | Phase 2 complete (built + tested) | 2 |
| 4 | FHE | Not started | 3+ |
| 5 | Federated behavioral sync | Not started | 3B |
| 6 | zk-SNARK audit proofs | Not started (SHA-256 precursor exists) | 3+ |
| 7 | Post-quantum cryptography | Not started | 3B |

Currently implemented: AES-256-GCM vault, Argon2id key derivation, SHA-256 audit chain, 4-tier permission model, ZKQP.

## Phase 3A task list

- **3A.0** — verification baseline + commit/tag Phase 1+2 ✅ **complete** (combined into `v0.3.0-phase2`)
- **3A.1** — Persistent conversation memory (`die/orchestrator/src/conversation.rs` + `reference.rs` + `services/src/conversation.rs` — SQLite with FTS5 + WAL, reference resolution, memory tiering, "forget today"/"forget topic"/"forget older than", D-Bus `org.delphi.Conversation`, 49 tests) — ✅ **complete** at commit `2d67a29`
- **3A.2** — Goal and planning architecture (`die/orchestrator/src/goals.rs` + `services/src/goals.rs` — DAG with O(depth) cycle detection, priority heuristic (7/21/45/90 days) + learned-pace timeline estimator, DeadlineRisk banding (OnTrack/Tight/AtRisk/Missed/NoDeadline), stale detection, D-Bus `org.delphi.Goals` with tri-state JSON patch and 4 signal declarations, 42 + 27 tests) — ✅ **complete** at commit `609826d`
- **3A.3** — Ambient environmental awareness (`die/orchestrator/src/environment.rs` + `services/src/environment.rs` — fidelity-tagged sensors, layered battery probe, /proc/meminfo + PSI, TOML LocationMap, activity classifier, D-Bus `org.delphi.Environment` with 8 methods + 6 signal declarations, 69 + 18 = 87 tests) — ✅ **complete** at commit `62201ee`
- **3A.4** — Predictive crisis prevention (`die/orchestrator/src/health.rs` + `risk.rs` + `services/src/health.rs` — `Severity` ordered enum, rolling `Baseline` median+std_dev windows, disk SMART probes (smartctl JSON), process memory leak detection (RSS monotonic-climb), crash aggregation (journalctl coredump+oom), dependency CVE comparison (dpkg-query), git porcelain v2 staleness, goal deadline-vs-progress, /proc/net/tcp parsing with verified IPv4 byte-order reversal, USB device tracking, `CrisisMonitor` composing all monitors, D-Bus `org.delphi.Health` with 8 methods + 2 signal declarations, 38 + 29 + 20 = 87 tests) — ✅ **complete** at commit `b6864f9` (merged to main via `188516c` after explicit "Codex security review: NOT REQUIRED" determination)
- **3A.5** — Knowledge synthesis engine (`KnowledgeNode` + `KnowledgeEdge` graph, SQLite hybrid storage, openat2 RESOLVE_NO_SYMLINKS|RESOLVE_BENEATH path safety, atomic schema migration with version table, retry-with-backoff opener loop, shared `die_orchestrator::sqlite` SQLite-policy helpers used by all stores, D-Bus `org.delphi.Knowledge`, 436 tests in knowledge.rs) — ✅ **complete** at feature-branch tip `1482f51` + Cargo.lock cleanup `2b52f7e` + PROGRESS.md cleanup, merged to main via tag `v0.4.0-phase3a-3a5` after **nine rounds of Codex adversarial security hardening (23 findings F4–F26 resolved)**
- **3A.6** — Generative workspace creation (hybrid template architecture: 4 compile-time-audited baseline templates + cloud-inferred specs validated through a strict `WorkspaceSpec` validator, `COMMAND_ALLOWLIST` git/cargo/uv `init`, `ALLOWED_LEAF_DOTFILES` deny-by-default dot-prefix path policy, openat2 `RESOLVE_NO_SYMLINKS` path-safe execution, record-before-execute `Pending` timeline + symmetric undo, D-Bus `org.delphi.Workspace`, dry-run preview UI) — ✅ **complete** at implementation `201aafe` + R1–R5 review fixes (`2865d3b` / `4c2d013` / `9aa1a1b` / `5fbd425`), merged to main via merge commit `29ddf85` after **five rounds of Codex adversarial security hardening (14 findings R1–R5; R5 APPROVED with 0 findings)**
- **End of Phase 3A** — ✅ **complete**: phase-end verification protocol run (`cargo clippy --workspace --all-targets -- -D warnings` rc=0, `cargo test --workspace` = 1,655 Rust / 0 failed, `pnpm test --run` = 93 TS / 0 failed, `pnpm build` clean), umbrella tag `v0.4.0-phase3a` created at merge commit `29ddf85`. Final total **1,748 tests** (1,655 Rust + 93 TS), well past the 1,150+ target.

## Phase 3B priority items (carried from Task 3A.6 five-round review lessons)

The 3A.6 review surfaced a coherent threat model whose lessons should be applied retroactively across existing crates during the Phase 3B Codex sweep:

1. **User-content-execution framing for existing allowlists.** An `(program, argv)` allowlist defends against shell/argv injection but NOT against an allowlisted program executing user-controlled content from its working directory (R1 npm/pnpm/conda lifecycle scripts; R3 `python -m` cwd-module resolution). Audit every existing allowlist / subprocess invocation (die-builder, die-browser, ssi capability execution, semantic-fs indexers) under this framing.
2. **Config-discovery framing for filesystem operations.** `env_clear()`+PATH-only neutralizes environment-based config discovery but does NOT stop a tool from reading workspace-controlled dotfiles (R4 `.git/config` → `init.templateDir` exfiltration). Audit any code that runs a tool with `current_dir` set into user-controlled content; apply the `ALLOWED_LEAF_DOTFILES` deny-by-default dot-prefix policy pattern where applicable.
3. **TDD-soundness audit.** Verify existing security-critical tests actually fail against buggy code (R3 caught a descendant-survival test that passed for the wrong reason because the backgrounded descendant inherited the capture pipes, masking whether cleanup actually killed it). Tests that pass for the wrong reason are worse than no tests.
4. **Python allowlist re-evaluation.** `python` was removed from `COMMAND_ALLOWLIST` entirely in R3. If pilot-user feedback indicates the auto-venv UX is missed, re-evaluate admitting a content-safe pattern (e.g. `python -I -m venv` — `-I` isolated mode drops cwd from `sys.path` — run from a Delphi-controlled directory), with explicit review, since allowlisting a flag-sensitive invocation makes safety hinge on exact argv order.
5. **`.gitattributes` allowlist-scope re-evaluation (Codex R5 forward-looking note).** `.gitattributes` is inert today because the only allowlisted git operation is `git init`. If future allowlist growth admits `git add`/`checkout`/`diff`/`merge`/`archive`, re-evaluate `.gitattributes` in `ALLOWED_LEAF_DOTFILES`: those operations honor `filter`/`diff`/`merge` driver directives that can execute configured commands, which would turn a currently-inert leaf dotfile into a code-execution vector.

## Notes

- **Blocker:** None active.
- **Phase 1+2 split caveat:** `git log` shows a single combined commit `90a25f8` for both phases. Granular 16-commit split was infeasible because Phase 2 code is interwoven with Phase 1 files (`services/src/learning.rs` inside the services crate, `shell-bridge/src/handler.rs` has 150+ lines of learning handlers mixed with Phase 1 handlers, `die/orchestrator/src/error.rs` enum has both `BrowserError` and `LearningError` variants). Tagging both v0.2.0-phase1 and v0.3.0-phase2 at the same SHA would have been misleading, so only `v0.3.0-phase2` was created. A later `git rebase -i` with file-level patches can reconstruct the boundary if desired.
- **Remote:** None configured — user to create private GitHub repo and push for off-disk backup.
- **WIP:** none. `dirs` workspace dep landed with 3A.1; `chrono` promoted to workspace dep with 3A.2 (orchestrator + services both depend on it for RFC 3339 encoding and deadline arithmetic); `tempfile = "3"` promoted to `[workspace.dependencies]` with 3A.3 (orchestrator + inference dev-deps now share it for tempdir-backed mock-filesystem tests).
- **Dev environment:** Windows host (source of truth), WSL2 Ubuntu-24.04 at `/home/raven/delphi` mirror for cargo operations (Smithay/llama-cpp-2 need Linux system libs). Shell (pnpm) works on either. `rsync -a --delete --exclude='target/' --exclude='node_modules/' --exclude='.claude/' --exclude='.claude-flow/' --exclude='.mcp.json' /mnt/c/Users/kvlnr/OneDrive/Desktop/Delphi/ /home/raven/delphi/` syncs Windows → WSL.
- **Anti-hallucination protocol:** CLAUDE.md Section 13 in effect. All test counts, commit counts, and codebase claims must come from executed commands in the current session. Section 13 + Iron Law #12 landed at commit `dae8bf2`. The 3A.2 session-report numbers (1,109 Rust tests, 73 TS tests, 42 + 27 = 69 new unit tests, 4,044 insertions) were all produced by commands executed this session (`cargo test --workspace`, `pnpm test --run`, `grep -cE`, `git diff --stat`, `git show --stat 609826d`).
- **Phase 3A.2 zbus 5.x signal pattern (for future reference):** signal declarations live inside the `#[interface]` impl block as `#[zbus(signal)] async fn name(signal_emitter: &SignalEmitter<'_>, ...) -> zbus::Result<()>;` with no body and no `&self`. The macro generates both the introspection XML entry and the emission method on `SignalEmitter<'_>`. Emission requires a live `Connection`, so the services wrapper declares signals (for introspection completeness + unit-testability without a bus) and defers actual emission to the orchestrator daemon that owns the `SignalEmitter`.
- **Phase 3A.3 fidelity-first design notes (for future reference per Iron Law #13):** every external-source integration must declare its fidelity hierarchy in module doc comments and probe top-down (highest fidelity first; fall back on failure with a `tracing::debug!` log). The `Fidelity` enum is wire-stable via `as_str()` so D-Bus consumers can filter or weight readings. `Fidelity::Unavailable` is the cross-platform default — sensors return it when target paths/binaries don't exist, which is how the module compiles cleanly on Windows without `#[cfg(target_os = "linux")]`. Cross-platform compile is achieved through `Path` being platform-agnostic and `Command::new("missing-binary")` returning `Err` (mapped to Unavailable). Per-domain Fidelity provenance (one Fidelity per BatteryInfo / ThermalInfo / MemoryInfo / LocationContext, plus a `disk_fidelity` field on EnvironmentState) is finer-grained than per-state and gives consumers actionable provenance for each subdomain. The activity classifier is a pure function with no I/O — observations come from compositor + learning observer wiring (a future task) and the classifier just maps observations → ActivityState. WSL Hyper-V dev-system caveat: `/sys/class/thermal/` exposes only `cooling_device*` (12 of them, all type "Processor"), no `thermal_zone*`, so on this dev box thermal readings are legitimately Fidelity::Unavailable; the same code on a real laptop will return Fidelity::Direct.

## Codex adversarial security review - `78c5ba4..6ea6c36`

Scope: one commit, `6ea6c36 fix(sqlite): extend transient-lock policy to sibling stores + retry off-by-one (F22, F23, F24)`. Diff stat matched the requested seven changed files; `die/orchestrator/src/error.rs` was not touched in this range.

Verification run:

- `git log --oneline 78c5ba4..6ea6c36` -> one commit, `6ea6c36`.
- `git diff 78c5ba4..6ea6c36 --stat` -> 7 files, 566 insertions, 143 deletions.
- Requested per-file diffs reviewed for `sqlite.rs`, `lib.rs`, `knowledge.rs` first 200 lines, `timeline.rs`, `goals.rs`, `conversation.rs`, and `CLAUDE.md`.
- WSL sync/test command passed: workspace total is 1,466 passing tests.
- Targeted tests passed: `routes_database` 10 passed; `in_memory_busy_timeout` 3 passed; `retry_with_backoff` 2 passed; `open_or_init_survives_n_thread_contention` 1 passed; `map_sqlite_err` 8 passed; targeted migration/FK checks for F14/F17/F19 passed.

F22 helper review:

- Public symbols in `die/orchestrator/src/sqlite.rs`: `SQLITE_BUSY_TIMEOUT`, `init_sqlite_connection(&Connection)`, and `map_sqlite_err(rusqlite::Error, &str)`. Contracts are documented. `init_sqlite_connection` currently only pins `busy_timeout`; it does not enable `foreign_keys`. `map_sqlite_err` correctly routes `DatabaseBusy` and `DatabaseLocked` to `TransientLock`, preserving `Planning("{context}: {err}")` for all other rusqlite errors.
- `pub mod sqlite;` is registered in `lib.rs`.
- `sqlite.rs` imports only std time, rusqlite connection/error types, and `OrchestratorError`; no new dependency, unsafe block, or production FFI surface was added. Test-only code synthesizes rusqlite ffi error constants.
- Added unwraps are test-only in `sqlite.rs` helper tests and sibling `in_memory_busy_timeout` tests. No new production unwrap, expect, or unsafe block.
- New `sqlite.rs` tests cover the important branches, but not every non-`SqliteFailure` enum variant in `rusqlite::Error` 0.35.0. They cover one non-`SqliteFailure` representative (`QueryReturnedNoRows`), which is enough for branch behavior but not exhaustive variant parity with the round-7 walkthrough.

F22 call-site audit:

- Random spot-check sample, 5 map sites per sibling:
  - `timeline.rs`: `failed to open timeline db`, `timeline init_sqlite_connection`, `timeline in_memory init`, `failed to mark undone`, `count failed`.
  - `goals.rs`: `insert goal failed`, `query failed`, `row`, `row read failed`, `count failed`.
  - `conversation.rs`: `search failed`, `forget_older_than failed`, `conv count failed`, `msgs_since prepare`, `forget_topic failed`.
- Most remaining `OrchestratorError::Planning(format!(...))` hits are legitimate non-rusqlite paths: enum parsing, validation, serde JSON, `std::fs::create_dir_all`, or explicit domain errors after already-mapped existence checks.
- Manual block-form fixes mostly hold: `goals.rs` dynamic `goal {id} not found`, `goals.rs` row helper `sql_err`, and `conversation.rs` row collection now route through `map_sqlite_err`.
- The missed block forms below are real findings.

F23/F24 behavior:

- SQLite docs confirm unadorned `:memory:` databases are private to the opening connection; shared in-memory databases require a URI/shared-cache form and only share within one process. The current constructors call `Connection::open_in_memory()`, so F23 remains a policy/regression-detection change for current code, not a functional cross-process safety fix. References checked: <https://www.sqlite.org/inmemorydb.html>, <https://www.sqlite.org/sharedcache.html>, <https://www.sqlite.org/pragma.html#pragma_busy_timeout>.
- `Connection::open` grep found only the expected production public-store paths: `Timeline::open`, `GoalStore::open`, `ConversationStore::open`, `KnowledgeStore::try_open_and_backfill_once`, and their `open_in_memory` counterparts. Other hits are tests/fixtures.
- `retry_with_backoff` has one production caller: `KnowledgeStore::open`.
- F24 worst-case latency is approximately `6 * 5s busy_timeout + 3.1s sleep = 33.1s`, not 28s. No Delphi systemd unit, container startup timeout, or daemon startup timeout was found in repo docs/config that would currently conflict with this.
- The F24 test adds about 3.1s of deliberate sleep; CI cost is noticeable but bounded. Existing F20 contention coverage is already about 5.4s, so keeping the F24 unit enabled is defensible.

Round 1-7 regression checks:

- No added production `File::open`, `std::fs::*`, `openat2`, or `safe_open_under_root` use in the diff; only an added comment mentions `std::fs::create_dir_all`.
- F7 public rejection: new `map_sqlite_err` context strings are static except `goal {id} not found`, where `id` is numeric. No sqlite context string includes a filesystem path. The pre-existing non-sqlite `conversation.rs` directory-create error still includes `parent.display()`, but F22 did not add a sqlite path leak.
- F12 FK enforcement: `init_sqlite_connection` does not set `foreign_keys`. `KnowledgeStore::init_schema` enables and verifies `PRAGMA foreign_keys = ON` on every knowledge connection; `GoalStore::{open,in_memory}` enable it explicitly; `ConversationStore::open` enables it in `configure_pragmas`; `ConversationStore::in_memory` still skips `configure_pragmas` and therefore does not enable FK enforcement for the in-memory fixture path. That is pre-existing and not caused by F22/F23/F24, but it is worth fixing if the conversation store wants in-memory/test parity beyond busy-timeout.
- F14/F17 atomic FK check + version write is intact: migration and current-schema backfill keep `PRAGMA foreign_key_check` and `schema_version` write inside one transaction, with rollback on error.
- F19 backfill serialization is intact: `backfill_version_with_integrity_check` uses `TransactionBehavior::Immediate` and re-reads `schema_version` under the write lock.
- F20 retry loop and F21 typed routing tests pass after the F24 attempt bump.

Findings:

### F25 - P2-medium - F22 missed two rusqlite `query_row` error paths that still collapse lock contention into `Planning("...not found")`

Locations:

- `die/orchestrator/src/timeline.rs:241`
- `die/orchestrator/src/conversation.rs:414`

Root cause:

The F22 regex/manual sweep converted the common `.map_err(|e| Planning(format!("...: {e}")))` forms, but missed `.map_err(|_| Planning(format!("...not found")))` forms that discard the original `rusqlite::Error`. Both call sites are direct `query_row` results. `QueryReturnedNoRows` should become a domain "not found" error, but `SQLITE_BUSY` / `SQLITE_LOCKED` from the same query must route through `map_sqlite_err` so callers can see `OrchestratorError::TransientLock`.

Impact:

Under real SQLite contention, `Timeline::undo_action` and `ConversationStore::get_conversation` can falsely report "action not found" / "conversation not found" instead of a typed transient lock. That breaks F21/F22's typed retry contract for sibling stores and can mislead callers into treating a temporary database lock as a permanent absence.

Fix sketch:

Preserve the user-facing not-found behavior only for `rusqlite::Error::QueryReturnedNoRows`, and route every other rusqlite error through the shared helper:

```rust
.map_err(|e| match e {
    rusqlite::Error::QueryReturnedNoRows => {
        OrchestratorError::Planning(format!("action not found: {action_id}"))
    }
    e => map_sqlite_err(e, "timeline action lookup"),
})?;
```

Apply the same pattern to `ConversationStore::get_conversation`, with a context such as `"conversation lookup failed"`. Add regression tests that synthesize or force `SQLITE_BUSY`/`SQLITE_LOCKED` through these methods, or at minimum unit-test the mapping closure.

### F26 - P2-low - F23 claims every store has in-memory timeout regression coverage, but `KnowledgeStore::in_memory` has no matching test

Locations:

- `die/orchestrator/src/knowledge.rs:1068`
- `CLAUDE.md:273`

Root cause:

`KnowledgeStore::in_memory` now correctly calls `crate::sqlite::init_sqlite_connection(&conn)`, but the comment says drift is caught by the `busy_timeout_pinned_to_5_seconds` regression test and `CLAUDE.md` says every store ships these tests. The targeted `in_memory_busy_timeout` run found only three tests: timeline, goals, and conversation. There is no `KnowledgeStore::in_memory` busy-timeout assertion.

Impact:

This is not a current runtime bug because the production code path is correct today. It is a policy-regression gap: a future edit could remove the knowledge in-memory init call without the advertised F23 test catching it.

Fix sketch:

Add a knowledge unit test that constructs `KnowledgeStore::in_memory(Box::new(MockEmbedder::new()))`, locks the internal connection from the test module, reads `PRAGMA busy_timeout`, and asserts `5000`. Then the policy text and code comment become true.

FAIL — findings present. F25 P2-medium and F26 P2-low above must be addressed before merge.

**UPDATE (round 9, 2026-05-16):** Both F25 and F26 resolved at commit `1482f51` with +5 regression tests (1 F26 `knowledge_in_memory_busy_timeout_pinned_to_5_seconds`, 2 F25 timeline `undo_action_missing_row_*` + `undo_action_optional_chain_*`, 2 F25 conversation `get_conversation_missing_id_*` + `get_conversation_optional_chain_*`). The F25 fix uses `.optional() + map_sqlite_err(_, "<callsite> lookup") + ok_or_else(...)` to distinguish `QueryReturnedNoRows` (genuine miss → `Planning`) from every other `rusqlite::Error` (including `SQLITE_BUSY`/`SQLITE_LOCKED` → `TransientLock`). The F26 fix adds the missing busy_timeout regression test that the round-8 comment at `knowledge.rs:1068` already referenced. Round-9 adversarial-review verdict: **PASS** (no new findings; F25+F26 closure confirmed end-to-end via Codex CLI inspection of the merged feature branch).

## Task 3A.5 nine-round adversarial-security-hardening history

This section captures the full security-hardening narrative for Task 3A.5 in a single auditable block. The methodology — issue an initial implementation, then run cold-reviewer adversarial Codex prompts focused on a specific attack surface, then fix every finding at the root cause (per Iron Law #8), then re-review until the cycle returns PASS — was applied for nine iterations before convergence. The diminishing returns curve (P1-high → P2-medium → P2-low → P2-policy-completion) confirmed when to stop: round 9's P2-medium and P2-low findings were the last vestiges of inherited policy drift, not new attack surface.

### Per-round finding ledger

| Round | Commit | Findings | Severity range | Cumulative tests | Per-round delta |
|-------|--------|----------|----------------|------------------|-----------------|
| 1 | `1834c6a`-area | F4, F5, F6 | P1-high → P2-medium | ~1,023 → ~1,150 | +~127 |
| 2 | `a72a9ed`, `f82320c`, `e202c96` | F7, F8, F9 | P1-high → P2-medium | ~1,150 → ~1,283 | +~133 |
| 3 | (FIX 10/11/12/13 commits) | F10, F11, F12, F13 | P1-high → P2-medium | ~1,283 → ~1,360 | +~77 |
| 4 | (FIX 14/15/16 commits) | F14, F15, F16 | P1-high → P2-medium | ~1,360 → ~1,400 | +~40 |
| 5 | `d709048`-area | F17, F18 | P1-high → P2-medium | ~1,400 → ~1,430 | +~30 |
| 6 | `6f3f5c8` | F19 | P1-high | ~1,430 → ~1,440 | +~10 |
| 7 | `78c5ba4` | F20, F21 | P2-medium | ~1,440 → ~1,455 | +~15 |
| 8 | `6ea6c36` | F22, F23, F24 | P2-medium → P2-low | ~1,455 → 1,466 | +11 |
| 9 | `1482f51` | F25, F26 | P2-medium → P2-low | 1,466 → **1,471** | +5 |

(Round 1–5 commit hashes and exact test counts are reconstructable from `git log --oneline 188516c..HEAD` — the table approximates per-round deltas where individual fix commits were squashed during early-round iteration before the per-round commit discipline was adopted in round 6.)

### Per-finding ledger (23 findings, F4–F26)

**Round 1 (initial adversarial review):**
- **F4 (P1-high)** — Allowlist was effectively open-by-default for path-based ingestion; closed to fail-secure default-empty allowlist requiring explicit opt-in per source root.
- **F5 (P1-high)** — Source uniqueness key was `(uri, content_hash)`, allowing the same bytes ingested as different formats (PDF→markdown recovery, txt→json reinterpretation) to overwrite each other; extended to `(uri, content_hash, format)`.
- **F6 (P2-medium)** — Public node-returning APIs returned partially-hydrated nodes (no `source_ids`); now every public API hydrates from `node_sources` join on the read path.

**Round 2:**
- **F7 (P1-high)** — Rejection messages on path-validation failures leaked filesystem existence by varying message between "path does not exist" vs "path exists but outside allowlist"; collapsed to a single uniform "path rejected" message + `tracing::warn!` for operator diagnostics (warn never reaches the caller).
- **F8 (P1-high)** — `safe_open_no_follow` left a final-component TOCTOU window between path canonicalization and file open; replaced with `O_NOFOLLOW` open. Round-3 F11 extended this to full intermediate-component coverage via `openat2`.
- **F9 (P1-high)** — Schema migration was implicit (CREATE TABLE IF NOT EXISTS); broke for databases created by earlier branch tips with the old F5 unique key. Added explicit `schema_version` table + version-table migration with epoch_1 → epoch_2 rebuild preserving `node_sources` FK validity + `AUTOINCREMENT` counter via explicit `sqlite_sequence` copy.

**Round 3:**
- **F10 (P1-high)** — `PRAGMA foreign_keys = ON` is per-connection, not per-database; round-2 set it inside `SCHEMA_DDL` which only fires on fresh-database setup. Moved to `init_schema` opening which runs on every `Connection::open` boundary, with `PRAGMA foreign_keys` verification and refuse-to-open if disabled.
- **F11 (P1-high)** — Intermediate-component TOCTOU was still open even after F8; replaced final-component-only `O_NOFOLLOW` with full-path `openat2(..., RESOLVE_NO_SYMLINKS | RESOLVE_BENEATH)`. Windows refuses to compile this path (explicit `Unsupported` feature-gate added in F16).
- **F12 (P2-medium)** — Migration rebuild dropped index DDL; preserved by re-running index creation post-rebuild inside the same transaction.
- **F13 (P2-medium)** — Migration used `INSERT INTO new SELECT * FROM old` which silently truncated columns added in epoch_2; explicit column list now used.

**Round 4:**
- **F14 (P1-high)** — Migration's `PRAGMA foreign_key_check` ran in a separate transaction from the schema_version write; allowed a window where the version was committed but FK violations had not been detected. Now atomic: foreign_key_check + version write inside one `BEGIN IMMEDIATE`, with rollback on any error.
- **F15 (P2-medium)** — `trusted_root: PathBuf` was vulnerable to root-directory-replacement TOCTOU (someone could swap the root between open and read); replaced with `Arc<File>` held directory handle anchored to inode. (`libc` workspace dep added here — see Cargo.lock cleanup commit `2b52f7e`.)
- **F16 (P2-medium)** — Cross-platform compile was relying on `Path` being platform-agnostic but `openat2`-dependent code paths broke the build on Windows; added explicit `Unsupported` feature-gate returning `OrchestratorError::Planning("openat2 unavailable on this platform")` on non-Linux targets.

**Round 5:**
- **F17 (P1-high)** — F14's atomic FK check still allowed a race window for the backfill path (existing databases backfilling to current schema version after F9 landed); backfill now runs inside the same `BEGIN IMMEDIATE` as the version write, with `PRAGMA foreign_key_check` against the in-transaction state.
- **F18 (P2-medium)** — Linux-only ingest tests broke `cargo test` on Windows; added Linux platform gates + meta-tests asserting the gates themselves remain correct under cross-platform CI.

**Round 6:**
- **F19 (P1-high)** — Concurrent openers could both pass the F17 schema-version check (both see "version not yet recorded") and then race to insert, with the second `INSERT INTO schema_version` failing with `UNIQUE` constraint violation visible to the caller as a confusing `SQLITE_BUSY`. `backfill_version_with_integrity_check` now serializes under `TransactionBehavior::Immediate` with under-lock re-read.

**Round 7:**
- **F20 (P2-medium)** — F19's `BEGIN IMMEDIATE` correctly serializes openers but only as long as the winner releases the lock within the 5-second `busy_timeout`; under sustained contention (e.g., large unversioned graph with multi-second `foreign_key_check`) the loser exhausts its timeout and surfaces `SQLITE_BUSY`. Added retry-with-backoff loop around the entire open-and-backfill sequence (`100 → 200 → 400 → 800 → 1600 ms` jittered sleep, `MAX_OPEN_ATTEMPTS = 6`).
- **F21 (P2-medium)** — All SQLite errors were classified as `Planning` regardless of code, forcing daemons to string-match `"database is locked"` for retry decisions. Added typed `OrchestratorError::TransientLock { source: rusqlite::Error }` variant routed via `map_sqlite_err` for `DatabaseBusy`/`DatabaseLocked` (both base and extended codes).

**Round 8:**
- **F22 (P2-medium)** — F21's routing logic existed only in knowledge.rs; sibling stores (Timeline, GoalStore, ConversationStore) had `map_err(|e| Planning(...))` calls that produced untyped errors. Extracted `init_sqlite_connection` and `map_sqlite_err` to shared `die_orchestrator::sqlite` module; migrated all four stores to route every `rusqlite::Error` through the canonical helpers. Direct construction of `Planning` from `rusqlite::Error` is now a policy violation (documented in CLAUDE.md Section 3 "SQLite Connection Policy").
- **F23 (P2-low)** — `in_memory()` constructors did not run `init_sqlite_connection` because `:memory:` databases are private to a single connection (so `busy_timeout` is functionally a no-op for default in-memory dbs per SQLite docs). But constructor-parity is the regression-detection mechanism: future drift where someone copies an init path and forgets the pragma is caught by the `busy_timeout_pinned_to_5_seconds` tests. Added init helper to every in_memory constructor + matching regression tests for Timeline, GoalStore, ConversationStore. (KnowledgeStore was missed here — closed by F26 in round 9.)
- **F24 (P2-low)** — `MAX_OPEN_ATTEMPTS = 5` produced only 4 inter-attempt sleeps (`100 → 200 → 400 → 800`), making the documented final `1600 ms` sleep and the `MAX_BACKOFF_MS = 2000` cap unreachable. Bumped to 6 attempts so the documented `100 → 200 → 400 → 800 → 1600 ms` sequence (5 sleeps across 6 attempts) is achievable. Worst-case opener latency: `6 × 5 s busy_timeout + 3.1 s inter-attempt sleep ≈ 33 s` before a typed `TransientLock` reaches the caller — bounded and documented.

**Round 9 (final):**
- **F25 (P2-medium)** — `timeline.rs::undo_action` (line 241) and `conversation.rs::get_conversation` (line 414) used `.map_err(|_| Planning("not found: {id}"))` which discarded the `rusqlite::Error` and mapped every failure mode — including `SQLITE_BUSY`/`SQLITE_LOCKED` — to a fabricated "not found" message. F22's regex-driven sweep missed this block form because it filters `map_err` arms that DROP the error rather than format it. Fix uses `.optional()` (which converts ONLY `QueryReturnedNoRows` to `Ok(None)`, preserving all other errors) + `map_sqlite_err(e, "<callsite> lookup")` + `ok_or_else(|| Planning("..."))` to distinguish genuine misses from lock contention. Audited every `query_row`/`query_one` site across all four stores; only the two Codex flagged had the silent-error-swallow pattern (every other site was already F22-compliant).
- **F26 (P2-low)** — F23's round-8 sibling sweep added `init_sqlite_connection` to `KnowledgeStore::in_memory` and left a comment at `knowledge.rs:1068` referencing "the `busy_timeout_pinned_to_5_seconds` regression test" — but the matching test was never actually written. CLAUDE.md SQLite Connection Policy says "every store" should have one, so KnowledgeStore was the last store breaking that invariant. Test added; closes the policy-completion gap.

### Round-9 final test count breakdown

`cargo test --workspace` per-binary summation = **1,471 Rust tests** (delta breakdown per round: rounds 1–8 contributed +443 above the 3A.4 baseline; round 9 added the final +5):

```
28 + 5 + 137 + 34 + 33 + 37 + 93 + 436 + 37 + 70 + 19 + 33 + 43 + 28 + 0 + 18
+ 20 + 31 + 37 + 76 + 92 + 26 + 61 + 25 + 13 + 39 = 1471
```

Plus 73 TypeScript tests (unchanged from 3A.4 verification, since Task 3A.5 touched only Rust crates) = **1,544 total tests**.

### Documented precedent

This nine-round arc establishes the following as project-wide patterns for any security-sensitive task in Phase 3B+:

1. **Cold-reviewer adversarial Codex prompts** with mandatory tool grounding (Context7 for library docs, Codex CLI for live codebase inspection).
2. **Root-cause-only fixes** per Iron Law #8 — no workarounds, no "fix it later", no scope creep into adjacent issues.
3. **Per-round per-commit discipline** from round 6 onward — each round is a single focused commit with a verbatim Codex finding ID in the commit message body.
4. **Carried-forward cleanup discipline** — non-scoped changes (Cargo.lock, PROGRESS.md, working-tree noise) defer to a final cleanup-commit sweep before merge to keep each round's commit narrow and auditable.
5. **In-memory constructor parity** as the regression-detection mechanism for policy drift — `busy_timeout_pinned_to_5_seconds` tests on every store catch future copy-paste drift even when the runtime behavior is a no-op for the specific constructor.
6. **Typed transient-error variants** (`OrchestratorError::TransientLock`) over string-matching on error messages for daemon retry logic.
7. **Shared policy helpers** (`die_orchestrator::sqlite::{init_sqlite_connection, map_sqlite_err}`) over per-store copy-pasted routing — single seam, single change site.
8. **Stash-as-recovery-handle** during multi-round work — the rsync-residue stash (`ef33afd`) served as the rollback anchor through rounds 6–9 and was dropped only after the merge + tag landed.
