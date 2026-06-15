# Starter Tasks (good first issues)

Real, honestly-scoped work grounded in gaps the codebase actually has — not invented
exercises. Each entry cites the file and the finding it comes from (the quality review's
`SFS-*` / `INF-*` / `BVB-*` IDs, or the honesty pass). Scopes: **S** ≈ <half a day, **M** ≈
a day or two. Read [`CONTRIBUTING.md`](CONTRIBUTING.md) first; every fix ships a regression
test proven to fail against the pre-fix code.

> **Security-relevant** tasks (marked 🔒) change code under `fortress/`, ZKQP, or an
> agent-input boundary and therefore require the Codex adversarial review before merge
> (`CLAUDE.md` §8) — still fine for a first contribution, just expect that gate.
>
> These are not filed as GitHub issues yet. A maintainer will open them (or confirm before
> you do) — do not bulk-file via `gh` without checking first.

## Small

1. **Cap file size in the indexer** — `semantic-fs/src/indexer.rs:243` (`SFS-3`). `index_file`
   does `fs::read_to_string` with no size limit, so a multi-GB file stalls the indexer. Add a
   configurable max-size guard that skips oversized files and logs at `warn`. *(S)*

2. **Lenient search query parsing** — `semantic-fs/src/indexer.rs` `search` (`SFS-4`). Strict
   `parse_query` turns user metacharacters (`:`, `AND`, `(`) into hard errors. Switch to
   tantivy's lenient parser (verify the exact API against tantivy 0.25 docs first) so
   natural-language input returns results instead of erroring. *(S)*

3. **Use the `tempfile` crate in semantic-fs tests** — (`SFS-6`). Tests hand-roll
   `std::env::temp_dir()` directories that litter on failure; the workspace convention is the
   `tempfile` dev-dep (already used elsewhere). Add the dev-dep and convert the tests. *(S)*

4. **Add a `Generation` inference error variant** — `die/inference/src/model.rs` (`INF-5`).
   Tokenization/decode/context failures *during generation* are all wrapped as
   `InferenceError::ModelLoad`, so the message reads "model load failed: decode failed"
   mid-generation. Add a `Generation(String)` variant and route generation-time failures to it. *(S)*

5. **Locate models via the `dirs` crate** — `die/inference/src/model.rs:66` (`INF-6`).
   `model_dir()` hardcodes the XDG layout via `home_dir()`, which is wrong on macOS/Windows
   (Phase 3C cross-OS) and against `CLAUDE.md` §3. Use `dirs::data_local_dir()`; drop the
   Unix-only `/tmp` fallback. *(S)*

6. **Drain subprocess stderr** — `die/browser/src/engine.rs:252`, `die/voice/src/tts.rs:197`
   (`BVB-2`). Both engines pipe stderr and never read it; a chatty child fills the ~64 KB pipe
   buffer and deadlocks. Drain stderr to `tracing` on a background task (or `Stdio::null()` it
   deliberately). A real latent bug with a clean fix. *(S)*

7. **🔒 URL scheme allowlist on browser navigation** — `die/browser/src/engine.rs` `navigate`
   (`BVB-3`). Any URL is accepted, including `file://` (a local-file read path adjacent to the
   prompt-injection boundary). Add an `http`/`https` allowlist at the engine door. Security-
   relevant → Codex review before merge. *(S)*

## Medium

8. **Implement watcher debounce + batch commit** — `semantic-fs/src/watcher.rs` (`SFS-2`; the
   doc was just corrected to admit it's unimplemented). Coalesce editor write-rename-delete
   save-bursts and commit in batches instead of after every file (Tantivy commits fsync, so a
   save-burst is a commit storm today). *(M)*

9. **Gate cloud retries on transience** — `die/inference/src/cloud.rs` (`INF-4`). The client
   retries *all* failures with backoff, including deterministic 4xx (401 bad key, 400
   malformed) — three identical failures plus sleeps for a request that will never succeed.
   Retry only on transient conditions (timeout / connect / 5xx / 429). *(M)*

10. **`{{project_name}}` substitution in the builder** — `die/builder` (`BVB-1`). Templates copy
    verbatim and the placeholder survives (a test currently *asserts* it survives). Add
    `minijinja` (per `CLAUDE.md` §2) and substitute template variables on scaffold. *(M)*

11. **Implement `LocalEmbedder`** — `die/orchestrator/src/knowledge.rs` (the documented stub).
    `embed()` returns an empty vector with `Unavailable` fidelity. Fulfill the **existing**
    contract — this is implementation, not design: the `Embedder` trait and the
    `with_model(path, dimension)` constructor are already defined, and the model is settled by
    `CLAUDE.md` §2 (**all-MiniLM-L6-v2 via `candle`**, 384-dim). Load the model at the given path,
    run inference (tokenize → encode → mean-pool → normalize), and keep the `Unavailable`
    fallback when no model is present. (If you find yourself *choosing* a model, dimension, or
    trait shape, stop — that's a design task, not this one.) *(M; candle/transformer-inference
    experience helpful)*

12. **Adopt `rustfmt`** — workspace (`CLAUDE.md` §6, deferred item). The tree is not
    rustfmt-clean (no `rustfmt.toml`). Land formatting as its **own isolated** `style(workspace)`
    commit with a pinned `rustfmt.toml` and a `.git-blame-ignore-revs` entry, then add the fmt
    gate to the pre-commit hook and CI — never bundled into a logic change. *(M)*

## Larger, tracked — not first issues

These are real and recorded, but too involved for a first contribution (design + review):

- **At-rest encryption** (`fortress` `EncryptionService` stub) — security-critical; needs design
  + Codex review.
- **Incremental re-index correctness** (`SFS-1`) — re-saving a file adds a duplicate document;
  the fix is a schema change (`path` as an indexed term so `delete_term` works) and a behavioral
  change requiring ratification.
- **A runnable daemon** — the workspace has no executable target; bringing one up is the next
  major arc, not a starter task.
