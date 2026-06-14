# Contributing to Delphi

Delphi is a pre-product research codebase with an unusually strict verifiable-record
discipline. The rules below are a contributor-facing summary; [`CLAUDE.md`](CLAUDE.md) is
the authoritative law (it is written for AI coding sessions but applies to all contributors).

## Development setup

**Toolchain:** Rust 1.85+ (edition 2024, stable), Node 20+ with pnpm, Python 3.12+.

```bash
git clone <repo-url> delphi && cd delphi

# Rust workspace
cargo test --workspace                                   # 1891 tests
cargo clippy --workspace --all-targets -- -D warnings    # zero warnings required

# Shell UI
cd shell && pnpm install && pnpm test && pnpm build       # 94 tests
```

There is **no runnable binary** yet — Delphi builds as libraries and runs as a test suite
(see the [README](README.md) status table). On macOS/Windows, add `--exclude compositor`
(it needs Linux Wayland libraries).

**WSL note:** the workspace `.cargo/config.toml` pins `build.target-dir` to a WSL-native
path so artifacts stay off the slow `/mnt/c` mount; `CARGO_TARGET_DIR` overrides it (CI sets
its own). See the comments in that file.

**Pre-commit hook (recommended):** enable the clippy gate once per clone:

```bash
git config core.hooksPath .githooks
```

`.githooks/pre-commit` runs `clippy -D warnings` on the crates with staged changes. There is
intentionally **no `cargo fmt` gate yet** — the workspace is not rustfmt-clean; rustfmt
adoption is deferred to its own isolated `style(workspace)` commit.

## Code quality (non-negotiable)

- `cargo clippy --workspace --all-targets -- -D warnings` must be clean.
- **No `.unwrap()` / `.expect()` in production code** (tests only). Libraries use `thiserror`;
  the orchestrator application boundary uses `anyhow`.
- Every public function has a `///` doc comment with an `# Examples` block.
- Functions ≤ 50 lines; decompose beyond that.
- `tracing` for logging — never `println!` in production.
- `#[must_use]` on functions returning `Result`/`Option`.
- All `unsafe` carries a `// SAFETY:` justification.
- TypeScript is `strict`; no `any`; functional components with hooks; Zustand for global state.
- See [`CLAUDE.md`](CLAUDE.md) §3 for the full rules and §5 for naming conventions.

## Testing

- Unit tests live with the code (`#[cfg(test)]`); integration tests in `crate/tests/`.
- Every fix ships a regression test **proven to fail against the pre-fix code** and pass
  after. A test that passes against the buggy code is worse than no test.
- CI enforces a workspace test-count floor ([`.github/rust-test-count-baseline`](.github/rust-test-count-baseline)):
  the count may rise freely; a drop fails CI (a test silently disappeared). Lowering it
  requires an explicit, justified commit.

## Git workflow

- Work on a feature branch; never commit directly to `main`.
- **Conventional Commits**: `type(scope): description` — e.g. `feat(die): …`, `fix(fortress): …`,
  `test(infra): …`, `docs(readme): …`. Types: feat/fix/refactor/docs/test/ci/perf/security.
- Every commit must compile and pass existing tests.
- `Cargo.lock` is committed (reproducible builds).

## Adversarial review

Security-critical changes get a **cold adversarial review** by an external model (Codex CLI,
run by the operator) before merge — distinct from CI. The reviewer verifies library/API
claims against documentation and the live code rather than memory, and returns a structured
**APPROVE / REVISE / FAIL** verdict with per-finding severity, root cause, and fix sketch.
Each round fixes every finding at its root with a RED-proven regression test. A review is
required for any change touching `fortress/`, credential/permission code in `services/`,
the orchestrator's ZKQP/permission/vault/cloud-routing paths, `ssi/` capability execution,
any new external network call, or a phase-boundary merge. See [`CLAUDE.md`](CLAUDE.md) §6 / §8.

## The verifiable-record principle

The thing that makes this codebase distinctive: **claims are grounded, not asserted.** Every
number in a report comes from a command that was run; every "it works" has a passing test;
"I don't know, let me check" is always correct and fabricating a plausible answer is always
wrong. Recurring defect classes are catalogued in [`docs/DEFECT_CLASSES.md`](docs/DEFECT_CLASSES.md)
and foreclosed by shared primitives in `delphi-hardening`. See [`CLAUDE.md`](CLAUDE.md) §13
(anti-hallucination protocol) and §12 (the Iron Laws — user sovereignty, mathematical
privacy, graceful degradation, fix-the-root-cause, verify-don't-fabricate, and the rest).

## License

By contributing, you agree your contributions are licensed under the MIT License.
