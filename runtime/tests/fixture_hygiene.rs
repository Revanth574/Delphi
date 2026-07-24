// SPDX-License-Identifier: MIT

//! **Fixture hygiene — no test may delete a system file it did not create.**
//!
//! `docs/DEFECT_CLASSES.md` **Class 16**. This guard exists because the defect was found
//! three times in one crate, and the first fix caught only two of them: `b1_integration.rs`
//! and `end_to_end.rs` were repaired while `pam_interposition.rs` — a third file writing and
//! `remove_file`-ing the same `/etc/pam.d/delphi-runtime` — was missed, so the operator's
//! installed stack was still deleted mid-run. The fix that only covers the copies you
//! happened to know about is not a fix; a copy-paste defect needs a check that sees ALL
//! copies.
//!
//! **Then it recurred on a DIFFERENT path (Class 17).** After all three PAM copies were
//! fixed, `systemd_smoke.rs` was found deleting `/usr/libexec/delphi-runtimed` — the
//! operator's installed *daemon binary* — with the same unconditional-`remove_file`
//! teardown. The original version of this guard watched only ONE shared path
//! (`/etc/pam.d/delphi-runtime`), so it was blind to the identical defect on the binary
//! path: the very "covers-one-shape-misses-the-others" mistake it was written to stop,
//! reproduced one level up. **The guard now watches EVERY operator-owned system path the
//! fixtures touch, not just the PAM one** — because the defect propagates by copy onto
//! whatever shared path a new test happens to write.
//!
//! # What is checked
//!
//! Any file under `runtime/tests/` that `remove_file`s one of the operator-owned
//! `SHARED_SYSTEM_PATHS` (by the path literal, or by a `const` bound to it) must also carry
//! the ownership flag (`provisioned`) that gates removal on having created the file. That is
//! the adopt-or-provision / backup-and-restore contract from Class 16.
//!
//! **Operator-owned, deliberately.** `/etc/systemd/system/delphi-runtimed@.service` is NOT
//! on the list: the installer ships the unit to `/usr/lib/systemd/system/`, so the `/etc`
//! copy is exclusively test scaffolding and a test may freely delete it. The list is exactly
//! the paths the installer writes and the operator therefore owns.
//!
//! # Why this is a source audit, and how it avoids Class 15
//!
//! The property is "no OTHER file in this directory reintroduces the pattern" — inherently
//! about files this test does not contain, so it cannot be expressed as a `compile_fail`
//! doctest (Class 15's enumerative mechanism reaches only named shapes from outside a
//! module). It also **excludes its own source**, which is the Class-15 trap: this file
//! necessarily mentions the shared paths and `remove_file` as literals, and scanning itself
//! would make it its own violation.
//!
//! It is a heuristic, deliberately: it cannot prove a fixture is correct, only that a
//! known-destructive shape (`remove_file` of a shared operator path) carries the known
//! guard. That is enough to stop the copy-paste, which is how this defect actually
//! propagated — twice, onto two different paths.

use std::path::Path;

/// The operator-owned system paths the installer writes and a fixture must therefore never
/// delete without proving it created the file. Extend this the moment a fixture writes a NEW
/// installer-owned path — that is the Class-17 lesson made mechanical.
const SHARED_SYSTEM_PATHS: &[&str] = &[
    "/etc/pam.d/delphi-runtime",                     // PAM stack (installer/install.sh)
    "/usr/libexec/delphi-runtimed",                  // daemon binary (installer/install.sh)
    "/usr/lib/systemd/system/delphi-runtimed",       // unit, installer's path (NOT the /etc test copy)
];
/// The ownership flag that gates removal (Class 16's adopt-or-provision contract).
const OWNERSHIP_FLAG: &str = "provisioned";
/// This file — excluded from its own audit (see the module docs).
const SELF: &str = "fixture_hygiene.rs";

/// `const NAME: &str = "…<one of the shared paths>…";` → `NAME`. Lets the audit follow a
/// `remove_file(NAME)` back to the shared path it names, so `remove_file(&base)` (a
/// test-owned `/run` dir) is correctly NOT treated as deleting a shared path.
fn shared_path_consts(src: &str) -> Vec<String> {
    src.lines()
        .filter_map(|line| {
            let l = line.trim();
            let rest = l.strip_prefix("const ")?;
            if !SHARED_SYSTEM_PATHS.iter().any(|p| l.contains(p)) {
                return None;
            }
            let name = rest.split(':').next()?.trim();
            (!name.is_empty()).then(|| name.to_string())
        })
        .collect()
}

/// Does `src` `remove_file` one of the shared operator paths — by a bound const, or by the
/// path literal directly?
fn deletes_a_shared_path(src: &str) -> bool {
    let by_const = shared_path_consts(src).iter().any(|c| {
        src.contains(&format!("remove_file({c}")) || src.contains(&format!("remove_file(&{c}"))
    });
    let by_literal = SHARED_SYSTEM_PATHS
        .iter()
        .any(|p| src.contains(&format!("remove_file(\"{p}")));
    by_const || by_literal
}

#[test]
fn no_test_fixture_deletes_a_system_file_it_may_not_own() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests");
    let mut offenders = Vec::new();
    let mut audited = 0usize;

    for entry in std::fs::read_dir(&dir).expect("read runtime/tests").flatten() {
        let path = entry.path();
        let name = path.file_name().unwrap_or_default().to_string_lossy().to_string();
        if path.extension().is_none_or(|e| e != "rs") || name == SELF {
            continue;
        }
        let src = std::fs::read_to_string(&path).unwrap_or_default();
        if !SHARED_SYSTEM_PATHS.iter().any(|p| src.contains(p)) {
            continue;
        }
        audited += 1;
        // A fixture that can DELETE a shared operator path must gate that on having created
        // it (adopt-or-provision) or on having backed it up (backup-and-restore) — both carry
        // the `provisioned` token.
        if deletes_a_shared_path(&src) && !src.contains(OWNERSHIP_FLAG) {
            offenders.push(name);
        }
    }

    // Guard the guard: if the audit matched nothing, it is vacuous and would stay green
    // through any regression. The crate is known to have several fixtures touching these
    // paths (the PAM stack, the daemon binary).
    assert!(
        audited >= 2,
        "fixture-hygiene audit examined only {audited} file(s) referencing any of \
         {SHARED_SYSTEM_PATHS:?} — it has stopped matching and would pass vacuously. Check the \
         path constants."
    );

    assert!(
        offenders.is_empty(),
        "Class 16/17 VIOLATION — these fixtures can delete an operator-owned system path \
         (one of {SHARED_SYSTEM_PATHS:?}) without proving they created it: {offenders:?}.\n\
         A test must NEVER delete a system file it did not create: once the installer writes \
         that path, teardown destroys the operator's real artifact, and the symptom surfaces \
         far away as later tests / runs reporting `not installed`.\n\
         Fix with adopt-or-provision (config the operator owns: if present, ADOPT and record \
         `{OWNERSHIP_FLAG} = false`; if absent, write it and record `{OWNERSHIP_FLAG} = true`; \
         teardown removes ONLY when true) OR backup-and-restore (an artifact the test must \
         supply fresh: rename the operator's file aside, install the test's, and RESTORE the \
         original on teardown instead of deleting it)."
    );
}
