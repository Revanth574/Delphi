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
//! # What is checked
//!
//! Any file under `runtime/tests/` that BOTH references the shared PAM path AND calls
//! `remove_file` must also carry the ownership flag (`provisioned`) that gates removal on
//! having created the file. That is the adopt-or-provision contract from Class 16.
//!
//! # Why this is a source audit, and how it avoids Class 15
//!
//! The property is "no OTHER file in this directory reintroduces the pattern" — inherently
//! about files this test does not contain, so it cannot be expressed as a `compile_fail`
//! doctest (Class 15's enumerative mechanism reaches only named shapes from outside a
//! module). It also **excludes its own source**, which is the Class-15 trap: this file
//! necessarily mentions both `remove_file` and the PAM path as literals, and scanning
//! itself would make it its own violation.
//!
//! It is a heuristic, deliberately: it cannot prove a fixture is correct, only that the
//! known-destructive shape carries the known guard. That is enough to stop the copy-paste,
//! which is how this defect actually propagated.

use std::path::Path;

/// The shared system path the fixtures contend over.
const SHARED_SYSTEM_PATH: &str = "/etc/pam.d/delphi-runtime";
/// The ownership flag that gates removal (Class 16's adopt-or-provision contract).
const OWNERSHIP_FLAG: &str = "provisioned";
/// This file — excluded from its own audit (see the module docs).
const SELF: &str = "fixture_hygiene.rs";

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
        if !src.contains(SHARED_SYSTEM_PATH) {
            continue;
        }
        audited += 1;
        // A fixture that can DELETE the shared path must gate that on having created it.
        if src.contains("remove_file") && !src.contains(OWNERSHIP_FLAG) {
            offenders.push(name);
        }
    }

    // Guard the guard: if the audit matched nothing, it is vacuous and would stay green
    // through any regression. The crate is known to have several such fixtures.
    assert!(
        audited >= 2,
        "fixture-hygiene audit examined only {audited} file(s) referencing {SHARED_SYSTEM_PATH} \
         — it has stopped matching and would pass vacuously. Check the path constant."
    );

    assert!(
        offenders.is_empty(),
        "Class 16 VIOLATION — these fixtures can delete {SHARED_SYSTEM_PATH} without proving \
         they created it: {offenders:?}.\n\
         A test must NEVER delete a system file it did not create: once production installs \
         that path, teardown destroys the operator's real artifact, and the symptom surfaces \
         far away as later tests reporting `not installed`.\n\
         Fix with adopt-or-provision: if the file already exists, ADOPT it and record \
         `{OWNERSHIP_FLAG} = false`; only if absent, write it and record `{OWNERSHIP_FLAG} = \
         true`. Teardown removes it ONLY when `{OWNERSHIP_FLAG}` is true."
    );
}
