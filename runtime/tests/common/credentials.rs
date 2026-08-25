// SPDX-License-Identifier: MIT

//! Plan the tool credentials the way the daemon does — for INTEGRATION tests.
//!
//! `execute::tests::plan_credentials_once` is `#[cfg(test)]`, so it does not exist for an
//! integration test: those link the library compiled WITHOUT `cfg(test)`. That is why the
//! lib-target fix (D0A lane run 3) left seven integration fixtures still broken — the same
//! defect, in the half of the tree the first fix could not reach.
//!
//! At euid 0 with no plan recorded, `decide_credentials` REFUSES by design (D0A-R11-06):
//! "execution denied: no validated tool identity was recorded before this action". A fixture
//! that never plans therefore never executes, and asserts on an empty result.

/// Record the validated tuple once per test process, and return it. No-op unless euid 0.
pub fn plan_credentials_once() -> Option<(u32, u32)> {
    static PLANNED: std::sync::OnceLock<Option<(u32, u32)>> = std::sync::OnceLock::new();
    *PLANNED.get_or_init(|| {
        if nix::unistd::geteuid().as_raw() != 0 {
            return None;
        }
        // A missing account at root is a real condition other tests assert on; recording
        // `None` would MASK it by making the drop silently not happen.
        let creds = nix::unistd::User::from_name(delphi_runtime::execute::TOOL_ACCOUNT)
            .ok()
            .flatten()
            .map(|u| (u.uid.as_raw(), u.gid.as_raw()));
        if let Some(c) = creds {
            let _ = delphi_runtime::execute::set_tool_credentials(Some(c));
        }
        creds
    })
}

/// Chown a directory the action will WRITE to, to the PLANNED tuple.
///
/// At root the tool is `delphi-tool`, so a directory created by the test process is not
/// writable by the thing under test. The action then writes NOTHING, and the assertion reads
/// `left: ""` — an empty result, never a permission error, because the failure happens inside
/// the jail. That signature cost five tests on lane run 4.
///
/// **This is the second implementation of a helper the library already has** — `execute::
/// tests::chown_to_tool`. Not duplication by choice: `#[cfg(test)]` items do not exist for an
/// integration test, which links the library compiled without them. The guard in execute.rs
/// is what keeps the two honest.
pub fn chown_to_tool(dir: &std::path::Path) {
    if let Some((uid, gid)) = plan_credentials_once() {
        std::os::unix::fs::chown(dir, Some(uid), Some(gid))
            .expect("chown the out dir to the tool account");
    }
}
