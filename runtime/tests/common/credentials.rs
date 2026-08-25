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

/// Record the validated tuple once per test process. No-op unless euid 0.
pub fn plan_credentials_once() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        if nix::unistd::geteuid().as_raw() != 0 {
            return;
        }
        // A missing account at root is a real condition other tests assert on; recording
        // `None` would MASK it by making the drop silently not happen.
        if let Some(u) = nix::unistd::User::from_name(delphi_runtime::execute::TOOL_ACCOUNT)
            .ok()
            .flatten()
        {
            let _ = delphi_runtime::execute::set_tool_credentials(Some((
                u.uid.as_raw(),
                u.gid.as_raw(),
            )));
        }
    });
}
