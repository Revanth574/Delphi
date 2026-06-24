// SPDX-License-Identifier: MIT

//! Child privilege drop — `setgroups([]) → setgid → setuid`, in that order.
//!
//! The root daemon forks the shell and the AI and drops each child to the
//! unprivileged session user *before* `execve` (`docs/TRUST_MODEL.md` §4, R3-01:
//! "Children dropped to the user"). The **order is load-bearing**: `setgroups`
//! and `setgid` must run while still privileged, and `setuid` must run **last** —
//! once root is relinquished the process can no longer set its gid or drop its
//! supplementary groups, so a `setuid`-first sequence would silently leave the
//! child in the root group set.
//!
//! 1a exercises this only enough to spawn a same-uid process for the anchor test;
//! the full shell/AI spawn is Increment 1b. The drop is written behind the
//! [`PrivDropOps`] seam so the *order* can be asserted in normal CI without root
//! (a real drop needs privileges and would unrecoverably mutate the test
//! process).

use nix::unistd::{setgid, setgroups, setuid, Gid, Uid};

use crate::RuntimeError;

/// The three privilege-management syscalls the drop performs, as a seam.
///
/// The production path uses [`RealPrivDropOps`] (which calls `nix`). Tests use a
/// recording implementation to assert the call *order* without dropping real
/// privileges.
pub trait PrivDropOps {
    /// Set the supplementary group list (the drop passes an empty slice).
    fn set_groups(&self, groups: &[Gid]) -> nix::Result<()>;
    /// Set the real/effective/saved gid.
    fn set_gid(&self, gid: Gid) -> nix::Result<()>;
    /// Set the real/effective/saved uid (must be called last).
    fn set_uid(&self, uid: Uid) -> nix::Result<()>;
}

/// The production [`PrivDropOps`], backed by `nix` syscalls.
#[derive(Debug, Default, Clone, Copy)]
pub struct RealPrivDropOps;

impl PrivDropOps for RealPrivDropOps {
    fn set_groups(&self, groups: &[Gid]) -> nix::Result<()> {
        setgroups(groups)
    }
    fn set_gid(&self, gid: Gid) -> nix::Result<()> {
        setgid(gid)
    }
    fn set_uid(&self, uid: Uid) -> nix::Result<()> {
        setuid(uid)
    }
}

/// Drop privileges to `(uid, gid)` in the canonical order
/// `setgroups([]) → setgid → setuid`.
///
/// Returns a typed [`RuntimeError::Syscall`] naming the first step that failed,
/// so the caller can report which privilege transition was rejected.
///
/// # Examples
///
/// ```no_run
/// use delphi_runtime::{drop_privileges, RealPrivDropOps};
/// use nix::unistd::{Gid, Uid};
///
/// // In a freshly forked child, before `execve`, drop to the session user.
/// drop_privileges(&RealPrivDropOps, Uid::from_raw(1000), Gid::from_raw(1000))
///     .expect("privilege drop must succeed in the child");
/// ```
pub fn drop_privileges(
    ops: &impl PrivDropOps,
    uid: Uid,
    gid: Gid,
) -> Result<(), RuntimeError> {
    ops.set_groups(&[])
        .map_err(|source| RuntimeError::Syscall { op: "setgroups", source })?;
    ops.set_gid(gid)
        .map_err(|source| RuntimeError::Syscall { op: "setgid", source })?;
    ops.set_uid(uid)
        .map_err(|source| RuntimeError::Syscall { op: "setuid", source })?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    /// Records the order in which the drop calls the seam, without touching real
    /// privileges — so this runs in normal CI (no root).
    struct RecordingOps {
        calls: RefCell<Vec<&'static str>>,
    }

    impl PrivDropOps for RecordingOps {
        fn set_groups(&self, _groups: &[Gid]) -> nix::Result<()> {
            self.calls.borrow_mut().push("setgroups");
            Ok(())
        }
        fn set_gid(&self, _gid: Gid) -> nix::Result<()> {
            self.calls.borrow_mut().push("setgid");
            Ok(())
        }
        fn set_uid(&self, _uid: Uid) -> nix::Result<()> {
            self.calls.borrow_mut().push("setuid");
            Ok(())
        }
    }

    #[test]
    fn drops_in_canonical_setgroups_setgid_setuid_order() {
        let ops = RecordingOps {
            calls: RefCell::new(Vec::new()),
        };

        drop_privileges(&ops, Uid::from_raw(60000), Gid::from_raw(60000)).unwrap();

        // The order is the property under test (R4-01 / privilege-drop discipline):
        // setuid LAST, after the gid and supplementary groups are already dropped.
        // RED-proof for this unit test: reordering `drop_privileges` to call
        // `set_uid` first makes this assertion fail.
        assert_eq!(*ops.calls.borrow(), ["setgroups", "setgid", "setuid"]);
    }

    /// A failing step short-circuits and is reported with its op name, and no
    /// later step runs.
    #[test]
    fn stops_and_names_the_failing_step() {
        struct FailGid {
            calls: RefCell<Vec<&'static str>>,
        }
        impl PrivDropOps for FailGid {
            fn set_groups(&self, _: &[Gid]) -> nix::Result<()> {
                self.calls.borrow_mut().push("setgroups");
                Ok(())
            }
            fn set_gid(&self, _: Gid) -> nix::Result<()> {
                self.calls.borrow_mut().push("setgid");
                Err(nix::errno::Errno::EPERM)
            }
            fn set_uid(&self, _: Uid) -> nix::Result<()> {
                self.calls.borrow_mut().push("setuid");
                Ok(())
            }
        }

        let ops = FailGid {
            calls: RefCell::new(Vec::new()),
        };
        let err = drop_privileges(&ops, Uid::from_raw(60000), Gid::from_raw(60000))
            .expect_err("setgid failure must propagate");

        match err {
            RuntimeError::Syscall { op, .. } => assert_eq!(op, "setgid"),
            other => panic!("expected Syscall(setgid), got {other:?}"),
        }
        // setuid must NOT have run after setgid failed.
        assert_eq!(*ops.calls.borrow(), ["setgroups", "setgid"]);
    }
}
