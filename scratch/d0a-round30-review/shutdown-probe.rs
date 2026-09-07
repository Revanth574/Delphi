// Retained review probe for pinned 9fa4017. Links the actual shutdown source.
#[path = "../../runtime/src/shutdown.rs"]
mod shutdown;
use std::process::{Command, Stdio};
use std::time::Duration;
fn main() {
    for (name, script) in [("exit7", "exit 7"), ("sigterm", "kill -TERM $$")] {
        let child = Command::new("sh").args(["-c", script]).stdout(Stdio::null()).stderr(Stdio::null()).spawn().unwrap();
        let pid = child.id() as i32;
        let mut info: nix::libc::siginfo_t = unsafe { std::mem::zeroed() };
        // Wait for a terminal condition WITHOUT reaping, removing scheduler dependence.
        let rc = unsafe { nix::libc::waitid(nix::libc::P_PID, pid as u32, &mut info, nix::libc::WEXITED | nix::libc::WNOWAIT) };
        assert_eq!(rc, 0);
        let actual = shutdown::shutdown_child(pid, Duration::from_secs(1), Duration::from_secs(1));
        println!("{name}: {actual:?}");
    }
}
