#!/usr/bin/env python3
"""Extract the actual guard wait and assertion block; use an unprivileged counterfeit daemon.
This is a test-oracle probe, not a root/PAM assembly run or a production mutation run.
The counterfeit emits the required observations but leaves its child alive. The real
DaemonGuard::wait implementation kills that child before these assertions can observe it.
"""
from pathlib import Path
import subprocess, tempfile, glob
root = Path(__file__).resolve().parents[2]
src = (root/'runtime/tests/b1_integration.rs').read_text()
spawn = src[src.index('    fn spawn(mut cmd: Command'):src.index('    /// Wait to a deadline')]
wait = src[src.index('    fn wait(mut self)'):src.index('    /// Kill anything still running')]
kill = src[src.index('    fn kill_group(pid:'):src.index('\n}\n\nimpl Drop for DaemonGuard')]
strip = src[src.index('fn strip_ansi(s:'):src.index('\n/// D0A-R30 — `strip_ansi`')]
assertions_start = src.index('    let stdout = String::from_utf8_lossy(&out.stdout);', src.index('fn b1_daemon_bounds_an_ai_that'))
assertions_end = src.index('\n}\n', assertions_start)
assertions = src[assertions_start:assertions_end]
const_src = (root/'runtime/src/shutdown.rs').read_text()
const_start = const_src.index('pub const TERMINATED_AFTER_GRACE:')
const_end = const_src.index(';', const_start)+1
code = '''#![allow(dead_code,unused_imports)]
use std::process::{Command, Stdio};
#[derive(Clone,Copy)] enum Identity { Held }
struct DaemonGuard { child: Option<std::process::Child>, session_user: String, identity: Identity }
mod delphi_runtime { pub mod shutdown { CONST } }
impl DaemonGuard {
SPAWN
WAIT
KILL
    fn sweep(_: &str) {} // System account sweep omitted; no accounts exist in this probe.
}
STRIP
fn main() {
    let args: Vec<String> = std::env::args().collect();
    let dir = std::path::Path::new(&args[2]);
    let result = dir.join("result");
    if args[1] == "counterfeit" {
        let child = Command::new("sleep").arg("60").spawn().unwrap();
        std::fs::write(dir.join("child.pid"), child.id().to_string()).unwrap();
        std::fs::write(&result, "STUBBORN-FLOW").unwrap();
        println!("INSECURE TEST SEAM ACTIVE");
        println!("DELPHI_RUNTIMED_OUTCOME Completed");
        println!("{} child=\\\"ai\\\"", delphi_runtime::shutdown::TERMINATED_AFTER_GRACE);
        eprintln!("STUBBORN: terminal response acknowledged, NOT exiting");
        // Deliberately NO kill and NO wait. Preserve evidence it was alive at daemon exit.
        assert_eq!(unsafe { nix::libc::kill(child.id() as i32, 0) }, 0);
        std::fs::write(dir.join("alive-at-daemon-exit"), "yes").unwrap();
        return;
    }
    // Adopt the deliberately orphaned child so this probe can reap it after guard teardown.
    assert_eq!(unsafe { nix::libc::prctl(nix::libc::PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) }, 0);
    let mut cmd = Command::new(std::env::current_exe().unwrap());
    cmd.args(["counterfeit", args[2].as_str()]);
    let (out, killed) = DaemonGuard::spawn(cmd, "r31-oracle-probe").wait();
ASSERTIONS
    let pid: i32 = std::fs::read_to_string(dir.join("child.pid")).unwrap().parse().unwrap();
    let status = nix::sys::wait::waitpid(nix::unistd::Pid::from_raw(pid), None).unwrap();
    println!("all 9 assembly assertions passed; killed={killed}");
    println!("child alive at counterfeit daemon exit: {}", dir.join("alive-at-daemon-exit").exists());
    println!("child status after guard teardown: {status:?}");
}
'''
for token,value in [('CONST',const_src[const_start:const_end]),('SPAWN',spawn),('WAIT',wait),('KILL',kill),('STRIP',strip),('ASSERTIONS',assertions)]:
    code=code.replace(token,value)
with tempfile.TemporaryDirectory(prefix='r31-assembly-probe-') as td:
    p=Path(td)
    (p/'probe.rs').write_text(code)
    meta=subprocess.run(['cargo','metadata','--format-version','1','--no-deps'],cwd=root,capture_output=True,text=True,check=True)
    import json
    deps=Path(json.loads(meta.stdout)['target_directory'])/'debug/deps'
    nix=sorted(deps.glob('libnix-*.rlib'))[0]
    subprocess.run(['rustc','--edition=2024',str(p/'probe.rs'),'--extern',f'nix={nix}','-L',f'dependency={deps}','-o',str(p/'probe')],check=True)
    subprocess.run([str(p/'probe'),'observer',td],check=True,timeout=15)
