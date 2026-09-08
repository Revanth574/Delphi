#!/usr/bin/env python3
"""Retained real signal-injection experiment for ChildGuard::reap_status.
Build exact helper implementations at the pre-fix and reviewed revisions. The link wrapper
observes actual waitpid EINTR results; it does not inject errno. SIGUSR1 is delivered to the
waiting thread without SA_RESTART. All children belong to this probe and are cleaned up.
"""
from pathlib import Path
import json, subprocess, tempfile
ROOT=Path(__file__).resolve().parents[2]
meta=subprocess.run(['cargo','metadata','--format-version','1','--no-deps'],cwd=ROOT,capture_output=True,text=True,check=True)
deps=Path(json.loads(meta.stdout)['target_directory'])/'debug/deps'
nix=sorted(deps.glob('libnix-*.rlib'))[0]
probe=r'''
use std::sync::atomic::{AtomicBool,AtomicUsize,Ordering};
use std::sync::Arc;
use std::time::Duration;
static INTERRUPTS: AtomicUsize = AtomicUsize::new(0);
unsafe extern "C" {
    fn __real_waitpid(pid:i32,status:*mut i32,flags:i32)->i32;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn __wrap_waitpid(pid:i32,status:*mut i32,flags:i32)->i32 {
    let rc=unsafe { __real_waitpid(pid,status,flags) };
    if rc == -1 && unsafe { *nix::libc::__errno_location() } == nix::libc::EINTR {
        INTERRUPTS.fetch_add(1,Ordering::SeqCst);
    }
    rc
}
extern "C" fn handler(_:i32) {}
fn main() {
    unsafe {
        let mut sa:nix::libc::sigaction=std::mem::zeroed();
        sa.sa_sigaction=handler as usize;
        sa.sa_flags=0; // no SA_RESTART
        nix::libc::sigemptyset(&mut sa.sa_mask);
        assert_eq!(nix::libc::sigaction(nix::libc::SIGUSR1,&sa,std::ptr::null_mut()),0);
    }
    let child=std::process::Command::new("sleep").arg("1").spawn().unwrap();
    let pid=nix::unistd::Pid::from_raw(child.id() as i32);
    let target=unsafe { nix::libc::pthread_self() };
    let stop=Arc::new(AtomicBool::new(false));
    let sender_stop=Arc::clone(&stop);
    let sender=std::thread::spawn(move || {
        while !sender_stop.load(Ordering::SeqCst) {
            std::thread::sleep(Duration::from_millis(10));
            if !sender_stop.load(Ordering::SeqCst) {
                assert_eq!(unsafe { nix::libc::pthread_kill(target,nix::libc::SIGUSR1) },0);
            }
        }
    });
    let answer=std::panic::catch_unwind(|| helper::ChildGuard::arm(pid).reap_status());
    stop.store(true,Ordering::SeqCst);
    sender.join().unwrap();
    let state=nix::sys::wait::waitpid(pid,Some(nix::sys::wait::WaitPidFlag::WNOHANG));
    println!("observed_waitpid_EINTR={}, panicked={}, reap_return={:?}, child_after_guard={:?}",INTERRUPTS.load(Ordering::SeqCst),answer.is_err(),answer.as_ref().ok(),state);
    if matches!(state,Ok(nix::sys::wait::WaitStatus::StillAlive)) {
        nix::sys::signal::kill(pid,nix::sys::signal::Signal::SIGKILL).unwrap();
        nix::sys::wait::waitpid(pid,None).unwrap();
    }
    assert!(INTERRUPTS.load(Ordering::SeqCst)>0,"probe did not interrupt waitpid");
}
'''
with tempfile.TemporaryDirectory(prefix='r31-eintr-') as td:
    p=Path(td)
    for sha in ['2c7dee0','63af7f7']:
        source=subprocess.run(['git','show',f'{sha}:runtime/src/test_child_guard.rs'],cwd=ROOT,check=True,capture_output=True,text=True).stdout
        helper=source[source.index('use nix::unistd::Pid;'):source.index('/// Assert no previous run')]
        (p/'probe.rs').write_text('mod helper {\n'+helper+'\n}\n'+probe)
        subprocess.run(['rustc','--edition=2024',str(p/'probe.rs'),'--extern',f'nix={nix}','-L',f'dependency={deps}','-C','link-arg=-Wl,--wrap=waitpid','-o',str(p/'probe')],check=True)
        print('REVISION',sha,flush=True)
        subprocess.run([str(p/'probe')],check=True,timeout=10)
