#!/usr/bin/env python3
"""Compare old/fixed retry-deletion paths, including a subsequent reused test thread."""
import json
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]
meta = json.loads(subprocess.check_output(['cargo','metadata','--format-version','1','--no-deps'],cwd=ROOT))
deps = Path(meta['target_directory']) / 'debug/deps'
nix = sorted(deps.glob('libnix-*.rlib'))[0]
with tempfile.TemporaryDirectory(prefix='d0a-r34-sender-') as tmp:
    td = Path(tmp)
    for label, pin in [('before','04428d2'), ('after','d94875d')]:
        src = subprocess.check_output(['git','show',f'{pin}:runtime/src/test_child_guard.rs'],cwd=ROOT,text=True)
        guard = src[src.index('use nix::unistd::Pid;'):src.index('/// Assert no previous run')]
        guard = guard.replace('                Err(nix::errno::Errno::EINTR) => continue,\n','')
        test = src[src.index('#[cfg(test)]\nmod eintr_tests'):]
        test = test.replace('    #[test]\n','').replace('    fn reap_status_retries_', '    pub fn reap_status_retries_')
        test = test.rsplit('\n}',1)[0] + '''
    pub fn count() -> usize { DELIVERED.load(Ordering::Relaxed) }
}
'''
        code = guard + test + '''
fn main() {
    let (tx,rx) = std::sync::mpsc::channel();
    let test = std::thread::spawn(move || {
        tx.send(unsafe {nix::libc::pthread_self()}).unwrap();
        std::panic::catch_unwind(eintr_tests::reap_status_retries_a_waitpid_interrupted_by_a_signal).is_err()
    });
    let former_target = rx.recv().unwrap();
    assert!(test.join().unwrap(), "retry deletion must panic");
    let next = std::thread::spawn(move || {
        let reused = unsafe {nix::libc::pthread_self()} == former_target;
        let before = eintr_tests::count();
        std::thread::sleep(std::time::Duration::from_millis(300));
        let delivered = eintr_tests::count() - before;
        println!("thread_identity_reused={reused} signals_during_subsequent_thread={delivered}");
        let mut child = std::process::Command::new("sleep").arg("0.1").spawn().unwrap();
        let waited = nix::sys::wait::waitpid(nix::unistd::Pid::from_raw(child.id() as i32), None);
        println!("subsequent_thread_wait={waited:?}");
        if waited.is_err() {
            child.kill().unwrap();
            child.wait().unwrap();
        }
    });
    next.join().unwrap();
    // Any leaked sender ends with this isolated observer process.
}
'''
        rs, exe = td / f'{label}.rs', td / label
        rs.write_text(code)
        subprocess.run(['rustc','--edition=2024','--cfg','test',str(rs),'--extern',f'nix={nix}',
                        '-L',f'dependency={deps}','-o',str(exe)],check=True,capture_output=True)
        for i in range(3):
            result = subprocess.run([str(exe)],capture_output=True,text=True,timeout=5)
            print(f'{label} run={i+1} rc={result.returncode} {result.stdout.strip()}',flush=True)
            if result.returncode:
                print(result.stderr,flush=True)
