#!/usr/bin/env python3
"""Pinned-source, unprivileged review probes; no user checkout mutations."""
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]
PIN = '5fca885'


def source(rel):
    return subprocess.check_output(['git', 'show', f'{PIN}:{rel}'], cwd=ROOT, text=True)


def cleanup_probe(td):
    repo = td / 'repo'
    (repo / 'scripts').mkdir(parents=True)
    script = repo / 'scripts/mutation-campaign.py'
    script.write_text(source('scripts/mutation-campaign.py'))
    def git(*args):
        return subprocess.check_output(['git', '-c', 'core.hooksPath=/dev/null', *args],
                                       cwd=repo, stderr=subprocess.DEVNULL, text=True).strip()
    git('init', '-q')
    git('add', '.')
    git('-c', 'user.name=Review', '-c', 'user.email=review@example.invalid',
        'commit', '-qm', 'disposable fixture')
    spec = importlib.util.spec_from_file_location('mc', script)
    mc = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mc)
    work = mc.make_isolated_checkout(git('rev-parse', 'HEAD'))
    blocked = work / 'unreadable-fixture'
    blocked.mkdir()
    (blocked / 'payload').write_text('owned resource')
    blocked.chmod(0)
    try:
        mc.remove_isolated_checkout()
        print('cleanup:', json.dumps({'returned_normally': True,
              'parent_survives': work.parent.exists(), 'tree_survives': work.exists(),
              'ownership_record': mc._WORKTREE,
              'registered': str(work) in git('worktree', 'list')}), flush=True)
        assert work.exists() and mc._WORKTREE == {}
    finally:
        blocked.chmod(0o700)
        shutil.rmtree(work.parent)
        git('worktree', 'prune', '--expire', 'now')


def rust_probes(td):
    meta = json.loads(subprocess.check_output(
        ['cargo', 'metadata', '--format-version', '1', '--no-deps'], cwd=ROOT))
    deps = Path(meta['target_directory']) / 'debug/deps'
    nix = sorted(deps.glob('libnix-*.rlib'))[0]
    def compile_run(label, code):
        rs = td / f'{label}.rs'
        exe = td / label
        rs.write_text(code)
        subprocess.run(['rustc', '--edition=2024', '--cfg', 'test', str(rs),
                        '--extern', f'nix={nix}', '-L', f'dependency={deps}',
                        '-o', str(exe)], check=True, capture_output=True)
        r = subprocess.run([str(exe)], capture_output=True, text=True, timeout=10)
        print(label + ':', r.stdout.strip(), 'exit=' + str(r.returncode), flush=True)
        if r.returncode:
            print(r.stderr, flush=True)
        assert r.returncode == 0

    src = source('runtime/src/test_child_guard.rs')
    guard = src[src.index('use nix::unistd::Pid;'):src.index('/// Assert no previous run')]
    test = src[src.index('#[cfg(test)]\nmod eintr_tests'):]
    # Make the exact test callable and observe private handler state after unwind.
    test = test.replace('    #[test]\n', '')
    test = test.replace('    fn reap_status_retries_', '    pub fn reap_status_retries_')
    observer = '''
    pub fn count() -> usize { DELIVERED.load(Ordering::Relaxed) }
'''
    test = test.rsplit('\n}', 1)[0] + observer + '\n}\n'
    for weakened in (False, True):
        g = guard.replace('                Err(nix::errno::Errno::EINTR) => continue,\n', '') if weakened else guard
        code = g + test + '''
fn main() {
    let result = std::panic::catch_unwind(
        eintr_tests::reap_status_retries_a_waitpid_interrupted_by_a_signal);
    let before = eintr_tests::count();
    std::thread::sleep(std::time::Duration::from_millis(100));
    let after = eintr_tests::count();
    println!("panicked={} signals_after_return={}", result.is_err(), after-before);
    assert_eq!(result.is_err(), WEAKENED);
    assert_eq!(after > before, WEAKENED);
    // Exit the isolated process: the leaked sender is intentionally not left on the host.
    std::process::exit(0);
}
'''.replace('WEAKENED', str(weakened).lower())
        compile_run('eintr_weakened' if weakened else 'eintr_restored', code)

    src = source('runtime/tests/b1_integration.rs')
    scan = src[src.index('fn live_group_members(pgid:'):src.index('\n/// Strip ANSI SGR')]
    comm = src[src.index('fn comm_of(pid:'):src.index('\n/// D0A-R31-02', src.index('fn comm_of(pid:'))]
    control = src[src.index('    let probe = std::thread::spawn(move || {', src.index('fn b1_daemon_bounds_')):src.index('\n\n    let run = guard.wait();', src.index('fn b1_daemon_bounds_'))]
    # Only the observation horizon changes (140s -> 1s). Membership is stable throughout.
    control = control.replace('Duration::from_secs(140)', 'Duration::from_secs(1)')
    code = scan + comm + '''
use std::process::{Command, Stdio};
use std::os::unix::process::CommandExt;
fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() > 1 {
        unsafe { nix::libc::prctl(nix::libc::PR_SET_NAME, c"sai".as_ptr(), 0, 0, 0); }
        std::thread::sleep(std::time::Duration::from_secs(60));
        return;
    }
    assert_eq!(unsafe { nix::libc::prctl(nix::libc::PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) }, 0);
    // Actual child of the stand-in daemon/leader, but placed in a separate group.
    // Another child stays in the inherited group: this is a real topology defect,
    // not a comm mismatch or missed observation window.
    let mut leader = Command::new("python3").args(["-c",
        "import subprocess,sys,time; a=subprocess.Popen([sys.argv[1], 'ai'], process_group=0); s=subprocess.Popen(['sleep','60']); print(a.pid, s.pid, flush=True); time.sleep(60)",
        std::env::current_exe().unwrap().to_str().unwrap()])
        .process_group(0).stdout(Stdio::piped()).spawn().unwrap();
    use std::io::BufRead;
    let mut line = String::new();
    std::io::BufReader::new(leader.stdout.take().unwrap()).read_line(&mut line).unwrap();
    let children: Vec<i32> = line.split_whitespace().map(|s| s.parse().unwrap()).collect();
    let (ai_pid, shell_pid) = (children[0], children[1]);
    let daemon_pid = leader.id() as i32;
    let probe_comm = String::from("sai");
CONTROL
    let (seen, census, samples) = probe.join().unwrap();
    println!("seen={seen:?} census={census:?} samples={samples} ai_pgid={}",
             nix::unistd::getpgid(Some(nix::unistd::Pid::from_raw(ai_pid))).unwrap());
    unsafe { nix::libc::kill(ai_pid, nix::libc::SIGKILL); }
    unsafe { nix::libc::kill(shell_pid, nix::libc::SIGKILL); }
    leader.kill().unwrap(); leader.wait().unwrap();
    nix::sys::wait::waitpid(nix::unistd::Pid::from_raw(ai_pid), None).unwrap();
    nix::sys::wait::waitpid(nix::unistd::Pid::from_raw(shell_pid), None).unwrap();
    assert!(seen.is_empty() && !census.is_empty());
}
'''.replace('CONTROL', control)
    compile_run('control_attribution', code)


if __name__ == '__main__':
    with tempfile.TemporaryDirectory(prefix='d0a-r33-review-') as tmp:
        td = Path(tmp)
        cleanup_probe(td)
        rust_probes(td)
